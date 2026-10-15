using Microsoft.Data.Sqlite;
using ProcInsider.Models.Ai;
using ProcInsider.Services.Ai;

namespace ProcInsider.Services;

public sealed partial class AnnotationDatabaseService
{
    public Task<AgentExecution> ResumeInvestigationByAnalystAsync(AgentExecution execution,
        AiExecutionLifetime lifetime, CancellationToken cancellationToken = default) =>
        Task.Run(() => NotifyAiAnnotationsChanged(StartExecution(execution, lifetime, cancellationToken, analystReentry: true)), cancellationToken);

    public Task<AgentExecution> ResumeCheckedInvestigationByAnalystAsync(AgentExecution execution,
        AiExecutionLifetime lifetime, AgentToolSession session, Func<bool> isCurrent,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => NotifyAiAnnotationsChanged(StartExecution(execution, lifetime, cancellationToken, analystReentry: true,
            session, isCurrent)), cancellationToken);

    public Task<AgentExecution> ResumeCheckedInvestigationWithQuestionAsync(AgentExecution execution,
        AiExecutionLifetime lifetime, AiConversationMessage question, AgentToolSession session,
        Func<bool> isCurrent, CancellationToken cancellationToken = default) =>
        Task.Run(() => NotifyAiAnnotationsChanged(StartExecution(execution, lifetime, cancellationToken, analystReentry: true,
            session, isCurrent, question)), cancellationToken);

    public Task<int> ReconcileAbandonedExecutionsAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => ReconcileAbandonedExecutions(cancellationToken), cancellationToken);

    public Task<Investigation> CancelNewInvestigationByAnalystAsync(string investigationId, DateTime cancelledUtc,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => NotifyAiAnnotationsChanged(CancelNewInvestigationByAnalyst(investigationId, cancelledUtc, cancellationToken)), cancellationToken);

    public Task<InvestigationTask> CancelPendingTaskByAnalystAsync(string taskId, DateTime cancelledUtc,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => NotifyAiAnnotationsChanged(CancelPendingTaskByAnalyst(taskId, cancelledUtc, cancellationToken)), cancellationToken);

    private InvestigationFinding VerifyFindingByAnalyst(string findingId, string analystId, DateTime verifiedUtc, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(findingId) || string.IsNullOrWhiteSpace(analystId) ||
            analystId.Length > 240 || verifiedUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("Analyst verification requires a trusted identity and UTC time.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var finding = ReadFindingById(connection, tx, findingId) ?? throw new InvalidOperationException("Finding is unavailable.");
            if (finding.VerificationStatus == FindingVerificationState.AnalystVerified)
            {
                if (finding.AnalystVerifiedBy != analystId || finding.AnalystVerifiedUtc != verifiedUtc)
                    throw new InvalidOperationException("Finding verification is immutable.");
                tx.Commit(); return finding;
            }
            var investigation = ReadInvestigation(connection, tx, finding.InvestigationId) ??
                throw new InvalidOperationException("Finding investigation is unavailable.");
            if (verifiedUtc < finding.CreatedUtc || verifiedUtc < investigation.UpdatedUtc)
                throw new ArgumentException("Verification precedes persisted investigation activity.");
            Execute(connection, tx, """
                UPDATE AiInvestigationFindings SET VerificationStatus='AnalystVerified',
                    AnalystVerifiedBy=$Analyst,AnalystVerifiedUtc=$Utc WHERE Id=$Id AND VerificationStatus<>'AnalystVerified';
                """, ("$Id", findingId), ("$Analyst", analystId), ("$Utc", verifiedUtc));
            ct.ThrowIfCancellationRequested(); tx.Commit();
            return finding with { VerificationStatus = FindingVerificationState.AnalystVerified,
                AnalystVerifiedBy = analystId, AnalystVerifiedUtc = verifiedUtc };
        }
    }

    private static InvestigationFinding? ReadFindingById(SqliteConnection connection, SqliteTransaction tx, string id)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT * FROM AiInvestigationFindings WHERE Id=$Id;";
        Add(command, "$Id", id);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadFinding(reader) : null;
    }

    private Investigation CancelNewInvestigationByAnalyst(string id, DateTime utc, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(id) || utc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("Cancellation requires ID and UTC time.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var inv = ReadInvestigation(connection, tx, id) ?? throw new InvalidOperationException("Investigation is unavailable.");
            if (inv.Status != InvestigationState.New || utc < inv.UpdatedUtc)
                throw new InvalidOperationException("Only a new investigation can be cancelled without an execution result.");
            Execute(connection, tx, "UPDATE AiInvestigations SET Status='Cancelled',UpdatedUtc=$Utc WHERE Id=$Id AND Status='New';",
                ("$Id", id), ("$Utc", utc));
            ct.ThrowIfCancellationRequested(); tx.Commit(); return ReadInvestigation(connection, null, id)!;
        }
    }

    private InvestigationTask CancelPendingTaskByAnalyst(string id, DateTime utc, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(id) || utc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("Cancellation requires task ID and UTC time.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var task = ReadTask(connection, tx, id) ?? throw new InvalidOperationException("Task is unavailable.");
            var investigation = ReadInvestigation(connection, tx, task.InvestigationId) ??
                throw new InvalidOperationException("Task investigation is unavailable.");
            if (task.Status != InvestigationTaskState.Pending || utc < task.CreatedUtc ||
                utc < investigation.UpdatedUtc)
                throw new InvalidOperationException("Only a pending task can be cancelled by analyst.");
            Execute(connection, tx, "UPDATE AiInvestigationTasks SET Status='Cancelled',CompletedUtc=$Utc WHERE Id=$Id AND Status='Pending';",
                ("$Id", id), ("$Utc", utc));
            ct.ThrowIfCancellationRequested(); tx.Commit(); return task with { Status = InvestigationTaskState.Cancelled, CompletedUtc = utc };
        }
    }

    private Investigation CloseInvestigationByAnalyst(string id, DateTime utc, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(id) || utc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("Closing an investigation requires ID and UTC time.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var inv = ReadInvestigation(connection, tx, id) ?? throw new InvalidOperationException("Investigation is unavailable.");
            if (inv.Status == InvestigationState.Closed) { tx.Commit(); return inv; }
            if (inv.Status == InvestigationState.Investigating || HasRunningExecution(connection, tx, id) || utc < inv.UpdatedUtc)
                throw new InvalidOperationException("Active investigation cannot close.");
            Execute(connection, tx, "UPDATE AiInvestigations SET Status='Closed',UpdatedUtc=$Utc WHERE Id=$Id;",
                ("$Id", id), ("$Utc", utc));
            ct.ThrowIfCancellationRequested(); tx.Commit();
            return ReadInvestigation(connection, null, id)!;
        }
    }

    private static bool HasRunningExecution(SqliteConnection connection, SqliteTransaction tx, string investigationId)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT COUNT(*) FROM AiAgentExecutions WHERE InvestigationId=$Id AND Status='Running';";
        Add(command, "$Id", investigationId);
        return Convert.ToInt32(command.ExecuteScalar()) > 0;
    }

    private int ReconcileAbandonedExecutions(CancellationToken ct)
    {
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var candidates = new List<AgentExecution>();
            using (var command = connection.CreateCommand())
            {
                command.Transaction = tx;
                command.CommandText = "SELECT * FROM AiAgentExecutions WHERE Status='Running' ORDER BY StartedUtc,Id;";
                using var reader = command.ExecuteReader();
                while (reader.Read()) { ct.ThrowIfCancellationRequested(); candidates.Add(ReadExecution(reader)); }
            }
            var count = 0;
            foreach (var execution in candidates)
            {
                ct.ThrowIfCancellationRequested();
                if (AiExecutionLifetime.GetOwnerState(execution.Owner) != AiExecutionOwnerState.Abandoned) continue;
                var utc = DateTime.UtcNow;
                if (utc < execution.StartedUtc) utc = execution.StartedUtc;
                var latestToolUtc = LatestToolRecordedUtc(connection, tx, execution.Id);
                if (utc < latestToolUtc) utc = latestToolUtc;
                if (execution.TaskId is not null)
                {
                    var task = ReadTask(connection, tx, execution.TaskId);
                    if (task is not null)
                    {
                        if (utc < task.CreatedUtc) utc = task.CreatedUtc;
                        if (task.CompletedUtc is { } completed && utc < completed) utc = completed;
                    }
                }
                if (execution.InvestigationId is not null)
                {
                    var investigation = ReadInvestigation(connection, tx, execution.InvestigationId);
                    if (investigation is not null && utc < investigation.UpdatedUtc)
                        utc = investigation.UpdatedUtc;
                }
                Execute(connection, tx, """
                    UPDATE AiAgentToolCalls SET Status='Interrupted',CompletedUtc=$Utc,
                        ErrorCategory='OwnerAbandoned',ErrorText='Execution owner ended before tool completion.'
                    WHERE AgentExecutionId=$Id AND Status='Running';
                    """, ("$Id", execution.Id), ("$Utc", utc));
                Execute(connection, tx, """
                    UPDATE AiAgentExecutions SET Status='Interrupted',CompletedUtc=$Utc,
                        ToolCallCount=(SELECT COUNT(*) FROM AiAgentToolCalls WHERE AgentExecutionId=$Id),
                        ErrorCategory='OwnerAbandoned',ErrorText='Execution owner ended before publication.'
                    WHERE Id=$Id AND Status='Running' AND RuntimeLifetimeId=$Lifetime;
                    """, ("$Id", execution.Id), ("$Utc", utc), ("$Lifetime", execution.Owner!.LifetimeId));
                if (execution.TaskId is not null && !HasOtherRunningTaskExecution(connection, tx, execution.TaskId, execution.Id))
                    Execute(connection, tx, """
                        UPDATE AiInvestigationTasks SET Status='Failed',CompletedUtc=$Utc,
                            ResultSummary='Execution was interrupted after its owner ended.'
                        WHERE Id=$Id AND Status='Running';
                        """, ("$Id", execution.TaskId), ("$Utc", utc));
                if (execution.InvestigationId is not null && !HasRunningExecution(connection, tx, execution.InvestigationId))
                    Execute(connection, tx, """
                        UPDATE AiInvestigations SET Status='Failed',UpdatedUtc=$Utc,CompletedUtc=NULL
                        WHERE Id=$Id AND Status='Investigating';
                        """, ("$Id", execution.InvestigationId), ("$Utc", utc));
                count++;
            }
            ct.ThrowIfCancellationRequested(); tx.Commit(); return count;
        }
    }

    private static bool HasOtherRunningTaskExecution(SqliteConnection connection, SqliteTransaction tx,
        string taskId, string exceptExecutionId)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT COUNT(*) FROM AiAgentExecutions WHERE TaskId=$Task AND Id<>$Except AND Status='Running';";
        Add(command, "$Task", taskId); Add(command, "$Except", exceptExecutionId);
        return Convert.ToInt32(command.ExecuteScalar()) > 0;
    }

    private static DateTime LatestToolRecordedUtc(SqliteConnection connection, SqliteTransaction tx, string executionId)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT StartedUtc,CompletedUtc FROM AiAgentToolCalls WHERE AgentExecutionId=$Id;";
        Add(command, "$Id", executionId);
        var latest = DateTime.MinValue;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var started = ParseUtc(reader.GetString(0)) ??
                throw new InvalidOperationException("Tool start time is invalid.");
            if (latest < started) latest = started;
            if (!reader.IsDBNull(1))
            {
                var completed = ParseUtc(reader.GetString(1)) ??
                    throw new InvalidOperationException("Tool completion time is invalid.");
                if (latest < completed) latest = completed;
            }
        }
        return latest;
    }
}
