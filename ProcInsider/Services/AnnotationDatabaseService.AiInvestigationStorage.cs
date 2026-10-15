using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Analysis;
using ProcInsider.Services.Ai;

namespace ProcInsider.Services;

public sealed partial class AnnotationDatabaseService
{
    public Task<Investigation> CreateInvestigationAsync(Investigation investigation, InvestigationTask initialTask,
        CancellationToken cancellationToken = default)
    {
        var pinned = investigation with { OpenQuestions = investigation.OpenQuestions.ToArray() };
        return Task.Run(() => NotifyAiAnnotationsChanged(CreateInvestigation(pinned, initialTask, cancellationToken)), cancellationToken);
    }

    public Task<Investigation?> LoadInvestigationAsync(string id, CancellationToken cancellationToken = default) =>
        Task.Run(() => LoadInvestigation(id, cancellationToken), cancellationToken);

    public Task<IReadOnlyList<Investigation>> ListInvestigationsAsync(int limit = 200,
        CancellationToken cancellationToken = default) => Task.Run<IReadOnlyList<Investigation>>(() =>
            ListInvestigations(limit, cancellationToken), cancellationToken);

    public Task<IReadOnlyList<InvestigationTask>> LoadInvestigationTasksAsync(string investigationId,
        CancellationToken cancellationToken = default) => Task.Run<IReadOnlyList<InvestigationTask>>(() =>
            LoadInvestigationTasks(investigationId, cancellationToken), cancellationToken);

    public Task<IReadOnlyList<InvestigationFinding>> LoadInvestigationFindingsAsync(string investigationId,
        CancellationToken cancellationToken = default) => Task.Run<IReadOnlyList<InvestigationFinding>>(() =>
            LoadInvestigationFindings(investigationId, cancellationToken), cancellationToken);

    public Task<IReadOnlyList<InvestigationHypothesis>> LoadInvestigationHypothesesAsync(string investigationId,
        CancellationToken cancellationToken = default) => Task.Run<IReadOnlyList<InvestigationHypothesis>>(() =>
            LoadInvestigationHypotheses(investigationId, cancellationToken), cancellationToken);

    public Task<IReadOnlyList<AgentExecution>> LoadAgentExecutionsAsync(string conversationId,
        CancellationToken cancellationToken = default) => Task.Run<IReadOnlyList<AgentExecution>>(() =>
            LoadAgentExecutions(conversationId, cancellationToken), cancellationToken);

    public Task<IReadOnlyList<AgentToolCall>> LoadAgentToolCallsAsync(string executionId,
        CancellationToken cancellationToken = default) => Task.Run<IReadOnlyList<AgentToolCall>>(() =>
            LoadAgentToolCalls(executionId, cancellationToken), cancellationToken);

    public Task<IReadOnlyList<InvestigationEvidenceLink>> LoadInvestigationEvidenceAsync(
        InvestigationEvidenceOwner owner, string ownerId, CancellationToken cancellationToken = default) =>
        Task.Run<IReadOnlyList<InvestigationEvidenceLink>>(() =>
            LoadInvestigationEvidence(owner, ownerId, cancellationToken), cancellationToken);

    private Investigation CreateInvestigation(Investigation investigation, InvestigationTask initialTask, CancellationToken ct)
    {
        ValidateInvestigation(investigation, isNew: true);
        ValidateTask(initialTask, isInitial: true);
        if (initialTask.InvestigationId != investigation.Id)
            throw new ArgumentException("Initial task belongs to another investigation.");
        if (initialTask.CreatedUtc < investigation.CreatedUtc || initialTask.CreatedUtc > investigation.UpdatedUtc)
            throw new ArgumentException("Initial task time is outside investigation creation.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var transaction = connection.BeginTransaction();
            var existing = ReadInvestigation(connection, transaction, investigation.Id);
            if (existing is not null)
            {
                var savedInitial = ReadTask(connection, transaction, initialTask.Id);
                if (existing.ConversationId != investigation.ConversationId || existing.Title != investigation.Title ||
                    existing.Objective != investigation.Objective || existing.CreatedUtc != investigation.CreatedUtc ||
                    existing.Target != investigation.Target || savedInitial is null ||
                    savedInitial.InvestigationId != initialTask.InvestigationId ||
                    savedInitial.ParentTaskId != initialTask.ParentTaskId ||
                    savedInitial.Objective != initialTask.Objective ||
                    savedInitial.AssignedAgentId != initialTask.AssignedAgentId ||
                    savedInitial.CreatedByExecutionId != initialTask.CreatedByExecutionId ||
                    savedInitial.CreatedUtc != initialTask.CreatedUtc)
                    throw new InvalidOperationException("Investigation ID is already bound to different content.");
                ct.ThrowIfCancellationRequested();
                transaction.Commit();
                return existing;
            }
            var conversation = LoadConversationForWrite(connection, transaction, investigation.ConversationId);
            if (conversation is null || conversation.IsHistorical ||
                conversation.Scope.ContextType != AiConversationContextType.Investigation ||
                conversation.Scope.ContextId != investigation.Id ||
                (conversation.CreationOrigin is { } origin &&
                 (investigation.Target?.Evidence.Kind != EvidenceReferenceKind.ProcessEntity ||
                  investigation.Target.Evidence.Id != origin.ProcessEntityId ||
                  investigation.Target.Identity != origin.ProcessIdentity)) ||
                !InvestigationReferenceWithinScope(conversation.Scope, investigation.Target!.Identity) ||
                conversation.Scope.Identity.CaseId != investigation.Target.Identity.CaseId ||
                conversation.Scope.Identity.CaptureId != investigation.Target.Identity.CaptureId ||
                conversation.Scope.Identity.HostId != investigation.Target.Identity.HostId ||
                conversation.UpdatedUtc is { } conversationUpdated && investigation.CreatedUtc < conversationUpdated)
                throw new InvalidOperationException("Investigation conversation does not have the exact target scope.");
            InsertOrVerifyReference(connection, transaction, investigation.Target);
            using (var insert = connection.CreateCommand())
            {
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO AiInvestigations
                        (Id,ConversationId,Title,Objective,Status,TargetReferenceId,
                         CreatedUtc,UpdatedUtc,CompletedUtc,Summary,OpenQuestionsJson)
                    VALUES($Id,$Conversation,$Title,$Objective,$Status,$Target,
                           $Created,$Updated,NULL,$Summary,$Questions);
                    """;
                Add(insert, "$Id", investigation.Id);
                Add(insert, "$Conversation", investigation.ConversationId);
                Add(insert, "$Title", investigation.Title);
                Add(insert, "$Objective", investigation.Objective);
                Add(insert, "$Status", investigation.Status.ToString());
                Add(insert, "$Target", investigation.Target.ReferenceId);
                Add(insert, "$Created", investigation.CreatedUtc);
                Add(insert, "$Updated", investigation.UpdatedUtc);
                Add(insert, "$Summary", investigation.Summary);
                Add(insert, "$Questions", JsonSerializer.Serialize(investigation.OpenQuestions));
                insert.ExecuteNonQuery();
            }
            InsertTask(connection, transaction, initialTask);
            ct.ThrowIfCancellationRequested();
            transaction.Commit();
            return investigation;
        }
    }

    private Investigation? LoadInvestigation(string id, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(id)) return null;
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            return ReadInvestigation(connection, null, id);
        }
    }

    private IReadOnlyList<Investigation> ListInvestigations(int limit, CancellationToken ct)
    {
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id FROM AiInvestigations ORDER BY UpdatedUtc DESC,Id LIMIT $Limit;";
            Add(command, "$Limit", Math.Clamp(limit, 1, 200));
            var ids = new List<string>();
            using (var reader = command.ExecuteReader())
                while (reader.Read()) { ct.ThrowIfCancellationRequested(); ids.Add(reader.GetString(0)); }
            var rows = new List<Investigation>(ids.Count);
            foreach (var id in ids)
            {
                ct.ThrowIfCancellationRequested();
                rows.Add(ReadInvestigation(connection, null, id) ??
                    throw new InvalidOperationException("Saved investigation disappeared during its read."));
            }
            return rows;
        }
    }

    private static Investigation? ReadInvestigation(SqliteConnection connection, SqliteTransaction? transaction, string id)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM AiInvestigations WHERE Id=$Id;";
        Add(command, "$Id", id);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var targetId = reader.GetString(reader.GetOrdinal("TargetReferenceId"));
        var result = new Investigation(reader.GetString(reader.GetOrdinal("Id")),
            reader.GetString(reader.GetOrdinal("ConversationId")),
            reader.GetString(reader.GetOrdinal("Title")), reader.GetString(reader.GetOrdinal("Objective")),
            Enum.Parse<InvestigationState>(reader.GetString(reader.GetOrdinal("Status"))), null,
            ParseUtc(reader.GetString(reader.GetOrdinal("CreatedUtc"))) ?? throw new InvalidOperationException("Invalid investigation creation time."),
            ParseUtc(reader.GetString(reader.GetOrdinal("UpdatedUtc"))) ?? throw new InvalidOperationException("Invalid investigation update time."),
            reader.IsDBNull(reader.GetOrdinal("CompletedUtc")) ? null : ParseUtc(reader.GetString(reader.GetOrdinal("CompletedUtc"))),
            reader.GetString(reader.GetOrdinal("Summary")),
            JsonSerializer.Deserialize<string[]>(reader.GetString(reader.GetOrdinal("OpenQuestionsJson"))) ?? []);
        reader.Close();
        return result with { Target = LoadReference(connection, transaction, targetId) ??
            throw new InvalidOperationException("Investigation target reference is missing.") };
    }

    private static void ValidateInvestigation(Investigation investigation, bool isNew)
    {
        if (investigation is null || string.IsNullOrWhiteSpace(investigation.Id) ||
            string.IsNullOrWhiteSpace(investigation.ConversationId) || string.IsNullOrWhiteSpace(investigation.Title) ||
            investigation.Title.Length > 240 || string.IsNullOrWhiteSpace(investigation.Objective) ||
            investigation.Objective.Length > 4000 || !Enum.IsDefined(investigation.Status) ||
            investigation.Target is null || investigation.CreatedUtc.Kind != DateTimeKind.Utc ||
            investigation.UpdatedUtc.Kind != DateTimeKind.Utc || investigation.UpdatedUtc < investigation.CreatedUtc ||
            investigation.Summary.Length > 20_000 || investigation.OpenQuestions.Count > 100 ||
            investigation.OpenQuestions.Any(q => string.IsNullOrWhiteSpace(q) || q.Length > 2000))
            throw new ArgumentException("Investigation has invalid identity, state or bounds.");
        if (isNew && (investigation.Status != InvestigationState.New || investigation.CompletedUtc is not null ||
            investigation.UpdatedUtc != investigation.CreatedUtc ||
            !string.IsNullOrEmpty(investigation.Summary) || investigation.OpenQuestions.Count != 0))
            throw new ArgumentException("New investigation must start with no model result.");
        ValidateReference(investigation.Target);
    }

    private static void ValidateTask(InvestigationTask task, bool isInitial)
    {
        if (task is null || string.IsNullOrWhiteSpace(task.Id) || string.IsNullOrWhiteSpace(task.InvestigationId) ||
            string.IsNullOrWhiteSpace(task.Objective) || task.Objective.Length > 4000 ||
            string.IsNullOrWhiteSpace(task.AssignedAgentId) || task.AssignedAgentId.Length > 120 ||
            !Enum.IsDefined(task.Status) || task.CreatedUtc.Kind != DateTimeKind.Utc ||
            task.CompletedUtc is { Kind: not DateTimeKind.Utc } || task.ResultSummary.Length > 4000)
            throw new ArgumentException("Investigation task is invalid.");
        if (isInitial && (task.ParentTaskId is not null || task.CreatedByExecutionId is not null ||
            task.Status != InvestigationTaskState.Pending || task.CompletedUtc is not null ||
            task.ResultSummary.Length != 0))
            throw new ArgumentException("Initial human task cannot have invented execution provenance.");
        if (task.Status == InvestigationTaskState.Pending &&
            (task.CompletedUtc is not null || task.ResultSummary.Length != 0))
            throw new ArgumentException("Pending task cannot already have a result.");
    }

    private static void InsertTask(SqliteConnection connection, SqliteTransaction transaction, InvestigationTask task)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO AiInvestigationTasks
                (Id,InvestigationId,ParentTaskId,Objective,Status,AssignedAgentId,CreatedByExecutionId,
                 CreatedUtc,CompletedUtc,ResultSummary)
            VALUES($Id,$Investigation,$Parent,$Objective,$Status,$Agent,$Creator,$Created,$Completed,$Summary);
            """;
        Add(command, "$Id", task.Id);
        Add(command, "$Investigation", task.InvestigationId);
        Add(command, "$Parent", task.ParentTaskId);
        Add(command, "$Objective", task.Objective);
        Add(command, "$Status", task.Status.ToString());
        Add(command, "$Agent", task.AssignedAgentId);
        Add(command, "$Creator", task.CreatedByExecutionId);
        Add(command, "$Created", task.CreatedUtc);
        Add(command, "$Completed", task.CompletedUtc);
        Add(command, "$Summary", task.ResultSummary);
        command.ExecuteNonQuery();
    }

    private IReadOnlyList<InvestigationTask> LoadInvestigationTasks(string id, CancellationToken ct)
    {
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM AiInvestigationTasks WHERE InvestigationId=$Id ORDER BY CreatedUtc,Id;";
            Add(command, "$Id", id);
            using var reader = command.ExecuteReader();
            var result = new List<InvestigationTask>();
            while (reader.Read()) { ct.ThrowIfCancellationRequested(); result.Add(ReadTask(reader)); }
            return result;
        }
    }

    private static InvestigationTask ReadTask(SqliteDataReader r) => new(
        r.GetString(r.GetOrdinal("Id")), r.GetString(r.GetOrdinal("InvestigationId")),
        r.IsDBNull(r.GetOrdinal("ParentTaskId")) ? null : r.GetString(r.GetOrdinal("ParentTaskId")),
        r.GetString(r.GetOrdinal("Objective")), Enum.Parse<InvestigationTaskState>(r.GetString(r.GetOrdinal("Status"))),
        r.GetString(r.GetOrdinal("AssignedAgentId")),
        r.IsDBNull(r.GetOrdinal("CreatedByExecutionId")) ? null : r.GetString(r.GetOrdinal("CreatedByExecutionId")),
        ParseUtc(r.GetString(r.GetOrdinal("CreatedUtc"))) ?? throw new InvalidOperationException("Invalid task time."),
        r.IsDBNull(r.GetOrdinal("CompletedUtc")) ? null : ParseUtc(r.GetString(r.GetOrdinal("CompletedUtc"))),
        r.GetString(r.GetOrdinal("ResultSummary")));

    private static InvestigationTask? ReadTask(SqliteConnection connection, SqliteTransaction transaction, string id)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM AiInvestigationTasks WHERE Id=$Id;";
        Add(command, "$Id", id);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadTask(reader) : null;
    }

    private IReadOnlyList<InvestigationFinding> LoadInvestigationFindings(string id, CancellationToken ct)
    {
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM AiInvestigationFindings WHERE InvestigationId=$Id ORDER BY CreatedUtc,Id;";
            Add(command, "$Id", id);
            using var reader = command.ExecuteReader();
            var result = new List<InvestigationFinding>();
            while (reader.Read()) { ct.ThrowIfCancellationRequested(); result.Add(ReadFinding(reader)); }
            return result;
        }
    }

    private static InvestigationFinding ReadFinding(SqliteDataReader r) => new(
        r.GetString(r.GetOrdinal("Id")), r.GetString(r.GetOrdinal("InvestigationId")),
        r.GetString(r.GetOrdinal("Title")), r.GetString(r.GetOrdinal("Claim")),
        r.GetString(r.GetOrdinal("Description")), Enum.Parse<AnalysisFindingSeverity>(r.GetString(r.GetOrdinal("Severity"))),
        r.IsDBNull(r.GetOrdinal("Confidence")) ? null : r.GetDouble(r.GetOrdinal("Confidence")),
        Enum.Parse<FindingVerificationState>(r.GetString(r.GetOrdinal("VerificationStatus"))),
        r.GetString(r.GetOrdinal("CreatedByExecutionId")),
        ParseUtc(r.GetString(r.GetOrdinal("CreatedUtc"))) ?? throw new InvalidOperationException("Invalid finding time."),
        r.IsDBNull(r.GetOrdinal("AnalystVerifiedBy")) ? null : r.GetString(r.GetOrdinal("AnalystVerifiedBy")),
        r.IsDBNull(r.GetOrdinal("AnalystVerifiedUtc")) ? null : ParseUtc(r.GetString(r.GetOrdinal("AnalystVerifiedUtc"))),
        r.IsDBNull(r.GetOrdinal("AssessedByExecutionId")) ? null : r.GetString(r.GetOrdinal("AssessedByExecutionId")));

    private IReadOnlyList<InvestigationHypothesis> LoadInvestigationHypotheses(string id, CancellationToken ct)
    {
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM AiInvestigationHypotheses WHERE InvestigationId=$Id ORDER BY CreatedUtc,Id;";
            Add(command, "$Id", id);
            using var reader = command.ExecuteReader();
            var result = new List<InvestigationHypothesis>();
            while (reader.Read()) { ct.ThrowIfCancellationRequested(); result.Add(ReadHypothesis(reader)); }
            return result;
        }
    }

    private static InvestigationHypothesis ReadHypothesis(SqliteDataReader r) => new(
        r.GetString(r.GetOrdinal("Id")), r.GetString(r.GetOrdinal("InvestigationId")),
        r.GetString(r.GetOrdinal("Statement")), Enum.Parse<HypothesisState>(r.GetString(r.GetOrdinal("Status"))),
        r.IsDBNull(r.GetOrdinal("Confidence")) ? null : r.GetDouble(r.GetOrdinal("Confidence")),
        r.GetString(r.GetOrdinal("CreatedByExecutionId")),
        ParseUtc(r.GetString(r.GetOrdinal("CreatedUtc"))) ?? throw new InvalidOperationException("Invalid hypothesis time."),
        ParseUtc(r.GetString(r.GetOrdinal("UpdatedUtc"))) ?? throw new InvalidOperationException("Invalid hypothesis update time."),
        r.IsDBNull(r.GetOrdinal("UpdatedByExecutionId")) ? null : r.GetString(r.GetOrdinal("UpdatedByExecutionId")));

    private IReadOnlyList<AgentExecution> LoadAgentExecutions(string conversationId, CancellationToken ct)
    {
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM AiAgentExecutions WHERE ConversationId=$Id ORDER BY StartedUtc,Id;";
            Add(command, "$Id", conversationId);
            using var reader = command.ExecuteReader();
            var result = new List<AgentExecution>();
            while (reader.Read()) { ct.ThrowIfCancellationRequested(); result.Add(ReadExecution(reader)); }
            return result;
        }
    }

    private static AgentExecution ReadExecution(SqliteDataReader r)
    {
        static int? NullableInt(SqliteDataReader reader, string name) =>
            reader.IsDBNull(reader.GetOrdinal(name)) ? null : reader.GetInt32(reader.GetOrdinal(name));
        var input = NullableInt(r, "InputTokens");
        var output = NullableInt(r, "OutputTokens");
        var total = NullableInt(r, "TotalTokens");
        return new AgentExecution(r.GetString(r.GetOrdinal("Id")), r.GetString(r.GetOrdinal("ConversationId")),
            r.IsDBNull(r.GetOrdinal("InvestigationId")) ? null : r.GetString(r.GetOrdinal("InvestigationId")),
            r.IsDBNull(r.GetOrdinal("TaskId")) ? null : r.GetString(r.GetOrdinal("TaskId")),
            r.GetString(r.GetOrdinal("AgentId")), r.GetString(r.GetOrdinal("SkillId")),
            r.GetString(r.GetOrdinal("ProviderId")), r.GetString(r.GetOrdinal("ModelId")),
            ParseUtc(r.GetString(r.GetOrdinal("StartedUtc"))) ?? throw new InvalidOperationException("Invalid execution start time."),
            r.IsDBNull(r.GetOrdinal("CompletedUtc")) ? null : ParseUtc(r.GetString(r.GetOrdinal("CompletedUtc"))),
            Enum.Parse<AgentExecutionState>(r.GetString(r.GetOrdinal("Status"))),
            r.GetInt32(r.GetOrdinal("IterationCount")), r.GetInt32(r.GetOrdinal("ToolCallCount")),
            input is null && output is null && total is null ? null : new ModelTokenUsage(input, output, total),
            r.GetString(r.GetOrdinal("ErrorCategory")), r.GetString(r.GetOrdinal("ErrorText")),
            new AiExecutionOwner(r.GetString(r.GetOrdinal("RuntimeLifetimeId")),
                r.GetString(r.GetOrdinal("OwnerMachineFingerprint")), r.GetInt32(r.GetOrdinal("OwnerWindowsSessionId"))));
    }

    private static AgentExecution? ReadExecution(SqliteConnection connection, SqliteTransaction transaction, string id)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM AiAgentExecutions WHERE Id=$Id;";
        Add(command, "$Id", id);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadExecution(reader) : null;
    }

    private IReadOnlyList<AgentToolCall> LoadAgentToolCalls(string executionId, CancellationToken ct)
    {
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM AiAgentToolCalls WHERE AgentExecutionId=$Id ORDER BY StartedUtc,Id;";
            Add(command, "$Id", executionId);
            using var reader = command.ExecuteReader();
            var result = new List<AgentToolCall>();
            while (reader.Read()) { ct.ThrowIfCancellationRequested(); result.Add(ReadToolCall(reader)); }
            return result;
        }
    }

    private static AgentToolCall ReadToolCall(SqliteDataReader r) => new(
        r.GetString(r.GetOrdinal("Id")), r.GetString(r.GetOrdinal("AgentExecutionId")),
        r.GetString(r.GetOrdinal("ToolName")),
        ParseUtc(r.GetString(r.GetOrdinal("StartedUtc"))) ?? throw new InvalidOperationException("Invalid tool start time."),
        r.IsDBNull(r.GetOrdinal("CompletedUtc")) ? null : ParseUtc(r.GetString(r.GetOrdinal("CompletedUtc"))),
        Enum.Parse<AgentToolCallState>(r.GetString(r.GetOrdinal("Status"))),
        r.GetString(r.GetOrdinal("InputSummary")), r.GetString(r.GetOrdinal("ResultSummary")),
        r.GetString(r.GetOrdinal("ErrorCategory")), r.GetString(r.GetOrdinal("ErrorText")));

    private static AgentToolCall? ReadToolCall(SqliteConnection connection, SqliteTransaction transaction, string id)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM AiAgentToolCalls WHERE Id=$Id;";
        Add(command, "$Id", id);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadToolCall(reader) : null;
    }

    private IReadOnlyList<InvestigationEvidenceLink> LoadInvestigationEvidence(InvestigationEvidenceOwner owner,
        string ownerId, CancellationToken ct)
    {
        if (!Enum.IsDefined(owner)) throw new ArgumentException("Invalid evidence owner.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT ReferenceId,Polarity FROM {EvidenceTable(owner)} WHERE {EvidenceOwnerColumn(owner)}=$Id ORDER BY ReferenceId,Polarity;";
            Add(command, "$Id", ownerId);
            var keys = new List<(string Id, InvestigationEvidencePolarity Polarity)>();
            using (var reader = command.ExecuteReader())
                while (reader.Read()) { ct.ThrowIfCancellationRequested(); keys.Add((reader.GetString(0), Enum.Parse<InvestigationEvidencePolarity>(reader.GetString(1)))); }
            return keys.Select(key => new InvestigationEvidenceLink(owner, ownerId, key.Polarity,
                LoadReference(connection, null, key.Id) ?? throw new InvalidOperationException("Evidence reference is missing."))).ToArray();
        }
    }

    private static string EvidenceTable(InvestigationEvidenceOwner owner) => owner switch
    {
        InvestigationEvidenceOwner.Finding => "AiFindingEvidence",
        InvestigationEvidenceOwner.Hypothesis => "AiHypothesisEvidence",
        InvestigationEvidenceOwner.ToolCall => "AiToolCallEvidence",
        _ => throw new ArgumentException("Invalid evidence owner.")
    };

    private static string EvidenceOwnerColumn(InvestigationEvidenceOwner owner) => owner switch
    {
        InvestigationEvidenceOwner.Finding => "FindingId",
        InvestigationEvidenceOwner.Hypothesis => "HypothesisId",
        InvestigationEvidenceOwner.ToolCall => "ToolCallId",
        _ => throw new ArgumentException("Invalid evidence owner.")
    };

    private static bool InvestigationReferenceWithinScope(AiConversationScope scope,
        ProcInsider.Models.EvidenceIdentity reference)
    {
        var pinned = scope.Identity;
        return scope.ContextType == AiConversationContextType.Investigation &&
            pinned.CaseId == reference.CaseId &&
            pinned.EvidenceSessionId == reference.EvidenceSessionId &&
            pinned.CaptureId == reference.CaptureId &&
            pinned.HostId == reference.HostId &&
            (string.IsNullOrEmpty(pinned.SourceIdentityId) || pinned.SourceIdentityId == reference.SourceIdentityId) &&
            (string.IsNullOrEmpty(pinned.ExecutionRootId) || pinned.ExecutionRootId == reference.ExecutionRootId);
    }
}
