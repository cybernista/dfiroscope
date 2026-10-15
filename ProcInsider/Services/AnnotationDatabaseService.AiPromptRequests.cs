using System.IO;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models.Ai;
using ProcInsider.Services.Ai;

namespace ProcInsider.Services;

public sealed partial class AnnotationDatabaseService
{
    public const int MaximumPromptRequestBytes = 2_000_000;

    private static void InitializePromptRequestSchema(SqliteConnection connection)
    {
        using var tx = connection.BeginTransaction();
        var hasDetails = false;
        using (var columns = connection.CreateCommand())
        {
            columns.Transaction = tx; columns.CommandText = "PRAGMA table_info(AiMessages);";
            using var reader = columns.ExecuteReader();
            while (reader.Read()) if (reader.GetString(1) == "TechnicalDetails") hasDetails = true;
        }
        if (!hasDetails) Execute(connection, tx, "ALTER TABLE AiMessages ADD COLUMN TechnicalDetails TEXT NOT NULL DEFAULT '';" );
        var hasQuestionId = false;
        using (var columns = connection.CreateCommand())
        {
            columns.Transaction = tx; columns.CommandText = "PRAGMA table_info(AiAgentExecutions);";
            using var reader = columns.ExecuteReader();
            while (reader.Read()) if (reader.GetString(1) == "OriginalQuestionId") hasQuestionId = true;
        }
        if (!hasQuestionId) Execute(connection, tx, "ALTER TABLE AiAgentExecutions ADD COLUMN OriginalQuestionId TEXT REFERENCES AiMessages(Id);" );
        Execute(connection, tx, """
            CREATE TABLE IF NOT EXISTS AiPromptRequests (
                Id TEXT PRIMARY KEY,
                ConversationId TEXT NOT NULL REFERENCES AiConversations(Id),
                MessageId TEXT NOT NULL REFERENCES AiMessages(Id) ON DELETE CASCADE,
                ExecutionId TEXT NOT NULL REFERENCES AiAgentExecutions(Id),
                Iteration INTEGER NOT NULL CHECK(Iteration BETWEEN 1 AND 32),
                ProviderId TEXT NOT NULL, ModelId TEXT NOT NULL, SubmittedUtc TEXT NOT NULL,
                RequestBody TEXT NOT NULL CHECK(length(CAST(RequestBody AS BLOB))<=2000000),
                UNIQUE(ExecutionId,Iteration)
            );
            CREATE INDEX IF NOT EXISTS IX_AiPromptRequests_Message ON AiPromptRequests(ConversationId,MessageId,Iteration);
            INSERT OR IGNORE INTO SchemaMigrations(MigrationId,AppliedUtc,Description)
            VALUES('008_ai_submitted_requests',$Utc,'Exact attempted provider request bodies and separate answer technical details.');
            INSERT INTO SchemaInfo(Key,Value) VALUES('SchemaVersion','8')
            ON CONFLICT(Key) DO UPDATE SET Value=CASE WHEN CAST(SchemaInfo.Value AS INTEGER)<8 THEN '8' ELSE SchemaInfo.Value END;
            """, ("$Utc", DateTime.UtcNow));
        tx.Commit();
    }

    public Task<AiPromptRequest> SaveCheckedPromptRequestAsync(AiPromptRequest submitted, AgentToolSession session,
        Func<bool> isCurrent, CancellationToken cancellationToken = default) => Task.Run(() =>
            SaveCheckedPromptRequest(submitted, session, isCurrent, cancellationToken), cancellationToken);

    private AiPromptRequest SaveCheckedPromptRequest(AiPromptRequest submitted, AgentToolSession session,
        Func<bool> isCurrent, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(isCurrent);
        if (submitted is null || string.IsNullOrWhiteSpace(submitted.Id) || string.IsNullOrWhiteSpace(submitted.MessageId) ||
            string.IsNullOrWhiteSpace(submitted.ExecutionId) || submitted.SubmittedUtc.Kind != DateTimeKind.Utc ||
            submitted.Iteration < 1 || submitted.Iteration > session.Definition.Limits.MaximumIterations ||
            submitted.Iteration != session.AttemptedIterations || string.IsNullOrWhiteSpace(submitted.ProviderId) ||
            string.IsNullOrWhiteSpace(submitted.ModelId) || submitted.ProviderId.Length > 200 || submitted.ModelId.Length > 500 ||
            submitted.RequestBody is null || Encoding.UTF8.GetByteCount(submitted.RequestBody) > MaximumPromptRequestBytes)
            throw new ArgumentException("Submitted request identity or whole-body bounds are invalid.");
        using (var body = JsonDocument.Parse(submitted.RequestBody))
            if (body.RootElement.ValueKind != JsonValueKind.Object) throw new ArgumentException("Submitted request body must be JSON object.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var tx = connection.BeginTransaction();
            var execution = ReadExecution(connection, tx, submitted.ExecutionId) ?? throw new InvalidOperationException("Execution unavailable.");
            var conversation = LoadConversationForWrite(connection, tx, submitted.ConversationId);
            AssertCheckedWrite(session, conversation, isCurrent, ct);
            var question = LoadMessageForWrite(connection, tx, submitted.MessageId);
            using var original = connection.CreateCommand(); original.Transaction = tx;
            original.CommandText = "SELECT OriginalQuestionId FROM AiAgentExecutions WHERE Id=$Id;";
            Add(original, "$Id", execution.Id);
            if (!Equals(original.ExecuteScalar(), submitted.MessageId))
                throw new InvalidOperationException("Submitted request belongs to a different original question.");
            if (execution.ConversationId != submitted.ConversationId || execution.Status != AgentExecutionState.Running ||
                execution.AgentId != session.AgentId || execution.SkillId != session.SkillId ||
                AiExecutionLifetime.GetOwnerState(execution.Owner) != AiExecutionOwnerState.Active ||
                execution.IterationCount != submitted.Iteration || execution.ProviderId != submitted.ProviderId || execution.ModelId != submitted.ModelId ||
                submitted.SubmittedUtc < execution.StartedUtc || question is null || question.IsHistorical ||
                question.ConversationId != execution.ConversationId || !question.Role.Equals("user", StringComparison.OrdinalIgnoreCase) ||
                question.TimestampUtc != execution.StartedUtc)
                throw new InvalidOperationException("Submitted request does not match the live execution and original question.");
            Execute(connection, tx, """
                INSERT INTO AiPromptRequests(Id,ConversationId,MessageId,ExecutionId,Iteration,ProviderId,ModelId,SubmittedUtc,RequestBody)
                VALUES($Id,$Conversation,$Message,$Execution,$Iteration,$Provider,$Model,$Utc,$Body);
                """, ("$Id", submitted.Id), ("$Conversation", submitted.ConversationId), ("$Message", submitted.MessageId),
                ("$Execution", submitted.ExecutionId), ("$Iteration", submitted.Iteration), ("$Provider", submitted.ProviderId),
                ("$Model", submitted.ModelId), ("$Utc", submitted.SubmittedUtc), ("$Body", submitted.RequestBody));
            AssertCheckedWrite(session, conversation, isCurrent, ct);
            tx.Commit();
            return submitted;
        }
    }

    // Exactly one original question; metadata-only transcript readers do not join these bodies.
    public Task<IReadOnlyList<AiPromptRequest>> LoadPromptRequestsAsync(string conversationId, string messageId,
        CancellationToken cancellationToken = default) => Task.Run<IReadOnlyList<AiPromptRequest>>(() =>
    {
        lock (_lock)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT p.*, length(CAST(p.RequestBody AS BLOB)) AS BodyBytes FROM AiPromptRequests p JOIN AiMessages m ON m.Id=p.MessageId AND m.ConversationId=p.ConversationId
                JOIN AiAgentExecutions e ON e.Id=p.ExecutionId AND e.ConversationId=p.ConversationId
                WHERE e.OriginalQuestionId=p.MessageId AND p.ConversationId=$Conversation AND p.MessageId=$Message AND lower(m.Role)='user' AND m.IsHistorical=0
                ORDER BY p.Iteration LIMIT 33;
                """;
            Add(command, "$Conversation", conversationId); Add(command, "$Message", messageId);
            using var reader = command.ExecuteReader();
            var rows = new List<AiPromptRequest>();
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (rows.Count == 32) throw new InvalidDataException("Submitted request iteration count exceeds the execution bound.");
                if (reader.GetInt64(reader.GetOrdinal("BodyBytes")) > MaximumPromptRequestBytes) throw new InvalidDataException("Submitted request body exceeds the whole-body bound.");
                rows.Add(new AiPromptRequest(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    reader.GetInt32(4), reader.GetString(5), reader.GetString(6), ParseUtc(reader.GetString(7)) ??
                        throw new InvalidDataException("Submitted request time is invalid."), reader.GetString(8)));
            }
            return rows;
        }
    }, cancellationToken);
}
