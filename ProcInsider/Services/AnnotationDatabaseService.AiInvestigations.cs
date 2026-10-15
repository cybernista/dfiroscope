using Microsoft.Data.Sqlite;

namespace ProcInsider.Services;

public sealed partial class AnnotationDatabaseService
{
    private static void InitializeInvestigationSchema(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS AiInvestigations (
                Id TEXT PRIMARY KEY,
                ConversationId TEXT NOT NULL UNIQUE REFERENCES AiConversations(Id),
                Title TEXT NOT NULL, Objective TEXT NOT NULL, Status TEXT NOT NULL,
                TargetReferenceId TEXT NOT NULL REFERENCES AiEvidenceReferences(ReferenceId),
                CreatedUtc TEXT NOT NULL, UpdatedUtc TEXT NOT NULL, CompletedUtc TEXT,
                Summary TEXT NOT NULL, OpenQuestionsJson TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS AiAgentExecutions (
                Id TEXT PRIMARY KEY,
                ConversationId TEXT NOT NULL REFERENCES AiConversations(Id),
                InvestigationId TEXT REFERENCES AiInvestigations(Id),
                TaskId TEXT,
                AgentId TEXT NOT NULL, SkillId TEXT NOT NULL, ProviderId TEXT NOT NULL, ModelId TEXT NOT NULL,
                StartedUtc TEXT NOT NULL, CompletedUtc TEXT, Status TEXT NOT NULL,
                IterationCount INTEGER NOT NULL, ToolCallCount INTEGER NOT NULL,
                InputTokens INTEGER, OutputTokens INTEGER, TotalTokens INTEGER,
                RuntimeLifetimeId TEXT NOT NULL, OwnerMachineFingerprint TEXT NOT NULL,
                OwnerWindowsSessionId INTEGER NOT NULL,
                ErrorCategory TEXT NOT NULL, ErrorText TEXT NOT NULL,
                UNIQUE(Id,InvestigationId),
                CHECK(TaskId IS NULL OR InvestigationId IS NOT NULL),
                FOREIGN KEY(TaskId,InvestigationId) REFERENCES AiInvestigationTasks(Id,InvestigationId)
            );
            CREATE TABLE IF NOT EXISTS AiInvestigationTasks (
                Id TEXT PRIMARY KEY,
                InvestigationId TEXT NOT NULL REFERENCES AiInvestigations(Id),
                ParentTaskId TEXT,
                Objective TEXT NOT NULL, Status TEXT NOT NULL, AssignedAgentId TEXT NOT NULL,
                CreatedByExecutionId TEXT,
                CreatedUtc TEXT NOT NULL, CompletedUtc TEXT, ResultSummary TEXT NOT NULL,
                UNIQUE(Id,InvestigationId),
                FOREIGN KEY(ParentTaskId,InvestigationId) REFERENCES AiInvestigationTasks(Id,InvestigationId),
                FOREIGN KEY(CreatedByExecutionId,InvestigationId) REFERENCES AiAgentExecutions(Id,InvestigationId)
            );
            CREATE TABLE IF NOT EXISTS AiInvestigationFindings (
                Id TEXT PRIMARY KEY,
                InvestigationId TEXT NOT NULL REFERENCES AiInvestigations(Id),
                Title TEXT NOT NULL, Claim TEXT NOT NULL, Description TEXT NOT NULL,
                Severity TEXT NOT NULL, Confidence REAL, VerificationStatus TEXT NOT NULL,
                CreatedByExecutionId TEXT NOT NULL, CreatedUtc TEXT NOT NULL,
                AnalystVerifiedBy TEXT, AnalystVerifiedUtc TEXT, AssessedByExecutionId TEXT,
                UNIQUE(Id,InvestigationId),
                FOREIGN KEY(CreatedByExecutionId,InvestigationId) REFERENCES AiAgentExecutions(Id,InvestigationId),
                FOREIGN KEY(AssessedByExecutionId,InvestigationId) REFERENCES AiAgentExecutions(Id,InvestigationId)
            );
            CREATE TABLE IF NOT EXISTS AiInvestigationHypotheses (
                Id TEXT PRIMARY KEY,
                InvestigationId TEXT NOT NULL REFERENCES AiInvestigations(Id),
                Statement TEXT NOT NULL, Status TEXT NOT NULL, Confidence REAL,
                CreatedByExecutionId TEXT NOT NULL, CreatedUtc TEXT NOT NULL, UpdatedUtc TEXT NOT NULL,
                UpdatedByExecutionId TEXT,
                UNIQUE(Id,InvestigationId),
                FOREIGN KEY(CreatedByExecutionId,InvestigationId) REFERENCES AiAgentExecutions(Id,InvestigationId),
                FOREIGN KEY(UpdatedByExecutionId,InvestigationId) REFERENCES AiAgentExecutions(Id,InvestigationId)
            );
            CREATE TABLE IF NOT EXISTS AiAgentToolCalls (
                Id TEXT PRIMARY KEY,
                AgentExecutionId TEXT NOT NULL REFERENCES AiAgentExecutions(Id),
                ToolName TEXT NOT NULL, StartedUtc TEXT NOT NULL, CompletedUtc TEXT,
                Status TEXT NOT NULL, InputSummary TEXT NOT NULL, ResultSummary TEXT NOT NULL,
                ErrorCategory TEXT NOT NULL, ErrorText TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS AiFindingEvidence (
                FindingId TEXT NOT NULL REFERENCES AiInvestigationFindings(Id),
                ReferenceId TEXT NOT NULL REFERENCES AiEvidenceReferences(ReferenceId),
                Polarity TEXT NOT NULL CHECK(Polarity IN ('Supporting','Contradicting')),
                PRIMARY KEY(FindingId,ReferenceId,Polarity)
            );
            CREATE TABLE IF NOT EXISTS AiHypothesisEvidence (
                HypothesisId TEXT NOT NULL REFERENCES AiInvestigationHypotheses(Id),
                ReferenceId TEXT NOT NULL REFERENCES AiEvidenceReferences(ReferenceId),
                Polarity TEXT NOT NULL CHECK(Polarity IN ('Supporting','Contradicting')),
                PRIMARY KEY(HypothesisId,ReferenceId,Polarity)
            );
            CREATE TABLE IF NOT EXISTS AiToolCallEvidence (
                ToolCallId TEXT NOT NULL REFERENCES AiAgentToolCalls(Id),
                ReferenceId TEXT NOT NULL REFERENCES AiEvidenceReferences(ReferenceId),
                Polarity TEXT NOT NULL CHECK(Polarity IN ('Supporting','Contradicting')),
                PRIMARY KEY(ToolCallId,ReferenceId,Polarity)
            );
            CREATE INDEX IF NOT EXISTS IX_AiTasks_Investigation ON AiInvestigationTasks(InvestigationId,CreatedUtc);
            CREATE INDEX IF NOT EXISTS IX_AiFindings_Investigation ON AiInvestigationFindings(InvestigationId,CreatedUtc);
            CREATE INDEX IF NOT EXISTS IX_AiHypotheses_Investigation ON AiInvestigationHypotheses(InvestigationId,CreatedUtc);
            CREATE INDEX IF NOT EXISTS IX_AiExecutions_Conversation ON AiAgentExecutions(ConversationId,StartedUtc);
            CREATE INDEX IF NOT EXISTS IX_AiToolCalls_Execution ON AiAgentToolCalls(AgentExecutionId,StartedUtc);
            INSERT OR IGNORE INTO SchemaMigrations(MigrationId,AppliedUtc,Description)
            VALUES('007_ai_investigation_state',$AppliedUtc,'Persistent investigation state and authoritative agent execution audit.');
            INSERT INTO SchemaInfo(Key,Value) VALUES('SchemaVersion','7')
            ON CONFLICT(Key) DO UPDATE SET Value=excluded.Value;
            """;
        Add(command, "$AppliedUtc", DateTime.UtcNow);
        command.ExecuteNonQuery();
        transaction.Commit();
    }
}
