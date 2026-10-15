using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services;

public sealed partial class AnnotationDatabaseService
{
    private static void RejectUnknownAnnotationVersion(SqliteConnection connection)
    {
        using var exists = connection.CreateCommand();
        exists.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name='SchemaInfo';";
        if (exists.ExecuteScalar() is null) return;
        using var version = connection.CreateCommand();
        version.CommandText = "SELECT Value FROM SchemaInfo WHERE Key='SchemaVersion';";
        var raw = version.ExecuteScalar()?.ToString();
        if (raw is not null && (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) || parsed > CurrentSchemaVersion || parsed < 1))
            throw new InvalidOperationException($"Unsupported annotation schema version '{raw}'.");
    }

    private static void InitializeConversationSchema(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS AiEvidenceReferences (
                ReferenceId TEXT PRIMARY KEY,
                IdentityJson TEXT NOT NULL,
                EvidenceKind TEXT NOT NULL,
                EvidenceId TEXT NOT NULL,
                DataSource TEXT NOT NULL,
                SourceRunId TEXT NOT NULL,
                SourceRevision TEXT NOT NULL,
                TimestampUtc TEXT,
                DisplayName TEXT NOT NULL,
                CompactSnapshot TEXT NOT NULL,
                SnapshotProvenance TEXT NOT NULL,
                ProcessJson TEXT,
                CanonicalObjectKey TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS AiConversations (
                Id TEXT PRIMARY KEY,
                Title TEXT NOT NULL,
                ContextType TEXT NOT NULL CHECK(ContextType IN ('General','Object','Investigation')),
                ContextId TEXT NOT NULL,
                ScopeKey TEXT NOT NULL UNIQUE,
                IdentityJson TEXT NOT NULL,
                HostId TEXT NOT NULL,
                EvidenceReferenceId TEXT REFERENCES AiEvidenceReferences(ReferenceId),
                CreatedUtc TEXT NOT NULL,
                UpdatedUtc TEXT NOT NULL,
                IsHistorical INTEGER NOT NULL DEFAULT 0,
                LegacyConversationId TEXT UNIQUE
            );
            CREATE TABLE IF NOT EXISTS AiMessages (
                Id TEXT PRIMARY KEY,
                ConversationId TEXT NOT NULL REFERENCES AiConversations(Id) ON DELETE CASCADE,
                Role TEXT NOT NULL,
                Content TEXT NOT NULL,
                TimestampUtc TEXT NOT NULL,
                ProviderId TEXT NOT NULL,
                ModelId TEXT NOT NULL,
                Status TEXT NOT NULL,
                ErrorText TEXT NOT NULL,
                IsHistorical INTEGER NOT NULL DEFAULT 0,
                OriginalProviderKind TEXT,
                OriginalBaseUrl TEXT,
                OriginalCreatedUtc TEXT,
                OriginalProviderName TEXT,
                OriginalModelName TEXT,
                OriginalErrorText TEXT
            );
            CREATE TABLE IF NOT EXISTS AiMessageEvidence (
                MessageId TEXT NOT NULL REFERENCES AiMessages(Id) ON DELETE CASCADE,
                ReferenceId TEXT NOT NULL REFERENCES AiEvidenceReferences(ReferenceId),
                PRIMARY KEY(MessageId, ReferenceId)
            );
            CREATE INDEX IF NOT EXISTS IX_AiConversations_Context ON AiConversations(ContextType, ContextId);
            CREATE INDEX IF NOT EXISTS IX_AiMessages_Conversation ON AiMessages(ConversationId, TimestampUtc);
            INSERT OR IGNORE INTO AiConversations
                (Id,Title,ContextType,ContextId,ScopeKey,IdentityJson,HostId,
                 CreatedUtc,UpdatedUtc,IsHistorical,LegacyConversationId)
            SELECT 'legacy-chat:' || ConversationId, 'Historical chat', 'General', ConversationId,
                   'legacy-chat:' || ConversationId, '{}', '', MIN(CreatedUtc), MAX(CreatedUtc), 1, ConversationId
            FROM AiChatMessages GROUP BY ConversationId;
            INSERT OR IGNORE INTO SchemaMigrations(MigrationId,AppliedUtc,Description)
            VALUES('006_ai_conversations',$AppliedUtc,'Scoped AI conversations, messages and immutable annotation evidence links.');
            INSERT INTO SchemaInfo(Key,Value) VALUES('SchemaVersion','6')
            ON CONFLICT(Key) DO UPDATE SET Value=CASE WHEN CAST(SchemaInfo.Value AS INTEGER)<6 THEN '6' ELSE SchemaInfo.Value END;
            """;
        Add(command, "$AppliedUtc", DateTime.UtcNow);
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private static void InitializeConversationOriginSchema(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        var columns = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["ScopeQualifier"] = "TEXT NOT NULL DEFAULT ''",
            ["CreationSurface"] = "TEXT NOT NULL DEFAULT 'Unknown'",
            ["CreationProcessEntityId"] = "TEXT NOT NULL DEFAULT ''",
            ["CreationCaseId"] = "TEXT NOT NULL DEFAULT ''",
            ["CreationEvidenceSessionId"] = "TEXT NOT NULL DEFAULT ''",
            ["CreationCaptureId"] = "TEXT NOT NULL DEFAULT ''",
            ["CreationSourceIdentityId"] = "TEXT NOT NULL DEFAULT ''",
            ["CreationHostId"] = "TEXT NOT NULL DEFAULT ''",
            ["CreationExecutionRootId"] = "TEXT NOT NULL DEFAULT ''"
        };
        var existing = new HashSet<string>(StringComparer.Ordinal);
        using (var info = connection.CreateCommand())
        {
            info.Transaction = transaction;
            info.CommandText = "PRAGMA table_info(AiConversations);";
            using var reader = info.ExecuteReader();
            while (reader.Read()) existing.Add(reader.GetString(1));
        }
        foreach (var column in columns)
            if (!existing.Contains(column.Key))
            {
                using var alter = connection.CreateCommand();
                alter.Transaction = transaction;
                alter.CommandText = $"ALTER TABLE AiConversations ADD COLUMN {column.Key} {column.Value};";
                alter.ExecuteNonQuery();
            }
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE INDEX IF NOT EXISTS IX_AiConversations_ProcessOrigin
            ON AiConversations(CreationSurface,CreationProcessEntityId,CreationCaseId,
                CreationEvidenceSessionId,CreationCaptureId,CreationSourceIdentityId,
                CreationHostId,CreationExecutionRootId,UpdatedUtc DESC,Id);
            INSERT OR IGNORE INTO SchemaMigrations(MigrationId,AppliedUtc,Description)
            VALUES('009_ai_conversation_origin',$AppliedUtc,
                'Immutable Processes creation origin and exact durable process scoped saved-list reads.');
            INSERT INTO SchemaInfo(Key,Value) VALUES('SchemaVersion','9')
            ON CONFLICT(Key) DO UPDATE SET Value=CASE WHEN CAST(SchemaInfo.Value AS INTEGER)<9 THEN '9' ELSE SchemaInfo.Value END;
            """;
        Add(command, "$AppliedUtc", DateTime.UtcNow);
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private static void RemoveObsoleteAiInvestigationOutputs(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            DROP TABLE IF EXISTS AiInvestigationOutputs;
            INSERT OR IGNORE INTO SchemaMigrations(MigrationId,AppliedUtc,Description)
            VALUES('010_remove_ai_investigation_outputs',$AppliedUtc,
                'Remove obsolete one-shot AI output annotations and their indexes.');
            INSERT INTO SchemaInfo(Key,Value) VALUES('SchemaVersion','10')
            ON CONFLICT(Key) DO UPDATE SET Value=CASE WHEN CAST(SchemaInfo.Value AS INTEGER)<10 THEN '10' ELSE SchemaInfo.Value END;
            """;
        Add(command, "$AppliedUtc", DateTime.UtcNow);
        command.ExecuteNonQuery();
        transaction.Commit();
    }
}
