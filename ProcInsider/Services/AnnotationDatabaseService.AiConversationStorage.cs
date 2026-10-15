using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services;

public sealed partial class AnnotationDatabaseService
{
    // Presentation observers receive no annotation content and cannot change an already committed write outcome.
    internal event Action<AnnotationDatabaseService>? AiAnnotationsChanged;
    private T NotifyAiAnnotationsChanged<T>(T committed)
    {
        var observers = AiAnnotationsChanged;
        if (observers is not null)
            foreach (Action<AnnotationDatabaseService> observer in observers.GetInvocationList())
                try { observer(this); }
                catch (Exception) { System.Diagnostics.Trace.TraceWarning("An AI annotation refresh observer was unavailable."); }
        return committed;
    }
    public Task<AiConversation> GetOrCreateConversationAsync(
        AiConversationScope scope, string title, CancellationToken cancellationToken = default) =>
        GetOrCreateConversationAsync(scope, title, null, cancellationToken);

    public Task<AiConversation> GetOrCreateConversationAsync(AiConversationScope scope, string title,
        AiConversationCreationOrigin? creationOrigin, CancellationToken cancellationToken = default) =>
        Task.Run(() => NotifyAiAnnotationsChanged(GetOrCreateConversation(scope, title, creationOrigin, cancellationToken)), cancellationToken);

    public Task<AiConversation?> LoadConversationAsync(string id, CancellationToken cancellationToken = default) =>
        Task.Run(() => LoadConversation(id, cancellationToken), cancellationToken);

    public Task<AiConversation?> FindConversationByScopeAsync(AiConversationScope scope,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => FindConversationByScope(scope, cancellationToken), cancellationToken);

    public Task<IReadOnlyList<AiConversation>> ListConversationsAsync(int limit = 200,
        CancellationToken cancellationToken = default) =>
        Task.Run<IReadOnlyList<AiConversation>>(() => ListConversations(limit, cancellationToken), cancellationToken);

    public Task<IReadOnlyList<AiConversation>> ListProcessOriginConversationsAsync(
        AiConversationCreationOrigin origin, int limit = 200, int offset = 0,
        CancellationToken cancellationToken = default) =>
        Task.Run<IReadOnlyList<AiConversation>>(() => ListProcessOriginConversations(origin, limit, offset,
            cancellationToken), cancellationToken);

    public Task SaveConversationMessageAsync(AiConversationMessage message,
        IReadOnlyList<AiEvidenceReference>? references = null, CancellationToken cancellationToken = default)
    {
        var pinnedReferences = references?.ToArray() ?? [];
        return Task.Run(() => { SaveConversationMessage(message, pinnedReferences, cancellationToken); NotifyAiAnnotationsChanged(true); }, cancellationToken);
    }

    public Task<IReadOnlyList<AiConversationMessage>> LoadConversationMessagesAsync(string conversationId,
        int limit = 200, CancellationToken cancellationToken = default) =>
        Task.Run<IReadOnlyList<AiConversationMessage>>(() => LoadConversationMessages(conversationId, limit, cancellationToken), cancellationToken);

    public Task<AiRuntimeHistoryPage> LoadRuntimeHistoryPageAsync(string conversationId, int limit = 500,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => LoadRuntimeHistoryPage(conversationId, limit, cancellationToken), cancellationToken);

    public Task<IReadOnlyList<AiEvidenceReference>> LoadMessageEvidenceAsync(string conversationId, string messageId,
        CancellationToken cancellationToken = default) =>
        Task.Run<IReadOnlyList<AiEvidenceReference>>(() => LoadMessageEvidence(conversationId, messageId, cancellationToken), cancellationToken);

    private AiConversation GetOrCreateConversation(AiConversationScope scope, string title,
        AiConversationCreationOrigin? creationOrigin, CancellationToken ct)
    {
        ValidateScope(scope);
        ValidateCreationOrigin(scope, creationOrigin);
        if (string.IsNullOrWhiteSpace(title) || title.Length > 240) throw new ArgumentException("Conversation title is invalid.", nameof(title));
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var transaction = connection.BeginTransaction();
            using (var existing = connection.CreateCommand())
            {
                existing.Transaction = transaction;
                existing.CommandText = "SELECT Id FROM AiConversations WHERE ScopeKey=$ScopeKey;";
                Add(existing, "$ScopeKey", scope.ScopeKey);
                if (existing.ExecuteScalar() is null && scope.ObjectReference is not null)
                    InsertOrVerifyReference(connection, transaction, scope.ObjectReference);
            }
            using (var insert = connection.CreateCommand())
            {
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT OR IGNORE INTO AiConversations
                        (Id,Title,ContextType,ContextId,ScopeKey,IdentityJson,HostId,EvidenceReferenceId,
                         CreatedUtc,UpdatedUtc,IsHistorical,ScopeQualifier,CreationSurface,
                         CreationProcessEntityId,CreationCaseId,CreationEvidenceSessionId,CreationCaptureId,
                         CreationSourceIdentityId,CreationHostId,CreationExecutionRootId)
                    VALUES($Id,$Title,$Type,$ContextId,$ScopeKey,$Identity,$HostId,$ReferenceId,
                           $CreatedUtc,$UpdatedUtc,0,$Qualifier,$Surface,$ProcessEntityId,$CaseId,
                           $EvidenceSessionId,$CaptureId,$SourceIdentityId,$CreationHostId,$ExecutionRootId);
                    """;
                var now = DateTime.UtcNow;
                Add(insert, "$Id", Guid.NewGuid().ToString("N"));
                Add(insert, "$Title", title);
                Add(insert, "$Type", scope.ContextType.ToString());
                Add(insert, "$ContextId", scope.ContextId);
                Add(insert, "$ScopeKey", scope.ScopeKey);
                Add(insert, "$Identity", JsonSerializer.Serialize(scope.Identity));
                Add(insert, "$HostId", scope.Identity.HostId);
                Add(insert, "$ReferenceId", scope.ObjectReference?.ReferenceId);
                Add(insert, "$CreatedUtc", now);
                Add(insert, "$UpdatedUtc", now);
                Add(insert, "$Qualifier", scope.ScopeQualifier);
                Add(insert, "$Surface", creationOrigin?.Surface ?? "Unknown");
                Add(insert, "$ProcessEntityId", creationOrigin?.ProcessEntityId ?? string.Empty);
                Add(insert, "$CaseId", creationOrigin?.ProcessIdentity.CaseId ?? string.Empty);
                Add(insert, "$EvidenceSessionId", creationOrigin?.ProcessIdentity.EvidenceSessionId ?? string.Empty);
                Add(insert, "$CaptureId", creationOrigin?.ProcessIdentity.CaptureId ?? string.Empty);
                Add(insert, "$SourceIdentityId", creationOrigin?.ProcessIdentity.SourceIdentityId ?? string.Empty);
                Add(insert, "$CreationHostId", creationOrigin?.ProcessIdentity.HostId ?? string.Empty);
                Add(insert, "$ExecutionRootId", creationOrigin?.ProcessIdentity.ExecutionRootId ?? string.Empty);
                insert.ExecuteNonQuery();
            }
            using var select = connection.CreateCommand();
            select.Transaction = transaction;
            select.CommandText = "SELECT * FROM AiConversations WHERE ScopeKey=$ScopeKey;";
            Add(select, "$ScopeKey", scope.ScopeKey);
            using var reader = select.ExecuteReader();
            if (!reader.Read()) throw new InvalidOperationException("Conversation lookup failed.");
            var storedRefId = reader.IsDBNull(reader.GetOrdinal("EvidenceReferenceId")) ? null :
                reader.GetString(reader.GetOrdinal("EvidenceReferenceId"));
            var conversation = ReadConversation(reader, null);
            reader.Close();
            var storedRef = storedRefId is null ? null : LoadReference(connection, transaction, storedRefId);
            conversation = conversation with { Scope = conversation.Scope with { ObjectReference = storedRef } };
            if (conversation.Scope.ScopeKey != scope.ScopeKey || conversation.IsHistorical ||
                (creationOrigin is not null && conversation.CreationOrigin != creationOrigin) ||
                (scope.ContextType == AiConversationContextType.Object && storedRef?.CanonicalObjectKey != scope.ContextId))
                throw new InvalidOperationException("Conversation scope collision.");
            ct.ThrowIfCancellationRequested();
            transaction.Commit();
            return conversation;
        }
    }

    private AiConversation? LoadConversation(string id, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(id)) return null;
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM AiConversations WHERE Id=$Id;";
            Add(command, "$Id", id);
            using var reader = command.ExecuteReader();
            if (!reader.Read()) return null;
            var referenceId = reader.IsDBNull(reader.GetOrdinal("EvidenceReferenceId")) ? null :
                reader.GetString(reader.GetOrdinal("EvidenceReferenceId"));
            var conversation = ReadConversation(reader, null);
            reader.Close();
            return referenceId is null ? conversation : conversation with
            {
                Scope = conversation.Scope with { ObjectReference = LoadReference(connection, null, referenceId) }
            };
        }
    }

    private AiConversation? FindConversationByScope(AiConversationScope scope, CancellationToken ct)
    {
        ValidateScope(scope);
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id FROM AiConversations WHERE ScopeKey=$ScopeKey AND IsHistorical=0;";
            Add(command, "$ScopeKey", scope.ScopeKey);
            var id = command.ExecuteScalar() as string;
            return id is null ? null : LoadConversation(id, ct);
        }
    }

    private IReadOnlyList<AiConversation> ListConversations(int limit, CancellationToken ct)
    {
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM AiConversations ORDER BY UpdatedUtc DESC, Id LIMIT $Limit;";
            Add(command, "$Limit", Math.Clamp(limit, 1, 1000));
            using var reader = command.ExecuteReader();
            var result = new List<AiConversation>();
            var references = new List<string?>();
            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();
                result.Add(ReadConversation(reader, null));
                references.Add(reader.IsDBNull(reader.GetOrdinal("EvidenceReferenceId")) ? null :
                    reader.GetString(reader.GetOrdinal("EvidenceReferenceId")));
            }
            reader.Close();
            for (var index = 0; index < result.Count; index++)
                if (references[index] is { } referenceId)
                    result[index] = result[index] with
                    {
                        Scope = result[index].Scope with { ObjectReference = LoadReference(connection, null, referenceId) }
                    };
            return result;
        }
    }

    private IReadOnlyList<AiConversation> ListProcessOriginConversations(
        AiConversationCreationOrigin origin, int limit, int offset, CancellationToken ct)
    {
        ValidateProcessOrigin(origin);
        if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT * FROM AiConversations
                WHERE IsHistorical=0 AND CreationSurface='Processes'
                  AND CreationProcessEntityId=$ProcessEntityId AND CreationCaseId=$CaseId
                  AND CreationEvidenceSessionId=$EvidenceSessionId AND CreationCaptureId=$CaptureId
                  AND CreationSourceIdentityId=$SourceIdentityId AND CreationHostId=$HostId
                  AND CreationExecutionRootId=$ExecutionRootId
                ORDER BY UpdatedUtc DESC, Id LIMIT $Limit OFFSET $Offset;
                """;
            Add(command, "$ProcessEntityId", origin.ProcessEntityId);
            Add(command, "$CaseId", origin.ProcessIdentity.CaseId);
            Add(command, "$EvidenceSessionId", origin.ProcessIdentity.EvidenceSessionId);
            Add(command, "$CaptureId", origin.ProcessIdentity.CaptureId);
            Add(command, "$SourceIdentityId", origin.ProcessIdentity.SourceIdentityId);
            Add(command, "$HostId", origin.ProcessIdentity.HostId);
            Add(command, "$ExecutionRootId", origin.ProcessIdentity.ExecutionRootId);
            Add(command, "$Limit", Math.Clamp(limit, 1, 1000));
            Add(command, "$Offset", offset);
            var result = new List<AiConversation>();
            var referenceIds = new List<string?>();
            using (var reader = command.ExecuteReader())
                while (reader.Read())
                {
                    ct.ThrowIfCancellationRequested();
                    result.Add(ReadConversation(reader, null));
                    referenceIds.Add(reader.IsDBNull(reader.GetOrdinal("EvidenceReferenceId")) ? null :
                        reader.GetString(reader.GetOrdinal("EvidenceReferenceId")));
                }
            for (var i = 0; i < result.Count; i++)
                if (referenceIds[i] is { } referenceId)
                    result[i] = result[i] with
                    {
                        Scope = result[i].Scope with { ObjectReference = LoadReference(connection, null, referenceId) }
                    };
            return result;
        }
    }

    private static AiConversation ReadConversation(SqliteDataReader reader, AiEvidenceReference? supplied)
    {
        var type = Enum.Parse<AiConversationContextType>(reader.GetString(reader.GetOrdinal("ContextType")));
        var identity = JsonSerializer.Deserialize<EvidenceIdentity>(reader.GetString(reader.GetOrdinal("IdentityJson"))) ?? new EvidenceIdentity();
        var scope = new AiConversationScope(type, reader.GetString(reader.GetOrdinal("ContextId")), identity, supplied,
            reader.GetString(reader.GetOrdinal("ScopeQualifier")));
        var historical = reader.GetInt32(reader.GetOrdinal("IsHistorical")) != 0;
        var created = reader.GetString(reader.GetOrdinal("CreatedUtc"));
        var updated = reader.GetString(reader.GetOrdinal("UpdatedUtc"));
        var surface = reader.GetString(reader.GetOrdinal("CreationSurface"));
        var creationOrigin = surface == "Processes" ? new AiConversationCreationOrigin(surface,
            new EvidenceIdentity
            {
                CaseId = reader.GetString(reader.GetOrdinal("CreationCaseId")),
                EvidenceSessionId = reader.GetString(reader.GetOrdinal("CreationEvidenceSessionId")),
                CaptureId = reader.GetString(reader.GetOrdinal("CreationCaptureId")),
                SourceIdentityId = reader.GetString(reader.GetOrdinal("CreationSourceIdentityId")),
                HostId = reader.GetString(reader.GetOrdinal("CreationHostId")),
                ExecutionRootId = reader.GetString(reader.GetOrdinal("CreationExecutionRootId"))
            }, reader.GetString(reader.GetOrdinal("CreationProcessEntityId"))) : null;
        return new AiConversation(reader.GetString(reader.GetOrdinal("Id")), reader.GetString(reader.GetOrdinal("Title")),
            scope, reader.GetString(reader.GetOrdinal("HostId")), ParseUtc(created), ParseUtc(updated), historical,
            historical ? created : string.Empty, historical ? updated : string.Empty, creationOrigin);
    }

    private static DateTime? ParseUtc(string? raw) => DateTimeOffset.TryParse(raw,
        CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed) ? parsed.UtcDateTime : null;

    private static void ValidateScope(AiConversationScope scope)
    {
        if (scope is null || scope.Identity is null || string.IsNullOrWhiteSpace(scope.ContextId) ||
            string.IsNullOrWhiteSpace(scope.Identity.EvidenceSessionId) || !Enum.IsDefined(scope.ContextType))
            throw new ArgumentException("Conversation scope requires an evidence session identity.");
        if (scope.ContextType == AiConversationContextType.Object)
        {
            if (string.IsNullOrWhiteSpace(scope.Identity.CaptureId) || string.IsNullOrWhiteSpace(scope.Identity.HostId))
                throw new ArgumentException("Object conversation requires exact capture and host scope.");
            if (scope.ObjectReference is null || scope.ContextId != scope.ObjectReference.CanonicalObjectKey ||
                scope.Identity != scope.ObjectReference.Identity)
                throw new ArgumentException("Object conversation reference does not match its canonical scope.");
            ValidateReference(scope.ObjectReference);
        }
        else if (scope.ObjectReference is not null)
            throw new ArgumentException("Only object conversations can own a target evidence reference.");
        var processQualifier = IsProcessQualifier(scope.ScopeQualifier);
        if (scope.ScopeQualifier != "" && !processQualifier ||
            processQualifier && scope.ContextType != AiConversationContextType.Object)
            throw new ArgumentException("Unsupported conversation scope qualifier.");
    }

    private static bool IsProcessQualifier(string? qualifier) =>
        qualifier == "Processes" ||
        qualifier is not null && qualifier.StartsWith("Processes:", StringComparison.Ordinal) &&
        Guid.TryParseExact(qualifier["Processes:".Length..], "N", out var id) &&
        qualifier == "Processes:" + id.ToString("N");

    private static void ValidateProcessOrigin(AiConversationCreationOrigin origin)
    {
        if (origin is null || origin.Surface != "Processes" || origin.ProcessIdentity is null ||
            string.IsNullOrWhiteSpace(origin.ProcessEntityId) ||
            string.IsNullOrWhiteSpace(origin.ProcessIdentity.EvidenceSessionId) ||
            string.IsNullOrWhiteSpace(origin.ProcessIdentity.CaptureId) ||
            string.IsNullOrWhiteSpace(origin.ProcessIdentity.SourceIdentityId) ||
            string.IsNullOrWhiteSpace(origin.ProcessIdentity.HostId))
            throw new ArgumentException("Process creation origin requires exact durable evidence scope.");
    }

    private static void ValidateCreationOrigin(AiConversationScope scope, AiConversationCreationOrigin? origin)
    {
        if (origin is null)
        {
            if (IsProcessQualifier(scope.ScopeQualifier))
                throw new ArgumentException("Processes conversation requires a creation origin.");
            return;
        }
        ValidateProcessOrigin(origin);
        if (scope.Identity != origin.ProcessIdentity ||
            (scope.ContextType == AiConversationContextType.Object &&
             (!IsProcessQualifier(scope.ScopeQualifier) ||
              scope.ObjectReference?.Evidence.Kind != EvidenceReferenceKind.ProcessEntity ||
              scope.ObjectReference.Evidence.Id != origin.ProcessEntityId)) ||
            scope.ContextType == AiConversationContextType.General)
            throw new ArgumentException("Creation origin does not match the conversation's exact process scope.");
    }

    private static void ValidateReference(AiEvidenceReference reference)
    {
        if (string.IsNullOrWhiteSpace(reference.ReferenceId) || reference.Identity is null ||
            !Enum.IsDefined(reference.Evidence.Kind) ||
            string.IsNullOrWhiteSpace(reference.Identity.EvidenceSessionId) ||
            string.IsNullOrWhiteSpace(reference.Identity.CaptureId) ||
            string.IsNullOrWhiteSpace(reference.Identity.SourceIdentityId) ||
            string.IsNullOrWhiteSpace(reference.Identity.HostId) ||
            string.IsNullOrWhiteSpace(reference.DataSource) || reference.DataSource.Length > 120 ||
            reference.CompactSnapshot.Length > 4096 || reference.DisplayName.Length > 500 ||
            (reference.TimestampUtc is { } timestamp && timestamp.Kind != DateTimeKind.Utc) ||
            (!string.IsNullOrEmpty(reference.CompactSnapshot) && string.IsNullOrWhiteSpace(reference.SnapshotProvenance)))
            throw new ArgumentException("Evidence reference has missing scope or an unbounded snapshot.");
        if (reference.Evidence.Kind == EvidenceReferenceKind.ProcessEntity)
        {
            if (!string.IsNullOrWhiteSpace(reference.SourceRunId) || !string.IsNullOrWhiteSpace(reference.SourceRevision) ||
                (string.IsNullOrWhiteSpace(reference.Evidence.Id) && string.IsNullOrWhiteSpace(reference.Process?.ProcessKey)))
                throw new ArgumentException("Process entity reference needs durable identity or exact scoped legacy key.");
            if (reference.Process is not null &&
                (!string.Equals(reference.Process.ProcessEntityId, reference.Evidence.Id, StringComparison.Ordinal) ||
                 !string.Equals(reference.Process.CaseId, reference.Identity.CaseId, StringComparison.Ordinal) ||
                 !string.Equals(reference.Process.EvidenceSessionId, reference.Identity.EvidenceSessionId, StringComparison.Ordinal) ||
                 !string.Equals(reference.Process.CaptureId, reference.Identity.CaptureId, StringComparison.Ordinal) ||
                 !string.Equals(reference.Process.SourceIdentityId, reference.Identity.SourceIdentityId, StringComparison.Ordinal) ||
                 !string.Equals(reference.Process.HostId, reference.Identity.HostId, StringComparison.Ordinal) ||
                 !string.Equals(reference.Process.ExecutionRootId, reference.Identity.ExecutionRootId, StringComparison.Ordinal)))
                throw new ArgumentException("Process reference scope does not match evidence identity.");
        }
        else if (string.IsNullOrWhiteSpace(reference.Evidence.Id) ||
                 (string.IsNullOrWhiteSpace(reference.SourceRunId) && string.IsNullOrWhiteSpace(reference.SourceRevision)))
            throw new ArgumentException("Observation reference requires exact row and run or revision.");
    }

    private static void InsertOrVerifyReference(SqliteConnection connection, SqliteTransaction transaction,
        AiEvidenceReference reference)
    {
        ValidateReference(reference);
        using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT OR IGNORE INTO AiEvidenceReferences
                    (ReferenceId,IdentityJson,EvidenceKind,EvidenceId,DataSource,SourceRunId,SourceRevision,
                     TimestampUtc,DisplayName,CompactSnapshot,SnapshotProvenance,ProcessJson,CanonicalObjectKey)
                VALUES($Id,$Identity,$Kind,$EvidenceId,$DataSource,$Run,$Revision,
                       $Timestamp,$Display,$Snapshot,$Provenance,$Process,$Canonical);
                """;
            Add(insert, "$Id", reference.ReferenceId);
            Add(insert, "$Identity", JsonSerializer.Serialize(reference.Identity));
            Add(insert, "$Kind", reference.Evidence.Kind.ToString());
            Add(insert, "$EvidenceId", reference.Evidence.Id);
            Add(insert, "$DataSource", reference.DataSource);
            Add(insert, "$Run", reference.SourceRunId);
            Add(insert, "$Revision", reference.SourceRevision);
            Add(insert, "$Timestamp", reference.TimestampUtc);
            Add(insert, "$Display", reference.DisplayName);
            Add(insert, "$Snapshot", reference.CompactSnapshot);
            Add(insert, "$Provenance", reference.SnapshotProvenance);
            Add(insert, "$Process", reference.Process is null ? null : JsonSerializer.Serialize(reference.Process));
            Add(insert, "$Canonical", reference.CanonicalObjectKey);
            insert.ExecuteNonQuery();
        }
        var stored = LoadReference(connection, transaction, reference.ReferenceId);
        if (stored != reference) throw new InvalidOperationException("Evidence reference ID is bound to different immutable content.");
    }

    private static AiEvidenceReference? LoadReference(SqliteConnection connection, SqliteTransaction? transaction, string id)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM AiEvidenceReferences WHERE ReferenceId=$Id;";
        Add(command, "$Id", id);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var identity = JsonSerializer.Deserialize<EvidenceIdentity>(reader.GetString(reader.GetOrdinal("IdentityJson")))
            ?? throw new InvalidOperationException("Evidence identity is invalid.");
        var processOrdinal = reader.GetOrdinal("ProcessJson");
        var process = reader.IsDBNull(processOrdinal) ? null :
            JsonSerializer.Deserialize<AiProcessReference>(reader.GetString(processOrdinal));
        return new AiEvidenceReference(reader.GetString(reader.GetOrdinal("ReferenceId")), identity,
            new EvidenceReference(Enum.Parse<EvidenceReferenceKind>(reader.GetString(reader.GetOrdinal("EvidenceKind"))),
                reader.GetString(reader.GetOrdinal("EvidenceId"))),
            reader.GetString(reader.GetOrdinal("DataSource")), reader.GetString(reader.GetOrdinal("SourceRunId")),
            reader.GetString(reader.GetOrdinal("SourceRevision")),
            ParseUtc(reader.IsDBNull(reader.GetOrdinal("TimestampUtc")) ? null : reader.GetString(reader.GetOrdinal("TimestampUtc"))),
            reader.GetString(reader.GetOrdinal("DisplayName")), reader.GetString(reader.GetOrdinal("CompactSnapshot")),
            reader.GetString(reader.GetOrdinal("SnapshotProvenance")), process);
    }

    private void SaveConversationMessage(AiConversationMessage message, IReadOnlyList<AiEvidenceReference> references,
        CancellationToken ct)
    {
        if (message is null || string.IsNullOrWhiteSpace(message.Id) || string.IsNullOrWhiteSpace(message.ConversationId) ||
            message.TimestampUtc is null || message.TimestampUtc.Value.Kind != DateTimeKind.Utc ||
            !new[] { "user", "assistant" }.Contains(message.Role, StringComparer.OrdinalIgnoreCase) ||
            message.Status is not ("Pending" or "Succeeded" or "Failed" or "ConfigurationRequired" or "Disabled" or "Cancelled" or "Interrupted") ||
            message.IsHistorical || message.OriginalProviderKind is not null ||
            message.OriginalBaseUrl is not null || message.OriginalCreatedUtc is not null ||
            message.OriginalProviderName is not null || message.OriginalModelName is not null ||
            message.OriginalErrorText is not null || message.Content.Length > 100_000 ||
            message.ErrorText.Length > ModelDiagnosticRedactor.MaximumDiagnosticCharacters || message.TechnicalDetails is null || message.TechnicalDetails.Length > 48_000 || references.Count > 32)
            throw new ArgumentException("Conversation message is invalid or contains historical metadata.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadWrite);
            using var transaction = connection.BeginTransaction();
            var conversation = LoadConversationForWrite(connection, transaction, message.ConversationId);
            if (conversation is null || conversation.IsHistorical)
                throw new InvalidOperationException("Conversation is unavailable for new messages.");
            foreach (var reference in references)
            {
                ct.ThrowIfCancellationRequested();
                if (!ReferenceWithinScope(conversation.Scope, reference.Identity))
                    throw new InvalidOperationException("Message evidence is outside the conversation scope.");
                InsertOrVerifyReference(connection, transaction, reference);
            }
            var existing = LoadMessageForWrite(connection, transaction, message.Id);
            if (existing is not null && existing != message)
                throw new InvalidOperationException("Message ID is bound to different content.");
            if (existing is null)
            {
                using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO AiMessages
                        (Id,ConversationId,Role,Content,TimestampUtc,ProviderId,ModelId,Status,ErrorText,TechnicalDetails)
                    VALUES($Id,$ConversationId,$Role,$Content,$Timestamp,$ProviderId,$ModelId,$Status,$ErrorText,$Technical);
                    """;
                Add(insert, "$Id", message.Id);
                Add(insert, "$ConversationId", message.ConversationId);
                Add(insert, "$Role", message.Role);
                Add(insert, "$Content", message.Content);
                Add(insert, "$Timestamp", message.TimestampUtc.Value);
                Add(insert, "$ProviderId", message.ProviderId);
                Add(insert, "$ModelId", message.ModelId);
                Add(insert, "$Status", message.Status);
                Add(insert, "$ErrorText", message.ErrorText);
                Add(insert, "$Technical", message.TechnicalDetails);
                insert.ExecuteNonQuery();
                foreach (var reference in references)
                {
                    using var link = connection.CreateCommand();
                    link.Transaction = transaction;
                    link.CommandText = "INSERT INTO AiMessageEvidence(MessageId,ReferenceId) VALUES($Message,$Reference);";
                    Add(link, "$Message", message.Id);
                    Add(link, "$Reference", reference.ReferenceId);
                    link.ExecuteNonQuery();
                }
                using var update = connection.CreateCommand();
                update.Transaction = transaction;
                update.CommandText = "UPDATE AiConversations SET UpdatedUtc=$Updated WHERE Id=$Id;";
                Add(update, "$Updated", DateTime.UtcNow);
                Add(update, "$Id", message.ConversationId);
                update.ExecuteNonQuery();
            }
            else
            {
                using var links = connection.CreateCommand();
                links.Transaction = transaction;
                links.CommandText = "SELECT ReferenceId FROM AiMessageEvidence WHERE MessageId=$Message;";
                Add(links, "$Message", message.Id);
                var savedIds = new HashSet<string>(StringComparer.Ordinal);
                using var reader = links.ExecuteReader();
                while (reader.Read()) savedIds.Add(reader.GetString(0));
                if (!savedIds.SetEquals(references.Select(r => r.ReferenceId)))
                    throw new InvalidOperationException("Message ID is bound to different evidence links.");
            }
            ct.ThrowIfCancellationRequested();
            transaction.Commit();
        }
    }

    private static AiConversation? LoadConversationForWrite(SqliteConnection connection, SqliteTransaction transaction, string id)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM AiConversations WHERE Id=$Id;";
        Add(command, "$Id", id);
        AiConversation? conversation;
        string? referenceId;
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read()) return null;
            conversation = ReadConversation(reader, null);
            var ordinal = reader.GetOrdinal("EvidenceReferenceId");
            referenceId = reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
        }
        if (referenceId is not null)
            conversation = conversation with { Scope = conversation.Scope with
                { ObjectReference = LoadReference(connection, transaction, referenceId) ??
                    throw new InvalidOperationException("Conversation target reference is missing.") } };
        return conversation;
    }

    private static AiConversationMessage? LoadMessageForWrite(SqliteConnection connection, SqliteTransaction transaction, string id)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM AiMessages WHERE Id=$Id;";
        Add(command, "$Id", id);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadMessage(reader) : null;
    }

    private static AiConversationMessage ReadMessage(SqliteDataReader reader) => new(
        reader.GetString(reader.GetOrdinal("Id")), reader.GetString(reader.GetOrdinal("ConversationId")),
        reader.GetString(reader.GetOrdinal("Role")), reader.GetString(reader.GetOrdinal("Content")),
        ParseUtc(reader.GetString(reader.GetOrdinal("TimestampUtc"))),
        reader.GetString(reader.GetOrdinal("ProviderId")), reader.GetString(reader.GetOrdinal("ModelId")),
        reader.GetString(reader.GetOrdinal("Status")), reader.GetString(reader.GetOrdinal("ErrorText")),
        reader.GetInt32(reader.GetOrdinal("IsHistorical")) != 0,
        GetNullableString(reader, reader.GetOrdinal("OriginalProviderKind")),
        GetNullableString(reader, reader.GetOrdinal("OriginalBaseUrl")),
        GetNullableString(reader, reader.GetOrdinal("OriginalCreatedUtc")),
        GetNullableString(reader, reader.GetOrdinal("OriginalProviderName")),
        GetNullableString(reader, reader.GetOrdinal("OriginalModelName")),
        GetNullableString(reader, reader.GetOrdinal("OriginalErrorText")),
        reader.GetString(reader.GetOrdinal("TechnicalDetails")),
        Enumerable.Range(0, reader.FieldCount).Any(i => reader.GetName(i) == "HasPromptRequests") &&
            reader.GetInt32(reader.GetOrdinal("HasPromptRequests")) != 0);

    private static string? GetNullableString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private IReadOnlyList<AiConversationMessage> LoadConversationMessages(string conversationId, int limit, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(conversationId)) return [];
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            var result = new List<AiConversationMessage>();
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "SELECT *, EXISTS(SELECT 1 FROM AiPromptRequests p WHERE p.MessageId=AiMessages.Id AND p.ConversationId=AiMessages.ConversationId) AS HasPromptRequests FROM AiMessages WHERE ConversationId=$Id ORDER BY TimestampUtc DESC, Id LIMIT $Limit;";
                Add(command, "$Id", conversationId);
                Add(command, "$Limit", Math.Clamp(limit, 1, 1000));
                using var reader = command.ExecuteReader();
                while (reader.Read()) { ct.ThrowIfCancellationRequested(); result.Add(ReadMessage(reader)); }
            }
            string? legacyId;
            using (var lookup = connection.CreateCommand())
            {
                lookup.CommandText = "SELECT LegacyConversationId FROM AiConversations WHERE Id=$Id;";
                Add(lookup, "$Id", conversationId);
                legacyId = lookup.ExecuteScalar() as string;
            }
            if (legacyId is not null)
            {
                using var legacy = connection.CreateCommand();
                legacy.CommandText = """
                    SELECT MessageId,ConversationId,Role,Content,ProviderKind,ProviderName,BaseUrl,ModelName,
                           CreatedUtc,Status,ErrorText
                    FROM AiChatMessages WHERE ConversationId=$Id ORDER BY CreatedUtc DESC,MessageId LIMIT $Limit;
                    """;
                Add(legacy, "$Id", legacyId);
                Add(legacy, "$Limit", Math.Clamp(limit, 1, 1000));
                using var reader = legacy.ExecuteReader();
                while (reader.Read())
                {
                    ct.ThrowIfCancellationRequested();
                    var rawTime = GetString(reader, 8);
                    result.Add(new AiConversationMessage(GetString(reader, 0), conversationId,
                        GetString(reader, 2), GetString(reader, 3), ParseUtc(rawTime),
                        GetString(reader, 5), GetString(reader, 7), GetString(reader, 9), GetString(reader, 10),
                        true, GetNullableString(reader, 4), GetNullableString(reader, 6), rawTime,
                        GetNullableString(reader, 5), GetNullableString(reader, 7), GetNullableString(reader, 10)));
                }
            }
            return result.OrderBy(m => m.TimestampUtc).ThenBy(m => m.Id, StringComparer.Ordinal)
                .TakeLast(Math.Clamp(limit, 1, 1000)).ToArray();
        }
    }

    private AiRuntimeHistoryPage LoadRuntimeHistoryPage(string conversationId, int limit, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(conversationId) || limit is < 1 or > 500)
            throw new ArgumentException("Runtime history selection is invalid.");
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var tx = connection.BeginTransaction(deferred: true);
            var conversation = LoadConversationForWrite(connection, tx, conversationId);
            if (conversation is null || conversation.IsHistorical)
                throw new InvalidOperationException("Runtime conversation is unavailable.");
            int eligible;
            int diagnostics;
            using (var count = connection.CreateCommand())
            {
                count.Transaction = tx;
                count.CommandText = """
                    SELECT
                      COALESCE(SUM(CASE WHEN Status='Succeeded' AND lower(Role) IN ('user','assistant') THEN 1 ELSE 0 END),0),
                      COALESCE(SUM(CASE WHEN Status!='Succeeded' OR lower(Role) NOT IN ('user','assistant') THEN 1 ELSE 0 END),0)
                    FROM AiMessages WHERE ConversationId=$Id;
                    """;
                Add(count, "$Id", conversationId);
                using var reader = count.ExecuteReader();
                reader.Read();
                eligible = checked((int)reader.GetInt64(0));
                diagnostics = checked((int)reader.GetInt64(1));
            }
            var messages = new List<AiConversationMessage>();
            using (var select = connection.CreateCommand())
            {
                select.Transaction = tx;
                select.CommandText = """
                    SELECT * FROM AiMessages WHERE ConversationId=$Id AND Status='Succeeded'
                      AND lower(Role) IN ('user','assistant')
                      AND length(CAST(Content AS BLOB)) <= 256000
                    ORDER BY TimestampUtc DESC,Id DESC LIMIT $Limit;
                    """;
                Add(select, "$Id", conversationId);
                Add(select, "$Limit", limit);
                using var reader = select.ExecuteReader();
                var selectedBytes = 0L;
                while (reader.Read())
                {
                    ct.ThrowIfCancellationRequested();
                    var message = ReadMessage(reader);
                    selectedBytes += System.Text.Encoding.UTF8.GetByteCount(message.Content);
                    if (selectedBytes > 4_000_000) break;
                    messages.Add(message);
                }
            }
            messages.Reverse();
            ct.ThrowIfCancellationRequested();
            tx.Commit();
            return new AiRuntimeHistoryPage(Array.AsReadOnly(messages.ToArray()), eligible, diagnostics);
        }
    }

    private IReadOnlyList<AiEvidenceReference> LoadMessageEvidence(string conversationId, string messageId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(conversationId) || string.IsNullOrWhiteSpace(messageId)) return [];
        lock (_lock)
        {
            ct.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            var ids = new List<string>();
            using (var command = connection.CreateCommand())
            {
                command.CommandText = """
                    SELECT link.ReferenceId
                    FROM AiMessageEvidence AS link
                    JOIN AiMessages AS message ON message.Id=link.MessageId
                    JOIN AiConversations AS conversation ON conversation.Id=message.ConversationId
                    WHERE message.ConversationId=$Conversation AND message.Id=$Message
                      AND conversation.IsHistorical=0
                    ORDER BY link.ReferenceId;
                    """;
                Add(command, "$Conversation", conversationId);
                Add(command, "$Message", messageId);
                using var reader = command.ExecuteReader();
                while (reader.Read()) { ct.ThrowIfCancellationRequested(); ids.Add(reader.GetString(0)); }
            }
            return ids.Select(id => LoadReference(connection, null, id) ??
                throw new InvalidOperationException("Saved evidence reference is missing.")).ToArray();
        }
    }

    private static void EnsureLegacyConversation(SqliteConnection connection, SqliteTransaction transaction, string legacyId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT OR IGNORE INTO AiConversations
                (Id,Title,ContextType,ContextId,ScopeKey,IdentityJson,HostId,
                 CreatedUtc,UpdatedUtc,IsHistorical,LegacyConversationId)
            SELECT 'legacy-chat:' || $Id, 'Historical chat', 'General', $Id,
                   'legacy-chat:' || $Id, '{}', '', MIN(CreatedUtc), MAX(CreatedUtc), 1, $Id
            FROM AiChatMessages WHERE ConversationId=$Id;
            UPDATE AiConversations
            SET UpdatedUtc=(SELECT MAX(CreatedUtc) FROM AiChatMessages WHERE ConversationId=$Id)
            WHERE LegacyConversationId=$Id;
            """;
        Add(command, "$Id", legacyId);
        command.ExecuteNonQuery();
    }

    private static bool ReferenceWithinScope(AiConversationScope conversation, EvidenceIdentity reference)
    {
        var scope = conversation.Identity;
        if (conversation.ContextType == AiConversationContextType.Object) return scope == reference;
        return
        (string.IsNullOrEmpty(scope.CaseId) || scope.CaseId == reference.CaseId) &&
        scope.EvidenceSessionId == reference.EvidenceSessionId &&
        (string.IsNullOrEmpty(scope.CaptureId) || scope.CaptureId == reference.CaptureId) &&
        (string.IsNullOrEmpty(scope.SourceIdentityId) || scope.SourceIdentityId == reference.SourceIdentityId) &&
        (string.IsNullOrEmpty(scope.HostId) || scope.HostId == reference.HostId) &&
        (string.IsNullOrEmpty(scope.ExecutionRootId) || scope.ExecutionRootId == reference.ExecutionRootId);
    }
}
