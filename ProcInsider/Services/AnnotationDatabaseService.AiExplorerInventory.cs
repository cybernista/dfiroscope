using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services;

internal sealed record AiExplorerAnnotationInventory(int ChatCount, int InvestigationCount,
    IReadOnlyList<AiConversation> Conversations,
    IReadOnlyList<(Investigation Investigation, AiConversation Conversation)> Investigations);

public sealed partial class AnnotationDatabaseService
{
    internal Task<AiExplorerAnnotationInventory> ReadAiExplorerInventoryAsync(string sessionId,
        int chatLimit, int investigationLimit, CancellationToken cancellationToken) =>
        Task.Run(() => ReadAiExplorerInventory(sessionId, chatLimit, investigationLimit, cancellationToken), cancellationToken);

    internal static bool IsExplorerChatCompatible(AiConversation conversation, string sessionId) =>
        !string.IsNullOrWhiteSpace(conversation.Id) && conversation.Scope.Identity.EvidenceSessionId == sessionId &&
        (conversation.Scope.ContextType == AiConversationContextType.General ||
         !conversation.IsHistorical && conversation.Scope.ContextType == AiConversationContextType.Object &&
         conversation.Scope.ObjectReference is { } reference && conversation.Scope.Identity == reference.Identity &&
         conversation.Scope.ContextId == reference.CanonicalObjectKey && conversation.HostId == reference.Identity.HostId &&
         !string.IsNullOrWhiteSpace(conversation.HostId));

    internal static bool IsExplorerInvestigationCompatible(string id, string conversationId,
        AiEvidenceReference? target, AiConversation? conversation, string sessionId) =>
        target is not null && conversation is { IsHistorical: false } && conversationId == conversation.Id &&
        !string.IsNullOrWhiteSpace(id) && conversation.Scope.ContextType == AiConversationContextType.Investigation &&
        conversation.Scope.ContextId == id && conversation.Scope.Identity == target.Identity &&
        target.Identity.EvidenceSessionId == sessionId && conversation.HostId == target.Identity.HostId &&
        !string.IsNullOrWhiteSpace(conversation.HostId);

    // Stream only scalar scope metadata for the exact counts. Snapshots, message bodies,
    // investigation summaries/questions and full references are loaded only for the visible page.
    private AiExplorerAnnotationInventory ReadAiExplorerInventory(string sessionId, int chatLimit,
        int investigationLimit, CancellationToken token)
    {
        lock (_lock)
        {
            token.ThrowIfCancellationRequested();
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var transaction = connection.BeginTransaction(deferred: true);
            var chats = new List<AiConversation>();
            var chatCount = 0;
            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = """
                    SELECT c.*, r.ReferenceId AS RefId,r.IdentityJson AS RefIdentity,
                        r.EvidenceKind AS RefKind,r.EvidenceId AS RefEvidenceId,
                        r.SourceRunId AS RefRun,r.SourceRevision AS RefRevision,
                        json_extract(r.ProcessJson,'$.ProcessKey') AS RefProcessKey
                    FROM AiConversations c LEFT JOIN AiEvidenceReferences r ON r.ReferenceId=c.EvidenceReferenceId
                    WHERE c.ContextType IN ('General','Object') ORDER BY c.UpdatedUtc DESC,c.Id;
                    """;
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    token.ThrowIfCancellationRequested();
                    var conversation = ReadConversation(reader, ReadExplorerScopeReference(reader));
                    if (!IsExplorerChatCompatible(conversation, sessionId)) continue;
                    chatCount++;
                    if (chats.Count < chatLimit) chats.Add(conversation);
                }
            }
            for (var index = 0; index < chats.Count; index++)
            {
                token.ThrowIfCancellationRequested();
                if (chats[index].Scope.ObjectReference is { } reference)
                    chats[index] = chats[index] with { Scope = chats[index].Scope with
                        { ObjectReference = LoadReference(connection, transaction, reference.ReferenceId) } };
            }
            var investigationCount = 0;
            var investigationPage = new List<(string Id, AiConversation Conversation)>();
            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = """
                    SELECT c.*, i.Id AS InvestigationId,i.ConversationId AS InvestigationConversationId,
                        r.ReferenceId AS RefId,r.IdentityJson AS RefIdentity,r.EvidenceKind AS RefKind,
                        r.EvidenceId AS RefEvidenceId,r.SourceRunId AS RefRun,r.SourceRevision AS RefRevision,
                        json_extract(r.ProcessJson,'$.ProcessKey') AS RefProcessKey
                    FROM AiInvestigations i JOIN AiConversations c ON c.Id=i.ConversationId
                    LEFT JOIN AiEvidenceReferences r ON r.ReferenceId=i.TargetReferenceId
                    ORDER BY i.UpdatedUtc DESC,i.Id;
                    """;
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    token.ThrowIfCancellationRequested();
                    var target = ReadExplorerScopeReference(reader);
                    var conversation = ReadConversation(reader, null);
                    var id = reader.GetString(reader.GetOrdinal("InvestigationId"));
                    var conversationId = reader.GetString(reader.GetOrdinal("InvestigationConversationId"));
                    if (!IsExplorerInvestigationCompatible(id, conversationId, target, conversation, sessionId)) continue;
                    investigationCount++;
                    if (investigationPage.Count < investigationLimit) investigationPage.Add((id, conversation));
                }
            }
            var investigations = new List<(Investigation, AiConversation)>();
            foreach (var entry in investigationPage)
            {
                token.ThrowIfCancellationRequested();
                investigations.Add((ReadInvestigation(connection, transaction, entry.Id) ??
                    throw new InvalidOperationException("Saved investigation disappeared during its inventory read."), entry.Conversation));
            }
            transaction.Commit();
            return new(chatCount, investigationCount, chats, investigations);
        }
    }

    // This scope-only reference is never returned as evidence or supplied to a model.
    private static AiEvidenceReference? ReadExplorerScopeReference(SqliteDataReader reader)
    {
        var id = reader.GetOrdinal("RefId");
        if (reader.IsDBNull(id)) return null;
        var identity = JsonSerializer.Deserialize<EvidenceIdentity>(reader.GetString(reader.GetOrdinal("RefIdentity"))) ??
            throw new InvalidOperationException("Saved Explorer reference identity is invalid.");
        var evidenceId = reader.GetString(reader.GetOrdinal("RefEvidenceId"));
        var processOrdinal = reader.GetOrdinal("RefProcessKey");
        var process = reader.IsDBNull(processOrdinal) ? null : new AiProcessReference(evidenceId,
            reader.GetString(processOrdinal), identity.CaseId, identity.EvidenceSessionId, identity.CaptureId,
            identity.SourceIdentityId, identity.HostId, identity.ExecutionRootId);
        return new(reader.GetString(id), identity,
            new EvidenceReference(Enum.Parse<EvidenceReferenceKind>(reader.GetString(reader.GetOrdinal("RefKind"))), evidenceId),
            "", reader.GetString(reader.GetOrdinal("RefRun")), reader.GetString(reader.GetOrdinal("RefRevision")),
            null, "", "", "", process);
    }
}
