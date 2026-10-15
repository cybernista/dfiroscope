using ProcInsider.Models.Ai;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

// Resolves saved answer citations through the current query owner; never treats annotation snapshots as originals.
internal static class AiAnswerEvidencePresentation
{
    internal static async Task<IReadOnlyList<AiEvidenceReference>> LoadAsync(
        AnnotationDatabaseService store, AiConversationMessage message,
        Func<AiEvidenceReference, CancellationToken, Task<AiObjectContext?>>? resolve,
        Func<bool> current, CancellationToken token = default)
    {
        var references = await store.LoadMessageEvidenceAsync(message.ConversationId, message.Id, token);
        var result = new List<AiEvidenceReference>();
        foreach (var reference in references.Take(50))
        {
            token.ThrowIfCancellationRequested();
            if (!current()) return [];
            if (resolve is null)
            {
                result.Add(reference with { CompactSnapshot = "Exact original details are unavailable in this view.", SnapshotProvenance = "Saved checked citation; original not resolved." });
                continue;
            }
            try
            {
                var original = await resolve(reference, token);
                if (!current()) return [];
                var exact = original is not null && original.Reference.CanonicalObjectKey == reference.CanonicalObjectKey &&
                    original.Reference.Identity == reference.Identity;
                result.Add(reference with
                {
                    CompactSnapshot = exact
                        ? string.Join(Environment.NewLine, original!.DisplayProperties.Concat(original.KeyProperties)
                            .DistinctBy(field => field.Key).Select(field => $"{field.Key}: {field.Value}"))
                        : "The exact original is unavailable in the current capture.",
                    SnapshotProvenance = exact ? "Exact original resolved from the current evidence query binding." : "Saved checked citation; original unavailable."
                });
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception)
            {
                if (!current()) return [];
                result.Add(reference with { CompactSnapshot = "The exact original could not be loaded.", SnapshotProvenance = "Saved checked citation; original resolution failed." });
            }
        }
        return result;
    }

    internal static AiConversationMessage? SelectAnswer(IReadOnlyList<AiConversationMessage> messages, string? previousId = null) =>
        messages.FirstOrDefault(message => message.Id == previousId && message.Role == "assistant") ??
        messages.LastOrDefault(message => message.Role == "assistant");
}
