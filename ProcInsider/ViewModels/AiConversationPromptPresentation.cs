using System.Collections.ObjectModel;
using ProcInsider.Models.Ai;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public sealed record AiPromptInstructionDraft(string ConversationId, string MessageId, string Objective, string Instructions);

// Presentation state only. Request bodies are immutable annotations, never runtime history or replay inputs.
internal static class AiConversationPromptPresentation
{
    internal static Task PublishAsync(SynchronizationContext? context, ObservableCollection<AiConversationMessage> messages,
        AiConversationMessage question, AiPromptRequest request, Func<bool> current, CancellationToken token)
    {
        void Publish()
        {
            token.ThrowIfCancellationRequested();
            if (!current()) return;
            var existing = messages.FirstOrDefault(item => item.Id == question.Id);
            var prior = existing?.PromptRequests ?? [];
            var updated = (existing ?? question) with
            {
                HasPromptRequests = true,
                PromptRequests = prior.Where(item => item.Id != request.Id).Append(request).ToArray()
            };
            if (existing is not null) messages[messages.IndexOf(existing)] = updated;
            else
            {
                while (messages.Count >= 200) messages.RemoveAt(0);
                messages.Add(updated);
            }
        }
        if (context is null || ReferenceEquals(context, SynchronizationContext.Current)) { Publish(); return Task.CompletedTask; }
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        context.Post(_ => { try { Publish(); completion.SetResult(); } catch (Exception error) { completion.SetException(error); } }, null);
        return completion.Task;
    }

    internal static async Task LoadAsync(AnnotationDatabaseService store, ObservableCollection<AiConversationMessage> messages,
        AiConversationMessage message, Func<bool> current, CancellationToken token = default)
    {
        if (!current() || !messages.Any(item => item.Id == message.Id && item.ConversationId == message.ConversationId)) return;
        if (messages.FirstOrDefault(item => item.Id == message.Id && item.ConversationId == message.ConversationId)
            is { PromptRequests.Count: > 0 }) return;
        var requests = await store.LoadPromptRequestsAsync(message.ConversationId, message.Id, token);
        if (!current()) return;
        var existing = messages.FirstOrDefault(item => item.Id == message.Id && item.ConversationId == message.ConversationId);
        if (existing is not null && requests.Count > 0) messages[messages.IndexOf(existing)] = existing with { PromptRequests = requests };
    }

    internal static async Task<IReadOnlyList<AiConversationMessage>> LoadLatestAsync(AnnotationDatabaseService store,
        IReadOnlyList<AiConversationMessage> messages, CancellationToken token = default)
    {
        var latest = messages.LastOrDefault(item => item.Role.Equals("user", StringComparison.OrdinalIgnoreCase) && item.HasPromptRequests);
        if (latest is null) return messages;
        var requests = await store.LoadPromptRequestsAsync(latest.ConversationId, latest.Id, token);
        return messages.Select(item => item.Id == latest.Id ? item with { PromptRequests = requests } : item).ToArray();
    }

    internal const string OversizeInstructionsMessage =
        "Edited instructions exceed the 16,000-byte UTF-8 limit. Shorten the draft and prepare it again.";

    internal static bool InstructionsTooLarge(AiPromptInstructionDraft? draft) =>
        draft?.Instructions is { } instructions && System.Text.Encoding.UTF8.GetByteCount(instructions) > 16_000;

    internal static bool ValidDraft(AiPromptInstructionDraft? draft, ObservableCollection<AiConversationMessage> messages) =>
        draft is not null && draft.Instructions is not null && System.Text.Encoding.UTF8.GetByteCount(draft.Instructions) <= 16_000 &&
        messages.Any(item => item.Id == draft.MessageId && item.ConversationId == draft.ConversationId &&
            item.HasPromptRequests && item.Content == draft.Objective && !item.IsHistorical);
}
