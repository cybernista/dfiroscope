using ProcInsider.Models.Ai;

namespace ProcInsider.ViewModels;

// Display projection from saved annotations; the configured next model is never substituted.
public sealed record AiConversationBrief(string Id, string Title, DateTime? StartedUtc, string Model)
{
    public static AiConversationBrief From(AiConversation conversation, IReadOnlyList<AiConversationMessage> messages) =>
        new(conversation.Id, conversation.Title, conversation.CreatedUtc,
            messages.LastOrDefault(message => !string.IsNullOrWhiteSpace(message.ModelId))?.ModelId ?? "No model used");
}