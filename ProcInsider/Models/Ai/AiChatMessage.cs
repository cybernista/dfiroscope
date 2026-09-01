namespace ProcInsider.Models.Ai;

public sealed class AiChatMessage
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");

    public string ConversationId { get; set; } = string.Empty;

    public string Role { get; set; } = string.Empty;

    public string Content { get; set; } = string.Empty;

    public AiProviderKind ProviderKind { get; set; } = AiProviderKind.Disabled;

    public string ProviderName { get; set; } = string.Empty;

    public string BaseUrl { get; set; } = string.Empty;

    public string ModelName { get; set; } = string.Empty;

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    public AiInvestigationStatus Status { get; set; } = AiInvestigationStatus.Pending;

    public string ErrorText { get; set; } = string.Empty;

    public string CreatedDisplay => CreatedUtc.ToLocalTime().ToString("HH:mm:ss");

    public string AuthorDisplay => Role.Equals("assistant", StringComparison.OrdinalIgnoreCase)
        ? "Assistant"
        : "Analyst";

    public string ProviderDisplay => string.IsNullOrWhiteSpace(ModelName)
        ? ProviderName
        : $"{ProviderName} / {ModelName}";
}

public sealed class AiChatCompletionResult
{
    public bool Success { get; init; }

    public AiProviderKind ProviderKind { get; init; } = AiProviderKind.Disabled;

    public string ProviderName { get; init; } = string.Empty;

    public string BaseUrl { get; init; } = string.Empty;

    public string ModelName { get; init; } = string.Empty;

    public string ResponseText { get; init; } = string.Empty;

    public string ErrorText { get; init; } = string.Empty;

    public int? PromptTokens { get; init; }

    public int? CompletionTokens { get; init; }

    public int? TotalTokens { get; init; }
}
