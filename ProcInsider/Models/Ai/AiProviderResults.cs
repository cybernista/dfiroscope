namespace ProcInsider.Models.Ai;

public sealed class AiProviderResponse
{
    public bool Success { get; init; }

    public string Content { get; init; } = string.Empty;

    public string ErrorMessage { get; init; } = string.Empty;

    public string ProviderName { get; init; } = string.Empty;

    public string ModelName { get; init; } = string.Empty;

    public int? PromptTokens { get; init; }

    public int? CompletionTokens { get; init; }

    public int? TotalTokens { get; init; }
}

public sealed class AiProviderTestResult
{
    public bool Success { get; init; }

    public string Message { get; init; } = string.Empty;
}
