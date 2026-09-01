namespace ProcInsider.Models.Ai;

public sealed class AiPromptTemplate
{
    public string Id { get; init; } = string.Empty;

    public string Title { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    public string SystemPrompt { get; init; } = string.Empty;

    public string UserPromptPrefix { get; init; } = string.Empty;
}
