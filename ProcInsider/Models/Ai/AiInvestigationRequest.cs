namespace ProcInsider.Models.Ai;

public sealed class AiInvestigationRequest
{
    public string InvestigationId { get; init; } = Guid.NewGuid().ToString("N");

    public AiSourceScope SourceScope { get; init; } = new();

    public AiPromptTemplate PromptTemplate { get; init; } = new();

    public string AnalystPromptSuffix { get; init; } = string.Empty;

    public string EvidenceText { get; init; } = string.Empty;

    public AiProviderSettings Settings { get; init; } = AiProviderSettings.CreateDefault();
}
