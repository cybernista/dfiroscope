namespace ProcInsider.Models.Ai;

public sealed class AiInvestigationRecord
{
    public string InvestigationId { get; set; } = string.Empty;

    public string TargetKind { get; set; } = string.Empty;

    public string TargetTable { get; set; } = string.Empty;

    public string TargetId { get; set; } = string.Empty;

    public string ArtifactId { get; set; } = string.Empty;

    public string CaseId { get; set; } = string.Empty;

    public string EvidenceSessionId { get; set; } = string.Empty;

    public string CaptureId { get; set; } = string.Empty;

    public string SourceIdentityId { get; set; } = string.Empty;

    public string HostId { get; set; } = string.Empty;

    public string ProcessKey { get; set; } = string.Empty;

    public int ProcessId { get; set; }

    public string ProcessName { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    public string DisplayPath { get; set; } = string.Empty;

    public string SourceScopeKind { get; set; } = string.Empty;

    public string SourceScopeSummary { get; set; } = string.Empty;

    public string PromptTemplateId { get; set; } = string.Empty;

    public string PromptTemplateTitle { get; set; } = string.Empty;

    public string SystemPrompt { get; set; } = string.Empty;

    public string AnalystPrompt { get; set; } = string.Empty;

    public string FinalPrompt { get; set; } = string.Empty;

    public AiProviderKind ProviderKind { get; set; } = AiProviderKind.Disabled;

    public string ProviderName { get; set; } = string.Empty;

    public string BaseUrl { get; set; } = string.Empty;

    public string ModelName { get; set; } = string.Empty;

    public DateTime RequestedUtc { get; set; } = DateTime.UtcNow;

    public DateTime? CompletedUtc { get; set; }

    public AiInvestigationStatus Status { get; set; } = AiInvestigationStatus.Pending;

    public int RequestCharacterCount { get; set; }

    public int ResponseCharacterCount { get; set; }

    public int? PromptTokens { get; set; }

    public int? CompletionTokens { get; set; }

    public int? TotalTokens { get; set; }

    public string ErrorText { get; set; } = string.Empty;

    public string ResponseText { get; set; } = string.Empty;

    public string RequestedDisplay => RequestedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public string CompletedDisplay => CompletedUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty;

    public string ProviderDisplay => string.IsNullOrWhiteSpace(ModelName)
        ? ProviderName
        : $"{ProviderName} / {ModelName}";

    public string ResponsePreview
    {
        get
        {
            var text = string.IsNullOrWhiteSpace(ResponseText) ? ErrorText : ResponseText;
            if (string.IsNullOrWhiteSpace(text))
            {
                return string.Empty;
            }

            text = text.Replace("\r", " ").Replace("\n", " ").Trim();
            return text.Length <= 160 ? text : $"{text[..160]}...";
        }
    }
}
