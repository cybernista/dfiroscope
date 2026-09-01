using ProcInsider.Models.ApplicationCatalog;
using ProcInsider.Models.Ai;

namespace ProcInsider.Models.Telemetry;

public sealed class ApplicationMetadataRecord
{
    public string ApplicationId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string ExecutableNamePattern { get; set; } = string.Empty;

    public bool IsRegexPattern { get; set; }

    public string PackageFamilyName { get; set; } = string.Empty;

    public string AppUserModelId { get; set; } = string.Empty;

    public string BaseProfileId { get; set; } = string.Empty;

    public string BaseProfileRevision { get; set; } = string.Empty;

    public string BaseCatalogRevision { get; set; } = string.Empty;

    public ApplicationProfileOrigin RecordOrigin { get; set; } = ApplicationProfileOrigin.LegacySessionMetadata;

    public ApplicationProfileReviewState ReviewState { get; set; } = ApplicationProfileReviewState.Unreviewed;

    public string PathPattern { get; set; } = string.Empty;

    public string CompanyVendor { get; set; } = string.Empty;

    public string ProductName { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string ApplicationCategory { get; set; } = string.Empty;

    public string ExpectedResponsibilities { get; set; } = string.Empty;

    public string NormalBehavior { get; set; } = string.Empty;

    public string LaunchTriggers { get; set; } = string.Empty;

    public string ExpectedContext { get; set; } = string.Empty;

    public string CommandLineExpectations { get; set; } = string.Empty;

    public string FilesystemRegistryExpectations { get; set; } = string.Empty;

    public string ChildProcessExpectations { get; set; } = string.Empty;

    public string NetworkExpectations { get; set; } = string.Empty;

    public string NormalVariants { get; set; } = string.Empty;

    public string AnalystValidationChecks { get; set; } = string.Empty;

    public string KnownBenignNotes { get; set; } = string.Empty;

    public string CybersecurityNotes { get; set; } = string.Empty;

    public string Source { get; set; } = string.Empty;

    public double Confidence { get; set; }

    public bool IsAiGenerated { get; set; }

    public string ProviderName { get; set; } = string.Empty;

    public string ModelName { get; set; } = string.Empty;

    public string Prompt { get; set; } = string.Empty;

    public AiProviderKind AiProviderKind { get; set; } = AiProviderKind.Disabled;

    public string AiEndpointMode { get; set; } = string.Empty;

    public string AiPromptTemplateId { get; set; } = string.Empty;

    public DateTime? AiRequestedUtc { get; set; }

    public string AiUncertainty { get; set; } = string.Empty;

    public string AiValidationWarnings { get; set; } = string.Empty;

    public bool AiSourceClaimsUnverified { get; set; }

    public List<ApplicationProfileSourceReference> SourceReferences { get; set; } = [];

    public string CatalogProvenance { get; set; } = string.Empty;

    public DateTime? ProfileLastReviewedUtc { get; set; }

    public DateTime? ReviewedUtc { get; set; }

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;

    public DateTime? LastMatchedUtc { get; set; }

    public string MatchReason { get; set; } = string.Empty;

    public string ProvenanceDisplay
    {
        get
        {
            var source = string.IsNullOrWhiteSpace(Source) ? "Manual" : Source;
            if (RecordOrigin == ApplicationProfileOrigin.BuiltInCatalog)
            {
                var profile = string.IsNullOrWhiteSpace(BaseProfileId) ? "built-in profile" : BaseProfileId;
                return $"Built-in catalog {BaseCatalogRevision}; {profile} revision {BaseProfileRevision}";
            }

            var origin = RecordOrigin switch
            {
                ApplicationProfileOrigin.SessionAnalystOverride => "session analyst override",
                ApplicationProfileOrigin.SessionAiOverride => "session AI override",
                ApplicationProfileOrigin.UnsavedDraft => "unsaved draft",
                _ => "legacy session metadata"
            };
            if (!IsAiGenerated)
            {
                return $"{source}; {origin}";
            }

            var provider = string.IsNullOrWhiteSpace(ModelName)
                ? ProviderName
                : $"{ProviderName} / {ModelName}";
            var request = AiRequestedUtc.HasValue
                ? $"; requested {AiRequestedUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}"
                : string.Empty;
            var template = string.IsNullOrWhiteSpace(AiPromptTemplateId)
                ? string.Empty
                : $"; template {AiPromptTemplateId}";
            var endpointMode = string.IsNullOrWhiteSpace(AiEndpointMode)
                ? string.Empty
                : $"; {AiEndpointMode}";
            return string.IsNullOrWhiteSpace(provider)
                ? $"{source}; {origin}"
                : $"{source}; {origin} from {provider}{endpointMode}{template}{request}";
        }
    }
}
