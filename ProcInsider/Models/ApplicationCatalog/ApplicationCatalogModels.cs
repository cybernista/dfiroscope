using System.Text.Json.Serialization;

namespace ProcInsider.Models.ApplicationCatalog;

public enum ApplicationFilenameMatchKind
{
    Exact = 0,
    Regex = 1
}

public enum ApplicationCategory
{
    Unknown = 0,
    OperatingSystem = 1,
    Security = 2,
    Administration = 3,
    Productivity = 4,
    Development = 5,
    Service = 6,
    Other = 7
}

public enum ApplicationProfileOrigin
{
    None = 0,
    BuiltInCatalog = 1,
    SessionAnalystOverride = 2,
    SessionAiOverride = 3,
    LegacySessionMetadata = 4,
    UnsavedDraft = 5
}

public enum ApplicationProfileReviewState
{
    Unreviewed = 0,
    CatalogReviewed = 1,
    AnalystReviewed = 2,
    AiDraft = 3
}

public sealed class ApplicationCatalogDocument
{
    public int SchemaVersion { get; set; }

    public string CatalogRevision { get; set; } = string.Empty;

    public List<ApplicationProfileDefinition> Profiles { get; set; } = [];
}

public sealed class ApplicationCatalogSourceIndex
{
    public int SchemaVersion { get; set; }

    public string CatalogRevision { get; set; } = string.Empty;

    public List<ApplicationCatalogSourceEntry> Entries { get; set; } = [];
}

public sealed class ApplicationCatalogSourceEntry
{
    public string ProfileId { get; set; } = string.Empty;

    public string Path { get; set; } = string.Empty;
}

public sealed class ApplicationProfileDefinition
{
    public string ProfileId { get; set; } = string.Empty;

    public string ProfileRevision { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public bool IsEnabled { get; set; }

    [JsonRequired]
    public bool IsEvaluationCandidate { get; set; }

    [JsonConverter(typeof(JsonStringEnumConverter<ApplicationProfileReviewState>))]
    public ApplicationProfileReviewState ReviewState { get; set; }

    [JsonConverter(typeof(JsonStringEnumConverter<ApplicationCategory>))]
    public ApplicationCategory Category { get; set; }

    public ApplicationFilenameMatcher Filename { get; set; } = new();

    public ApplicationProfileDiscriminators Discriminators { get; set; } = new();

    public string RoleSummary { get; set; } = string.Empty;

    public List<string> ExpectedResponsibilities { get; set; } = [];

    public List<string> NormalBehavior { get; set; } = [];

    public List<string> LaunchTriggers { get; set; } = [];

    public ApplicationExpectedContext ExpectedContext { get; set; } = new();

    public ApplicationObservableExpectations ObservableExpectations { get; set; } = new();

    public List<string> NormalVariants { get; set; } = [];

    public List<string> AbuseAndMasqueradingNotes { get; set; } = [];

    public List<string> AnalystValidationChecks { get; set; } = [];

    public double Confidence { get; set; }

    public List<ApplicationProfileSourceReference> Sources { get; set; } = [];

    public DateTime DraftedUtc { get; set; }

    public DateTime? LastReviewedUtc { get; set; }

    public string Provenance { get; set; } = string.Empty;
}

public sealed class ApplicationFilenameMatcher
{
    [JsonConverter(typeof(JsonStringEnumConverter<ApplicationFilenameMatchKind>))]
    public ApplicationFilenameMatchKind Kind { get; set; }

    public string Pattern { get; set; } = string.Empty;
}

public sealed class ApplicationProfileDiscriminators
{
    public List<string> PathPatterns { get; set; } = [];

    public List<string> OriginalFilenames { get; set; } = [];

    public List<string> Companies { get; set; } = [];

    public List<string> Products { get; set; } = [];

    public List<string> FileDescriptions { get; set; } = [];

    public List<string> PackageFamilyNames { get; set; } = [];
}

public sealed class ApplicationExpectedContext
{
    public List<string> ParentExecutables { get; set; } = [];

    public List<string> Accounts { get; set; } = [];

    public List<string> Sessions { get; set; } = [];

    public List<string> PrivilegeLevels { get; set; } = [];

    public List<string> Lifetimes { get; set; } = [];
}

public sealed class ApplicationObservableExpectations
{
    public List<string> CommandLine { get; set; } = [];

    public List<ApplicationCommandLineRule> CommandLineRules { get; set; } = [];

    public List<string> Filesystem { get; set; } = [];

    public List<string> Registry { get; set; } = [];

    public List<string> ChildProcesses { get; set; } = [];

    public List<string> Network { get; set; } = [];
}

public enum ApplicationCommandLineRuleKind
{
    Unknown = 0,
    RequiredAllMarkers = 1,
    RequiredAnyMarker = 2,
    ForbiddenMarkers = 3
}

public sealed class ApplicationCommandLineRule
{
    [JsonConverter(typeof(JsonStringEnumConverter<ApplicationCommandLineRuleKind>))]
    public ApplicationCommandLineRuleKind Kind { get; set; }

    public List<string> Markers { get; set; } = [];

    public string Rationale { get; set; } = string.Empty;
}

public sealed class ApplicationProfileSourceReference
{
    public string Title { get; set; } = string.Empty;

    public string Publisher { get; set; } = string.Empty;

    public string Uri { get; set; } = string.Empty;

    public DateTime RetrievedUtc { get; set; }

    public string SupportingNote { get; set; } = string.Empty;
}

public sealed class ApplicationCatalogQualityReport
{
    public int SchemaVersion { get; init; } = 3;

    public string CatalogRevision { get; init; } = string.Empty;

    public string SourceSha256 { get; init; } = string.Empty;

    public int AuthoringProfileCount { get; init; }

    public int PublishedProfileCount { get; init; }

    public int EvaluationCandidateProfileCount { get; init; }

    public int RuntimeProfileCount { get; init; }

    public int SourceReferenceCount { get; init; }

    public int ProfilesWithMultipleSources { get; init; }

    public int DistinctSourceUriCount { get; init; }

    public int ContentCompleteProfileCount { get; init; }

    public int ContentCompleteAiDraftCount { get; init; }

    public int IncompleteProfileCount { get; init; }

    public int DuplicateContentGroupCount { get; init; }

    public bool ContentReadyForEvaluation { get; init; }

    public List<string> ContentQualityBlockers { get; init; } = [];

    public List<string> SemanticSampleProfileIds { get; init; } = [];

    public List<ApplicationCatalogProfileQuality> Profiles { get; init; } = [];

    public bool PublicationReady { get; init; }

    public List<string> PublicationBlockers { get; init; } = [];

    public List<ApplicationCatalogQualityCount> Categories { get; init; } = [];

    public List<ApplicationCatalogQualityCount> Vendors { get; init; } = [];

    public List<ApplicationCatalogQualityCount> ConfidenceBands { get; init; } = [];

    public List<ApplicationCatalogQualityCount> ReviewStates { get; init; } = [];

    public List<string> AmbiguousFilenames { get; init; } = [];
}

public sealed class ApplicationCatalogQualityCount
{
    public string Name { get; init; } = string.Empty;

    public int Count { get; init; }
}

public sealed class ApplicationCatalogProfileQuality
{
    public string ProfileId { get; init; } = string.Empty;

    public bool IsEvaluationCandidate { get; init; }

    public bool ContentComplete { get; set; }

    public int RoleSummaryLength { get; init; }

    public int StatementCount { get; init; }

    public int DistinctStatementCount { get; init; }

    public int SourceReferenceCount { get; init; }

    public string ContentSha256 { get; init; } = string.Empty;

    public List<string> Issues { get; init; } = [];
}

public sealed class ApplicationCatalogContentQualityAssessment
{
    public int ContentCompleteProfileCount { get; init; }

    public int ContentCompleteAiDraftCount { get; init; }

    public int IncompleteProfileCount { get; init; }

    public int DuplicateContentGroupCount { get; init; }

    public bool ContentReadyForEvaluation { get; init; }

    public List<string> ContentQualityBlockers { get; init; } = [];

    public List<string> SemanticSampleProfileIds { get; init; } = [];

    public List<ApplicationCatalogProfileQuality> Profiles { get; init; } = [];
}

public sealed class ApplicationProfileLookupContext
{
    public string ExecutableFilename { get; init; } = string.Empty;

    public string ProcessPath { get; init; } = string.Empty;

    public string OriginalFilename { get; init; } = string.Empty;

    public string Company { get; init; } = string.Empty;

    public string Product { get; init; } = string.Empty;

    public string PackageFamilyName { get; init; } = string.Empty;
}

public sealed class ApplicationCatalogMatch
{
    public required ApplicationProfileDefinition Profile { get; init; }

    public string CatalogRevision { get; init; } = string.Empty;

    public int Score { get; init; }

    public int MatchedDiscriminatorCount { get; init; }

    public string SelectionReason { get; init; } = string.Empty;
}
