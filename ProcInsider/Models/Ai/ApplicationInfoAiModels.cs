namespace ProcInsider.Models.Ai;

public sealed class ApplicationInfoAiDraftDocument
{
    public string RoleSummary { get; set; } = string.Empty;
    public string ApplicationCategory { get; set; } = string.Empty;
    public List<string> ExpectedResponsibilities { get; set; } = [];
    public List<string> LaunchTriggers { get; set; } = [];
    public ApplicationInfoAiTypicalContext TypicalContext { get; set; } = new();
    public ApplicationInfoAiExpectedBehavior ExpectedBehavior { get; set; } = new();
    public List<string> NormalVariantsAndCaveats { get; set; } = [];
    public List<string> CommonAbuseAndMasquerading { get; set; } = [];
    public List<string> AnalystValidationChecks { get; set; } = [];
    public string Uncertainty { get; set; } = string.Empty;
    public double? Confidence { get; set; }
    public List<ApplicationInfoAiClaimedSource> ClaimedSources { get; set; } = [];
}

public sealed class ApplicationInfoAiTypicalContext
{
    public List<string> Parents { get; set; } = [];
    public List<string> Accounts { get; set; } = [];
    public List<string> Sessions { get; set; } = [];
    public List<string> PrivilegeLevels { get; set; } = [];
    public List<string> Lifetimes { get; set; } = [];
}

public sealed class ApplicationInfoAiExpectedBehavior
{
    public List<string> NormalBehavior { get; set; } = [];
    public List<string> CommandLine { get; set; } = [];
    public List<string> Filesystem { get; set; } = [];
    public List<string> Registry { get; set; } = [];
    public List<string> ChildProcesses { get; set; } = [];
    public List<string> Network { get; set; } = [];
}

public sealed class ApplicationInfoAiClaimedSource
{
    public string Title { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public string Uri { get; set; } = string.Empty;
}

public sealed class ApplicationInfoAiDraft
{
    public string RoleSummary { get; init; } = string.Empty;
    public string ApplicationCategory { get; init; } = string.Empty;
    public string ExpectedResponsibilities { get; init; } = string.Empty;
    public string NormalBehavior { get; init; } = string.Empty;
    public string LaunchTriggers { get; init; } = string.Empty;
    public string ExpectedContext { get; init; } = string.Empty;
    public string CommandLineExpectations { get; init; } = string.Empty;
    public string FilesystemRegistryExpectations { get; init; } = string.Empty;
    public string ChildProcessExpectations { get; init; } = string.Empty;
    public string NetworkExpectations { get; init; } = string.Empty;
    public string NormalVariants { get; init; } = string.Empty;
    public string CommonAbuseAndMasquerading { get; init; } = string.Empty;
    public string AnalystValidationChecks { get; init; } = string.Empty;
    public string Uncertainty { get; init; } = string.Empty;
    public double Confidence { get; init; }
    public IReadOnlyList<ApplicationInfoAiClaimedSource> ClaimedSources { get; init; } = [];
    public IReadOnlyList<string> ValidationWarnings { get; init; } = [];
    public bool IsFreeTextFallback { get; init; }
}

public sealed class ApplicationInfoAiDraftParseResult
{
    public bool Success { get; init; }
    public ApplicationInfoAiDraft? Draft { get; init; }
    public string Error { get; init; } = string.Empty;
}

public sealed class ApplicationSecurityAssessmentDocument
{
    public string Assessment { get; set; } = string.Empty;
    public List<string> Facts { get; set; } = [];
    public List<string> Hypotheses { get; set; } = [];
    public List<string> Uncertainty { get; set; } = [];
    public List<string> BenignExplanations { get; set; } = [];
    public List<string> RecommendedPivots { get; set; } = [];
}

public sealed class ApplicationSecurityAssessmentParseResult
{
    public bool Success { get; init; }
    public string NormalizedText { get; init; } = string.Empty;
    public string Error { get; init; } = string.Empty;
    public IReadOnlyList<string> Warnings { get; init; } = [];
}
