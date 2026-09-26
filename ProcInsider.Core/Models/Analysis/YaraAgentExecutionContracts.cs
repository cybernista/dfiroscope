using ProcInsider.Models;

namespace ProcInsider.Models.Analysis;

public enum YaraAgentExecutionAuthorizationFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    InvalidIdentity = 2,
    InvalidTimestamp = 3,
    AdmissionRejected = 4,
    TargetRejected = 5,
    RulesetIdentityMismatch = 6,
    UnsupportedTargetKind = 7,
    ScopeMismatch = 8,
    WorkspaceGenerationMismatch = 9,
    WorkspaceNotLive = 10,
    WorkspaceSealed = 11,
    AgentOwnershipUnavailable = 12,
    AnalystInitiationRequired = 13,
    InvalidWriteCategory = 14,
    RequestExpired = 15,
    InvalidLimits = 16,
    TargetLimitExceeded = 17
}

public sealed record YaraAgentExecutionLimits
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public long MaximumTargetBytes { get; init; }

    public int WallClockTimeoutSeconds { get; init; }

    public int CpuLimitPercent { get; init; }

    public long ProcessMemoryLimitBytes { get; init; }

    public int MaximumStdoutBytes { get; init; }

    public int MaximumStderrBytes { get; init; }

    public int MaximumMatches { get; init; }

    public int MaximumTagsPerMatch { get; init; }

    public int MaximumMetadataPerMatch { get; init; }

    public int MaximumStringMatchesPerMatch { get; init; }

    public int MaximumExcerptBytes { get; init; }

    public int ScannerThreadCount { get; init; }

    public int MaximumConcurrentScans { get; init; }
}

/// <summary>
/// Path-free request for one future Agent-owned YARA execution. The request
/// identifies exact evidence and admitted scanner/rules metadata, but grants no
/// authority to resolve a path, read bytes, launch a process, or persist output.
/// </summary>
public sealed record YaraAgentExecutionRequest
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string RequestId { get; init; } = string.Empty;

    public string ScanId { get; init; } = string.Empty;

    public string WorkspaceGenerationId { get; init; } = string.Empty;

    public DateTime RequestedUtc { get; init; }

    public DateTime DeadlineUtc { get; init; }

    public YaraScanTarget Target { get; init; } = new();

    public YaraScanAdmissionProfile AdmissionProfile { get; init; } = new();

    public YaraRulesetIdentity RulesetIdentity { get; init; } = new();

    public YaraAgentExecutionLimits Limits { get; init; } = new();
}

/// <summary>
/// Fresh Agent authority supplied independently from request data. Exact target
/// scope and workspace generation equality are additive to trust admission.
/// </summary>
public sealed record YaraAgentExecutionAuthorizationContext
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string WorkspaceGenerationId { get; init; } = string.Empty;

    public EvidenceIdentity AuthorizedEvidenceIdentity { get; init; } = new();

    public bool IsAnalystInitiated { get; init; }

    public bool IsCurrentAgentOwner { get; init; }

    public bool IsWorkspaceLive { get; init; }

    public bool IsCaptureSealed { get; init; }

    public CaptureWriteCategory RequestedWriteCategory { get; init; }

    public DateTime EvaluatedUtc { get; init; }
}

public sealed record YaraAgentExecutionAuthorizationDecision
{
    public bool Authorized { get; init; }

    public YaraAgentExecutionAuthorizationFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public YaraAgentExecutionRequest? Request { get; init; }

    public YaraAgentExecutionAuthorizationContext? Context { get; init; }
}

/// <summary>
/// Pure fail-closed policy for the last path-free boundary before future Agent
/// target materialization and scanner execution.
/// </summary>
public static class YaraAgentExecutionAuthorizationPolicy
{
    public const long MaximumTargetBytes = YaraAnalysisContractPolicy.MaximumTargetBytes;
    public const int MaximumWallClockTimeoutSeconds = 120;
    public const int MaximumCpuLimitPercent = 50;
    public const long MaximumProcessMemoryBytes = 512L * 1024 * 1024;
    public const int MaximumStdoutBytes = 4 * 1024 * 1024;
    public const int MaximumStderrBytes = 256 * 1024;
    public const int RequiredScannerThreadCount = 1;
    public const int MaximumConcurrentScans = 1;

    private static readonly TimeSpan MaximumAuthorizationAge = TimeSpan.FromMinutes(5);
    private const int MaximumIdentityLength = 512;

    public static YaraAgentExecutionAuthorizationDecision Authorize(
        YaraAgentExecutionRequest request,
        YaraAgentExecutionAuthorizationContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        if (request.AdmissionProfile == null || request.RulesetIdentity == null ||
            request.SchemaVersion != YaraAgentExecutionRequest.CurrentSchemaVersion ||
            context.SchemaVersion != YaraAgentExecutionAuthorizationContext.CurrentSchemaVersion ||
            request.Limits?.SchemaVersion != YaraAgentExecutionLimits.CurrentSchemaVersion)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.InvalidSchemaVersion);
        }

        if (!IsRequiredIdentity(request.RequestId) || !IsRequiredIdentity(request.ScanId) ||
            !IsRequiredIdentity(request.WorkspaceGenerationId) ||
            !IsRequiredIdentity(context.WorkspaceGenerationId))
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.InvalidIdentity);
        }

        if (!IsUtc(request.RequestedUtc) || !IsUtc(request.DeadlineUtc) ||
            !IsUtc(context.EvaluatedUtc) || request.DeadlineUtc <= request.RequestedUtc ||
            context.EvaluatedUtc < request.RequestedUtc)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.InvalidTimestamp);
        }

        if (context.EvaluatedUtc - request.RequestedUtc > MaximumAuthorizationAge ||
            context.EvaluatedUtc >= request.DeadlineUtc)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.RequestExpired);
        }

        if (!context.IsWorkspaceLive)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.WorkspaceNotLive);
        }

        if (context.IsCaptureSealed)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.WorkspaceSealed);
        }

        if (!context.IsCurrentAgentOwner)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.AgentOwnershipUnavailable);
        }

        if (!context.IsAnalystInitiated)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.AnalystInitiationRequired);
        }

        if (!Enum.IsDefined(context.RequestedWriteCategory) ||
            context.RequestedWriteCategory != CaptureWriteCategory.DerivedEnrichment)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.InvalidWriteCategory);
        }

        if (!string.Equals(request.WorkspaceGenerationId, context.WorkspaceGenerationId,
                StringComparison.Ordinal))
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.WorkspaceGenerationMismatch);
        }

        var admission = YaraTrustAdmissionPolicy.Validate(request.AdmissionProfile);
        if (!admission.Accepted || admission.Profile == null || admission.RulesetIdentity == null)
        {
            return Reject(
                YaraAgentExecutionAuthorizationFailure.AdmissionRejected,
                $"The YARA admission profile was rejected ({admission.Failure}).");
        }

        if (request.RulesetIdentity != admission.RulesetIdentity)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.RulesetIdentityMismatch);
        }

        var targetValidation = YaraAnalysisContractPolicy.Validate(new YaraScanResult
        {
            ScanId = request.ScanId,
            Availability = AnalysisSourceAvailability.Available,
            Target = request.Target,
            Ruleset = request.RulesetIdentity,
            RequestedUtc = request.RequestedUtc,
            CompletedUtc = request.RequestedUtc,
            Matches = Array.Empty<YaraRuleMatch>()
        });
        if (!targetValidation.Accepted || targetValidation.Result == null)
        {
            return Reject(
                YaraAgentExecutionAuthorizationFailure.TargetRejected,
                $"The exact YARA target was rejected ({targetValidation.Failure}).");
        }

        var canonicalTarget = targetValidation.Result.Target;
        if (!admission.Profile.AllowedTargetKinds.Contains(canonicalTarget.Kind) ||
            !admission.Profile.Scanner.SupportedTargetKinds.Contains(canonicalTarget.Kind))
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.UnsupportedTargetKind);
        }

        if (canonicalTarget.EvidenceIdentity != context.AuthorizedEvidenceIdentity)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.ScopeMismatch);
        }

        if (!AreLimitsValid(request.Limits, admission.Profile))
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.InvalidLimits);
        }

        if (canonicalTarget.LengthBytes > request.Limits.MaximumTargetBytes ||
            canonicalTarget.LengthBytes > admission.Profile.MaximumTargetBytes)
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.TargetLimitExceeded);
        }

        if (request.DeadlineUtc - request.RequestedUtc >
            TimeSpan.FromSeconds(request.Limits.WallClockTimeoutSeconds))
        {
            return Reject(YaraAgentExecutionAuthorizationFailure.InvalidLimits);
        }

        return new YaraAgentExecutionAuthorizationDecision
        {
            Authorized = true,
            Failure = YaraAgentExecutionAuthorizationFailure.None,
            Request = request with
            {
                Target = canonicalTarget with
                {
                    EvidenceIdentity = canonicalTarget.EvidenceIdentity with { },
                    EvidenceReference = canonicalTarget.EvidenceReference with { }
                },
                AdmissionProfile = admission.Profile,
                RulesetIdentity = admission.RulesetIdentity with { },
                Limits = request.Limits with { }
            },
            Context = context with
            {
                AuthorizedEvidenceIdentity = context.AuthorizedEvidenceIdentity with { }
            }
        };
    }

    private static bool AreLimitsValid(
        YaraAgentExecutionLimits limits,
        YaraScanAdmissionProfile profile) =>
        limits.MaximumTargetBytes is > 0 and <= MaximumTargetBytes &&
        limits.MaximumTargetBytes <= profile.MaximumTargetBytes &&
        limits.WallClockTimeoutSeconds is > 0 and <= MaximumWallClockTimeoutSeconds &&
        limits.CpuLimitPercent is > 0 and <= MaximumCpuLimitPercent &&
        limits.ProcessMemoryLimitBytes is > 0 and <= MaximumProcessMemoryBytes &&
        limits.MaximumStdoutBytes is > 0 and <= MaximumStdoutBytes &&
        limits.MaximumStderrBytes is > 0 and <= MaximumStderrBytes &&
        limits.MaximumMatches is > 0 &&
        limits.MaximumMatches <= profile.MaximumMatches &&
        limits.MaximumMatches <= YaraAnalysisContractPolicy.MaximumMatches &&
        limits.MaximumTagsPerMatch is > 0 &&
        limits.MaximumTagsPerMatch <= profile.MaximumTagsPerMatch &&
        limits.MaximumTagsPerMatch <= YaraAnalysisContractPolicy.MaximumTagsPerMatch &&
        limits.MaximumMetadataPerMatch is > 0 &&
        limits.MaximumMetadataPerMatch <= profile.MaximumMetadataPerMatch &&
        limits.MaximumMetadataPerMatch <= YaraAnalysisContractPolicy.MaximumMetadataPerMatch &&
        limits.MaximumStringMatchesPerMatch is > 0 &&
        limits.MaximumStringMatchesPerMatch <= profile.MaximumStringMatchesPerMatch &&
        limits.MaximumStringMatchesPerMatch <= YaraAnalysisContractPolicy.MaximumStringMatchesPerMatch &&
        limits.MaximumExcerptBytes is > 0 &&
        limits.MaximumExcerptBytes <= profile.MaximumExcerptBytes &&
        limits.MaximumExcerptBytes <= YaraAnalysisContractPolicy.MaximumExcerptBytes &&
        limits.ScannerThreadCount == RequiredScannerThreadCount &&
        limits.MaximumConcurrentScans == MaximumConcurrentScans;

    private static bool IsRequiredIdentity(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= MaximumIdentityLength;

    private static bool IsUtc(DateTime value) => value.Kind == DateTimeKind.Utc;

    private static YaraAgentExecutionAuthorizationDecision Reject(
        YaraAgentExecutionAuthorizationFailure failure,
        string? diagnostic = null) =>
        new()
        {
            Authorized = false,
            Failure = failure,
            Diagnostic = diagnostic ?? Diagnostic(failure)
        };

    private static string Diagnostic(YaraAgentExecutionAuthorizationFailure failure) => failure switch
    {
        YaraAgentExecutionAuthorizationFailure.InvalidSchemaVersion =>
            "The Agent YARA authorization schema version is unsupported.",
        YaraAgentExecutionAuthorizationFailure.InvalidIdentity =>
            "The Agent YARA request identity is incomplete or invalid.",
        YaraAgentExecutionAuthorizationFailure.InvalidTimestamp =>
            "The Agent YARA request timestamps are not coherent UTC values.",
        YaraAgentExecutionAuthorizationFailure.AdmissionRejected =>
            "The scanner and ruleset admission profile was rejected.",
        YaraAgentExecutionAuthorizationFailure.TargetRejected =>
            "The exact YARA target contract was rejected.",
        YaraAgentExecutionAuthorizationFailure.RulesetIdentityMismatch =>
            "The requested ruleset identity does not match the admitted projection.",
        YaraAgentExecutionAuthorizationFailure.UnsupportedTargetKind =>
            "The admitted profile does not authorize this exact target kind.",
        YaraAgentExecutionAuthorizationFailure.ScopeMismatch =>
            "The requested target does not match the freshly authorized evidence scope.",
        YaraAgentExecutionAuthorizationFailure.WorkspaceGenerationMismatch =>
            "The requested and active workspace generations do not match.",
        YaraAgentExecutionAuthorizationFailure.WorkspaceNotLive =>
            "Agent YARA execution requires the current compatible live workspace.",
        YaraAgentExecutionAuthorizationFailure.WorkspaceSealed =>
            "Agent YARA execution is unavailable for a sealed capture.",
        YaraAgentExecutionAuthorizationFailure.AgentOwnershipUnavailable =>
            "The current Agent does not own this execution request.",
        YaraAgentExecutionAuthorizationFailure.AnalystInitiationRequired =>
            "Agent YARA execution requires explicit analyst initiation.",
        YaraAgentExecutionAuthorizationFailure.InvalidWriteCategory =>
            "Agent YARA execution must retain the derived-enrichment classification.",
        YaraAgentExecutionAuthorizationFailure.RequestExpired =>
            "The Agent YARA authorization request is stale or expired.",
        YaraAgentExecutionAuthorizationFailure.InvalidLimits =>
            "The requested YARA execution limits are invalid or exceed a fixed ceiling.",
        YaraAgentExecutionAuthorizationFailure.TargetLimitExceeded =>
            "The exact target exceeds the admitted execution bound.",
        _ => "The Agent YARA authorization request was rejected."
    };
}
