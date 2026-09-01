using System.Collections.ObjectModel;

namespace ProcInsider.Models.Analysis;

public enum YaraProcessAttributionFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    InvalidProcessIdentity = 2,
    InvalidCorrelationState = 3,
    InvalidCorrelationMethod = 4,
    InvalidCorrelationCandidateCount = 5,
    ReferenceLimitExceeded = 6,
    InvalidReference = 7,
    DuplicateReference = 8,
    MissingProcessReference = 9,
    MissingTargetReference = 10,
    MissingSourceRunReference = 11,
    InvalidReviewTimestamp = 12,
    RiskResolutionRejected = 13
}

/// <summary>
/// Exact caller-established process attribution offered to the portable YARA
/// risk handoff. This request carries no PID, path, target bytes, or display text.
/// </summary>
public sealed record YaraProcessAttributionRequest
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public YaraRiskPolicy Policy { get; init; } = new();

    public YaraScanResult ScanResult { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public EvidenceCorrelationState CorrelationState { get; init; }

    public string CorrelationMethod { get; init; } = string.Empty;

    public int CorrelationCandidateCount { get; init; }

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();
}

/// <summary>
/// One canonical reviewed or explicit unclassified YARA match bound to an exact
/// durable process and immutable evidence scope. A score delta is only the
/// reviewed #393 disposition; this handoff does not create a Process Risk signal.
/// </summary>
public sealed record YaraProcessRiskEvidence
{
    public string ScanId { get; init; } = string.Empty;

    public string MatchId { get; init; } = string.Empty;

    public string RuleNamespace { get; init; } = string.Empty;

    public string RuleId { get; init; } = string.Empty;

    public bool IsPolicyMatched { get; init; }

    public AnalysisFindingSeverity Severity { get; init; }

    public int? ScoreDelta { get; init; }

    public string PolicyId { get; init; } = string.Empty;

    public string PolicyVersion { get; init; } = string.Empty;

    public string ReviewerId { get; init; } = string.Empty;

    public string ReviewPolicyId { get; init; } = string.Empty;

    public string ReviewPolicyVersion { get; init; } = string.Empty;

    public DateTime ReviewedUtc { get; init; }

    public YaraRulesetIdentity Ruleset { get; init; } = new();

    public YaraScanTarget Target { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public DateTime CompletedUtc { get; init; }

    public bool IsTruncated { get; init; }

    public EvidenceCorrelationState CorrelationState { get; init; }

    public string CorrelationMethod { get; init; } = string.Empty;

    public int CorrelationCandidateCount { get; init; }

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();
}

public sealed record YaraProcessAttributionResult
{
    public string ScanId { get; init; } = string.Empty;

    public AnalysisSourceAvailability Availability { get; init; }

    public bool IsTruncated { get; init; }

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public YaraRiskPolicy Policy { get; init; } = new();

    public YaraScanTarget Target { get; init; } = new();

    public YaraRulesetIdentity Ruleset { get; init; } = new();

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();

    public IReadOnlyList<YaraProcessRiskEvidence> Evidence { get; init; } =
        Array.Empty<YaraProcessRiskEvidence>();
}

public sealed record YaraProcessAttributionDecision
{
    public bool Accepted { get; init; }

    public YaraProcessAttributionFailure Failure { get; init; }

    public YaraRiskPolicyFailure RiskPolicyFailure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public YaraProcessAttributionResult? Result { get; init; }
}

/// <summary>
/// Pure fail-closed boundary between reviewed YARA rule disposition and any
/// later Process Risk mapper. It validates caller-established exact attribution
/// and never reads evidence, persists state, executes YARA, or creates signals.
/// </summary>
public static class YaraProcessAttributionContract
{
    public const int MaximumEvidenceReferences = 64;

    private const int MaximumIdentityLength = 512;
    private const int MaximumCorrelationMethodLength = 256;

    private static readonly HashSet<EvidenceReferenceKind> AllowedReferenceKinds =
    [
        EvidenceReferenceKind.ProcessEntity,
        EvidenceReferenceKind.ProcessObservation,
        EvidenceReferenceKind.FileArtifact,
        EvidenceReferenceKind.MemoryImage,
        EvidenceReferenceKind.MemoryProcess,
        EvidenceReferenceKind.SourceRun,
        EvidenceReferenceKind.VolatilityPluginRun,
        EvidenceReferenceKind.MemoryDump,
        EvidenceReferenceKind.EvidenceRelation
    ];

    private static readonly HashSet<EvidenceReferenceKind> TargetReferenceKinds =
    [
        EvidenceReferenceKind.FileArtifact,
        EvidenceReferenceKind.MemoryDump,
        EvidenceReferenceKind.MemoryImage
    ];

    public static YaraProcessAttributionDecision Attribute(
        YaraProcessAttributionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.SchemaVersion != YaraProcessAttributionRequest.CurrentSchemaVersion)
        {
            return Reject(
                YaraProcessAttributionFailure.InvalidSchemaVersion,
                "The YARA process-attribution schema version is unsupported.");
        }

        if (!Required(request.ProcessEntityId) || !Optional(request.ProcessKey))
        {
            return Reject(
                YaraProcessAttributionFailure.InvalidProcessIdentity,
                "YARA process attribution requires a bounded durable process entity identity.");
        }

        if (!Enum.IsDefined(request.CorrelationState) ||
            request.CorrelationState != EvidenceCorrelationState.Exact)
        {
            return Reject(
                YaraProcessAttributionFailure.InvalidCorrelationState,
                "YARA process attribution requires exact correlation.");
        }

        if (!Required(request.CorrelationMethod, MaximumCorrelationMethodLength))
        {
            return Reject(
                YaraProcessAttributionFailure.InvalidCorrelationMethod,
                "YARA process attribution requires one bounded correlation method.");
        }

        if (request.CorrelationCandidateCount != 1)
        {
            return Reject(
                YaraProcessAttributionFailure.InvalidCorrelationCandidateCount,
                "YARA process attribution requires exactly one correlation candidate.");
        }

        var policyDecision = YaraRiskPolicyContract.Validate(request.Policy);
        if (!policyDecision.Accepted || policyDecision.Policy == null)
        {
            return RejectRisk(policyDecision.Failure, policyDecision.Diagnostic);
        }

        var scanDecision = YaraAnalysisContractPolicy.Validate(request.ScanResult);
        if (!scanDecision.Accepted || scanDecision.Result == null)
        {
            return RejectRisk(
                YaraRiskPolicyFailure.InvalidScanResult,
                $"The normalized YARA scan failed attribution validation: {scanDecision.Failure}.");
        }

        var acceptedPolicy = policyDecision.Policy;
        var acceptedScan = scanDecision.Result;
        var resolutionDecision = YaraRiskPolicyContract.Resolve(acceptedPolicy, acceptedScan);
        if (!resolutionDecision.Accepted || resolutionDecision.Resolution == null)
        {
            return RejectRisk(resolutionDecision.Failure, resolutionDecision.Diagnostic);
        }

        if (acceptedPolicy.ReviewedUtc > acceptedScan.CompletedUtc)
        {
            return Reject(
                YaraProcessAttributionFailure.InvalidReviewTimestamp,
                "The reviewed YARA policy cannot postdate the attributed scan.");
        }

        var referenceDecision = ValidateReferences(
            request.EvidenceReferences,
            request.ProcessEntityId,
            acceptedScan.Target,
            out var acceptedReferences);
        if (referenceDecision != YaraProcessAttributionFailure.None)
        {
            return Reject(referenceDecision, ReferenceDiagnostic(referenceDecision));
        }

        var target = CopyTarget(acceptedScan.Target);
        var ruleset = acceptedScan.Ruleset with { };
        var resolution = resolutionDecision.Resolution;
        var evidence = new List<YaraProcessRiskEvidence>(resolution.Dispositions.Count);
        foreach (var disposition in resolution.Dispositions)
        {
            evidence.Add(new YaraProcessRiskEvidence
            {
                ScanId = acceptedScan.ScanId,
                MatchId = disposition.MatchId,
                RuleNamespace = disposition.RuleNamespace,
                RuleId = disposition.RuleId,
                IsPolicyMatched = disposition.IsPolicyMatched,
                Severity = disposition.Severity,
                ScoreDelta = disposition.ScoreDelta,
                PolicyId = acceptedPolicy.PolicyId,
                PolicyVersion = acceptedPolicy.PolicyVersion,
                ReviewerId = acceptedPolicy.ReviewerId,
                ReviewPolicyId = acceptedPolicy.ReviewPolicyId,
                ReviewPolicyVersion = acceptedPolicy.ReviewPolicyVersion,
                ReviewedUtc = acceptedPolicy.ReviewedUtc,
                Ruleset = ruleset with { },
                Target = CopyTarget(target),
                ProcessEntityId = request.ProcessEntityId,
                ProcessKey = request.ProcessKey,
                CompletedUtc = acceptedScan.CompletedUtc,
                IsTruncated = acceptedScan.IsTruncated,
                CorrelationState = request.CorrelationState,
                CorrelationMethod = request.CorrelationMethod,
                CorrelationCandidateCount = request.CorrelationCandidateCount,
                EvidenceReferences = acceptedReferences
            });
        }

        return new YaraProcessAttributionDecision
        {
            Accepted = true,
            Failure = YaraProcessAttributionFailure.None,
            RiskPolicyFailure = YaraRiskPolicyFailure.None,
            Result = new YaraProcessAttributionResult
            {
                ScanId = acceptedScan.ScanId,
                Availability = acceptedScan.Availability,
                IsTruncated = acceptedScan.IsTruncated,
                ProcessEntityId = request.ProcessEntityId,
                ProcessKey = request.ProcessKey,
                Policy = acceptedPolicy,
                Target = target,
                Ruleset = ruleset,
                EvidenceReferences = acceptedReferences,
                Evidence = new ReadOnlyCollection<YaraProcessRiskEvidence>(evidence)
            }
        };
    }

    private static YaraProcessAttributionFailure ValidateReferences(
        IReadOnlyList<EvidenceReference>? references,
        string processEntityId,
        YaraScanTarget target,
        out IReadOnlyList<EvidenceReference> accepted)
    {
        accepted = Array.Empty<EvidenceReference>();
        if (references == null)
        {
            return YaraProcessAttributionFailure.InvalidReference;
        }

        if (references.Count > MaximumEvidenceReferences)
        {
            return YaraProcessAttributionFailure.ReferenceLimitExceeded;
        }

        var canonical = new List<EvidenceReference>(references.Count);
        var identities = new HashSet<(EvidenceReferenceKind Kind, string Id)>();
        foreach (var reference in references)
        {
            if (reference == null || !Enum.IsDefined(reference.Kind) ||
                !AllowedReferenceKinds.Contains(reference.Kind) || !Required(reference.Id))
            {
                return YaraProcessAttributionFailure.InvalidReference;
            }

            if (reference.Kind == EvidenceReferenceKind.ProcessEntity &&
                !string.Equals(reference.Id, processEntityId, StringComparison.Ordinal) ||
                reference.Kind == EvidenceReferenceKind.SourceRun &&
                !string.Equals(reference.Id, target.SourceRunId, StringComparison.Ordinal) ||
                TargetReferenceKinds.Contains(reference.Kind) &&
                (reference.Kind != target.EvidenceReference.Kind ||
                 !string.Equals(reference.Id, target.EvidenceReference.Id, StringComparison.Ordinal)))
            {
                return YaraProcessAttributionFailure.InvalidReference;
            }

            if (!identities.Add((reference.Kind, reference.Id)))
            {
                return YaraProcessAttributionFailure.DuplicateReference;
            }

            canonical.Add(reference with { });
        }

        if (!identities.Contains((EvidenceReferenceKind.ProcessEntity, processEntityId)))
        {
            return YaraProcessAttributionFailure.MissingProcessReference;
        }

        if (!identities.Contains((target.EvidenceReference.Kind, target.EvidenceReference.Id)))
        {
            return YaraProcessAttributionFailure.MissingTargetReference;
        }

        if (!identities.Contains((EvidenceReferenceKind.SourceRun, target.SourceRunId)))
        {
            return YaraProcessAttributionFailure.MissingSourceRunReference;
        }

        accepted = new ReadOnlyCollection<EvidenceReference>(canonical
            .OrderBy(reference => reference.Kind)
            .ThenBy(reference => reference.Id, StringComparer.Ordinal)
            .ToArray());
        return YaraProcessAttributionFailure.None;
    }

    private static YaraScanTarget CopyTarget(YaraScanTarget target) => target with
    {
        EvidenceIdentity = target.EvidenceIdentity with { },
        EvidenceReference = target.EvidenceReference with { }
    };

    private static bool Required(string? value, int maximumLength = MaximumIdentityLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;

    private static bool Optional(string? value) =>
        value != null && value.Length <= MaximumIdentityLength;

    private static YaraProcessAttributionDecision Reject(
        YaraProcessAttributionFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = diagnostic
        };

    private static YaraProcessAttributionDecision RejectRisk(
        YaraRiskPolicyFailure riskFailure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = YaraProcessAttributionFailure.RiskResolutionRejected,
            RiskPolicyFailure = riskFailure,
            Diagnostic = diagnostic
        };

    private static string ReferenceDiagnostic(YaraProcessAttributionFailure failure) => failure switch
    {
        YaraProcessAttributionFailure.ReferenceLimitExceeded =>
            "YARA process attribution exceeds the bounded immutable-reference limit.",
        YaraProcessAttributionFailure.DuplicateReference =>
            "YARA process attribution contains a duplicate immutable reference.",
        YaraProcessAttributionFailure.MissingProcessReference =>
            "YARA process attribution requires the exact durable ProcessEntity reference.",
        YaraProcessAttributionFailure.MissingTargetReference =>
            "YARA process attribution requires the exact scan-target evidence reference.",
        YaraProcessAttributionFailure.MissingSourceRunReference =>
            "YARA process attribution requires the exact target SourceRun reference.",
        _ => "YARA process attribution contains an invalid or mismatched immutable reference."
    };
}
