using System.Collections.ObjectModel;

namespace ProcInsider.Models.Analysis;

/// <summary>
/// Availability of the bounded input set evaluated by an analyzer. An unavailable
/// input is explicit analysis state and must never be projected as a benign result.
/// </summary>
public enum AnalysisSourceAvailability
{
    Unknown = 0,
    Available = 1,
    NotCollected = 2,
    Unavailable = 3,
    Failed = 4,
    Stale = 5
}

public enum AnalysisFindingSeverity
{
    Unknown = 0,
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

/// <summary>
/// Analyst-owned disposition. The referenced annotation owns review text and
/// provenance; findings and signals remain immutable rebuildable projections.
/// </summary>
public enum AnalysisReviewDisposition
{
    Unknown = 0,
    AnalystReviewed = 1,
    Suppressed = 2
}

public enum AnalysisContractFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    UnknownAvailability = 2,
    UnknownSeverity = 3,
    UnknownReviewDisposition = 4,
    MissingIdentity = 5,
    ValueTooLong = 6,
    InvalidScope = 7,
    InvalidTimestamp = 8,
    InvalidConfidence = 9,
    InvalidScoreDelta = 10,
    MissingRuleVersion = 11,
    InvalidInputSnapshot = 12,
    InvalidHash = 13,
    MissingEvidence = 14,
    DuplicateEvidence = 15,
    EvidenceNotInSnapshot = 16,
    ContradictoryAvailability = 17,
    FindingMismatch = 18,
    SignalMismatch = 19,
    PolicyMismatch = 20,
    ProcessScopeMismatch = 21,
    InvalidReviewReference = 22
}

/// <summary>
/// Versions the analyzer, rule, policy, and optional external provider that produced
/// a result. Provider identity is descriptive only and grants no network authority.
/// </summary>
public sealed record AnalysisRuleIdentity
{
    public string ToolId { get; init; } = string.Empty;

    public string ToolVersion { get; init; } = string.Empty;

    public string RuleId { get; init; } = string.Empty;

    public string RuleVersion { get; init; } = string.Empty;

    public string PolicyId { get; init; } = string.Empty;

    public string PolicyVersion { get; init; } = string.Empty;

    public string ProviderId { get; init; } = string.Empty;

    public string ProviderVersion { get; init; } = string.Empty;
}

/// <summary>
/// Reproducible identity for the bounded evidence set offered to one analyzer. The
/// hash identifies the normalized input set; it is not an evidence-file hash.
/// </summary>
public sealed record AnalysisInputSnapshot
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string SnapshotId { get; init; } = string.Empty;

    public AnalysisSourceAvailability Availability { get; init; }

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public string SourceKind { get; init; } = string.Empty;

    public string SourceVersion { get; init; } = string.Empty;

    public string SourceRunId { get; init; } = string.Empty;

    public string InputSetHashSha256 { get; init; } = string.Empty;

    public DateTime CreatedUtc { get; init; }

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();
}

/// <summary>
/// Source-neutral analysis result. Available results cite immutable evidence; all
/// unavailable states carry diagnostics but cannot carry severity or risk signals.
/// </summary>
public sealed record AnalysisFinding
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string FindingId { get; init; } = string.Empty;

    public AnalysisSourceAvailability Availability { get; init; }

    public AnalysisFindingSeverity Severity { get; init; }

    public double Confidence { get; init; }

    public string Summary { get; init; } = string.Empty;

    public string Diagnostic { get; init; } = string.Empty;

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public AnalysisRuleIdentity Rule { get; init; } = new();

    public AnalysisInputSnapshot InputSnapshot { get; init; } = new();

    public DateTime EvaluatedUtc { get; init; }

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();
}

/// <summary>
/// One nonzero, bounded contributor to a later Process Risk Score projection. It is
/// not an aggregate score and does not mutate the finding or cited evidence.
/// </summary>
public sealed record ProcessRiskSignal
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string SignalId { get; init; } = string.Empty;

    public string FindingId { get; init; } = string.Empty;

    public string InputSnapshotId { get; init; } = string.Empty;

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public string PolicyId { get; init; } = string.Empty;

    public string PolicyVersion { get; init; } = string.Empty;

    public int ScoreDelta { get; init; }

    public AnalysisFindingSeverity Severity { get; init; }

    public double Confidence { get; init; }

    public DateTime EvaluatedUtc { get; init; }

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();
}

/// <summary>
/// Reference to a separate annotation-owned review. No analyst note or mutable
/// review content is embedded in the analysis result.
/// </summary>
public sealed record AnalysisReviewReference
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string ReviewId { get; init; } = string.Empty;

    public string AnalystAnnotationId { get; init; } = string.Empty;

    public string FindingId { get; init; } = string.Empty;

    public string SignalId { get; init; } = string.Empty;

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public string ReviewerIdentity { get; init; } = string.Empty;

    public AnalysisReviewDisposition Disposition { get; init; }

    public DateTime ReviewedUtc { get; init; }
}

public sealed record AnalysisFindingValidationDecision
{
    public bool Accepted { get; init; }

    public AnalysisContractFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public AnalysisFinding? Finding { get; init; }
}

public sealed record ProcessRiskSignalValidationDecision
{
    public bool Accepted { get; init; }

    public AnalysisContractFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ProcessRiskSignal? Signal { get; init; }
}

public sealed record AnalysisReviewValidationDecision
{
    public bool Accepted { get; init; }

    public AnalysisContractFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public AnalysisReviewReference? Review { get; init; }
}

/// <summary>
/// Side-effect-free, fail-closed validation for portable analysis contracts. It does
/// not calculate an aggregate score, persist results, run tools, or contact providers.
/// </summary>
public static class AnalysisContractPolicy
{
    private const int MaximumIdentityLength = 512;
    private const int MaximumVersionLength = 256;
    private const int MaximumSummaryLength = 4096;
    private const int MaximumDiagnosticLength = 8192;
    private const int MaximumEvidenceReferences = 256;
    private const int MaximumScoreDelta = 100;

    public static AnalysisFindingValidationDecision ValidateFinding(AnalysisFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        if (finding.SchemaVersion != AnalysisFinding.CurrentSchemaVersion)
        {
            return RejectFinding(AnalysisContractFailure.InvalidSchemaVersion,
                "The analysis finding schema version is unsupported.");
        }

        if (!IsKnownAvailability(finding.Availability))
        {
            return RejectFinding(AnalysisContractFailure.UnknownAvailability,
                "The analysis source availability is unknown or unsupported.");
        }

        if (!IsKnownSeverity(finding.Severity))
        {
            return RejectFinding(AnalysisContractFailure.UnknownSeverity,
                "The analysis finding severity is unknown or unsupported.");
        }

        var commonFailure = ValidateFindingCommon(finding);
        if (commonFailure != null)
        {
            return commonFailure;
        }

        var snapshotFailure = ValidateSnapshot(finding.InputSnapshot, finding.Availability);
        if (snapshotFailure != AnalysisContractFailure.None)
        {
            return RejectFinding(snapshotFailure, SnapshotDiagnostic(snapshotFailure));
        }

        if (!SameScope(finding.EvidenceIdentity, finding.InputSnapshot.EvidenceIdentity) ||
            !string.Equals(finding.ProcessEntityId, finding.InputSnapshot.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(finding.ProcessKey, finding.InputSnapshot.ProcessKey, StringComparison.Ordinal))
        {
            return RejectFinding(AnalysisContractFailure.ProcessScopeMismatch,
                "The finding and input snapshot do not target the same exact process scope.");
        }

        var findingReferences = finding.EvidenceReferences ?? Array.Empty<EvidenceReference>();
        var referenceFailure = ValidateReferences(findingReferences);
        if (referenceFailure != AnalysisContractFailure.None)
        {
            return RejectFinding(referenceFailure, ReferenceDiagnostic(referenceFailure));
        }

        if (finding.Availability == AnalysisSourceAvailability.Available)
        {
            if (finding.Severity == AnalysisFindingSeverity.Unknown ||
                !double.IsFinite(finding.Confidence) ||
                finding.Confidence <= 0 ||
                finding.Confidence > 1)
            {
                return RejectFinding(AnalysisContractFailure.InvalidConfidence,
                    "An available finding requires known severity and confidence in the range (0, 1].");
            }

            if (findingReferences.Count == 0)
            {
                return RejectFinding(AnalysisContractFailure.MissingEvidence,
                    "An available finding must cite at least one exact evidence reference.");
            }

            var snapshotReferences = finding.InputSnapshot.EvidenceReferences.ToHashSet();
            if (findingReferences.Any(reference => !snapshotReferences.Contains(reference)))
            {
                return RejectFinding(AnalysisContractFailure.EvidenceNotInSnapshot,
                    "Every finding reference must belong to the bounded input snapshot.");
            }
        }
        else if (finding.Severity != AnalysisFindingSeverity.Unknown ||
                 finding.Confidence != 0 ||
                 findingReferences.Count != 0 ||
                 string.IsNullOrWhiteSpace(finding.Diagnostic))
        {
            return RejectFinding(AnalysisContractFailure.ContradictoryAvailability,
                "Unavailable inputs must carry a diagnostic and cannot carry severity, confidence, or evidence-backed conclusions.");
        }

        return new AnalysisFindingValidationDecision
        {
            Accepted = true,
            Diagnostic = finding.Availability == AnalysisSourceAvailability.Available
                ? "The evidence-backed analysis finding is valid."
                : "The unavailable analysis input is explicit and cannot contribute a risk signal.",
            Finding = CopyFinding(finding)
        };
    }

    public static ProcessRiskSignalValidationDecision ValidateSignal(
        AnalysisFinding finding,
        ProcessRiskSignal signal)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(signal);

        var findingDecision = ValidateFinding(finding);
        if (!findingDecision.Accepted)
        {
            return RejectSignal(AnalysisContractFailure.FindingMismatch,
                "The risk signal references an invalid finding.");
        }

        if (finding.Availability != AnalysisSourceAvailability.Available)
        {
            return RejectSignal(AnalysisContractFailure.ContradictoryAvailability,
                "Only an available evidence-backed finding may contribute a risk signal.");
        }

        if (signal.SchemaVersion != ProcessRiskSignal.CurrentSchemaVersion)
        {
            return RejectSignal(AnalysisContractFailure.InvalidSchemaVersion,
                "The process-risk signal schema version is unsupported.");
        }

        if (!IsRequiredIdentity(signal.SignalId) || !IsRequiredIdentity(signal.FindingId) ||
            !IsRequiredIdentity(signal.InputSnapshotId) || !IsRequiredIdentity(signal.ProcessEntityId))
        {
            return RejectSignal(AnalysisContractFailure.MissingIdentity,
                "The process-risk signal identity, finding, snapshot, and process entity are required.");
        }

        if (!IsBoundedOptional(signal.ProcessKey, MaximumIdentityLength) ||
            !IsRequiredIdentity(signal.PolicyId) || !IsRequiredVersion(signal.PolicyVersion))
        {
            return RejectSignal(AnalysisContractFailure.ValueTooLong,
                "A process-risk signal identity or policy version is missing or oversized.");
        }

        if (!IsValidScope(signal.EvidenceIdentity))
        {
            return RejectSignal(AnalysisContractFailure.InvalidScope,
                "The process-risk signal evidence scope is incomplete or malformed.");
        }

        if (signal.EvaluatedUtc.Kind != DateTimeKind.Utc)
        {
            return RejectSignal(AnalysisContractFailure.InvalidTimestamp,
                "The process-risk signal timestamp must be UTC.");
        }

        if (!IsKnownSeverity(signal.Severity) || signal.Severity == AnalysisFindingSeverity.Unknown)
        {
            return RejectSignal(AnalysisContractFailure.UnknownSeverity,
                "The process-risk signal severity is unknown or unsupported.");
        }

        if (!double.IsFinite(signal.Confidence) || signal.Confidence <= 0 || signal.Confidence > 1)
        {
            return RejectSignal(AnalysisContractFailure.InvalidConfidence,
                "The process-risk signal confidence must be in the range (0, 1].");
        }

        if (signal.ScoreDelta == 0 ||
            signal.ScoreDelta < -MaximumScoreDelta ||
            signal.ScoreDelta > MaximumScoreDelta)
        {
            return RejectSignal(AnalysisContractFailure.InvalidScoreDelta,
                "A process-risk signal must carry a nonzero score delta from -100 through 100.");
        }

        if (!string.Equals(signal.FindingId, finding.FindingId, StringComparison.Ordinal) ||
            !string.Equals(signal.InputSnapshotId, finding.InputSnapshot.SnapshotId, StringComparison.Ordinal))
        {
            return RejectSignal(AnalysisContractFailure.FindingMismatch,
                "The process-risk signal does not reference the exact finding and input snapshot.");
        }

        if (!SameScope(signal.EvidenceIdentity, finding.EvidenceIdentity) ||
            !string.Equals(signal.ProcessEntityId, finding.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(signal.ProcessKey, finding.ProcessKey, StringComparison.Ordinal))
        {
            return RejectSignal(AnalysisContractFailure.ProcessScopeMismatch,
                "The process-risk signal and finding do not target the same exact process scope.");
        }

        if (!string.Equals(signal.PolicyId, finding.Rule.PolicyId, StringComparison.Ordinal) ||
            !string.Equals(signal.PolicyVersion, finding.Rule.PolicyVersion, StringComparison.Ordinal))
        {
            return RejectSignal(AnalysisContractFailure.PolicyMismatch,
                "The process-risk signal policy does not match the finding policy.");
        }

        if (signal.Severity != finding.Severity || signal.Confidence != finding.Confidence)
        {
            return RejectSignal(AnalysisContractFailure.SignalMismatch,
                "The process-risk signal severity and confidence must preserve the finding values.");
        }

        var referenceFailure = ValidateReferences(signal.EvidenceReferences);
        if (referenceFailure != AnalysisContractFailure.None)
        {
            return RejectSignal(referenceFailure, ReferenceDiagnostic(referenceFailure));
        }

        if (!ReferenceSetsEqual(signal.EvidenceReferences, finding.EvidenceReferences))
        {
            return RejectSignal(AnalysisContractFailure.SignalMismatch,
                "The process-risk signal must preserve the finding evidence references.");
        }

        return new ProcessRiskSignalValidationDecision
        {
            Accepted = true,
            Diagnostic = "The traceable nonzero process-risk signal is valid.",
            Signal = CopySignal(signal)
        };
    }

    public static AnalysisReviewValidationDecision ValidateReview(
        AnalysisFinding finding,
        ProcessRiskSignal? signal,
        AnalysisReviewReference review)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(review);

        var findingDecision = ValidateFinding(finding);
        if (!findingDecision.Accepted)
        {
            return RejectReview(AnalysisContractFailure.FindingMismatch,
                "The analyst review references an invalid finding.");
        }

        if (signal != null && !ValidateSignal(finding, signal).Accepted)
        {
            return RejectReview(AnalysisContractFailure.SignalMismatch,
                "The analyst review references an invalid process-risk signal.");
        }

        if (review.SchemaVersion != AnalysisReviewReference.CurrentSchemaVersion)
        {
            return RejectReview(AnalysisContractFailure.InvalidSchemaVersion,
                "The analyst-review reference schema version is unsupported.");
        }

        if (!Enum.IsDefined(review.Disposition) || review.Disposition == AnalysisReviewDisposition.Unknown)
        {
            return RejectReview(AnalysisContractFailure.UnknownReviewDisposition,
                "The analyst-review disposition is unknown or unsupported.");
        }

        if (!IsRequiredIdentity(review.ReviewId) || !IsRequiredIdentity(review.AnalystAnnotationId) ||
            !IsRequiredIdentity(review.FindingId) || !IsRequiredIdentity(review.ProcessEntityId) ||
            !IsRequiredIdentity(review.ReviewerIdentity))
        {
            return RejectReview(AnalysisContractFailure.InvalidReviewReference,
                "The review, annotation, finding, process, and analyst identities are required.");
        }

        if (!IsBoundedOptional(review.SignalId, MaximumIdentityLength) ||
            !IsBoundedOptional(review.ProcessKey, MaximumIdentityLength) ||
            !IsValidScope(review.EvidenceIdentity))
        {
            return RejectReview(AnalysisContractFailure.InvalidReviewReference,
                "The analyst-review reference scope or optional identity is malformed.");
        }

        if (review.ReviewedUtc.Kind != DateTimeKind.Utc)
        {
            return RejectReview(AnalysisContractFailure.InvalidTimestamp,
                "The analyst-review timestamp must be UTC.");
        }

        if (!string.Equals(review.FindingId, finding.FindingId, StringComparison.Ordinal) ||
            !SameScope(review.EvidenceIdentity, finding.EvidenceIdentity) ||
            !string.Equals(review.ProcessEntityId, finding.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(review.ProcessKey, finding.ProcessKey, StringComparison.Ordinal))
        {
            return RejectReview(AnalysisContractFailure.ProcessScopeMismatch,
                "The analyst review does not target the exact finding process scope.");
        }

        if ((signal == null && !string.IsNullOrEmpty(review.SignalId)) ||
            (signal != null && !string.Equals(review.SignalId, signal.SignalId, StringComparison.Ordinal)))
        {
            return RejectReview(AnalysisContractFailure.SignalMismatch,
                "The analyst review signal reference does not match the validated signal.");
        }

        return new AnalysisReviewValidationDecision
        {
            Accepted = true,
            Diagnostic = "The annotation-owned analyst-review reference is valid.",
            Review = review with { EvidenceIdentity = CopyScope(review.EvidenceIdentity) }
        };
    }

    private static AnalysisFindingValidationDecision? ValidateFindingCommon(AnalysisFinding finding)
    {
        if (!IsRequiredIdentity(finding.FindingId) || !IsRequiredIdentity(finding.ProcessEntityId))
        {
            return RejectFinding(AnalysisContractFailure.MissingIdentity,
                "The finding and durable process entity identities are required.");
        }

        if (!IsBoundedOptional(finding.ProcessKey, MaximumIdentityLength) ||
            !IsBoundedText(finding.Summary, MaximumSummaryLength, required: true) ||
            !IsBoundedText(finding.Diagnostic, MaximumDiagnosticLength, required: false))
        {
            return RejectFinding(AnalysisContractFailure.ValueTooLong,
                "A finding identity, summary, or diagnostic is missing or oversized.");
        }

        if (!IsValidScope(finding.EvidenceIdentity))
        {
            return RejectFinding(AnalysisContractFailure.InvalidScope,
                "The finding evidence scope is incomplete or malformed.");
        }

        if (finding.EvaluatedUtc.Kind != DateTimeKind.Utc)
        {
            return RejectFinding(AnalysisContractFailure.InvalidTimestamp,
                "The finding evaluation timestamp must be UTC.");
        }

        if (!IsValidRule(finding.Rule))
        {
            return RejectFinding(AnalysisContractFailure.MissingRuleVersion,
                "Tool, rule, and policy identities and versions are required; provider identity/version must be paired.");
        }

        return null;
    }

    private static AnalysisContractFailure ValidateSnapshot(
        AnalysisInputSnapshot snapshot,
        AnalysisSourceAvailability expectedAvailability)
    {
        if (snapshot == null || snapshot.SchemaVersion != AnalysisInputSnapshot.CurrentSchemaVersion)
        {
            return AnalysisContractFailure.InvalidSchemaVersion;
        }

        if (!IsKnownAvailability(snapshot.Availability) || snapshot.Availability != expectedAvailability)
        {
            return AnalysisContractFailure.ContradictoryAvailability;
        }

        if (!IsRequiredIdentity(snapshot.SnapshotId) || !IsRequiredIdentity(snapshot.ProcessEntityId) ||
            !IsRequiredIdentity(snapshot.SourceKind) || !IsRequiredVersion(snapshot.SourceVersion) ||
            !IsBoundedOptional(snapshot.ProcessKey, MaximumIdentityLength) ||
            !IsBoundedOptional(snapshot.SourceRunId, MaximumIdentityLength) ||
            !IsValidScope(snapshot.EvidenceIdentity))
        {
            return AnalysisContractFailure.InvalidInputSnapshot;
        }

        if (snapshot.CreatedUtc.Kind != DateTimeKind.Utc)
        {
            return AnalysisContractFailure.InvalidTimestamp;
        }

        var references = snapshot.EvidenceReferences ?? Array.Empty<EvidenceReference>();
        var referenceFailure = ValidateReferences(references);
        if (referenceFailure != AnalysisContractFailure.None)
        {
            return referenceFailure;
        }

        if (snapshot.Availability == AnalysisSourceAvailability.Available)
        {
            if (references.Count == 0)
            {
                return AnalysisContractFailure.MissingEvidence;
            }

            if (!IsSha256(snapshot.InputSetHashSha256))
            {
                return AnalysisContractFailure.InvalidHash;
            }
        }
        else if (references.Count != 0 || !string.IsNullOrEmpty(snapshot.InputSetHashSha256))
        {
            return AnalysisContractFailure.ContradictoryAvailability;
        }

        return AnalysisContractFailure.None;
    }

    private static AnalysisContractFailure ValidateReferences(IReadOnlyList<EvidenceReference>? references)
    {
        if (references == null || references.Count > MaximumEvidenceReferences)
        {
            return AnalysisContractFailure.ValueTooLong;
        }

        var distinct = new HashSet<EvidenceReference>();
        foreach (var reference in references)
        {
            if (reference == null || !Enum.IsDefined(reference.Kind) || reference.IsEmpty ||
                reference.Id.Length > MaximumIdentityLength)
            {
                return AnalysisContractFailure.MissingEvidence;
            }

            if (!distinct.Add(reference))
            {
                return AnalysisContractFailure.DuplicateEvidence;
            }
        }

        return AnalysisContractFailure.None;
    }

    private static bool IsValidRule(AnalysisRuleIdentity? rule) =>
        rule != null &&
        IsRequiredIdentity(rule.ToolId) &&
        IsRequiredVersion(rule.ToolVersion) &&
        IsRequiredIdentity(rule.RuleId) &&
        IsRequiredVersion(rule.RuleVersion) &&
        IsRequiredIdentity(rule.PolicyId) &&
        IsRequiredVersion(rule.PolicyVersion) &&
        ((string.IsNullOrEmpty(rule.ProviderId) && string.IsNullOrEmpty(rule.ProviderVersion)) ||
         (IsRequiredIdentity(rule.ProviderId) && IsRequiredVersion(rule.ProviderVersion)));

    private static bool IsValidScope(EvidenceIdentity? identity) =>
        identity != null &&
        IsBoundedOptional(identity.CaseId, MaximumIdentityLength) &&
        IsRequiredIdentity(identity.EvidenceSessionId) &&
        IsBoundedOptional(identity.CaptureId, MaximumIdentityLength) &&
        IsRequiredIdentity(identity.SourceIdentityId) &&
        IsRequiredIdentity(identity.HostId) &&
        IsRequiredIdentity(identity.ExecutionRootId);

    private static bool SameScope(EvidenceIdentity left, EvidenceIdentity right) =>
        string.Equals(left.CaseId, right.CaseId, StringComparison.Ordinal) &&
        string.Equals(left.EvidenceSessionId, right.EvidenceSessionId, StringComparison.Ordinal) &&
        string.Equals(left.CaptureId, right.CaptureId, StringComparison.Ordinal) &&
        string.Equals(left.SourceIdentityId, right.SourceIdentityId, StringComparison.Ordinal) &&
        string.Equals(left.HostId, right.HostId, StringComparison.Ordinal) &&
        string.Equals(left.ExecutionRootId, right.ExecutionRootId, StringComparison.Ordinal);

    private static bool ReferenceSetsEqual(
        IReadOnlyList<EvidenceReference> left,
        IReadOnlyList<EvidenceReference> right) =>
        left.Count == right.Count && left.ToHashSet().SetEquals(right);

    private static bool IsKnownAvailability(AnalysisSourceAvailability availability) =>
        Enum.IsDefined(availability) && availability != AnalysisSourceAvailability.Unknown;

    private static bool IsKnownSeverity(AnalysisFindingSeverity severity) => Enum.IsDefined(severity);

    private static bool IsRequiredIdentity(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= MaximumIdentityLength;

    private static bool IsRequiredVersion(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= MaximumVersionLength;

    private static bool IsBoundedOptional(string? value, int maximumLength) =>
        value != null && value.Length <= maximumLength;

    private static bool IsBoundedText(string? value, int maximumLength, bool required) =>
        value != null && value.Length <= maximumLength && (!required || !string.IsNullOrWhiteSpace(value));

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static AnalysisFinding CopyFinding(AnalysisFinding finding) =>
        finding with
        {
            EvidenceIdentity = CopyScope(finding.EvidenceIdentity),
            Rule = finding.Rule with { },
            InputSnapshot = CopySnapshot(finding.InputSnapshot),
            EvidenceReferences = CopyReferences(finding.EvidenceReferences)
        };

    private static AnalysisInputSnapshot CopySnapshot(AnalysisInputSnapshot snapshot) =>
        snapshot with
        {
            EvidenceIdentity = CopyScope(snapshot.EvidenceIdentity),
            EvidenceReferences = CopyReferences(snapshot.EvidenceReferences)
        };

    private static ProcessRiskSignal CopySignal(ProcessRiskSignal signal) =>
        signal with
        {
            EvidenceIdentity = CopyScope(signal.EvidenceIdentity),
            EvidenceReferences = CopyReferences(signal.EvidenceReferences)
        };

    private static EvidenceIdentity CopyScope(EvidenceIdentity identity) => identity with { };

    private static IReadOnlyList<EvidenceReference> CopyReferences(
        IReadOnlyList<EvidenceReference> references) =>
        new ReadOnlyCollection<EvidenceReference>(references
            .OrderBy(reference => reference.Kind)
            .ThenBy(reference => reference.Id, StringComparer.Ordinal)
            .ToArray());

    private static string SnapshotDiagnostic(AnalysisContractFailure failure) => failure switch
    {
        AnalysisContractFailure.InvalidSchemaVersion => "The analysis input-snapshot schema version is unsupported.",
        AnalysisContractFailure.InvalidTimestamp => "The analysis input-snapshot timestamp must be UTC.",
        AnalysisContractFailure.InvalidHash => "An available analysis input snapshot requires a SHA-256 input-set hash.",
        AnalysisContractFailure.MissingEvidence => "An available analysis input snapshot requires exact evidence references.",
        AnalysisContractFailure.DuplicateEvidence => "The analysis input snapshot contains duplicate evidence references.",
        AnalysisContractFailure.ContradictoryAvailability => "The finding and input snapshot availability or evidence state is contradictory.",
        _ => "The analysis input snapshot is incomplete or malformed."
    };

    private static string ReferenceDiagnostic(AnalysisContractFailure failure) => failure switch
    {
        AnalysisContractFailure.DuplicateEvidence => "Evidence references must be unique.",
        AnalysisContractFailure.ValueTooLong => "The evidence-reference collection exceeds its bound.",
        _ => "An evidence reference is empty, unknown, or oversized."
    };

    private static AnalysisFindingValidationDecision RejectFinding(
        AnalysisContractFailure failure,
        string diagnostic) =>
        new() { Failure = failure, Diagnostic = diagnostic };

    private static ProcessRiskSignalValidationDecision RejectSignal(
        AnalysisContractFailure failure,
        string diagnostic) =>
        new() { Failure = failure, Diagnostic = diagnostic };

    private static AnalysisReviewValidationDecision RejectReview(
        AnalysisContractFailure failure,
        string diagnostic) =>
        new() { Failure = failure, Diagnostic = diagnostic };
}
