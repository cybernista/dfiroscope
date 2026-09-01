using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum BaselineRiskEvidenceNormalizationFailure
{
    None = 0,
    InvalidRequest = 1,
    InvalidComparisonIdentity = 2,
    UnsupportedArtifactKind = 3,
    UnsupportedVerdict = 4,
    InvalidSnapshotIdentity = 5,
    InvalidProcessObservation = 6,
    InvalidTimestamp = 7,
    WeakCorrelation = 8,
    FindingMismatch = 9,
    InvalidVerdictShape = 10
}

public sealed record BaselineRiskEvidenceNormalizationRequest
{
    public SnapshotComparisonFinding Finding { get; init; } = new();

    public ProcessObservation ProcessObservation { get; init; } = new();

    public string ComparisonId { get; init; } = string.Empty;

    public string ComparisonVersion { get; init; } = string.Empty;

    public string BaselineId { get; init; } = string.Empty;

    public string BaselineSnapshotHashSha256 { get; init; } = string.Empty;

    public string CurrentSnapshotHashSha256 { get; init; } = string.Empty;

    public DateTime ComparedUtc { get; init; }

    public DateTime EvaluatedUtc { get; init; }
}

public sealed record BaselineRiskEvidenceNormalizationDecision
{
    public bool Accepted { get; init; }

    public BaselineRiskEvidenceNormalizationFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public LocalProcessBaselineComparisonEvidence? Evidence { get; init; }
}

/// <summary>
/// Converts one rich Baseline Comparison process finding into the portable
/// Process Risk input only when the producer identity can be reproduced from
/// one exact persisted current process observation. Presentation text and paths
/// outside that observation never enter the normalized output.
/// </summary>
public static class BaselineRiskEvidenceNormalizer
{
    private const int MaximumIdentityLength = 512;

    public static BaselineRiskEvidenceNormalizationDecision Normalize(
        BaselineRiskEvidenceNormalizationRequest? request)
    {
        if (request?.Finding == null || request.ProcessObservation?.Fields == null)
        {
            return Fail(
                BaselineRiskEvidenceNormalizationFailure.InvalidRequest,
                "One Baseline Comparison finding and one persisted process observation are required.");
        }

        if (!Required(request.ComparisonId) ||
            !string.Equals(
                request.ComparisonVersion,
                SnapshotComparisonService.CurrentComparisonVersion,
                StringComparison.Ordinal) ||
            !Required(request.BaselineId))
        {
            return Fail(
                BaselineRiskEvidenceNormalizationFailure.InvalidComparisonIdentity,
                "A stable comparison ID, the current comparison version, and a stable baseline ID are required.");
        }

        if (!ValidSha256(request.BaselineSnapshotHashSha256) ||
            !ValidSha256(request.CurrentSnapshotHashSha256))
        {
            return Fail(
                BaselineRiskEvidenceNormalizationFailure.InvalidSnapshotIdentity,
                "The baseline and current snapshots require SHA-256 byte identities.");
        }

        var finding = request.Finding;
        if (!Enum.IsDefined(finding.ArtifactKind) ||
            finding.ArtifactKind != SnapshotComparisonArtifactKind.Process)
        {
            return Fail(
                BaselineRiskEvidenceNormalizationFailure.UnsupportedArtifactKind,
                "Only a Process Baseline Comparison finding can enter this normalizer.");
        }

        if (!Enum.IsDefined(finding.Verdict) || finding.Verdict == SnapshotComparisonVerdict.Missing)
        {
            return Fail(
                BaselineRiskEvidenceNormalizationFailure.UnsupportedVerdict,
                "Missing and unknown Baseline Comparison verdicts cannot target a current process.");
        }

        var observation = request.ProcessObservation;
        var observationFailure = ValidateProcessObservationForRisk(
            observation,
            request.ComparedUtc,
            request.EvaluatedUtc,
            out var observationDiagnostic);
        if (observationFailure != BaselineRiskEvidenceNormalizationFailure.None)
        {
            return Fail(observationFailure, observationDiagnostic);
        }

        var process = observation.Fields;

        var stableKey = SnapshotComparisonService.BuildProcessStableKeyForRisk(process);
        var currentFingerprint = SnapshotComparisonService
            .BuildProcessMeaningfulFingerprintForRisk(process);
        if (!string.Equals(finding.StableKey, stableKey, StringComparison.Ordinal) ||
            !string.Equals(finding.Fingerprint, currentFingerprint, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(finding.CurrentFingerprint, currentFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            return Fail(
                BaselineRiskEvidenceNormalizationFailure.FindingMismatch,
                "The finding stable key or current fingerprint does not match the persisted process observation.");
        }

        if (!TryMapVerdict(finding, out var verdict))
        {
            return Fail(
                BaselineRiskEvidenceNormalizationFailure.InvalidVerdictShape,
                "The Baseline Comparison verdict, fingerprints, and reviewed policy identity are incoherent.");
        }

        var scope = new EvidenceIdentity
        {
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId
        };
        var stableKeyHash = Sha256(stableKey);
        var normalizedBaselineFingerprint = finding.BaselineFingerprint.ToLowerInvariant();
        var normalizedCurrentFingerprint = currentFingerprint.ToLowerInvariant();
        var normalizedBaselineSnapshotHash = request.BaselineSnapshotHashSha256.ToLowerInvariant();
        var normalizedCurrentSnapshotHash = request.CurrentSnapshotHashSha256.ToLowerInvariant();
        var correlationMethod = observation.CorrelationMethod.ToString();
        var canonical = Canonical(
            ("comparison-id", request.ComparisonId),
            ("comparison-version", request.ComparisonVersion),
            ("baseline-id", request.BaselineId),
            ("baseline-snapshot-hash", normalizedBaselineSnapshotHash),
            ("current-snapshot-hash", normalizedCurrentSnapshotHash),
            ("artifact-kind", LocalProcessBaselineArtifactKind.Process.ToString()),
            ("verdict", verdict.ToString()),
            ("stable-key-hash", stableKeyHash),
            ("baseline-fingerprint", normalizedBaselineFingerprint),
            ("current-fingerprint", normalizedCurrentFingerprint),
            ("policy-rule-id", finding.PolicyRuleId),
            ("case-id", scope.CaseId),
            ("session-id", scope.EvidenceSessionId),
            ("capture-id", scope.CaptureId),
            ("source-identity-id", scope.SourceIdentityId),
            ("host-id", scope.HostId),
            ("execution-root-id", scope.ExecutionRootId),
            ("process-entity-id", observation.ProcessEntityId),
            ("process-key", process.ProcessKey),
            ("process-observation-id", observation.ObservationId),
            ("source-run-id", observation.SourceRunId),
            ("compared-utc", request.ComparedUtc.ToString("O", CultureInfo.InvariantCulture)),
            ("correlation-method", correlationMethod));
        var evidence = new LocalProcessBaselineComparisonEvidence
        {
            FindingId = $"baseline-finding-{Sha256(canonical)[..32]}",
            ComparisonId = request.ComparisonId,
            ComparisonVersion = request.ComparisonVersion,
            BaselineId = request.BaselineId,
            BaselineSnapshotHashSha256 = normalizedBaselineSnapshotHash,
            CurrentSnapshotHashSha256 = normalizedCurrentSnapshotHash,
            ArtifactKind = LocalProcessBaselineArtifactKind.Process,
            Verdict = verdict,
            StableKeyHashSha256 = stableKeyHash,
            BaselineFingerprintSha256 = normalizedBaselineFingerprint,
            CurrentFingerprintSha256 = normalizedCurrentFingerprint,
            PolicyRuleId = finding.PolicyRuleId,
            EvidenceIdentity = scope,
            ProcessEntityId = observation.ProcessEntityId,
            ProcessKey = process.ProcessKey,
            ComparedUtc = request.ComparedUtc,
            CorrelationState = EvidenceCorrelationState.Exact,
            CorrelationMethod = correlationMethod,
            CorrelationCandidateCount = 1,
            EvidenceReferences =
            [
                new EvidenceReference(EvidenceReferenceKind.ProcessEntity, observation.ProcessEntityId),
                new EvidenceReference(EvidenceReferenceKind.ProcessObservation, observation.ObservationId),
                new EvidenceReference(EvidenceReferenceKind.SourceRun, observation.SourceRunId)
            ]
        };

        return new BaselineRiskEvidenceNormalizationDecision
        {
            Accepted = true,
            Failure = BaselineRiskEvidenceNormalizationFailure.None,
            Diagnostic = "The exact persisted Baseline Comparison process finding was normalized for portable risk mapping.",
            Evidence = evidence
        };
    }

    private static bool ValidProcessObservation(ProcessObservation observation)
    {
        var process = observation.Fields;
        return Required(observation.ObservationId) &&
               Required(observation.AdapterId) &&
               Required(observation.ParserVersion) &&
               Required(observation.SourceRunId) &&
               Required(observation.ProcessEntityId) &&
               Enum.IsDefined(observation.ObservationKind) &&
               observation.ObservationKind != ProcessObservationKind.LegacyCompatibility &&
               Enum.IsDefined(observation.StatusAssertion) &&
               observation.FieldStates != null &&
               observation.FieldStates.All(pair => Required(pair.Key) && Enum.IsDefined(pair.Value)) &&
               Required(process.CaseId) &&
               Required(process.EvidenceSessionId) &&
               Required(process.CaptureId) &&
               Required(process.SourceIdentityId) &&
               Required(process.HostId) &&
               Required(process.ExecutionRootId) &&
               Required(process.ProcessEntityId) &&
               Optional(process.ProcessKey) &&
               string.Equals(observation.ProcessEntityId, process.ProcessEntityId, StringComparison.Ordinal);
    }

    internal static BaselineRiskEvidenceNormalizationFailure ValidateProcessObservationForRisk(
        ProcessObservation? observation,
        DateTime comparedUtc,
        DateTime evaluatedUtc,
        out string diagnostic)
    {
        if (observation?.Fields == null || !ValidProcessObservation(observation))
        {
            diagnostic = "The persisted process observation must carry complete exact identity, scope, and provenance.";
            return BaselineRiskEvidenceNormalizationFailure.InvalidProcessObservation;
        }

        var process = observation.Fields;
        if (comparedUtc.Kind != DateTimeKind.Utc ||
            evaluatedUtc.Kind != DateTimeKind.Utc ||
            observation.ObservedUtc.Kind != DateTimeKind.Utc ||
            process.LastObservedUtc.Kind != DateTimeKind.Utc ||
            process.LastObservedUtc != observation.ObservedUtc ||
            observation.ObservedUtc > comparedUtc ||
            comparedUtc > evaluatedUtc)
        {
            diagnostic = "Observation, comparison, and evaluation times must form one bounded UTC sequence.";
            return BaselineRiskEvidenceNormalizationFailure.InvalidTimestamp;
        }

        if (!Enum.IsDefined(observation.CorrelationMethod) ||
            observation.CorrelationMethod == ProcessCorrelationMethod.LegacyCompatibility ||
            observation.CorrelationConfidence != 1d)
        {
            diagnostic = "Only confidence-1 non-legacy persisted process correlation is accepted.";
            return BaselineRiskEvidenceNormalizationFailure.WeakCorrelation;
        }

        diagnostic = string.Empty;
        return BaselineRiskEvidenceNormalizationFailure.None;
    }

    private static bool TryMapVerdict(
        SnapshotComparisonFinding finding,
        out LocalProcessBaselineVerdict verdict)
    {
        verdict = finding.Verdict switch
        {
            SnapshotComparisonVerdict.New => LocalProcessBaselineVerdict.New,
            SnapshotComparisonVerdict.Changed => LocalProcessBaselineVerdict.Changed,
            SnapshotComparisonVerdict.Known => LocalProcessBaselineVerdict.Known,
            SnapshotComparisonVerdict.Noisy => LocalProcessBaselineVerdict.Noisy,
            SnapshotComparisonVerdict.Accepted => LocalProcessBaselineVerdict.Accepted,
            _ => LocalProcessBaselineVerdict.Unknown
        };
        if (verdict == LocalProcessBaselineVerdict.Unknown ||
            finding.BaselineFingerprint == null ||
            finding.CurrentFingerprint == null ||
            finding.PolicyRuleId == null)
        {
            return false;
        }

        var hasBaseline = ValidSha256(finding.BaselineFingerprint);
        var hasCurrent = ValidSha256(finding.CurrentFingerprint);
        var sameFingerprint = string.Equals(
            finding.BaselineFingerprint,
            finding.CurrentFingerprint,
            StringComparison.OrdinalIgnoreCase);
        var hasPolicy = Required(finding.PolicyRuleId);
        return verdict switch
        {
            LocalProcessBaselineVerdict.New =>
                finding.BaselineFingerprint.Length == 0 && hasCurrent && finding.PolicyRuleId.Length == 0,
            LocalProcessBaselineVerdict.Changed =>
                hasBaseline && hasCurrent && !sameFingerprint && finding.PolicyRuleId.Length == 0,
            LocalProcessBaselineVerdict.Known or LocalProcessBaselineVerdict.Noisy =>
                hasBaseline && hasCurrent && sameFingerprint && finding.PolicyRuleId.Length == 0,
            LocalProcessBaselineVerdict.Accepted =>
                hasBaseline && hasCurrent && !sameFingerprint && hasPolicy,
            _ => false
        };
    }

    private static bool Required(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= MaximumIdentityLength &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal);

    private static bool Optional(string? value) =>
        value != null &&
        value.Length <= MaximumIdentityLength &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal);

    private static bool ValidSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string Canonical(params (string Key, string Value)[] fields)
    {
        var builder = new StringBuilder();
        foreach (var (key, value) in fields)
        {
            builder.Append(key.Length.ToString(CultureInfo.InvariantCulture))
                .Append(':')
                .Append(key)
                .Append('=')
                .Append(value.Length.ToString(CultureInfo.InvariantCulture))
                .Append(':')
                .Append(value)
                .Append('\n');
        }

        return builder.ToString();
    }

    private static BaselineRiskEvidenceNormalizationDecision Fail(
        BaselineRiskEvidenceNormalizationFailure failure,
        string diagnostic) => new()
    {
        Accepted = false,
        Failure = failure,
        Diagnostic = diagnostic
    };
}
