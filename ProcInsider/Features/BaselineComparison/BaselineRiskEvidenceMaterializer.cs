using System.Globalization;
using System.IO;
using System.Text;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum BaselineRiskEvidenceMaterializationFailure
{
    None = 0,
    InvalidRequest = 1,
    InputLimitExceeded = 2,
    InvalidComparisonIdentity = 3,
    InvalidSnapshotIdentity = 4,
    InvalidComparisonResult = 5,
    UnsupportedArtifactKind = 6,
    UnsupportedVerdict = 7,
    InvalidFindingIdentity = 8,
    InvalidProcessObservation = 9,
    ProcessObservationNotFound = 10,
    AmbiguousProcessObservation = 11,
    NormalizationRejected = 12,
    DuplicateFindingIdentity = 13,
    DuplicateCanonicalInput = 14,
    ProcessFindingLimitExceeded = 15
}

public sealed record BaselineRiskEvidenceMaterializationRequest
{
    public SnapshotComparisonResult ComparisonResult { get; init; } = new();

    public string ComparisonId { get; init; } = string.Empty;

    public string ComparisonVersion { get; init; } = string.Empty;

    public string BaselineId { get; init; } = string.Empty;

    public string BaselineSnapshotHashSha256 { get; init; } = string.Empty;

    public string CurrentSnapshotHashSha256 { get; init; } = string.Empty;

    public DateTime EvaluatedUtc { get; init; }

    public IReadOnlyList<ProcessObservation> CurrentProcessObservations { get; init; } = [];
}

public sealed record BaselineRiskEvidenceMaterializationDiagnostic
{
    public BaselineRiskEvidenceMaterializationFailure Failure { get; init; }

    public BaselineRiskEvidenceNormalizationFailure NormalizationFailure { get; init; }

    public string ProcessEntityId { get; init; } = string.Empty;

    public string StableKey { get; init; } = string.Empty;

    public string CurrentFingerprintSha256 { get; init; } = string.Empty;

    public string ProcessObservationId { get; init; } = string.Empty;

    public string SourceRunId { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;
}

public sealed record BaselineRiskEvidenceMaterializationResult
{
    public IReadOnlyList<LocalProcessBaselineComparisonEvidence> Evidence { get; init; } = [];

    public IReadOnlyList<BaselineRiskEvidenceMaterializationDiagnostic> Diagnostics { get; init; } = [];

    public int AcceptedFindingCount { get; init; }

    public int RejectedFindingCount { get; init; }
}

/// <summary>
/// Resolves one bounded completed Baseline Comparison result to unique exact
/// persisted current process observations and delegates conversion to
/// <see cref="BaselineRiskEvidenceNormalizer"/>. This owner returns in-memory
/// mapper inputs only; it does not persist evidence or schedule risk rebuilds.
/// </summary>
public static class BaselineRiskEvidenceMaterializer
{
    public const int MaximumFindings = 1000;
    public const int MaximumCurrentProcessObservations = 10000;

    private const int MaximumIdentityLength = 512;
    private const int MaximumPathLength = 32768;

    public static BaselineRiskEvidenceMaterializationResult Materialize(
        BaselineRiskEvidenceMaterializationRequest? request)
    {
        if (request?.ComparisonResult == null ||
            request.ComparisonResult.Findings == null ||
            request.CurrentProcessObservations == null ||
            request.EvaluatedUtc.Kind != DateTimeKind.Utc)
        {
            return FailRequest(
                request?.ComparisonResult?.Findings?.Count ?? 0,
                BaselineRiskEvidenceMaterializationFailure.InvalidRequest,
                "A completed comparison, UTC evaluation boundary, and non-null bounded finding/observation collections are required.");
        }

        var comparison = request.ComparisonResult;
        if (comparison.Findings.Count > MaximumFindings ||
            request.CurrentProcessObservations.Count > MaximumCurrentProcessObservations)
        {
            return FailRequest(
                comparison.Findings.Count,
                BaselineRiskEvidenceMaterializationFailure.InputLimitExceeded,
                "The Baseline Comparison materialization input exceeds the fixed finding or current-observation bound.");
        }

        if (!Required(request.ComparisonId) ||
            !string.Equals(
                request.ComparisonVersion,
                SnapshotComparisonService.CurrentComparisonVersion,
                StringComparison.Ordinal) ||
            !Required(request.BaselineId))
        {
            return FailRequest(
                comparison.Findings.Count,
                BaselineRiskEvidenceMaterializationFailure.InvalidComparisonIdentity,
                "A stable comparison ID, the current comparison version, and a stable baseline ID are required.");
        }

        if (!ValidSha256(request.BaselineSnapshotHashSha256) ||
            !ValidSha256(request.CurrentSnapshotHashSha256))
        {
            return FailRequest(
                comparison.Findings.Count,
                BaselineRiskEvidenceMaterializationFailure.InvalidSnapshotIdentity,
                "The baseline and current snapshots require SHA-256 byte identities.");
        }

        if (!ValidComparisonResult(comparison, request.EvaluatedUtc))
        {
            return FailRequest(
                comparison.Findings.Count,
                BaselineRiskEvidenceMaterializationFailure.InvalidComparisonResult,
                "The completed comparison requires canonical full snapshot paths, bounded UTC order, non-negative counts, and known artifact/verdict values.");
        }

        var diagnostics = new List<BaselineRiskEvidenceMaterializationDiagnostic>();
        var observations = BuildObservationIndex(
            request.CurrentProcessObservations,
            comparison.ComparedUtc,
            request.EvaluatedUtc,
            diagnostics);
        var accepted = new List<MaterializedFinding>();

        foreach (var finding in comparison.Findings.OrderBy(FindingSortKey, StringComparer.Ordinal))
        {
            if (finding.ArtifactKind != SnapshotComparisonArtifactKind.Process)
            {
                diagnostics.Add(Diagnostic(
                    BaselineRiskEvidenceMaterializationFailure.UnsupportedArtifactKind,
                    finding,
                    null,
                    "Only Process Baseline Comparison findings can be materialized for Process Risk."));
                continue;
            }

            if (finding.Verdict == SnapshotComparisonVerdict.Missing ||
                string.IsNullOrEmpty(finding.CurrentFingerprint))
            {
                diagnostics.Add(Diagnostic(
                    BaselineRiskEvidenceMaterializationFailure.UnsupportedVerdict,
                    finding,
                    null,
                    "A Missing finding or finding without a current side cannot target a current process."));
                continue;
            }

            if (!RequiredStableKey(finding.StableKey) ||
                !ValidSha256(finding.Fingerprint) ||
                !ValidSha256(finding.CurrentFingerprint))
            {
                diagnostics.Add(Diagnostic(
                    BaselineRiskEvidenceMaterializationFailure.InvalidFindingIdentity,
                    finding,
                    null,
                    "A Process finding requires one bounded stable key and exact current SHA-256 fingerprint identity."));
                continue;
            }

            var observationKey = new CurrentObservationKey(
                finding.StableKey,
                finding.CurrentFingerprint.ToLowerInvariant());
            if (!observations.TryGetValue(observationKey, out var candidates) || candidates.Count == 0)
            {
                diagnostics.Add(Diagnostic(
                    BaselineRiskEvidenceMaterializationFailure.ProcessObservationNotFound,
                    finding,
                    null,
                    "No valid persisted current process observation matches the exact stable key and current fingerprint."));
                continue;
            }

            if (candidates.Count != 1)
            {
                diagnostics.Add(Diagnostic(
                    BaselineRiskEvidenceMaterializationFailure.AmbiguousProcessObservation,
                    finding,
                    null,
                    "More than one valid persisted current process observation matches the exact stable key and current fingerprint."));
                continue;
            }

            var observation = candidates[0];
            var decision = BaselineRiskEvidenceNormalizer.Normalize(
                new BaselineRiskEvidenceNormalizationRequest
                {
                    Finding = finding,
                    ProcessObservation = observation,
                    ComparisonId = request.ComparisonId,
                    ComparisonVersion = request.ComparisonVersion,
                    BaselineId = request.BaselineId,
                    BaselineSnapshotHashSha256 = request.BaselineSnapshotHashSha256,
                    CurrentSnapshotHashSha256 = request.CurrentSnapshotHashSha256,
                    ComparedUtc = comparison.ComparedUtc,
                    EvaluatedUtc = request.EvaluatedUtc
                });
            if (!decision.Accepted || decision.Evidence == null)
            {
                diagnostics.Add(Diagnostic(
                    BaselineRiskEvidenceMaterializationFailure.NormalizationRejected,
                    finding,
                    observation,
                    decision.Diagnostic,
                    decision.Failure));
                continue;
            }

            accepted.Add(new MaterializedFinding(finding, observation, decision.Evidence));
        }

        var evidence = new List<LocalProcessBaselineComparisonEvidence>();
        foreach (var processGroup in accepted
                     .GroupBy(item => item.Evidence.ProcessEntityId, StringComparer.Ordinal)
                     .OrderBy(group => group.Key, StringComparer.Ordinal))
        {
            var duplicateFindingIds = processGroup
                .GroupBy(item => item.Evidence.FindingId, StringComparer.Ordinal)
                .Where(group => group.Count() > 1)
                .OrderBy(group => group.Key, StringComparer.Ordinal)
                .ToArray();
            var duplicateCanonicalInputs = processGroup
                .GroupBy(item => CanonicalEvidenceInput(item.Evidence), StringComparer.Ordinal)
                .Where(group => group.Count() > 1)
                .OrderBy(group => group.Key, StringComparer.Ordinal)
                .ToArray();
            if (duplicateFindingIds.Length > 0 || duplicateCanonicalInputs.Length > 0)
            {
                foreach (var duplicate in duplicateFindingIds)
                {
                    var first = duplicate.OrderBy(item => FindingSortKey(item.Finding), StringComparer.Ordinal).First();
                    diagnostics.Add(Diagnostic(
                        BaselineRiskEvidenceMaterializationFailure.DuplicateFindingIdentity,
                        first.Finding,
                        first.Observation,
                        "A duplicate normalized Baseline finding identity suppressed the complete process group."));
                }

                foreach (var duplicate in duplicateCanonicalInputs)
                {
                    var first = duplicate.OrderBy(item => FindingSortKey(item.Finding), StringComparer.Ordinal).First();
                    diagnostics.Add(Diagnostic(
                        BaselineRiskEvidenceMaterializationFailure.DuplicateCanonicalInput,
                        first.Finding,
                        first.Observation,
                        "A duplicate canonical normalized Baseline input suppressed the complete process group."));
                }

                continue;
            }

            if (processGroup.Count() > LocalProcessRiskMapper.MaximumBaselineComparisonEvidence)
            {
                var first = processGroup
                    .OrderBy(item => item.Evidence.FindingId, StringComparer.Ordinal)
                    .First();
                diagnostics.Add(Diagnostic(
                    BaselineRiskEvidenceMaterializationFailure.ProcessFindingLimitExceeded,
                    first.Finding,
                    first.Observation,
                    $"More than {LocalProcessRiskMapper.MaximumBaselineComparisonEvidence} normalized Baseline findings suppressed the complete process group."));
                continue;
            }

            evidence.AddRange(processGroup
                .Select(item => item.Evidence)
                .OrderBy(item => item.FindingId, StringComparer.Ordinal));
        }

        var orderedEvidence = evidence
            .OrderBy(item => item.ProcessEntityId, StringComparer.Ordinal)
            .ThenBy(item => item.FindingId, StringComparer.Ordinal)
            .ToArray();
        var orderedDiagnostics = diagnostics
            .OrderBy(item => item.Failure)
            .ThenBy(item => item.ProcessEntityId, StringComparer.Ordinal)
            .ThenBy(item => item.StableKey, StringComparer.Ordinal)
            .ThenBy(item => item.CurrentFingerprintSha256, StringComparer.Ordinal)
            .ThenBy(item => item.ProcessObservationId, StringComparer.Ordinal)
            .ThenBy(item => item.SourceRunId, StringComparer.Ordinal)
            .ThenBy(item => item.NormalizationFailure)
            .ThenBy(item => item.Message, StringComparer.Ordinal)
            .ToArray();
        return new BaselineRiskEvidenceMaterializationResult
        {
            Evidence = orderedEvidence,
            Diagnostics = orderedDiagnostics,
            AcceptedFindingCount = orderedEvidence.Length,
            RejectedFindingCount = comparison.Findings.Count - orderedEvidence.Length
        };
    }

    private static Dictionary<CurrentObservationKey, List<ProcessObservation>> BuildObservationIndex(
        IReadOnlyList<ProcessObservation> source,
        DateTime comparedUtc,
        DateTime evaluatedUtc,
        List<BaselineRiskEvidenceMaterializationDiagnostic> diagnostics)
    {
        var index = new Dictionary<CurrentObservationKey, List<ProcessObservation>>();
        foreach (var observation in source.OrderBy(ObservationSortKey, StringComparer.Ordinal))
        {
            var validationFailure = BaselineRiskEvidenceNormalizer.ValidateProcessObservationForRisk(
                observation,
                comparedUtc,
                evaluatedUtc,
                out var validationDiagnostic);
            if (validationFailure != BaselineRiskEvidenceNormalizationFailure.None)
            {
                diagnostics.Add(new BaselineRiskEvidenceMaterializationDiagnostic
                {
                    Failure = BaselineRiskEvidenceMaterializationFailure.InvalidProcessObservation,
                    NormalizationFailure = validationFailure,
                    ProcessEntityId = observation?.ProcessEntityId ?? string.Empty,
                    ProcessObservationId = observation?.ObservationId ?? string.Empty,
                    SourceRunId = observation?.SourceRunId ?? string.Empty,
                    Message = validationDiagnostic
                });
                continue;
            }

            var process = observation.Fields;
            var key = new CurrentObservationKey(
                SnapshotComparisonService.BuildProcessStableKeyForRisk(process),
                SnapshotComparisonService.BuildProcessMeaningfulFingerprintForRisk(process).ToLowerInvariant());
            if (!index.TryGetValue(key, out var matches))
            {
                matches = [];
                index.Add(key, matches);
            }

            matches.Add(observation);
        }

        return index;
    }

    private static bool ValidComparisonResult(
        SnapshotComparisonResult comparison,
        DateTime evaluatedUtc)
    {
        if (comparison.ComparedUtc.Kind != DateTimeKind.Utc ||
            comparison.ComparedUtc > evaluatedUtc ||
            comparison.BaselineProcessCount < 0 ||
            comparison.CurrentProcessCount < 0 ||
            !CanonicalFullPath(comparison.BaselineSnapshotPath) ||
            !CanonicalFullPath(comparison.CurrentSnapshotPath))
        {
            return false;
        }

        return comparison.Findings.All(finding =>
            finding != null &&
            Enum.IsDefined(finding.ArtifactKind) &&
            finding.ArtifactKind != SnapshotComparisonArtifactKind.Unknown &&
            Enum.IsDefined(finding.Verdict));
    }

    private static bool CanonicalFullPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > MaximumPathLength ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
            !Path.IsPathFullyQualified(value))
        {
            return false;
        }

        try
        {
            return string.Equals(Path.GetFullPath(value), value, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static BaselineRiskEvidenceMaterializationResult FailRequest(
        int rejectedFindingCount,
        BaselineRiskEvidenceMaterializationFailure failure,
        string message) =>
        new()
        {
            Diagnostics =
            [
                new BaselineRiskEvidenceMaterializationDiagnostic
                {
                    Failure = failure,
                    Message = message
                }
            ],
            RejectedFindingCount = rejectedFindingCount
        };

    private static BaselineRiskEvidenceMaterializationDiagnostic Diagnostic(
        BaselineRiskEvidenceMaterializationFailure failure,
        SnapshotComparisonFinding finding,
        ProcessObservation? observation,
        string message,
        BaselineRiskEvidenceNormalizationFailure normalizationFailure =
            BaselineRiskEvidenceNormalizationFailure.None) =>
        new()
        {
            Failure = failure,
            NormalizationFailure = normalizationFailure,
            ProcessEntityId = observation?.ProcessEntityId ?? string.Empty,
            StableKey = finding.StableKey ?? string.Empty,
            CurrentFingerprintSha256 = finding.CurrentFingerprint?.ToLowerInvariant() ?? string.Empty,
            ProcessObservationId = observation?.ObservationId ?? string.Empty,
            SourceRunId = observation?.SourceRunId ?? string.Empty,
            Message = message
        };

    private static string FindingSortKey(SnapshotComparisonFinding finding) =>
        string.Join(
            "\u001f",
            ((int)finding.ArtifactKind).ToString(CultureInfo.InvariantCulture),
            ((int)finding.Verdict).ToString(CultureInfo.InvariantCulture),
            finding.StableKey,
            finding.CurrentFingerprint?.ToLowerInvariant() ?? string.Empty,
            finding.BaselineFingerprint?.ToLowerInvariant() ?? string.Empty,
            finding.PolicyRuleId);

    private static string ObservationSortKey(ProcessObservation? observation) =>
        observation == null
            ? string.Empty
            : string.Join(
                "\u001f",
                observation.ProcessEntityId,
                observation.ObservationId,
                observation.SourceRunId);

    private static string CanonicalEvidenceInput(LocalProcessBaselineComparisonEvidence item) =>
        Canonical(
            ("comparison-id", item.ComparisonId),
            ("comparison-version", item.ComparisonVersion),
            ("baseline-id", item.BaselineId),
            ("baseline-snapshot-hash", item.BaselineSnapshotHashSha256.ToLowerInvariant()),
            ("current-snapshot-hash", item.CurrentSnapshotHashSha256.ToLowerInvariant()),
            ("artifact-kind", item.ArtifactKind.ToString()),
            ("verdict", item.Verdict.ToString()),
            ("stable-key-hash", item.StableKeyHashSha256.ToLowerInvariant()),
            ("baseline-fingerprint", item.BaselineFingerprintSha256.ToLowerInvariant()),
            ("current-fingerprint", item.CurrentFingerprintSha256.ToLowerInvariant()),
            ("policy-rule-id", item.PolicyRuleId),
            ("case-id", item.EvidenceIdentity.CaseId),
            ("session-id", item.EvidenceIdentity.EvidenceSessionId),
            ("capture-id", item.EvidenceIdentity.CaptureId),
            ("source-identity-id", item.EvidenceIdentity.SourceIdentityId),
            ("host-id", item.EvidenceIdentity.HostId),
            ("execution-root-id", item.EvidenceIdentity.ExecutionRootId),
            ("process-entity-id", item.ProcessEntityId),
            ("process-key", item.ProcessKey),
            ("compared-utc", item.ComparedUtc.ToString("O", CultureInfo.InvariantCulture)),
            ("correlation-state", item.CorrelationState.ToString()),
            ("correlation-method", item.CorrelationMethod),
            ("correlation-candidate-count", item.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture)),
            ("evidence-references", string.Join(
                "\u001e",
                item.EvidenceReferences.Select(reference => $"{(int)reference.Kind}:{reference.Id}"))));

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

    private static bool Required(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= MaximumIdentityLength &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal);

    private static bool RequiredStableKey(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= MaximumPathLength &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal);

    private static bool ValidSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private sealed record MaterializedFinding(
        SnapshotComparisonFinding Finding,
        ProcessObservation Observation,
        LocalProcessBaselineComparisonEvidence Evidence);

    private readonly record struct CurrentObservationKey(
        string StableKey,
        string CurrentFingerprintSha256);
}
