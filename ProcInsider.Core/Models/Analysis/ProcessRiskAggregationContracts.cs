using System.Collections.ObjectModel;

namespace ProcInsider.Models.Analysis;

/// <summary>
/// Whether a numeric Process Risk Score could be projected from the configured
/// local sources. Partial coverage is explicit and never treated as complete.
/// </summary>
public enum ProcessRiskProjectionState
{
    Unknown = 0,
    Complete = 1,
    Partial = 2
}

/// <summary>
/// Triage band for a numeric Process Risk Score. Minimal means a calculated score
/// in the lowest range; it does not mean benign or safe.
/// </summary>
public enum ProcessRiskBand
{
    Unknown = 0,
    Minimal = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

/// <summary>
/// Canonical source families in the first local-only aggregation policy. These
/// identify analysis inputs, not evidence trust or collection authorization.
/// </summary>
public enum ProcessRiskSourceKind
{
    Unknown = 0,
    ProcessMetadata = 1,
    PeProperties = 2,
    Authenticode = 3,
    NetworkAndDns = 4,
    Events = 5,
    Filesystem = 6,
    MemoryAndVolatility = 7,
    Sigma = 8,
    BaselineComparison = 9,
    Yara = 10
}

public enum ProcessRiskAggregationFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    InvalidPolicy = 2,
    InvalidScope = 3,
    InvalidTimestamp = 4,
    InputLimitExceeded = 5,
    InvalidFinding = 6,
    InvalidSignal = 7,
    DuplicateFinding = 8,
    DuplicateSignal = 9,
    DuplicateFindingSignal = 10,
    UnknownSource = 11,
    PolicyMismatch = 12,
    ProcessScopeMismatch = 13,
    ContradictorySourceState = 14,
    SeverityDeltaExceeded = 15
}

public sealed record ProcessRiskSourcePolicy
{
    public ProcessRiskSourceKind SourceKind { get; init; }

    public string SourceId { get; init; } = string.Empty;

    public int ConfidenceWeight { get; init; }
}

public sealed record ProcessRiskSeverityDeltaPolicy
{
    public AnalysisFindingSeverity Severity { get; init; }

    public int MaximumAbsoluteDelta { get; init; }
}

public sealed record ProcessRiskBandThreshold
{
    public ProcessRiskBand Band { get; init; }

    public int MinimumScore { get; init; }
}

/// <summary>
/// Versioned aggregation policy. Source weights affect confidence only; validated
/// signal deltas remain individually visible and are summed without hidden weights.
/// </summary>
public sealed record ProcessRiskAggregationPolicy
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string PolicyId { get; init; } = string.Empty;

    public string PolicyVersion { get; init; } = string.Empty;

    public int MaximumFindings { get; init; }

    public int MaximumSignals { get; init; }

    public IReadOnlyList<ProcessRiskSourcePolicy> Sources { get; init; } =
        Array.Empty<ProcessRiskSourcePolicy>();

    public IReadOnlyList<ProcessRiskSeverityDeltaPolicy> SeverityDeltaBounds { get; init; } =
        Array.Empty<ProcessRiskSeverityDeltaPolicy>();

    public IReadOnlyList<ProcessRiskBandThreshold> BandThresholds { get; init; } =
        Array.Empty<ProcessRiskBandThreshold>();

    /// <summary>
    /// The first local-only policy. Access returns fresh defensive collections so
    /// callers cannot mutate process-wide policy state.
    /// </summary>
    public static ProcessRiskAggregationPolicy LocalFirstVersion1 =>
        CreateLocalFirstPolicy("1", includeYara: false);

    /// <summary>
    /// Additive policy that enrolls exact review-gated YARA attribution without
    /// changing the persisted version-1 production path.
    /// </summary>
    public static ProcessRiskAggregationPolicy LocalFirstVersion2 =>
        CreateLocalFirstPolicy("2", includeYara: true);

    private static ProcessRiskAggregationPolicy CreateLocalFirstPolicy(
        string policyVersion,
        bool includeYara)
    {
        var sources = new List<ProcessRiskSourcePolicy>
        {
            new ProcessRiskSourcePolicy
            {
                SourceKind = ProcessRiskSourceKind.ProcessMetadata,
                SourceId = "process-metadata",
                ConfidenceWeight = 15
            },
            new ProcessRiskSourcePolicy
            {
                SourceKind = ProcessRiskSourceKind.PeProperties,
                SourceId = "pe-properties",
                ConfidenceWeight = 10
            },
            new ProcessRiskSourcePolicy
            {
                SourceKind = ProcessRiskSourceKind.Authenticode,
                SourceId = "authenticode",
                ConfidenceWeight = 10
            },
            new ProcessRiskSourcePolicy
            {
                SourceKind = ProcessRiskSourceKind.NetworkAndDns,
                SourceId = "network-dns",
                ConfidenceWeight = 15
            },
            new ProcessRiskSourcePolicy
            {
                SourceKind = ProcessRiskSourceKind.Events,
                SourceId = "events",
                ConfidenceWeight = 15
            },
            new ProcessRiskSourcePolicy
            {
                SourceKind = ProcessRiskSourceKind.Filesystem,
                SourceId = "filesystem",
                ConfidenceWeight = 10
            },
            new ProcessRiskSourcePolicy
            {
                SourceKind = ProcessRiskSourceKind.MemoryAndVolatility,
                SourceId = "memory-volatility",
                ConfidenceWeight = 10
            },
            new ProcessRiskSourcePolicy
            {
                SourceKind = ProcessRiskSourceKind.Sigma,
                SourceId = "sigma",
                ConfidenceWeight = 10
            },
            new ProcessRiskSourcePolicy
            {
                SourceKind = ProcessRiskSourceKind.BaselineComparison,
                SourceId = "baseline-comparison",
                ConfidenceWeight = 5
            }
        };
        if (includeYara)
        {
            sources.Add(new ProcessRiskSourcePolicy
            {
                SourceKind = ProcessRiskSourceKind.Yara,
                SourceId = "yara",
                ConfidenceWeight = 10
            });
        }

        return new ProcessRiskAggregationPolicy
        {
            PolicyId = "dfiroscope.local-process-risk",
            PolicyVersion = policyVersion,
            MaximumFindings = 512,
            MaximumSignals = 512,
            Sources = new ReadOnlyCollection<ProcessRiskSourcePolicy>(sources.ToArray()),
            SeverityDeltaBounds = ReadOnly(
                new ProcessRiskSeverityDeltaPolicy
                {
                    Severity = AnalysisFindingSeverity.Informational,
                    MaximumAbsoluteDelta = 10
                },
                new ProcessRiskSeverityDeltaPolicy
                {
                    Severity = AnalysisFindingSeverity.Low,
                    MaximumAbsoluteDelta = 20
                },
                new ProcessRiskSeverityDeltaPolicy
                {
                    Severity = AnalysisFindingSeverity.Medium,
                    MaximumAbsoluteDelta = 40
                },
                new ProcessRiskSeverityDeltaPolicy
                {
                    Severity = AnalysisFindingSeverity.High,
                    MaximumAbsoluteDelta = 70
                },
                new ProcessRiskSeverityDeltaPolicy
                {
                    Severity = AnalysisFindingSeverity.Critical,
                    MaximumAbsoluteDelta = 100
                }),
            BandThresholds = ReadOnly(
                new ProcessRiskBandThreshold { Band = ProcessRiskBand.Minimal, MinimumScore = 0 },
                new ProcessRiskBandThreshold { Band = ProcessRiskBand.Low, MinimumScore = 20 },
                new ProcessRiskBandThreshold { Band = ProcessRiskBand.Medium, MinimumScore = 40 },
                new ProcessRiskBandThreshold { Band = ProcessRiskBand.High, MinimumScore = 60 },
                new ProcessRiskBandThreshold { Band = ProcessRiskBand.Critical, MinimumScore = 80 })
        };
    }

    private static IReadOnlyList<T> ReadOnly<T>(params T[] items) =>
        new ReadOnlyCollection<T>(items);
}

public sealed record ProcessRiskAggregationRequest
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public DateTime ProjectedUtc { get; init; }

    public ProcessRiskAggregationPolicy Policy { get; init; } = new();

    public IReadOnlyList<AnalysisFinding> Findings { get; init; } = Array.Empty<AnalysisFinding>();

    public IReadOnlyList<ProcessRiskSignal> Signals { get; init; } = Array.Empty<ProcessRiskSignal>();
}

public sealed record ProcessRiskSourceCoverage
{
    public ProcessRiskSourceKind SourceKind { get; init; }

    public string SourceId { get; init; } = string.Empty;

    public AnalysisSourceAvailability Availability { get; init; }

    public int ConfidenceWeight { get; init; }

    public double Confidence { get; init; }

    public int FindingCount { get; init; }

    public int SignalCount { get; init; }

    public string Diagnostic { get; init; } = string.Empty;
}

/// <summary>
/// One accepted contributor paired with the exact validated finding that produced
/// it. The pairing keeps the aggregate explainable without creating new evidence.
/// </summary>
public sealed record ProcessRiskContribution
{
    public ProcessRiskSourceKind SourceKind { get; init; }

    public string SourceId { get; init; } = string.Empty;

    public AnalysisFinding Finding { get; init; } = new();

    public ProcessRiskSignal Signal { get; init; } = new();
}

/// <summary>
/// Rebuildable derived Process Risk Score. Unknown has no numeric score; numeric
/// zero remains an evaluated triage result with visible confidence and coverage.
/// </summary>
public sealed record ProcessRiskScoreProjection
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ProcessRiskProjectionState State { get; init; }

    public int? Score { get; init; }

    public ProcessRiskBand Band { get; init; }

    public double Confidence { get; init; }

    public double Coverage { get; init; }

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public string PolicyId { get; init; } = string.Empty;

    public string PolicyVersion { get; init; } = string.Empty;

    public DateTime ProjectedUtc { get; init; }

    public IReadOnlyList<ProcessRiskSourceCoverage> Sources { get; init; } =
        Array.Empty<ProcessRiskSourceCoverage>();

    public IReadOnlyList<ProcessRiskContribution> Contributors { get; init; } =
        Array.Empty<ProcessRiskContribution>();
}

public sealed record ProcessRiskAggregationDecision
{
    public bool Accepted { get; init; }

    public ProcessRiskAggregationFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ProcessRiskScoreProjection? Projection { get; init; }
}

/// <summary>
/// Side-effect-free deterministic aggregation over validated #321 contracts. The
/// policy neither persists results nor executes analyzers or external providers.
/// </summary>
public static class ProcessRiskAggregationPolicyEngine
{
    private const int MaximumIdentityLength = 512;
    private const int MaximumVersionLength = 256;
    private const int MaximumPolicySources = 32;
    private const int AbsoluteInputLimit = 512;

    public static ProcessRiskAggregationDecision Aggregate(ProcessRiskAggregationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.SchemaVersion != ProcessRiskAggregationRequest.CurrentSchemaVersion)
        {
            return Reject(ProcessRiskAggregationFailure.InvalidSchemaVersion,
                "The process-risk aggregation request schema version is unsupported.");
        }

        var policyFailure = ValidatePolicy(request.Policy);
        if (policyFailure != ProcessRiskAggregationFailure.None)
        {
            return Reject(policyFailure, "The process-risk aggregation policy is incomplete or malformed.");
        }

        if (!IsValidScope(request.EvidenceIdentity) || !IsRequiredIdentity(request.ProcessEntityId) ||
            !IsBoundedOptional(request.ProcessKey, MaximumIdentityLength))
        {
            return Reject(ProcessRiskAggregationFailure.InvalidScope,
                "The process-risk aggregation request scope or process identity is incomplete.");
        }

        if (request.ProjectedUtc.Kind != DateTimeKind.Utc)
        {
            return Reject(ProcessRiskAggregationFailure.InvalidTimestamp,
                "The process-risk projection timestamp must be UTC.");
        }

        var findings = request.Findings ?? Array.Empty<AnalysisFinding>();
        var signals = request.Signals ?? Array.Empty<ProcessRiskSignal>();
        if (findings.Count > request.Policy.MaximumFindings ||
            signals.Count > request.Policy.MaximumSignals)
        {
            return Reject(ProcessRiskAggregationFailure.InputLimitExceeded,
                "The process-risk aggregation input exceeds the policy bounds.");
        }

        var sourcePolicies = request.Policy.Sources.ToDictionary(source => source.SourceId, StringComparer.Ordinal);
        var acceptedFindings = new Dictionary<string, AnalysisFinding>(StringComparer.Ordinal);
        var sourceFindings = request.Policy.Sources.ToDictionary(
            source => source.SourceId,
            _ => new List<AnalysisFinding>(),
            StringComparer.Ordinal);

        foreach (var finding in findings)
        {
            if (finding == null)
            {
                return Reject(ProcessRiskAggregationFailure.InvalidFinding,
                    "A process-risk aggregation finding is null or invalid.");
            }

            var decision = AnalysisContractPolicy.ValidateFinding(finding);
            if (!decision.Accepted || decision.Finding == null)
            {
                return Reject(ProcessRiskAggregationFailure.InvalidFinding,
                    "A process-risk aggregation finding failed the portable contract policy.");
            }

            var accepted = decision.Finding;
            if (!acceptedFindings.TryAdd(accepted.FindingId, accepted))
            {
                return Reject(ProcessRiskAggregationFailure.DuplicateFinding,
                    "Process-risk finding identities must be unique.");
            }

            if (!SameScope(accepted.EvidenceIdentity, request.EvidenceIdentity) ||
                !string.Equals(accepted.ProcessEntityId, request.ProcessEntityId, StringComparison.Ordinal) ||
                !string.Equals(accepted.ProcessKey, request.ProcessKey, StringComparison.Ordinal))
            {
                return Reject(ProcessRiskAggregationFailure.ProcessScopeMismatch,
                    "Every process-risk finding must target the aggregation request's exact process scope.");
            }

            if (!string.Equals(accepted.Rule.PolicyId, request.Policy.PolicyId, StringComparison.Ordinal) ||
                !string.Equals(accepted.Rule.PolicyVersion, request.Policy.PolicyVersion, StringComparison.Ordinal))
            {
                return Reject(ProcessRiskAggregationFailure.PolicyMismatch,
                    "Every process-risk finding must use the exact aggregation policy identity and version.");
            }

            if (!sourcePolicies.ContainsKey(accepted.InputSnapshot.SourceKind))
            {
                return Reject(ProcessRiskAggregationFailure.UnknownSource,
                    "A process-risk finding uses a source outside the aggregation policy.");
            }

            if (accepted.EvaluatedUtc > request.ProjectedUtc ||
                accepted.InputSnapshot.CreatedUtc > request.ProjectedUtc)
            {
                return Reject(ProcessRiskAggregationFailure.InvalidTimestamp,
                    "A process-risk finding or input snapshot is newer than the projection timestamp.");
            }

            sourceFindings[accepted.InputSnapshot.SourceKind].Add(accepted);
        }

        foreach (var pair in sourceFindings)
        {
            if (pair.Value.Count <= 1)
            {
                continue;
            }

            var availability = pair.Value[0].Availability;
            if (pair.Value.Any(finding => finding.Availability != availability) ||
                availability != AnalysisSourceAvailability.Available)
            {
                return Reject(ProcessRiskAggregationFailure.ContradictorySourceState,
                    "One source cannot mix availability states or repeat an unavailable diagnostic.");
            }
        }

        var acceptedSignals = new Dictionary<string, ProcessRiskSignal>(StringComparer.Ordinal);
        var signalByFinding = new Dictionary<string, ProcessRiskSignal>(StringComparer.Ordinal);
        var severityBounds = request.Policy.SeverityDeltaBounds.ToDictionary(item => item.Severity);
        foreach (var signal in signals)
        {
            if (signal == null)
            {
                return Reject(ProcessRiskAggregationFailure.InvalidSignal,
                    "A process-risk aggregation signal is null or invalid.");
            }

            if (!acceptedFindings.TryGetValue(signal.FindingId, out var finding))
            {
                return Reject(ProcessRiskAggregationFailure.InvalidSignal,
                    "Every process-risk signal must reference a supplied finding.");
            }

            var decision = AnalysisContractPolicy.ValidateSignal(finding, signal);
            if (!decision.Accepted || decision.Signal == null)
            {
                return Reject(ProcessRiskAggregationFailure.InvalidSignal,
                    "A process-risk aggregation signal failed the portable contract policy.");
            }

            var accepted = decision.Signal;
            if (!acceptedSignals.TryAdd(accepted.SignalId, accepted))
            {
                return Reject(ProcessRiskAggregationFailure.DuplicateSignal,
                    "Process-risk signal identities must be unique.");
            }

            if (!signalByFinding.TryAdd(accepted.FindingId, accepted))
            {
                return Reject(ProcessRiskAggregationFailure.DuplicateFindingSignal,
                    "At most one process-risk signal may contribute for one finding.");
            }

            if (accepted.EvaluatedUtc > request.ProjectedUtc)
            {
                return Reject(ProcessRiskAggregationFailure.InvalidTimestamp,
                    "A process-risk signal is newer than the projection timestamp.");
            }

            var maximumDelta = severityBounds[accepted.Severity].MaximumAbsoluteDelta;
            if (Math.Abs(accepted.ScoreDelta) > maximumDelta)
            {
                return Reject(ProcessRiskAggregationFailure.SeverityDeltaExceeded,
                    "A process-risk signal exceeds the policy delta bound for its severity.");
            }
        }

        var totalWeight = request.Policy.Sources.Sum(source => source.ConfidenceWeight);
        var availableWeight = 0;
        var weightedConfidence = 0d;
        var sourceCoverage = new List<ProcessRiskSourceCoverage>(request.Policy.Sources.Count);
        foreach (var source in request.Policy.Sources.OrderBy(source => source.SourceKind))
        {
            var matches = sourceFindings[source.SourceId];
            if (matches.Count == 0)
            {
                sourceCoverage.Add(new ProcessRiskSourceCoverage
                {
                    SourceKind = source.SourceKind,
                    SourceId = source.SourceId,
                    Availability = AnalysisSourceAvailability.NotCollected,
                    ConfidenceWeight = source.ConfidenceWeight,
                    Diagnostic = "No analysis finding was supplied for this configured source."
                });
                continue;
            }

            var availability = matches[0].Availability;
            var confidence = availability == AnalysisSourceAvailability.Available
                ? Round(matches.Average(finding => finding.Confidence))
                : 0d;
            var signalCount = matches.Count(finding => signalByFinding.ContainsKey(finding.FindingId));
            var diagnostic = availability == AnalysisSourceAvailability.Available
                ? string.Empty
                : matches[0].Diagnostic;

            if (availability == AnalysisSourceAvailability.Available)
            {
                availableWeight += source.ConfidenceWeight;
                weightedConfidence += source.ConfidenceWeight * confidence;
            }

            sourceCoverage.Add(new ProcessRiskSourceCoverage
            {
                SourceKind = source.SourceKind,
                SourceId = source.SourceId,
                Availability = availability,
                ConfidenceWeight = source.ConfidenceWeight,
                Confidence = confidence,
                FindingCount = matches.Count,
                SignalCount = signalCount,
                Diagnostic = diagnostic
            });
        }

        var coverage = Round((double)availableWeight / totalWeight);
        var confidenceScore = Round(weightedConfidence / totalWeight);
        var state = availableWeight == 0
            ? ProcessRiskProjectionState.Unknown
            : availableWeight == totalWeight
                ? ProcessRiskProjectionState.Complete
                : ProcessRiskProjectionState.Partial;

        int? score = null;
        var band = ProcessRiskBand.Unknown;
        if (state != ProcessRiskProjectionState.Unknown)
        {
            var rawScore = acceptedSignals.Values.Sum(signal => (long)signal.ScoreDelta);
            score = (int)Math.Clamp(rawScore, 0L, 100L);
            band = request.Policy.BandThresholds
                .OrderByDescending(threshold => threshold.MinimumScore)
                .First(threshold => score.Value >= threshold.MinimumScore)
                .Band;
        }

        var contributions = acceptedSignals.Values
            .Select(accepted =>
            {
                var acceptedFinding = acceptedFindings[accepted.FindingId];
                var source = sourcePolicies[acceptedFinding.InputSnapshot.SourceKind];
                return new ProcessRiskContribution
                {
                    SourceKind = source.SourceKind,
                    SourceId = source.SourceId,
                    Finding = CopyFinding(acceptedFinding),
                    Signal = CopySignal(accepted)
                };
            })
            .OrderBy(contribution => contribution.SourceKind)
            .ThenBy(contribution => contribution.Finding.FindingId, StringComparer.Ordinal)
            .ThenBy(contribution => contribution.Signal.SignalId, StringComparer.Ordinal)
            .ToArray();

        return new ProcessRiskAggregationDecision
        {
            Accepted = true,
            Diagnostic = state switch
            {
                ProcessRiskProjectionState.Unknown =>
                    "No configured source is available; no numeric Process Risk Score was projected.",
                ProcessRiskProjectionState.Partial =>
                    "A partial Process Risk Score was projected with explicit source gaps.",
                _ => "A complete Process Risk Score was projected from every configured source."
            },
            Projection = new ProcessRiskScoreProjection
            {
                State = state,
                Score = score,
                Band = band,
                Confidence = confidenceScore,
                Coverage = coverage,
                EvidenceIdentity = request.EvidenceIdentity with { },
                ProcessEntityId = request.ProcessEntityId,
                ProcessKey = request.ProcessKey,
                PolicyId = request.Policy.PolicyId,
                PolicyVersion = request.Policy.PolicyVersion,
                ProjectedUtc = request.ProjectedUtc,
                Sources = new ReadOnlyCollection<ProcessRiskSourceCoverage>(sourceCoverage.ToArray()),
                Contributors = new ReadOnlyCollection<ProcessRiskContribution>(contributions)
            }
        };
    }

    private static ProcessRiskAggregationFailure ValidatePolicy(ProcessRiskAggregationPolicy? policy)
    {
        if (policy == null || policy.SchemaVersion != ProcessRiskAggregationPolicy.CurrentSchemaVersion)
        {
            return ProcessRiskAggregationFailure.InvalidSchemaVersion;
        }

        if (!IsRequiredIdentity(policy.PolicyId) || !IsRequiredVersion(policy.PolicyVersion) ||
            policy.MaximumFindings <= 0 || policy.MaximumFindings > AbsoluteInputLimit ||
            policy.MaximumSignals <= 0 || policy.MaximumSignals > AbsoluteInputLimit)
        {
            return ProcessRiskAggregationFailure.InvalidPolicy;
        }

        var sources = policy.Sources ?? Array.Empty<ProcessRiskSourcePolicy>();
        if (sources.Count == 0 || sources.Count > MaximumPolicySources ||
            sources.Any(source => source == null || !Enum.IsDefined(source.SourceKind) ||
                source.SourceKind == ProcessRiskSourceKind.Unknown || !IsRequiredIdentity(source.SourceId) ||
                !string.Equals(source.SourceId, CanonicalSourceId(source.SourceKind), StringComparison.Ordinal) ||
                source.ConfidenceWeight <= 0 || source.ConfidenceWeight > 100) ||
            sources.Select(source => source.SourceKind).Distinct().Count() != sources.Count ||
            sources.Select(source => source.SourceId).Distinct(StringComparer.Ordinal).Count() != sources.Count)
        {
            return ProcessRiskAggregationFailure.InvalidPolicy;
        }

        var deltaBounds = policy.SeverityDeltaBounds ?? Array.Empty<ProcessRiskSeverityDeltaPolicy>();
        var expectedSeverities = Enum.GetValues<AnalysisFindingSeverity>()
            .Where(severity => severity != AnalysisFindingSeverity.Unknown)
            .ToArray();
        if (deltaBounds.Count != expectedSeverities.Length ||
            deltaBounds.Any(item => item == null || !Enum.IsDefined(item.Severity) ||
                item.Severity == AnalysisFindingSeverity.Unknown ||
                item.MaximumAbsoluteDelta <= 0 || item.MaximumAbsoluteDelta > 100) ||
            deltaBounds.Select(item => item.Severity).Distinct().Count() != deltaBounds.Count ||
            expectedSeverities.Any(severity => deltaBounds.All(item => item.Severity != severity)))
        {
            return ProcessRiskAggregationFailure.InvalidPolicy;
        }

        var orderedDeltaBounds = deltaBounds.OrderBy(item => item.Severity).ToArray();
        if (orderedDeltaBounds.Zip(orderedDeltaBounds.Skip(1),
                (left, right) => left.MaximumAbsoluteDelta < right.MaximumAbsoluteDelta).Any(increasing => !increasing))
        {
            return ProcessRiskAggregationFailure.InvalidPolicy;
        }

        var thresholds = policy.BandThresholds ?? Array.Empty<ProcessRiskBandThreshold>();
        var expectedBands = Enum.GetValues<ProcessRiskBand>()
            .Where(band => band != ProcessRiskBand.Unknown)
            .ToArray();
        if (thresholds.Count != expectedBands.Length ||
            thresholds.Any(item => item == null || !Enum.IsDefined(item.Band) ||
                item.Band == ProcessRiskBand.Unknown || item.MinimumScore < 0 || item.MinimumScore > 100) ||
            thresholds.Select(item => item.Band).Distinct().Count() != thresholds.Count ||
            expectedBands.Any(band => thresholds.All(item => item.Band != band)))
        {
            return ProcessRiskAggregationFailure.InvalidPolicy;
        }

        var orderedThresholds = thresholds.OrderBy(item => item.MinimumScore).ToArray();
        if (orderedThresholds[0].Band != ProcessRiskBand.Minimal || orderedThresholds[0].MinimumScore != 0 ||
            !orderedThresholds.Select(item => item.Band).SequenceEqual(expectedBands) ||
            orderedThresholds.Zip(orderedThresholds.Skip(1),
                (left, right) => left.MinimumScore < right.MinimumScore).Any(increasing => !increasing))
        {
            return ProcessRiskAggregationFailure.InvalidPolicy;
        }

        return ProcessRiskAggregationFailure.None;
    }

    private static string? CanonicalSourceId(ProcessRiskSourceKind sourceKind) => sourceKind switch
    {
        ProcessRiskSourceKind.ProcessMetadata => "process-metadata",
        ProcessRiskSourceKind.PeProperties => "pe-properties",
        ProcessRiskSourceKind.Authenticode => "authenticode",
        ProcessRiskSourceKind.NetworkAndDns => "network-dns",
        ProcessRiskSourceKind.Events => "events",
        ProcessRiskSourceKind.Filesystem => "filesystem",
        ProcessRiskSourceKind.MemoryAndVolatility => "memory-volatility",
        ProcessRiskSourceKind.Sigma => "sigma",
        ProcessRiskSourceKind.BaselineComparison => "baseline-comparison",
        ProcessRiskSourceKind.Yara => "yara",
        _ => null
    };

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

    private static bool IsRequiredIdentity(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= MaximumIdentityLength;

    private static bool IsRequiredVersion(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= MaximumVersionLength;

    private static bool IsBoundedOptional(string? value, int maximumLength) =>
        value != null && value.Length <= maximumLength;

    private static double Round(double value) =>
        Math.Round(value, 4, MidpointRounding.AwayFromZero);

    private static AnalysisFinding CopyFinding(AnalysisFinding finding) =>
        AnalysisContractPolicy.ValidateFinding(finding).Finding!;

    private static ProcessRiskSignal CopySignal(ProcessRiskSignal signal)
    {
        var references = new ReadOnlyCollection<EvidenceReference>(signal.EvidenceReferences
            .OrderBy(reference => reference.Kind)
            .ThenBy(reference => reference.Id, StringComparer.Ordinal)
            .ToArray());
        return signal with
        {
            EvidenceIdentity = signal.EvidenceIdentity with { },
            EvidenceReferences = references
        };
    }

    private static ProcessRiskAggregationDecision Reject(
        ProcessRiskAggregationFailure failure,
        string diagnostic) =>
        new() { Failure = failure, Diagnostic = diagnostic };
}
