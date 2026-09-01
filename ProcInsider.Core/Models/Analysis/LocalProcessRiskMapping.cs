using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ProcInsider.Models.Analysis;

public enum LocalProcessRiskMappingFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    InvalidPolicy = 2,
    InvalidTimestamp = 3,
    InvalidProcessObservation = 4,
    InvalidPeAnalysis = 5,
    InvalidAuthenticodeVerification = 6,
    ProcessScopeMismatch = 7,
    SourceRunMismatch = 8,
    ContradictoryEvidence = 9,
    InvalidMappedFinding = 10,
    InvalidMappedSignal = 11,
    InvalidSourceAvailability = 12,
    EventInputLimitExceeded = 13,
    InvalidProcessEvent = 14,
    DuplicateProcessEvent = 15,
    NetworkInputLimitExceeded = 16,
    InvalidNetworkEvent = 17,
    DuplicateNetworkEvent = 18,
    FilesystemInputLimitExceeded = 19,
    InvalidFilesystemEvidence = 20,
    DuplicateFilesystemEvidence = 21,
    MemoryInputLimitExceeded = 22,
    InvalidMemoryEvidence = 23,
    DuplicateMemoryEvidence = 24,
    SigmaInputLimitExceeded = 25,
    InvalidSigmaEvidence = 26,
    DuplicateSigmaEvidence = 27,
    BaselineInputLimitExceeded = 28,
    InvalidBaselineComparisonEvidence = 29,
    DuplicateBaselineComparisonEvidence = 30,
    YaraRequiresVersion2 = 31,
    YaraInputLimitExceeded = 32,
    InvalidYaraAttribution = 33,
    DuplicateYaraEvidence = 34
}

/// <summary>
/// Portable artifact families emitted by a normalized baseline comparison.
/// Viewer display models and free-form artifact values deliberately stay out.
/// </summary>
public enum LocalProcessBaselineArtifactKind
{
    Unknown = 0,
    Process = 1,
    Module = 2,
    PeAnalysis = 3,
    Event = 4,
    Network = 5,
    Filesystem = 6,
    Memory = 7
}

/// <summary>
/// Portable baseline verdicts. Missing is represented so a producer cannot
/// silently reinterpret it; process-risk mapping rejects it because there is
/// no current durable process entity to target.
/// </summary>
public enum LocalProcessBaselineVerdict
{
    Unknown = 0,
    New = 1,
    Missing = 2,
    Changed = 3,
    Known = 4,
    Noisy = 5,
    Accepted = 6
}

/// <summary>
/// One immutable filesystem artifact and the exact active relation that binds
/// it to the mapping request's durable process entity.
/// </summary>
public sealed record LocalProcessFilesystemEvidence
{
    public FilesystemArtifactRecord Artifact { get; init; } = new();

    public EvidenceRelation Relation { get; init; } = new();
}

/// <summary>
/// One immutable Volatility process row and the exact active relation that
/// binds it to the mapping request's durable process entity.
/// </summary>
public sealed record LocalProcessMemoryEvidence
{
    public MemoryProcessRecord MemoryProcess { get; init; } = new();

    public EvidenceRelation Relation { get; init; } = new();
}

/// <summary>
/// One normalized Sigma match whose durable process attribution and immutable
/// evidence references were established before entering the portable mapper.
/// Free-form rule and match text deliberately stays outside this contract.
/// </summary>
public sealed record LocalProcessSigmaEvidence
{
    public string MatchId { get; init; } = string.Empty;

    public string RuleId { get; init; } = string.Empty;

    public string RuleVersion { get; init; } = string.Empty;

    public AnalysisFindingSeverity Level { get; init; }

    public string MatchContentHashSha256 { get; init; } = string.Empty;

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public string SourceRunId { get; init; } = string.Empty;

    public DateTime MatchedUtc { get; init; }

    public EvidenceCorrelationState CorrelationState { get; init; }

    public string CorrelationMethod { get; init; } = string.Empty;

    public int CorrelationCandidateCount { get; init; }

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();
}

/// <summary>
/// One normalized, hash-bound baseline-comparison finding whose exact current
/// process attribution was established before entering the portable mapper.
/// Snapshot paths, stable keys, titles, explanations, trust notes, and other
/// free-form comparison content deliberately stay outside this contract.
/// </summary>
public sealed record LocalProcessBaselineComparisonEvidence
{
    public string FindingId { get; init; } = string.Empty;

    public string ComparisonId { get; init; } = string.Empty;

    public string ComparisonVersion { get; init; } = string.Empty;

    public string BaselineId { get; init; } = string.Empty;

    public string BaselineSnapshotHashSha256 { get; init; } = string.Empty;

    public string CurrentSnapshotHashSha256 { get; init; } = string.Empty;

    public LocalProcessBaselineArtifactKind ArtifactKind { get; init; }

    public LocalProcessBaselineVerdict Verdict { get; init; }

    public string StableKeyHashSha256 { get; init; } = string.Empty;

    public string BaselineFingerprintSha256 { get; init; } = string.Empty;

    public string CurrentFingerprintSha256 { get; init; } = string.Empty;

    public string PolicyRuleId { get; init; } = string.Empty;

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public DateTime ComparedUtc { get; init; }

    public EvidenceCorrelationState CorrelationState { get; init; }

    public string CorrelationMethod { get; init; } = string.Empty;

    public int CorrelationCandidateCount { get; init; }

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();
}

/// <summary>
/// Bounded local evidence offered to the first Process Risk Score mapper. The
/// mapper reads these records only; it never mutates or persists evidence.
/// </summary>
public sealed record LocalProcessRiskMappingRequest
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ProcessObservation ProcessObservation { get; init; } = new();

    public PeAnalysisRecord? PeAnalysis { get; init; }

    /// <summary>
    /// Optional snapshot-reader states. Null or Available lets the mapper derive
    /// availability from the exact record; explicit gaps suppress conclusions.
    /// </summary>
    public AnalysisSourceAvailability? ProcessMetadataAvailability { get; init; }

    public AnalysisSourceAvailability? PePropertiesAvailability { get; init; }

    public AnalysisSourceAvailability? AuthenticodeAvailability { get; init; }

    public IReadOnlyList<TelemetryEventRecord> NetworkEventRecords { get; init; } =
        Array.Empty<TelemetryEventRecord>();

    public AnalysisSourceAvailability? NetworkAndDnsAvailability { get; init; }

    public IReadOnlyList<TelemetryEventRecord> EventRecords { get; init; } =
        Array.Empty<TelemetryEventRecord>();

    public AnalysisSourceAvailability? EventsAvailability { get; init; }

    public IReadOnlyList<LocalProcessFilesystemEvidence> FilesystemEvidence { get; init; } =
        Array.Empty<LocalProcessFilesystemEvidence>();

    public AnalysisSourceAvailability? FilesystemAvailability { get; init; }

    public IReadOnlyList<LocalProcessMemoryEvidence> MemoryEvidence { get; init; } =
        Array.Empty<LocalProcessMemoryEvidence>();

    public AnalysisSourceAvailability? MemoryAndVolatilityAvailability { get; init; }

    public IReadOnlyList<LocalProcessSigmaEvidence> SigmaEvidence { get; init; } =
        Array.Empty<LocalProcessSigmaEvidence>();

    public AnalysisSourceAvailability? SigmaAvailability { get; init; }

    public IReadOnlyList<LocalProcessBaselineComparisonEvidence> BaselineComparisonEvidence { get; init; } =
        Array.Empty<LocalProcessBaselineComparisonEvidence>();

    public AnalysisSourceAvailability? BaselineComparisonAvailability { get; init; }

    public YaraProcessAttributionResult? YaraAttribution { get; init; }

    public DateTime EvaluatedUtc { get; init; }

    public ProcessRiskAggregationPolicy Policy { get; init; } =
        ProcessRiskAggregationPolicy.LocalFirstVersion1;
}

public sealed record LocalProcessRiskMappingResult
{
    public IReadOnlyList<AnalysisFinding> Findings { get; init; } =
        Array.Empty<AnalysisFinding>();

    public IReadOnlyList<ProcessRiskSignal> Signals { get; init; } =
        Array.Empty<ProcessRiskSignal>();
}

public sealed record LocalProcessRiskMappingDecision
{
    public bool Accepted { get; init; }

    public LocalProcessRiskMappingFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public LocalProcessRiskMappingResult? Result { get; init; }
}

/// <summary>
/// Pure version-10 mapping from exact process-observation, process-image PE,
/// Authenticode, bounded normalized network/DNS events, and bounded exact
/// process-event records plus exact process-to-file and memory-to-process
/// relations plus normalized exact Sigma, baseline-comparison, and review-gated
/// YARA attribution into the portable #321
/// finding/signal contracts. The
/// mapper is intentionally not a query owner, analyzer scheduler, or evidence
/// writer; later infrastructure supplies immutable snapshot records to it.
/// </summary>
public static class LocalProcessRiskMapper
{
    public const string MapperId = "dfiroscope.local-process-risk-mapper";
    public const string MapperVersion = "10";
    public const int MaximumEventRecords = 64;
    public const int MaximumNetworkEventRecords = 64;
    public const int MaximumFilesystemEvidence = 64;
    public const int MaximumMemoryEvidence = 64;
    public const int MaximumSigmaEvidence = 64;
    public const int MaximumSigmaEvidenceReferences = 16;
    public const int MaximumBaselineComparisonEvidence = 64;
    public const int MaximumBaselineEvidenceReferences = 16;
    public const int MaximumYaraEvidence = 64;
    public const int MaximumYaraEvidenceReferences = 64;

    private const string ToolVersion = "1";
    private const int MaximumIdentityLength = 512;
    private const int MaximumCorrelationMethodLength = 256;
    private const int MaximumPathLength = 32768;
    private const int MaximumFieldStates = 256;
    private const int MaximumEventSummaryLength = 4096;
    private const int MaximumEventDiagnosticLength = 8192;
    private const int MaximumEventDetailsLength = 65536;

    private const string ProcessSourceId = "process-metadata";
    private const string PeSourceId = "pe-properties";
    private const string AuthenticodeSourceId = "authenticode";
    private const string NetworkSourceId = "network-dns";
    private const string EventsSourceId = "events";
    private const string FilesystemSourceId = "filesystem";
    private const string MemorySourceId = "memory-volatility";
    private const string SigmaSourceId = "sigma";
    private const string BaselineSourceId = "baseline-comparison";
    private const string YaraSourceId = "yara";

    private static readonly HashSet<EvidenceReferenceKind> YaraReferenceKinds =
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

    public static LocalProcessRiskMappingDecision Map(LocalProcessRiskMappingRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.SchemaVersion != LocalProcessRiskMappingRequest.CurrentSchemaVersion)
        {
            return Reject(LocalProcessRiskMappingFailure.InvalidSchemaVersion,
                "The local process-risk mapping request schema version is unsupported.");
        }

        if (!IsSupportedPolicy(request.Policy))
        {
            return Reject(LocalProcessRiskMappingFailure.InvalidPolicy,
                "The local mapper requires an exact supported local aggregation policy.");
        }

        var usesYaraPolicy = IsExactPolicy(
            request.Policy,
            ProcessRiskAggregationPolicy.LocalFirstVersion2);
        if (!usesYaraPolicy && request.YaraAttribution != null)
        {
            return Reject(
                LocalProcessRiskMappingFailure.YaraRequiresVersion2,
                "Review-gated YARA mapping requires the exact version-2 local aggregation policy.");
        }

        if (request.EvaluatedUtc.Kind != DateTimeKind.Utc)
        {
            return Reject(LocalProcessRiskMappingFailure.InvalidTimestamp,
                "The local process-risk evaluation timestamp must be UTC.");
        }

        var availabilityFailure = ValidateRequestedAvailability(request);
        if (availabilityFailure != LocalProcessRiskMappingFailure.None)
        {
            return Reject(availabilityFailure, availabilityFailure ==
                LocalProcessRiskMappingFailure.InvalidSourceAvailability
                    ? "A requested source availability is unknown or unsupported."
                    : "A requested source gap has no corresponding exact record or contradicts the bounded input.");
        }

        var observationFailure = ValidateObservation(request.ProcessObservation, request.EvaluatedUtc);
        if (observationFailure != LocalProcessRiskMappingFailure.None)
        {
            return Reject(observationFailure, ObservationDiagnostic(observationFailure));
        }

        var observation = request.ProcessObservation;
        var process = observation.Fields;
        var scope = ScopeOf(process);
        var peFailure = ValidatePe(request.PeAnalysis, observation, request.EvaluatedUtc);
        if (peFailure != LocalProcessRiskMappingFailure.None)
        {
            return Reject(peFailure, PeDiagnostic(peFailure));
        }

        var authenticodeFailure = ValidateAuthenticode(
            request.PeAnalysis?.AuthenticodeVerification,
            request.PeAnalysis,
            observation,
            request.EvaluatedUtc);
        if (authenticodeFailure != LocalProcessRiskMappingFailure.None)
        {
            return Reject(authenticodeFailure, AuthenticodeDiagnostic(authenticodeFailure));
        }

        var networkFailure = ValidateNetworkEvents(
            request.NetworkEventRecords,
            observation,
            request.EvaluatedUtc);
        if (networkFailure != LocalProcessRiskMappingFailure.None)
        {
            return Reject(networkFailure, NetworkEventDiagnostic(networkFailure));
        }

        var eventFailure = ValidateEvents(
            request.EventRecords,
            observation,
            request.EvaluatedUtc);
        if (eventFailure != LocalProcessRiskMappingFailure.None)
        {
            return Reject(eventFailure, EventDiagnostic(eventFailure));
        }

        var filesystemFailure = ValidateFilesystemEvidence(
            request.FilesystemEvidence,
            observation,
            request.EvaluatedUtc);
        if (filesystemFailure != LocalProcessRiskMappingFailure.None)
        {
            return Reject(filesystemFailure, FilesystemDiagnostic(filesystemFailure));
        }

        var memoryFailure = ValidateMemoryEvidence(
            request.MemoryEvidence,
            observation,
            request.EvaluatedUtc);
        if (memoryFailure != LocalProcessRiskMappingFailure.None)
        {
            return Reject(memoryFailure, MemoryDiagnostic(memoryFailure));
        }

        var sigmaFailure = ValidateSigmaEvidence(
            request.SigmaEvidence,
            observation,
            request.EvaluatedUtc);
        if (sigmaFailure != LocalProcessRiskMappingFailure.None)
        {
            return Reject(sigmaFailure, SigmaDiagnostic(sigmaFailure));
        }

        var baselineFailure = ValidateBaselineComparisonEvidence(
            request.BaselineComparisonEvidence,
            observation,
            request.EvaluatedUtc);
        if (baselineFailure != LocalProcessRiskMappingFailure.None)
        {
            return Reject(baselineFailure, BaselineDiagnostic(baselineFailure));
        }

        if (usesYaraPolicy)
        {
            var yaraFailure = ValidateYaraAttribution(
                request.YaraAttribution,
                observation,
                request.Policy,
                request.EvaluatedUtc);
            if (yaraFailure != LocalProcessRiskMappingFailure.None)
            {
                return Reject(yaraFailure, YaraDiagnostic(yaraFailure));
            }
        }

        var mappedSources = new List<LocalMappedSource>(
            4 + request.NetworkEventRecords.Count + request.EventRecords.Count +
            request.FilesystemEvidence.Count + request.MemoryEvidence.Count +
            request.SigmaEvidence.Count + request.BaselineComparisonEvidence.Count +
            (request.YaraAttribution?.Evidence.Count ?? 0))
        {
            MapProcessMetadata(
                observation,
                request.ProcessMetadataAvailability),
            MapPeProperties(
                observation,
                request.PeAnalysis,
                request.PePropertiesAvailability,
                request.EvaluatedUtc),
            MapAuthenticode(
                request.PeAnalysis,
                request.AuthenticodeAvailability,
                request.EvaluatedUtc)
        };
        mappedSources.AddRange(MapNetworkAndDns(
            observation,
            request.NetworkEventRecords,
            request.NetworkAndDnsAvailability,
            request.EvaluatedUtc));
        mappedSources.AddRange(MapEvents(
            observation,
            request.EventRecords,
            request.EventsAvailability,
            request.EvaluatedUtc));
        mappedSources.AddRange(MapFilesystem(
            observation,
            request.FilesystemEvidence,
            request.FilesystemAvailability,
            request.EvaluatedUtc));
        mappedSources.AddRange(MapMemoryAndVolatility(
            observation,
            request.MemoryEvidence,
            request.MemoryAndVolatilityAvailability,
            request.EvaluatedUtc));
        mappedSources.AddRange(MapSigma(
            observation,
            request.SigmaEvidence,
            request.SigmaAvailability,
            request.EvaluatedUtc));
        mappedSources.AddRange(MapBaselineComparison(
            observation,
            request.BaselineComparisonEvidence,
            request.BaselineComparisonAvailability,
            request.EvaluatedUtc));
        if (usesYaraPolicy)
        {
            mappedSources.AddRange(MapYara(
                observation,
                request.YaraAttribution,
                request.EvaluatedUtc));
        }

        var findings = new List<AnalysisFinding>(mappedSources.Count);
        var signals = new List<ProcessRiskSignal>(mappedSources.Count);
        foreach (var source in mappedSources)
        {
            var finding = CreateFinding(
                scope,
                process.ProcessEntityId,
                process.ProcessKey,
                request.Policy,
                request.EvaluatedUtc,
                source);
            var findingDecision = AnalysisContractPolicy.ValidateFinding(finding);
            if (!findingDecision.Accepted || findingDecision.Finding == null)
            {
                return Reject(LocalProcessRiskMappingFailure.InvalidMappedFinding,
                    $"The mapped {source.SourceId} finding failed the portable contract policy.");
            }

            var acceptedFinding = findingDecision.Finding;
            findings.Add(acceptedFinding);
            if (source.ScoreDelta is not int scoreDelta)
            {
                continue;
            }

            var signal = CreateSignal(acceptedFinding, scoreDelta);
            var signalDecision = AnalysisContractPolicy.ValidateSignal(acceptedFinding, signal);
            if (!signalDecision.Accepted || signalDecision.Signal == null)
            {
                return Reject(LocalProcessRiskMappingFailure.InvalidMappedSignal,
                    $"The mapped {source.SourceId} signal failed the portable contract policy.");
            }

            signals.Add(signalDecision.Signal);
        }

        return new LocalProcessRiskMappingDecision
        {
            Accepted = true,
            Diagnostic = usesYaraPolicy
                ? "The exact local process, PE, Authenticode, bounded network/DNS, event, process-linked filesystem, process-linked memory, normalized Sigma/baseline, and review-gated YARA attribution were mapped without persistence or evidence mutation."
                : "The exact local process, PE, Authenticode, bounded network/DNS, event, process-linked filesystem, process-linked memory, normalized Sigma, and normalized baseline-comparison evidence was mapped without persistence or evidence mutation.",
            Result = new LocalProcessRiskMappingResult
            {
                Findings = new ReadOnlyCollection<AnalysisFinding>(findings.ToArray()),
                Signals = new ReadOnlyCollection<ProcessRiskSignal>(signals.ToArray())
            }
        };
    }

    private static LocalMappedSource MapProcessMetadata(
        ProcessObservation observation,
        AnalysisSourceAvailability? requestedAvailability)
    {
        var process = observation.Fields;
        if (requestedAvailability is { } explicitAvailability &&
            explicitAvailability != AnalysisSourceAvailability.Available)
        {
            return UnavailableSource(
                ProcessRiskSourceKind.ProcessMetadata,
                ProcessSourceId,
                "process-name-path-filename-consistency",
                explicitAvailability,
                $"The snapshot reader classified process metadata as {explicitAvailability}; the mismatch rule did not run.",
                observation.SourceRunId,
                observation.ObservedUtc,
                Canonical(
                    ("observation-id", observation.ObservationId),
                    ("requested-availability", explicitAvailability.ToString())));
        }

        var fieldAvailability = ProcessMetadataFieldAvailability(observation);
        if (fieldAvailability != AnalysisSourceAvailability.Available)
        {
            return UnavailableSource(
                ProcessRiskSourceKind.ProcessMetadata,
                ProcessSourceId,
                "process-name-path-filename-consistency",
                fieldAvailability,
                fieldAvailability == AnalysisSourceAvailability.Unavailable
                    ? "Executable name/path fields are unavailable or access denied; the mismatch rule did not run."
                    : "Executable name/path fields were marked not collected; the mismatch rule did not run.",
                observation.SourceRunId,
                observation.ObservedUtc,
                Canonical(
                    ("observation-id", observation.ObservationId),
                    ("field-availability", fieldAvailability.ToString())));
        }

        var name = Concrete(process.ProcessName);
        var path = Concrete(process.ProcessPath);
        var fileName = path == null ? null : FileName(path);
        if (name == null || fileName == null)
        {
            var availability = AnalysisSourceAvailability.NotCollected;
            return UnavailableSource(
                ProcessRiskSourceKind.ProcessMetadata,
                ProcessSourceId,
                "process-name-path-filename-consistency",
                availability,
                availability == AnalysisSourceAvailability.Unavailable
                    ? "Executable name/path metadata is unavailable or access denied; the mismatch rule did not run."
                    : "Executable name/path metadata was not collected; the mismatch rule did not run.",
                observation.SourceRunId,
                observation.ObservedUtc,
                Canonical(
                    ("observation-id", observation.ObservationId),
                    ("availability", availability.ToString())));
        }

        var mismatch = !string.Equals(name, fileName, StringComparison.OrdinalIgnoreCase);
        var references = new[]
        {
            new EvidenceReference(EvidenceReferenceKind.ProcessEntity, process.ProcessEntityId),
            new EvidenceReference(EvidenceReferenceKind.ProcessObservation, observation.ObservationId)
        };
        return new LocalMappedSource(
            ProcessRiskSourceKind.ProcessMetadata,
            ProcessSourceId,
            "process-name-path-filename-consistency",
            AnalysisSourceAvailability.Available,
            mismatch ? AnalysisFindingSeverity.Medium : AnalysisFindingSeverity.Informational,
            mismatch ? 0.95 : 0.9,
            mismatch
                ? "The observed executable name differs from the observed path filename."
                : "The executable name and path filename were evaluated by the local metadata rule.",
            mismatch
                ? "The mismatch is a potential masquerading lead and is not a malware verdict."
                : "This rule found no name/path mismatch; it does not establish benignness.",
            mismatch ? 30 : null,
            observation.SourceRunId,
            observation.ObservedUtc,
            references,
            Canonical(
                ("observation-id", observation.ObservationId),
                ("source-run-id", observation.SourceRunId),
                ("observed-utc", Utc(observation.ObservedUtc)),
                ("process-name", name.ToUpperInvariant()),
                ("path-file-name", fileName.ToUpperInvariant())));
    }

    private static LocalMappedSource MapPeProperties(
        ProcessObservation observation,
        PeAnalysisRecord? pe,
        AnalysisSourceAvailability? requestedAvailability,
        DateTime evaluatedUtc)
    {
        if (requestedAvailability is { } explicitAvailability &&
            explicitAvailability != AnalysisSourceAvailability.Available)
        {
            return UnavailableSource(
                ProcessRiskSourceKind.PeProperties,
                PeSourceId,
                "process-image-sha256-consistency",
                explicitAvailability,
                $"The snapshot reader classified PE properties as {explicitAvailability}; the hash-consistency rule did not run.",
                pe?.SourceRunId ?? string.Empty,
                pe?.AnalyzedUtc ?? evaluatedUtc,
                Canonical(
                    ("analysis-id", pe?.AnalysisId ?? "not-collected"),
                    ("requested-availability", explicitAvailability.ToString())));
        }

        if (pe == null)
        {
            return UnavailableSource(
                ProcessRiskSourceKind.PeProperties,
                PeSourceId,
                "process-image-sha256-consistency",
                AnalysisSourceAvailability.NotCollected,
                "No linked process-image PE analysis was supplied; the hash-consistency rule did not run.",
                string.Empty,
                evaluatedUtc,
                Canonical(("pe-analysis", "not-collected")));
        }

        if (pe.Status == PeAnalysisStatus.Failed)
        {
            return UnavailableSource(
                ProcessRiskSourceKind.PeProperties,
                PeSourceId,
                "process-image-sha256-consistency",
                AnalysisSourceAvailability.Failed,
                "The linked process-image PE analysis failed; no hash conclusion or signal was produced.",
                pe.SourceRunId,
                pe.AnalyzedUtc,
                Canonical(
                    ("analysis-id", pe.AnalysisId),
                    ("source-run-id", pe.SourceRunId),
                    ("status", pe.Status.ToString())));
        }

        var observedHash = FieldState(observation, nameof(ProcessRecord.Sha256Hash)) is
            ProcessObservationValueState.NotCollected or
            ProcessObservationValueState.Unavailable or
            ProcessObservationValueState.AccessDenied
                ? null
                : Concrete(observation.Fields.Sha256Hash);
        var peHash = Concrete(pe.Sha256Hash);
        if (observedHash == null || peHash == null)
        {
            return UnavailableSource(
                ProcessRiskSourceKind.PeProperties,
                PeSourceId,
                "process-image-sha256-consistency",
                AnalysisSourceAvailability.NotCollected,
                "Both exact SHA-256 values were not collected; the hash-consistency rule did not run.",
                pe.SourceRunId,
                pe.AnalyzedUtc,
                Canonical(
                    ("analysis-id", pe.AnalysisId),
                    ("observation-hash", observedHash ?? "not-collected"),
                    ("pe-hash", peHash ?? "not-collected")));
        }

        var mismatch = !string.Equals(observedHash, peHash, StringComparison.OrdinalIgnoreCase);
        var references = new[]
        {
            new EvidenceReference(EvidenceReferenceKind.ProcessEntity, observation.ProcessEntityId),
            new EvidenceReference(EvidenceReferenceKind.ProcessObservation, observation.ObservationId),
            new EvidenceReference(EvidenceReferenceKind.PeAnalysis, pe.AnalysisId)
        };
        return new LocalMappedSource(
            ProcessRiskSourceKind.PeProperties,
            PeSourceId,
            "process-image-sha256-consistency",
            AnalysisSourceAvailability.Available,
            mismatch ? AnalysisFindingSeverity.High : AnalysisFindingSeverity.Informational,
            mismatch ? 1 : 0.95,
            mismatch
                ? "The process observation and linked process-image PE analysis have different SHA-256 values."
                : "The process observation and linked process-image PE SHA-256 values were compared.",
            mismatch
                ? "The exact hash mismatch is an evidence-integrity lead and is not a malware verdict."
                : "This rule found no hash mismatch; it does not establish benignness.",
            mismatch ? 50 : null,
            pe.SourceRunId,
            pe.AnalyzedUtc,
            references,
            Canonical(
                ("observation-id", observation.ObservationId),
                ("analysis-id", pe.AnalysisId),
                ("source-run-id", pe.SourceRunId),
                ("analyzed-utc", Utc(pe.AnalyzedUtc)),
                ("observation-sha256", observedHash.ToLowerInvariant()),
                ("pe-sha256", peHash.ToLowerInvariant())));
    }

    private static LocalMappedSource MapAuthenticode(
        PeAnalysisRecord? pe,
        AnalysisSourceAvailability? requestedAvailability,
        DateTime evaluatedUtc)
    {
        var verification = pe?.AuthenticodeVerification;
        if (requestedAvailability is { } explicitAvailability &&
            explicitAvailability != AnalysisSourceAvailability.Available)
        {
            return UnavailableSource(
                ProcessRiskSourceKind.Authenticode,
                AuthenticodeSourceId,
                "authenticode-verification-status",
                explicitAvailability,
                $"The snapshot reader classified Authenticode evidence as {explicitAvailability}; no signature signal was produced.",
                verification?.SourceRunId ?? pe?.SourceRunId ?? string.Empty,
                verification?.VerificationTimeUtc ?? pe?.AnalyzedUtc ?? evaluatedUtc,
                Canonical(
                    ("verification-id", verification?.VerificationId ?? "not-collected"),
                    ("requested-availability", explicitAvailability.ToString())));
        }

        if (verification == null)
        {
            return UnavailableSource(
                ProcessRiskSourceKind.Authenticode,
                AuthenticodeSourceId,
                "authenticode-verification-status",
                AnalysisSourceAvailability.NotCollected,
                "No linked Authenticode verification was supplied; no signature conclusion or signal was produced.",
                pe?.SourceRunId ?? string.Empty,
                pe?.AnalyzedUtc ?? evaluatedUtc,
                Canonical(("authenticode", "not-collected")));
        }

        var unavailable = verification.VerificationStatus switch
        {
            AuthenticodeVerificationStatus.Unknown => AnalysisSourceAvailability.NotCollected,
            AuthenticodeVerificationStatus.AccessDenied => AnalysisSourceAvailability.Unavailable,
            AuthenticodeVerificationStatus.FileMissing => AnalysisSourceAvailability.Unavailable,
            AuthenticodeVerificationStatus.Unsupported => AnalysisSourceAvailability.Unavailable,
            AuthenticodeVerificationStatus.Error => AnalysisSourceAvailability.Failed,
            _ => AnalysisSourceAvailability.Available
        };
        if (unavailable != AnalysisSourceAvailability.Available)
        {
            return UnavailableSource(
                ProcessRiskSourceKind.Authenticode,
                AuthenticodeSourceId,
                "authenticode-verification-status",
                unavailable,
                $"Authenticode verification reported {verification.VerificationStatus}; no signature signal was produced.",
                verification.SourceRunId,
                verification.VerificationTimeUtc,
                Canonical(
                    ("verification-id", verification.VerificationId),
                    ("source-run-id", verification.SourceRunId),
                    ("status", verification.VerificationStatus.ToString())));
        }

        var mapped = verification.VerificationStatus switch
        {
            AuthenticodeVerificationStatus.Valid => new AuthenticodeMapping(
                AnalysisFindingSeverity.Informational, 0.95, null,
                "The linked process image has a valid Authenticode verification.",
                "A valid signature establishes publisher verification only and does not establish benignness."),
            AuthenticodeVerificationStatus.Unsigned => new AuthenticodeMapping(
                AnalysisFindingSeverity.Low, 0.9, 10,
                "The linked process image is unsigned.",
                "Unsigned code is a weak triage lead and is not a malware verdict."),
            AuthenticodeVerificationStatus.Invalid => new AuthenticodeMapping(
                AnalysisFindingSeverity.Medium, 0.95, 35,
                "The linked process image has an invalid Authenticode signature.",
                "Invalid signature evidence is a versioned local triage lead."),
            AuthenticodeVerificationStatus.Untrusted => new AuthenticodeMapping(
                AnalysisFindingSeverity.Medium, 0.9, 30,
                "The linked process image has an untrusted Authenticode signature.",
                "Untrusted signer evidence is a versioned local triage lead."),
            AuthenticodeVerificationStatus.Expired => new AuthenticodeMapping(
                AnalysisFindingSeverity.Low, 0.85, 10,
                "The linked process image has an expired Authenticode signature.",
                "An expired signature is a weak triage lead and is not a malware verdict."),
            AuthenticodeVerificationStatus.Revoked => new AuthenticodeMapping(
                AnalysisFindingSeverity.High, 1, 60,
                "The linked process image has a revoked Authenticode signature.",
                "A revoked signer is a high-severity versioned local triage lead."),
            AuthenticodeVerificationStatus.RevocationUnavailable => new AuthenticodeMapping(
                AnalysisFindingSeverity.Informational, 0.6, null,
                "Authenticode verification completed without a current revocation result.",
                "Unavailable revocation data neither reduces risk nor establishes benignness."),
            _ => throw new InvalidOperationException("Validated Authenticode status was not mapped exhaustively.")
        };
        var references = new[]
        {
            new EvidenceReference(EvidenceReferenceKind.ProcessEntity, verification.ProcessEntityId),
            new EvidenceReference(EvidenceReferenceKind.PeAnalysis, verification.AnalysisId),
            new EvidenceReference(EvidenceReferenceKind.AuthenticodeVerification, verification.VerificationId)
        };
        return new LocalMappedSource(
            ProcessRiskSourceKind.Authenticode,
            AuthenticodeSourceId,
            "authenticode-verification-status",
            AnalysisSourceAvailability.Available,
            mapped.Severity,
            mapped.Confidence,
            mapped.Summary,
            mapped.Diagnostic,
            mapped.ScoreDelta,
            verification.SourceRunId,
            verification.VerificationTimeUtc,
            references,
            Canonical(
                ("verification-id", verification.VerificationId),
                ("analysis-id", verification.AnalysisId),
                ("source-run-id", verification.SourceRunId),
                ("verified-utc", Utc(verification.VerificationTimeUtc)),
                ("signature-kind", verification.SignatureKind.ToString()),
                ("verification-status", verification.VerificationStatus.ToString()),
                ("revocation-mode", verification.RevocationMode.ToString()),
                ("revocation-status", verification.RevocationStatus.ToString()),
                ("sha256", Concrete(verification.Sha256Hash)?.ToLowerInvariant() ?? "not-collected")));
    }

    private static IReadOnlyList<LocalMappedSource> MapNetworkAndDns(
        ProcessObservation observation,
        IReadOnlyList<TelemetryEventRecord> events,
        AnalysisSourceAvailability? requestedAvailability,
        DateTime evaluatedUtc)
    {
        if (requestedAvailability is { } explicitAvailability &&
            explicitAvailability != AnalysisSourceAvailability.Available)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.NetworkAndDns,
                    NetworkSourceId,
                    "exact-network-dns-action",
                    explicitAvailability,
                    $"The snapshot reader classified exact network/DNS events as {explicitAvailability}; network coverage mapping did not run.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("requested-availability", explicitAvailability.ToString())))
            ];
        }

        if (events.Count == 0)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.NetworkAndDns,
                    NetworkSourceId,
                    "exact-network-dns-action",
                    AnalysisSourceAvailability.NotCollected,
                    "No exact Connect or DnsQuery process-event records were supplied; network/DNS coverage was not evaluated.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("network-dns-events", "not-collected")))
            ];
        }

        var process = observation.Fields;
        var mapped = new List<LocalMappedSource>(events.Count);
        foreach (var processEvent in events
                     .OrderBy(item => item.TimestampUtc)
                     .ThenBy(item => item.SequenceId))
        {
            var isDns = processEvent.Action == ProcessEventAction.DnsQuery;
            var references = new[]
            {
                new EvidenceReference(EvidenceReferenceKind.ProcessEntity, process.ProcessEntityId),
                new EvidenceReference(
                    EvidenceReferenceKind.Event,
                    processEvent.SequenceId.ToString(CultureInfo.InvariantCulture))
            };
            mapped.Add(new LocalMappedSource(
                ProcessRiskSourceKind.NetworkAndDns,
                NetworkSourceId,
                isDns ? "network-dns-query-observed" : "network-connect-observed",
                AnalysisSourceAvailability.Available,
                AnalysisFindingSeverity.Informational,
                0.9,
                isDns
                    ? "An exact normalized DNS-query event was evaluated for this process."
                    : "An exact normalized network-connect event was evaluated for this process.",
                "Ordinary network activity establishes source coverage only; destination content was not interpreted and no risk signal was produced.",
                null,
                processEvent.SourceRunId,
                processEvent.TimestampUtc,
                references,
                Canonical(
                    ("sequence-id", processEvent.SequenceId.ToString(CultureInfo.InvariantCulture)),
                    ("case-id", processEvent.CaseId),
                    ("session-id", processEvent.EvidenceSessionId),
                    ("capture-id", processEvent.CaptureId),
                    ("source-identity-id", processEvent.SourceIdentityId),
                    ("host-id", processEvent.HostId),
                    ("execution-root-id", processEvent.ExecutionRootId),
                    ("process-entity-id", processEvent.ProcessEntityId),
                    ("process-key", processEvent.ProcessKey),
                    ("source-run-id", processEvent.SourceRunId),
                    ("timestamp-utc", Utc(processEvent.TimestampUtc)),
                    ("category", processEvent.Category.ToString()),
                    ("action", processEvent.Action.ToString()),
                    ("event-code", processEvent.EventCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty),
                    ("repeat-count", processEvent.RepeatCount.ToString(CultureInfo.InvariantCulture)),
                    ("correlation-state", processEvent.CorrelationState.ToString()),
                    ("correlation-method", processEvent.CorrelationMethod))));
        }

        return mapped;
    }

    private static IReadOnlyList<LocalMappedSource> MapEvents(
        ProcessObservation observation,
        IReadOnlyList<TelemetryEventRecord> events,
        AnalysisSourceAvailability? requestedAvailability,
        DateTime evaluatedUtc)
    {
        if (requestedAvailability is { } explicitAvailability &&
            explicitAvailability != AnalysisSourceAvailability.Available)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.Events,
                    EventsSourceId,
                    "exact-process-event-action",
                    explicitAvailability,
                    $"The snapshot reader classified exact process events as {explicitAvailability}; event action rules did not run.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("requested-availability", explicitAvailability.ToString())))
            ];
        }

        if (events.Count == 0)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.Events,
                    EventsSourceId,
                    "exact-process-event-action",
                    AnalysisSourceAvailability.NotCollected,
                    "No exact process-event records were supplied; event action rules did not run.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("process-events", "not-collected")))
            ];
        }

        var process = observation.Fields;
        var mapped = new List<LocalMappedSource>(events.Count);
        foreach (var processEvent in events
                     .OrderBy(item => item.TimestampUtc)
                     .ThenBy(item => item.SequenceId))
        {
            var rule = EventRuleFor(processEvent.Action);
            var references = new[]
            {
                new EvidenceReference(EvidenceReferenceKind.ProcessEntity, process.ProcessEntityId),
                new EvidenceReference(
                    EvidenceReferenceKind.Event,
                    processEvent.SequenceId.ToString(CultureInfo.InvariantCulture))
            };
            mapped.Add(new LocalMappedSource(
                ProcessRiskSourceKind.Events,
                EventsSourceId,
                rule?.RuleId ?? "exact-process-event-action-no-contribution",
                AnalysisSourceAvailability.Available,
                rule?.Severity ?? AnalysisFindingSeverity.Informational,
                rule?.Confidence ?? 0.9,
                rule?.Summary ?? "An exact process event was evaluated by the local normalized-action rule table.",
                rule?.Diagnostic ?? "The normalized action is not one of the six versioned contributing event actions; no signal was produced and no event content was interpreted.",
                rule?.ScoreDelta,
                processEvent.SourceRunId,
                processEvent.TimestampUtc,
                references,
                Canonical(
                    ("sequence-id", processEvent.SequenceId.ToString(CultureInfo.InvariantCulture)),
                    ("case-id", processEvent.CaseId),
                    ("session-id", processEvent.EvidenceSessionId),
                    ("capture-id", processEvent.CaptureId),
                    ("source-identity-id", processEvent.SourceIdentityId),
                    ("host-id", processEvent.HostId),
                    ("execution-root-id", processEvent.ExecutionRootId),
                    ("process-entity-id", processEvent.ProcessEntityId),
                    ("process-key", processEvent.ProcessKey),
                    ("source-run-id", processEvent.SourceRunId),
                    ("timestamp-utc", Utc(processEvent.TimestampUtc)),
                    ("category", processEvent.Category.ToString()),
                    ("action", processEvent.Action.ToString()),
                    ("event-code", processEvent.EventCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty),
                    ("repeat-count", processEvent.RepeatCount.ToString(CultureInfo.InvariantCulture)),
                    ("correlation-state", processEvent.CorrelationState.ToString()),
                    ("correlation-method", processEvent.CorrelationMethod))));
        }

        return mapped;
    }

    private static IReadOnlyList<LocalMappedSource> MapFilesystem(
        ProcessObservation observation,
        IReadOnlyList<LocalProcessFilesystemEvidence> evidence,
        AnalysisSourceAvailability? requestedAvailability,
        DateTime evaluatedUtc)
    {
        if (requestedAvailability is { } explicitAvailability &&
            explicitAvailability != AnalysisSourceAvailability.Available)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.Filesystem,
                    FilesystemSourceId,
                    "exact-process-file-relation",
                    explicitAvailability,
                    $"The snapshot reader classified exact filesystem evidence as {explicitAvailability}; filesystem coverage mapping did not run.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("requested-availability", explicitAvailability.ToString())))
            ];
        }

        if (evidence.Count == 0)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.Filesystem,
                    FilesystemSourceId,
                    "exact-process-file-relation",
                    AnalysisSourceAvailability.NotCollected,
                    "No filesystem artifact with an exact active process relation was supplied; filesystem coverage was not evaluated.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("filesystem-evidence", "not-collected")))
            ];
        }

        var process = observation.Fields;
        return evidence
            .OrderBy(item => item.Artifact.TimestampUtc)
            .ThenBy(item => item.Artifact.ArtifactId, StringComparer.Ordinal)
            .Select(item =>
            {
                var artifact = item.Artifact;
                var relation = item.Relation;
                var references = new[]
                {
                    new EvidenceReference(EvidenceReferenceKind.ProcessEntity, process.ProcessEntityId),
                    new EvidenceReference(EvidenceReferenceKind.FileArtifact, artifact.ArtifactId),
                    new EvidenceReference(EvidenceReferenceKind.EvidenceRelation, relation.RelationId),
                    new EvidenceReference(EvidenceReferenceKind.SourceRun, artifact.SourceRunId)
                };
                return new LocalMappedSource(
                    ProcessRiskSourceKind.Filesystem,
                    FilesystemSourceId,
                    "filesystem-artifact-observed",
                    AnalysisSourceAvailability.Available,
                    AnalysisFindingSeverity.Informational,
                    1,
                    "An immutable filesystem artifact has an exact active relation to this process.",
                    "The relation establishes filesystem source coverage only; path, name, hash, size, and content were not interpreted and no risk signal was produced.",
                    null,
                    artifact.SourceRunId,
                    artifact.TimestampUtc,
                    references,
                    Canonical(
                        ("artifact-id", artifact.ArtifactId),
                        ("artifact-case-id", artifact.CaseId),
                        ("artifact-session-id", artifact.EvidenceSessionId),
                        ("artifact-capture-id", artifact.CaptureId),
                        ("artifact-source-identity-id", artifact.SourceIdentityId),
                        ("artifact-host-id", artifact.HostId),
                        ("artifact-execution-root-id", artifact.ExecutionRootId),
                        ("artifact-source-run-id", artifact.SourceRunId),
                        ("artifact-timestamp-utc", Utc(artifact.TimestampUtc)),
                        ("artifact-kind", artifact.Kind.ToString()),
                        ("relation-id", relation.RelationId),
                        ("relation-case-id", relation.CaseId),
                        ("relation-session-id", relation.EvidenceSessionId),
                        ("relation-capture-id", relation.CaptureId),
                        ("relation-source-identity-id", relation.SourceIdentityId),
                        ("relation-host-id", relation.HostId),
                        ("relation-execution-root-id", relation.ExecutionRootId),
                        ("relation-from-kind", relation.FromKind.ToString()),
                        ("relation-from-id", relation.FromId),
                        ("relation-to-kind", relation.ToKind.ToString()),
                        ("relation-to-id", relation.ToId),
                        ("relation-type", relation.RelationType.ToString()),
                        ("relation-state", relation.State.ToString()),
                        ("relation-status", relation.Status.ToString()),
                        ("relation-source-run-id", relation.SourceRunId),
                        ("relation-observed-from-utc", Utc(relation.ObservedFromUtc)),
                        ("process-entity-id", process.ProcessEntityId)));
            })
            .ToArray();
    }

    private static IReadOnlyList<LocalMappedSource> MapMemoryAndVolatility(
        ProcessObservation observation,
        IReadOnlyList<LocalProcessMemoryEvidence> evidence,
        AnalysisSourceAvailability? requestedAvailability,
        DateTime evaluatedUtc)
    {
        if (requestedAvailability is { } explicitAvailability &&
            explicitAvailability != AnalysisSourceAvailability.Available)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.MemoryAndVolatility,
                    MemorySourceId,
                    "exact-memory-process-relation",
                    explicitAvailability,
                    $"The snapshot reader classified exact memory/Volatility evidence as {explicitAvailability}; memory coverage mapping did not run.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("requested-availability", explicitAvailability.ToString())))
            ];
        }

        if (evidence.Count == 0)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.MemoryAndVolatility,
                    MemorySourceId,
                    "exact-memory-process-relation",
                    AnalysisSourceAvailability.NotCollected,
                    "No Volatility memory-process row with an exact active process relation was supplied; memory coverage was not evaluated.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("memory-evidence", "not-collected")))
            ];
        }

        var process = observation.Fields;
        return evidence
            .OrderBy(item => item.Relation.ObservedFromUtc)
            .ThenBy(item => item.MemoryProcess.ArtifactId, StringComparer.Ordinal)
            .Select(item =>
            {
                var memoryProcess = item.MemoryProcess;
                var relation = item.Relation;
                var references = new[]
                {
                    new EvidenceReference(EvidenceReferenceKind.ProcessEntity, process.ProcessEntityId),
                    new EvidenceReference(EvidenceReferenceKind.MemoryProcess, memoryProcess.ArtifactId),
                    new EvidenceReference(EvidenceReferenceKind.SourceRun, memoryProcess.SourceRunId),
                    new EvidenceReference(EvidenceReferenceKind.EvidenceRelation, relation.RelationId)
                };
                return new LocalMappedSource(
                    ProcessRiskSourceKind.MemoryAndVolatility,
                    MemorySourceId,
                    "memory-process-observed",
                    AnalysisSourceAvailability.Available,
                    AnalysisFindingSeverity.Informational,
                    1,
                    "An immutable Volatility memory-process row has an exact active relation to this process.",
                    "The relation establishes memory/Volatility source coverage only; process name, path, command line, raw JSON, and plugin-specific content were not interpreted and no risk signal was produced.",
                    null,
                    memoryProcess.SourceRunId,
                    relation.ObservedFromUtc,
                    references,
                    Canonical(
                        ("memory-artifact-id", memoryProcess.ArtifactId),
                        ("memory-image-id", memoryProcess.ImageId),
                        ("memory-plugin-run-id", memoryProcess.PluginRunId),
                        ("memory-case-id", memoryProcess.CaseId),
                        ("memory-session-id", memoryProcess.EvidenceSessionId),
                        ("memory-capture-id", memoryProcess.CaptureId),
                        ("memory-source-identity-id", memoryProcess.SourceIdentityId),
                        ("memory-host-id", memoryProcess.HostId),
                        ("memory-execution-root-id", memoryProcess.ExecutionRootId),
                        ("memory-source-run-id", memoryProcess.SourceRunId),
                        ("memory-evidence-kind", memoryProcess.EvidenceKind.ToString()),
                        ("memory-raw-row-hash", memoryProcess.RawRowHash),
                        ("relation-id", relation.RelationId),
                        ("relation-decision-key", relation.DecisionKey),
                        ("relation-case-id", relation.CaseId),
                        ("relation-session-id", relation.EvidenceSessionId),
                        ("relation-capture-id", relation.CaptureId),
                        ("relation-source-identity-id", relation.SourceIdentityId),
                        ("relation-host-id", relation.HostId),
                        ("relation-execution-root-id", relation.ExecutionRootId),
                        ("relation-source-run-id", relation.SourceRunId),
                        ("relation-from-kind", relation.FromKind.ToString()),
                        ("relation-from-id", relation.FromId),
                        ("relation-to-kind", relation.ToKind.ToString()),
                        ("relation-to-id", relation.ToId),
                        ("relation-type", relation.RelationType.ToString()),
                        ("relation-state", relation.State.ToString()),
                        ("relation-status", relation.Status.ToString()),
                        ("relation-observed-from-utc", Utc(relation.ObservedFromUtc)),
                        ("relation-resolver-name", relation.ResolverName),
                        ("relation-resolver-version", relation.ResolverVersion),
                        ("process-entity-id", process.ProcessEntityId)));
            })
            .ToArray();
    }

    private static IReadOnlyList<LocalMappedSource> MapSigma(
        ProcessObservation observation,
        IReadOnlyList<LocalProcessSigmaEvidence> evidence,
        AnalysisSourceAvailability? requestedAvailability,
        DateTime evaluatedUtc)
    {
        if (requestedAvailability is { } explicitAvailability &&
            explicitAvailability != AnalysisSourceAvailability.Available)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.Sigma,
                    SigmaSourceId,
                    "exact-normalized-sigma-match",
                    explicitAvailability,
                    $"The snapshot reader classified exact normalized Sigma matches as {explicitAvailability}; Sigma coverage mapping did not run.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("requested-availability", explicitAvailability.ToString())))
            ];
        }

        if (evidence.Count == 0)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.Sigma,
                    SigmaSourceId,
                    "exact-normalized-sigma-match",
                    AnalysisSourceAvailability.NotCollected,
                    "No exact normalized Sigma match was supplied; Sigma coverage was not evaluated.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("sigma-evidence", "not-collected")))
            ];
        }

        var process = observation.Fields;
        return evidence
            .OrderBy(item => item.MatchedUtc)
            .ThenBy(item => item.MatchId, StringComparer.Ordinal)
            .Select(item =>
            {
                var references = item.EvidenceReferences
                    .OrderBy(reference => reference.Kind)
                    .ThenBy(reference => reference.Id, StringComparer.Ordinal)
                    .Select(reference => new EvidenceReference(reference.Kind, reference.Id))
                    .ToArray();
                return new LocalMappedSource(
                    ProcessRiskSourceKind.Sigma,
                    SigmaSourceId,
                    item.RuleId,
                    AnalysisSourceAvailability.Available,
                    item.Level,
                    1,
                    "An exact normalized Sigma match is bound to this durable process entity.",
                    item.Level == AnalysisFindingSeverity.Informational
                        ? "The informational match establishes Sigma source coverage only; free-form rule or evidence text was not interpreted and no risk signal was produced."
                        : "The exact match contributes a versioned positive-only Sigma triage signal; free-form rule or evidence text was not interpreted and the signal is not a malware verdict.",
                    SigmaScoreDelta(item.Level),
                    item.SourceRunId,
                    item.MatchedUtc,
                    references,
                    SigmaCanonicalInput(item, process, includeMatchId: true),
                    item.RuleVersion);
            })
            .ToArray();
    }

    private static int? SigmaScoreDelta(AnalysisFindingSeverity level) => level switch
    {
        AnalysisFindingSeverity.Informational => null,
        AnalysisFindingSeverity.Low => 10,
        AnalysisFindingSeverity.Medium => 30,
        AnalysisFindingSeverity.High => 55,
        AnalysisFindingSeverity.Critical => 70,
        _ => throw new InvalidOperationException("Validated Sigma severity was not mapped exhaustively.")
    };

    private static string SigmaCanonicalInput(
        LocalProcessSigmaEvidence item,
        ProcessRecord process,
        bool includeMatchId)
    {
        var normalizedMatch = Canonical(
            ("rule-id", item.RuleId),
            ("rule-version", item.RuleVersion),
            ("level", item.Level.ToString()),
            ("match-content-hash", item.MatchContentHashSha256.ToLowerInvariant()),
            ("case-id", item.EvidenceIdentity.CaseId),
            ("session-id", item.EvidenceIdentity.EvidenceSessionId),
            ("capture-id", item.EvidenceIdentity.CaptureId),
            ("source-identity-id", item.EvidenceIdentity.SourceIdentityId),
            ("host-id", item.EvidenceIdentity.HostId),
            ("execution-root-id", item.EvidenceIdentity.ExecutionRootId),
            ("process-entity-id", process.ProcessEntityId),
            ("process-key", process.ProcessKey),
            ("source-run-id", item.SourceRunId),
            ("matched-utc", Utc(item.MatchedUtc)),
            ("correlation-state", item.CorrelationState.ToString()),
            ("correlation-method", item.CorrelationMethod),
            ("correlation-candidate-count", item.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture)),
            ("evidence-references", ReferenceIdentity(item.EvidenceReferences)));
        return includeMatchId
            ? Canonical(("match-id", item.MatchId), ("normalized-match", normalizedMatch))
            : normalizedMatch;
    }

    private static string ReferenceIdentity(IEnumerable<EvidenceReference> references) =>
        Canonical(references
            .OrderBy(reference => reference.Kind)
            .ThenBy(reference => reference.Id, StringComparer.Ordinal)
            .Select((reference, index) =>
                ($"reference-{index.ToString("D2", CultureInfo.InvariantCulture)}",
                    Canonical(
                        ("kind", reference.Kind.ToString()),
                        ("id", reference.Id))))
            .ToArray());

    private static IReadOnlyList<LocalMappedSource> MapBaselineComparison(
        ProcessObservation observation,
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> evidence,
        AnalysisSourceAvailability? requestedAvailability,
        DateTime evaluatedUtc)
    {
        if (requestedAvailability is { } explicitAvailability &&
            explicitAvailability != AnalysisSourceAvailability.Available)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.BaselineComparison,
                    BaselineSourceId,
                    "exact-normalized-baseline-comparison",
                    explicitAvailability,
                    $"The snapshot reader classified exact normalized baseline-comparison findings as {explicitAvailability}; baseline coverage mapping did not run.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("requested-availability", explicitAvailability.ToString())))
            ];
        }

        if (evidence.Count == 0)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.BaselineComparison,
                    BaselineSourceId,
                    "exact-normalized-baseline-comparison",
                    AnalysisSourceAvailability.NotCollected,
                    "No exact normalized baseline-comparison finding was supplied; baseline coverage was not evaluated.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("baseline-comparison-evidence", "not-collected")))
            ];
        }

        var process = observation.Fields;
        return evidence
            .OrderBy(item => item.ComparedUtc)
            .ThenBy(item => item.FindingId, StringComparer.Ordinal)
            .Select(item =>
            {
                var references = item.EvidenceReferences
                    .OrderBy(reference => reference.Kind)
                    .ThenBy(reference => reference.Id, StringComparer.Ordinal)
                    .Select(reference => new EvidenceReference(reference.Kind, reference.Id))
                    .ToArray();
                var artifact = item.ArtifactKind.ToString().ToLowerInvariant();
                var verdict = item.Verdict.ToString().ToLowerInvariant();
                var scoreDelta = BaselineScoreDelta(item.Verdict);
                return new LocalMappedSource(
                    ProcessRiskSourceKind.BaselineComparison,
                    BaselineSourceId,
                    $"baseline-{artifact}-{verdict}",
                    AnalysisSourceAvailability.Available,
                    BaselineSeverity(item.Verdict),
                    1,
                    $"An exact normalized {artifact} baseline comparison classified this process evidence as {verdict}.",
                    scoreDelta is null
                        ? "The comparison establishes baseline source coverage only; free-form comparison content was not interpreted and no risk increase or reduction was produced."
                        : "The exact comparison contributes a conservative versioned positive-only baseline-drift signal; free-form comparison content was not interpreted and the signal is not a compromise verdict.",
                    scoreDelta,
                    item.ComparisonId,
                    item.ComparedUtc,
                    references,
                    BaselineCanonicalInput(item, process, includeFindingId: true),
                    item.ComparisonVersion);
            })
            .ToArray();
    }

    private static AnalysisFindingSeverity BaselineSeverity(LocalProcessBaselineVerdict verdict) =>
        verdict switch
        {
            LocalProcessBaselineVerdict.New or LocalProcessBaselineVerdict.Changed =>
                AnalysisFindingSeverity.Low,
            LocalProcessBaselineVerdict.Known or LocalProcessBaselineVerdict.Noisy or
                LocalProcessBaselineVerdict.Accepted => AnalysisFindingSeverity.Informational,
            _ => throw new InvalidOperationException("Validated Baseline verdict was not mapped exhaustively.")
        };

    private static int? BaselineScoreDelta(LocalProcessBaselineVerdict verdict) => verdict switch
    {
        LocalProcessBaselineVerdict.New => 10,
        LocalProcessBaselineVerdict.Changed => 15,
        LocalProcessBaselineVerdict.Known or LocalProcessBaselineVerdict.Noisy or
            LocalProcessBaselineVerdict.Accepted => null,
        _ => throw new InvalidOperationException("Validated Baseline verdict was not mapped exhaustively.")
    };

    private static string BaselineCanonicalInput(
        LocalProcessBaselineComparisonEvidence item,
        ProcessRecord process,
        bool includeFindingId)
    {
        var normalizedFinding = Canonical(
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
            ("process-entity-id", process.ProcessEntityId),
            ("process-key", process.ProcessKey),
            ("compared-utc", Utc(item.ComparedUtc)),
            ("correlation-state", item.CorrelationState.ToString()),
            ("correlation-method", item.CorrelationMethod),
            ("correlation-candidate-count", item.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture)),
            ("evidence-references", ReferenceIdentity(item.EvidenceReferences)));
        return includeFindingId
            ? Canonical(("finding-id", item.FindingId), ("normalized-finding", normalizedFinding))
            : normalizedFinding;
    }

    private static IReadOnlyList<LocalMappedSource> MapYara(
        ProcessObservation observation,
        YaraProcessAttributionResult? attribution,
        DateTime evaluatedUtc)
    {
        if (attribution == null)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.Yara,
                    YaraSourceId,
                    "exact-reviewed-yara-attribution",
                    AnalysisSourceAvailability.NotCollected,
                    "No exact review-gated YARA attribution was supplied; YARA coverage was not evaluated.",
                    string.Empty,
                    evaluatedUtc,
                    Canonical(("yara-attribution", "not-collected")))
            ];
        }

        if (attribution.Availability != AnalysisSourceAvailability.Available)
        {
            return
            [
                UnavailableSource(
                    ProcessRiskSourceKind.Yara,
                    YaraSourceId,
                    "exact-reviewed-yara-attribution",
                    attribution.Availability,
                    $"The exact YARA attribution source is {attribution.Availability}; YARA coverage mapping did not run.",
                    attribution.Target.SourceRunId,
                    evaluatedUtc,
                    YaraAttributionCanonical(attribution, observation.Fields))
            ];
        }

        var topReferences = CopyOrderedReferences(attribution.EvidenceReferences);
        if (attribution.Evidence.Count == 0)
        {
            return
            [
                new LocalMappedSource(
                    ProcessRiskSourceKind.Yara,
                    YaraSourceId,
                    "exact-reviewed-yara-zero-match",
                    AnalysisSourceAvailability.Available,
                    AnalysisFindingSeverity.Informational,
                    1,
                    "An exact review-gated YARA scan completed with zero rule matches.",
                    "The completed zero-match scan establishes YARA source coverage only; it is not a benignness or trust conclusion.",
                    null,
                    attribution.Target.SourceRunId,
                    evaluatedUtc,
                    topReferences,
                    YaraAttributionCanonical(attribution, observation.Fields),
                    attribution.Policy.PolicyVersion)
            ];
        }

        return attribution.Evidence
            .OrderBy(item => item.CompletedUtc)
            .ThenBy(item => item.RuleNamespace, StringComparer.Ordinal)
            .ThenBy(item => item.RuleId, StringComparer.Ordinal)
            .ThenBy(item => item.MatchId, StringComparer.Ordinal)
            .Select(item =>
            {
                var references = CopyOrderedReferences(item.EvidenceReferences);
                var scoreDelta = item.IsPolicyMatched &&
                                 item.Severity != AnalysisFindingSeverity.Informational
                    ? item.ScoreDelta
                    : null;
                var canonicalRule = Canonical(
                    ("rule-namespace", item.RuleNamespace),
                    ("rule-id", item.RuleId));
                return new LocalMappedSource(
                    ProcessRiskSourceKind.Yara,
                    YaraSourceId,
                    StableId("yara-rule", canonicalRule),
                    AnalysisSourceAvailability.Available,
                    item.Severity,
                    1,
                    "An exact review-gated YARA rule match is bound to this durable process entity.",
                    scoreDelta is null
                        ? "The reviewed Informational or explicit unclassified match establishes YARA coverage only; tags, metadata, strings, paths, and prose were not interpreted."
                        : "The exact reviewed disposition contributes its positive-only YARA triage delta; the signal is not a malware verdict.",
                    scoreDelta,
                    item.Target.SourceRunId,
                    item.CompletedUtc,
                    references,
                    YaraEvidenceCanonical(item, observation.Fields, includeMatchId: true),
                    item.PolicyVersion);
            })
            .ToArray();
    }

    private static string YaraAttributionCanonical(
        YaraProcessAttributionResult attribution,
        ProcessRecord process) =>
        Canonical(
            ("scan-id", attribution.ScanId),
            ("availability", attribution.Availability.ToString()),
            ("truncated", attribution.IsTruncated.ToString(CultureInfo.InvariantCulture)),
            ("process-entity-id", process.ProcessEntityId),
            ("process-key", process.ProcessKey),
            ("policy-id", attribution.Policy.PolicyId),
            ("policy-version", attribution.Policy.PolicyVersion),
            ("reviewer-id", attribution.Policy.ReviewerId),
            ("review-policy-id", attribution.Policy.ReviewPolicyId),
            ("review-policy-version", attribution.Policy.ReviewPolicyVersion),
            ("reviewed-utc", Utc(attribution.Policy.ReviewedUtc)),
            ("ruleset", YaraRulesetCanonical(attribution.Ruleset)),
            ("target", YaraTargetCanonical(attribution.Target)),
            ("evidence-references", ReferenceIdentity(attribution.EvidenceReferences)));

    private static string YaraEvidenceCanonical(
        YaraProcessRiskEvidence item,
        ProcessRecord process,
        bool includeMatchId)
    {
        var normalizedMatch = Canonical(
            ("scan-id", item.ScanId),
            ("rule-namespace", item.RuleNamespace),
            ("rule-id", item.RuleId),
            ("policy-matched", item.IsPolicyMatched.ToString(CultureInfo.InvariantCulture)),
            ("severity", item.Severity.ToString()),
            ("score-delta", item.ScoreDelta?.ToString(CultureInfo.InvariantCulture) ?? string.Empty),
            ("policy-id", item.PolicyId),
            ("policy-version", item.PolicyVersion),
            ("reviewer-id", item.ReviewerId),
            ("review-policy-id", item.ReviewPolicyId),
            ("review-policy-version", item.ReviewPolicyVersion),
            ("reviewed-utc", Utc(item.ReviewedUtc)),
            ("ruleset", YaraRulesetCanonical(item.Ruleset)),
            ("target", YaraTargetCanonical(item.Target)),
            ("process-entity-id", process.ProcessEntityId),
            ("process-key", process.ProcessKey),
            ("completed-utc", Utc(item.CompletedUtc)),
            ("truncated", item.IsTruncated.ToString(CultureInfo.InvariantCulture)),
            ("correlation-state", item.CorrelationState.ToString()),
            ("correlation-method", item.CorrelationMethod),
            ("correlation-candidate-count", item.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture)),
            ("evidence-references", ReferenceIdentity(item.EvidenceReferences)));
        return includeMatchId
            ? Canonical(("match-id", item.MatchId), ("normalized-match", normalizedMatch))
            : normalizedMatch;
    }

    private static string YaraRulesetCanonical(YaraRulesetIdentity ruleset) =>
        Canonical(
            ("scanner-id", ruleset.ScannerId),
            ("scanner-version", ruleset.ScannerVersion),
            ("ruleset-id", ruleset.RulesetId),
            ("ruleset-version", ruleset.RulesetVersion),
            ("ruleset-hash", ruleset.RulesetHashSha256.ToLowerInvariant()));

    private static string YaraTargetCanonical(YaraScanTarget target) =>
        Canonical(
            ("kind", target.Kind.ToString()),
            ("case-id", target.EvidenceIdentity.CaseId),
            ("session-id", target.EvidenceIdentity.EvidenceSessionId),
            ("capture-id", target.EvidenceIdentity.CaptureId),
            ("source-identity-id", target.EvidenceIdentity.SourceIdentityId),
            ("host-id", target.EvidenceIdentity.HostId),
            ("execution-root-id", target.EvidenceIdentity.ExecutionRootId),
            ("source-run-id", target.SourceRunId),
            ("reference-kind", target.EvidenceReference.Kind.ToString()),
            ("reference-id", target.EvidenceReference.Id),
            ("content-hash", target.ContentHashSha256.ToLowerInvariant()),
            ("offset", target.OffsetBytes.ToString(CultureInfo.InvariantCulture)),
            ("length", target.LengthBytes.ToString(CultureInfo.InvariantCulture)));

    private static EvidenceReference[] CopyOrderedReferences(
        IEnumerable<EvidenceReference> references) =>
        references
            .OrderBy(reference => reference.Kind)
            .ThenBy(reference => reference.Id, StringComparer.Ordinal)
            .Select(reference => new EvidenceReference(reference.Kind, reference.Id))
            .ToArray();

    private static EventActionRiskRule? EventRuleFor(ProcessEventAction action) => action switch
    {
        ProcessEventAction.ProcessTampering => new EventActionRiskRule(
            "event-process-tampering",
            AnalysisFindingSeverity.Critical,
            0.95,
            70,
            "An exact event reports process tampering activity.",
            "Process tampering is a high-value triage lead and is not a malware verdict."),
        ProcessEventAction.CreateRemoteThread => new EventActionRiskRule(
            "event-create-remote-thread",
            AnalysisFindingSeverity.High,
            0.9,
            55,
            "An exact event reports remote-thread creation activity.",
            "Remote-thread creation is a dual-use injection lead and requires investigation context."),
        ProcessEventAction.RawAccessRead => new EventActionRiskRule(
            "event-raw-access-read",
            AnalysisFindingSeverity.High,
            0.9,
            50,
            "An exact event reports raw-access read activity.",
            "Raw-access reads are a high-value triage lead and are not a malware verdict."),
        ProcessEventAction.WmiBinding => new EventActionRiskRule(
            "event-wmi-binding",
            AnalysisFindingSeverity.Medium,
            0.85,
            30,
            "An exact event reports a WMI filter-to-consumer binding.",
            "A WMI binding can support persistence but is also used administratively; validate the exact objects."),
        ProcessEventAction.WmiConsumer => new EventActionRiskRule(
            "event-wmi-consumer",
            AnalysisFindingSeverity.Low,
            0.8,
            15,
            "An exact event reports WMI consumer activity.",
            "A WMI consumer is a weak persistence lead until correlated with its filter and binding."),
        ProcessEventAction.WmiFilter => new EventActionRiskRule(
            "event-wmi-filter",
            AnalysisFindingSeverity.Low,
            0.8,
            10,
            "An exact event reports WMI filter activity.",
            "A WMI filter is a weak persistence lead until correlated with its consumer and binding."),
        _ => null
    };

    private static AnalysisFinding CreateFinding(
        EvidenceIdentity scope,
        string processEntityId,
        string processKey,
        ProcessRiskAggregationPolicy policy,
        DateTime evaluatedUtc,
        LocalMappedSource source)
    {
        var available = source.Availability == AnalysisSourceAvailability.Available;
        var inputHash = available ? Sha256(source.CanonicalInput) : string.Empty;
        var snapshotId = StableId(
            "risk-snapshot",
            Canonical(
                ("scope", ScopeCanonical(scope, processEntityId, processKey)),
                ("source-id", source.SourceId),
                ("source-run-id", source.SourceRunId),
                ("availability", source.Availability.ToString()),
                ("input-hash", inputHash),
                ("source-fingerprint", Sha256(source.CanonicalInput)),
                ("created-utc", Utc(source.CreatedUtc)),
                ("evaluated-utc", Utc(evaluatedUtc))));
        var snapshot = new AnalysisInputSnapshot
        {
            SnapshotId = snapshotId,
            Availability = source.Availability,
            EvidenceIdentity = scope,
            ProcessEntityId = processEntityId,
            ProcessKey = processKey,
            SourceKind = source.SourceId,
            SourceVersion = MapperVersion,
            SourceRunId = source.SourceRunId,
            InputSetHashSha256 = inputHash,
            CreatedUtc = source.CreatedUtc,
            EvidenceReferences = available ? source.References : Array.Empty<EvidenceReference>()
        };
        var ruleVersion = string.IsNullOrWhiteSpace(source.RuleVersion)
            ? MapperVersion
            : source.RuleVersion;
        var findingId = StableId(
            "risk-finding",
            Canonical(
                ("snapshot-id", snapshotId),
                ("rule-id", source.RuleId),
                ("rule-version", ruleVersion),
                ("severity", source.Severity.ToString()),
                ("confidence", source.Confidence.ToString("R", CultureInfo.InvariantCulture)),
                ("summary", source.Summary),
                ("diagnostic", source.Diagnostic)));
        return new AnalysisFinding
        {
            FindingId = findingId,
            Availability = source.Availability,
            Severity = source.Severity,
            Confidence = source.Confidence,
            Summary = source.Summary,
            Diagnostic = source.Diagnostic,
            EvidenceIdentity = scope,
            ProcessEntityId = processEntityId,
            ProcessKey = processKey,
            Rule = new AnalysisRuleIdentity
            {
                ToolId = MapperId,
                ToolVersion = ToolVersion,
                RuleId = source.RuleId,
                RuleVersion = ruleVersion,
                PolicyId = policy.PolicyId,
                PolicyVersion = policy.PolicyVersion
            },
            InputSnapshot = snapshot,
            EvaluatedUtc = evaluatedUtc,
            EvidenceReferences = available ? source.References : Array.Empty<EvidenceReference>()
        };
    }

    private static ProcessRiskSignal CreateSignal(AnalysisFinding finding, int scoreDelta) => new()
    {
        SignalId = StableId(
            "risk-signal",
            Canonical(
                ("finding-id", finding.FindingId),
                ("score-delta", scoreDelta.ToString(CultureInfo.InvariantCulture)))),
        FindingId = finding.FindingId,
        InputSnapshotId = finding.InputSnapshot.SnapshotId,
        EvidenceIdentity = finding.EvidenceIdentity,
        ProcessEntityId = finding.ProcessEntityId,
        ProcessKey = finding.ProcessKey,
        PolicyId = finding.Rule.PolicyId,
        PolicyVersion = finding.Rule.PolicyVersion,
        ScoreDelta = scoreDelta,
        Severity = finding.Severity,
        Confidence = finding.Confidence,
        EvaluatedUtc = finding.EvaluatedUtc,
        EvidenceReferences = finding.EvidenceReferences
    };

    private static LocalProcessRiskMappingFailure ValidateObservation(
        ProcessObservation? observation,
        DateTime evaluatedUtc)
    {
        if (observation == null || observation.Fields == null ||
            !Required(observation.ObservationId) || !Required(observation.AdapterId) ||
            !Required(observation.ProcessEntityId) || !Required(observation.SourceRunId) ||
            !Required(observation.ParserVersion) || !Enum.IsDefined(observation.ObservationKind) ||
            !Enum.IsDefined(observation.CorrelationMethod) || !Enum.IsDefined(observation.StatusAssertion) ||
            observation.ObservedUtc.Kind != DateTimeKind.Utc || observation.ObservedUtc > evaluatedUtc)
        {
            return LocalProcessRiskMappingFailure.InvalidProcessObservation;
        }

        var process = observation.Fields;
        if (!ValidScope(ScopeOf(process)) || !Required(process.ProcessEntityId) ||
            !Optional(process.ProcessKey) ||
            !string.Equals(observation.ProcessEntityId, process.ProcessEntityId, StringComparison.Ordinal) ||
            !Bounded(process.ProcessName, MaximumIdentityLength) ||
            !Bounded(process.ProcessPath, MaximumPathLength) ||
            !ValidOptionalSha256(process.Sha256Hash))
        {
            return LocalProcessRiskMappingFailure.InvalidProcessObservation;
        }

        var fieldStates = observation.FieldStates;
        if (fieldStates == null || fieldStates.Count > MaximumFieldStates ||
            fieldStates.Any(pair => !Required(pair.Key) || !Enum.IsDefined(pair.Value)))
        {
            return LocalProcessRiskMappingFailure.InvalidProcessObservation;
        }

        if ((FieldState(observation, nameof(ProcessRecord.ProcessName)) == ProcessObservationValueState.Available &&
             Concrete(process.ProcessName) == null) ||
            (FieldState(observation, nameof(ProcessRecord.ProcessPath)) == ProcessObservationValueState.Available &&
             Concrete(process.ProcessPath) == null) ||
            (FieldState(observation, nameof(ProcessRecord.Sha256Hash)) == ProcessObservationValueState.Available &&
             Concrete(process.Sha256Hash) == null))
        {
            return LocalProcessRiskMappingFailure.ContradictoryEvidence;
        }

        return LocalProcessRiskMappingFailure.None;
    }

    private static LocalProcessRiskMappingFailure ValidateRequestedAvailability(
        LocalProcessRiskMappingRequest request)
    {
        var requested = new[]
        {
            request.ProcessMetadataAvailability,
            request.PePropertiesAvailability,
            request.AuthenticodeAvailability,
            request.NetworkAndDnsAvailability,
            request.EventsAvailability,
            request.FilesystemAvailability,
            request.MemoryAndVolatilityAvailability,
            request.SigmaAvailability,
            request.BaselineComparisonAvailability
        };
        if (requested.Any(item => item is { } value &&
                (!Enum.IsDefined(value) || value == AnalysisSourceAvailability.Unknown)))
        {
            return LocalProcessRiskMappingFailure.InvalidSourceAvailability;
        }

        if (request.PeAnalysis == null && request.PePropertiesAvailability is { } peAvailability &&
            peAvailability is not AnalysisSourceAvailability.NotCollected and not AnalysisSourceAvailability.Available)
        {
            return LocalProcessRiskMappingFailure.ContradictoryEvidence;
        }

        if (request.PeAnalysis?.AuthenticodeVerification == null &&
            request.AuthenticodeAvailability is { } authenticodeAvailability &&
            authenticodeAvailability is not AnalysisSourceAvailability.NotCollected and
                not AnalysisSourceAvailability.Available)
        {
            return LocalProcessRiskMappingFailure.ContradictoryEvidence;
        }

        var networkCount = request.NetworkEventRecords?.Count ?? 0;
        if (networkCount == 0 &&
            request.NetworkAndDnsAvailability == AnalysisSourceAvailability.Available)
        {
            return LocalProcessRiskMappingFailure.ContradictoryEvidence;
        }

        var filesystemCount = request.FilesystemEvidence?.Count ?? 0;
        if (filesystemCount == 0 &&
            request.FilesystemAvailability == AnalysisSourceAvailability.Available)
        {
            return LocalProcessRiskMappingFailure.ContradictoryEvidence;
        }

        var memoryCount = request.MemoryEvidence?.Count ?? 0;
        if (memoryCount == 0 &&
            request.MemoryAndVolatilityAvailability == AnalysisSourceAvailability.Available)
        {
            return LocalProcessRiskMappingFailure.ContradictoryEvidence;
        }

        var sigmaCount = request.SigmaEvidence?.Count ?? 0;
        if (sigmaCount == 0 &&
            request.SigmaAvailability == AnalysisSourceAvailability.Available)
        {
            return LocalProcessRiskMappingFailure.ContradictoryEvidence;
        }

        var baselineCount = request.BaselineComparisonEvidence?.Count ?? 0;
        if (baselineCount == 0 &&
            request.BaselineComparisonAvailability == AnalysisSourceAvailability.Available)
        {
            return LocalProcessRiskMappingFailure.ContradictoryEvidence;
        }

        return LocalProcessRiskMappingFailure.None;
    }

    private static LocalProcessRiskMappingFailure ValidateBaselineComparisonEvidence(
        IReadOnlyList<LocalProcessBaselineComparisonEvidence>? evidence,
        ProcessObservation observation,
        DateTime evaluatedUtc)
    {
        if (evidence == null)
        {
            return LocalProcessRiskMappingFailure.InvalidBaselineComparisonEvidence;
        }

        if (evidence.Count > MaximumBaselineComparisonEvidence)
        {
            return LocalProcessRiskMappingFailure.BaselineInputLimitExceeded;
        }

        var observationScope = ScopeOf(observation.Fields);
        var findingIds = new HashSet<string>(StringComparer.Ordinal);
        var canonicalInputs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in evidence)
        {
            if (item == null || item.EvidenceIdentity == null || item.EvidenceReferences == null ||
                item.BaselineFingerprintSha256 == null || item.CurrentFingerprintSha256 == null ||
                item.PolicyRuleId == null)
            {
                return LocalProcessRiskMappingFailure.InvalidBaselineComparisonEvidence;
            }

            if (!Required(item.FindingId) || !findingIds.Add(item.FindingId))
            {
                return findingIds.Contains(item?.FindingId ?? string.Empty)
                    ? LocalProcessRiskMappingFailure.DuplicateBaselineComparisonEvidence
                    : LocalProcessRiskMappingFailure.InvalidBaselineComparisonEvidence;
            }

            if (!Required(item.ComparisonId) || !Required(item.ComparisonVersion) ||
                !Required(item.BaselineId) ||
                !ValidSha256(item.BaselineSnapshotHashSha256) ||
                !ValidSha256(item.CurrentSnapshotHashSha256) ||
                !ValidSha256(item.StableKeyHashSha256) ||
                !Enum.IsDefined(item.ArtifactKind) ||
                item.ArtifactKind == LocalProcessBaselineArtifactKind.Unknown ||
                !Enum.IsDefined(item.Verdict) ||
                item.Verdict is LocalProcessBaselineVerdict.Unknown or LocalProcessBaselineVerdict.Missing ||
                !Required(item.ProcessEntityId) || !Optional(item.ProcessKey) ||
                item.ComparedUtc.Kind != DateTimeKind.Utc || item.ComparedUtc > evaluatedUtc ||
                !Enum.IsDefined(item.CorrelationState) ||
                item.CorrelationState != EvidenceCorrelationState.Exact ||
                item.CorrelationCandidateCount != 1 || !Required(item.CorrelationMethod) ||
                !ValidScope(item.EvidenceIdentity) ||
                !SameScope(item.EvidenceIdentity, observationScope) ||
                !string.Equals(item.ProcessEntityId, observation.ProcessEntityId, StringComparison.Ordinal) ||
                !string.Equals(item.ProcessKey, observation.Fields.ProcessKey, StringComparison.Ordinal) ||
                item.EvidenceReferences.Count < 2 ||
                item.EvidenceReferences.Count > MaximumBaselineEvidenceReferences ||
                !ValidBaselineVerdictShape(item))
            {
                return LocalProcessRiskMappingFailure.InvalidBaselineComparisonEvidence;
            }

            var referenceKeys = new HashSet<string>(StringComparer.Ordinal);
            var processReferenceCount = 0;
            var sourceEvidenceCount = 0;
            foreach (var reference in item.EvidenceReferences)
            {
                if (reference == null || !Enum.IsDefined(reference.Kind) ||
                    !Required(reference.Id) ||
                    !referenceKeys.Add($"{(int)reference.Kind}:{reference.Id}"))
                {
                    return LocalProcessRiskMappingFailure.InvalidBaselineComparisonEvidence;
                }

                if (reference.Kind == EvidenceReferenceKind.ProcessEntity)
                {
                    processReferenceCount++;
                    if (!string.Equals(reference.Id, observation.ProcessEntityId, StringComparison.Ordinal))
                    {
                        return LocalProcessRiskMappingFailure.InvalidBaselineComparisonEvidence;
                    }
                }
                else
                {
                    sourceEvidenceCount++;
                }
            }

            if (processReferenceCount != 1 || sourceEvidenceCount == 0)
            {
                return LocalProcessRiskMappingFailure.InvalidBaselineComparisonEvidence;
            }

            if (!canonicalInputs.Add(Sha256(
                    BaselineCanonicalInput(item, observation.Fields, includeFindingId: false))))
            {
                return LocalProcessRiskMappingFailure.DuplicateBaselineComparisonEvidence;
            }
        }

        return LocalProcessRiskMappingFailure.None;
    }

    private static bool ValidBaselineVerdictShape(LocalProcessBaselineComparisonEvidence item)
    {
        var hasBaseline = ValidSha256(item.BaselineFingerprintSha256);
        var hasCurrent = ValidSha256(item.CurrentFingerprintSha256);
        var hasPolicy = Required(item.PolicyRuleId);
        var hasNoPolicy = item.PolicyRuleId.Length == 0;
        return item.Verdict switch
        {
            LocalProcessBaselineVerdict.New =>
                item.BaselineFingerprintSha256.Length == 0 && hasCurrent && hasNoPolicy,
            LocalProcessBaselineVerdict.Changed =>
                hasBaseline && hasCurrent && hasNoPolicy &&
                !string.Equals(item.BaselineFingerprintSha256, item.CurrentFingerprintSha256,
                    StringComparison.OrdinalIgnoreCase),
            LocalProcessBaselineVerdict.Known or LocalProcessBaselineVerdict.Noisy =>
                hasBaseline && hasCurrent && hasNoPolicy &&
                string.Equals(item.BaselineFingerprintSha256, item.CurrentFingerprintSha256,
                    StringComparison.OrdinalIgnoreCase),
            LocalProcessBaselineVerdict.Accepted =>
                hasBaseline && hasCurrent && hasPolicy &&
                !string.Equals(item.BaselineFingerprintSha256, item.CurrentFingerprintSha256,
                    StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static LocalProcessRiskMappingFailure ValidateSigmaEvidence(
        IReadOnlyList<LocalProcessSigmaEvidence>? evidence,
        ProcessObservation observation,
        DateTime evaluatedUtc)
    {
        if (evidence == null)
        {
            return LocalProcessRiskMappingFailure.InvalidSigmaEvidence;
        }

        if (evidence.Count > MaximumSigmaEvidence)
        {
            return LocalProcessRiskMappingFailure.SigmaInputLimitExceeded;
        }

        var observationScope = ScopeOf(observation.Fields);
        var matchIds = new HashSet<string>(StringComparer.Ordinal);
        var canonicalInputs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in evidence)
        {
            if (item == null || item.EvidenceIdentity == null ||
                item.EvidenceReferences == null)
            {
                return LocalProcessRiskMappingFailure.InvalidSigmaEvidence;
            }

            if (!Required(item.MatchId) || !Required(item.MatchContentHashSha256))
            {
                return LocalProcessRiskMappingFailure.InvalidSigmaEvidence;
            }

            if (!matchIds.Add(item.MatchId))
            {
                return LocalProcessRiskMappingFailure.DuplicateSigmaEvidence;
            }

            if (!Required(item.RuleId) || !Required(item.RuleVersion) ||
                !ValidSha256(item.MatchContentHashSha256) ||
                !Enum.IsDefined(item.Level) || item.Level == AnalysisFindingSeverity.Unknown ||
                !Required(item.ProcessEntityId) || !Optional(item.ProcessKey) ||
                !Required(item.SourceRunId) ||
                item.MatchedUtc.Kind != DateTimeKind.Utc || item.MatchedUtc > evaluatedUtc ||
                !Enum.IsDefined(item.CorrelationState) ||
                item.CorrelationState != EvidenceCorrelationState.Exact ||
                item.CorrelationCandidateCount != 1 ||
                !Required(item.CorrelationMethod) ||
                !ValidScope(item.EvidenceIdentity) ||
                !SameScope(item.EvidenceIdentity, observationScope) ||
                !string.Equals(item.ProcessEntityId, observation.ProcessEntityId,
                    StringComparison.Ordinal) ||
                !string.Equals(item.ProcessKey, observation.Fields.ProcessKey,
                    StringComparison.Ordinal) ||
                item.EvidenceReferences.Count < 3 ||
                item.EvidenceReferences.Count > MaximumSigmaEvidenceReferences)
            {
                return LocalProcessRiskMappingFailure.InvalidSigmaEvidence;
            }

            var referenceKeys = new HashSet<string>(StringComparer.Ordinal);
            var processReferenceCount = 0;
            var sourceRunReferenceCount = 0;
            var sourceEvidenceCount = 0;
            foreach (var reference in item.EvidenceReferences)
            {
                if (reference == null || !Enum.IsDefined(reference.Kind) ||
                    !Required(reference.Id) ||
                    !referenceKeys.Add($"{(int)reference.Kind}:{reference.Id}"))
                {
                    return LocalProcessRiskMappingFailure.InvalidSigmaEvidence;
                }

                if (reference.Kind == EvidenceReferenceKind.ProcessEntity)
                {
                    processReferenceCount++;
                    if (!string.Equals(reference.Id, observation.ProcessEntityId,
                            StringComparison.Ordinal))
                    {
                        return LocalProcessRiskMappingFailure.InvalidSigmaEvidence;
                    }
                }
                else if (reference.Kind == EvidenceReferenceKind.SourceRun)
                {
                    sourceRunReferenceCount++;
                    if (!string.Equals(reference.Id, item.SourceRunId,
                            StringComparison.Ordinal))
                    {
                        return LocalProcessRiskMappingFailure.InvalidSigmaEvidence;
                    }
                }
                else
                {
                    sourceEvidenceCount++;
                }
            }

            if (processReferenceCount != 1 || sourceRunReferenceCount != 1 ||
                sourceEvidenceCount == 0)
            {
                return LocalProcessRiskMappingFailure.InvalidSigmaEvidence;
            }

            if (!canonicalInputs.Add(Sha256(
                    SigmaCanonicalInput(item, observation.Fields, includeMatchId: false))))
            {
                return LocalProcessRiskMappingFailure.DuplicateSigmaEvidence;
            }
        }

        return LocalProcessRiskMappingFailure.None;
    }

    private static LocalProcessRiskMappingFailure ValidateYaraAttribution(
        YaraProcessAttributionResult? attribution,
        ProcessObservation observation,
        ProcessRiskAggregationPolicy aggregationPolicy,
        DateTime evaluatedUtc)
    {
        if (attribution == null)
        {
            return LocalProcessRiskMappingFailure.None;
        }

        if (attribution.Policy == null || attribution.Target == null ||
            attribution.Ruleset == null || attribution.EvidenceReferences == null ||
            attribution.Evidence == null || !Required(attribution.ScanId) ||
            !Enum.IsDefined(attribution.Availability) ||
            attribution.Availability == AnalysisSourceAvailability.Unknown ||
            !Required(attribution.ProcessEntityId) || !Optional(attribution.ProcessKey) ||
            !string.Equals(attribution.ProcessEntityId, observation.ProcessEntityId,
                StringComparison.Ordinal) ||
            !string.Equals(attribution.ProcessKey, observation.Fields.ProcessKey,
                StringComparison.Ordinal))
        {
            return LocalProcessRiskMappingFailure.InvalidYaraAttribution;
        }

        if (attribution.Evidence.Count > MaximumYaraEvidence)
        {
            return LocalProcessRiskMappingFailure.YaraInputLimitExceeded;
        }

        var policyDecision = YaraRiskPolicyContract.Validate(attribution.Policy);
        if (!policyDecision.Accepted || policyDecision.Policy == null ||
            attribution.Ruleset != policyDecision.Policy.Ruleset)
        {
            return LocalProcessRiskMappingFailure.InvalidYaraAttribution;
        }

        var scope = ScopeOf(observation.Fields);
        if (!ValidYaraTarget(attribution.Target, scope) ||
            !ValidateYaraReferences(
                attribution.EvidenceReferences,
                observation,
                attribution.Target) ||
            (attribution.Availability != AnalysisSourceAvailability.Available &&
             (attribution.Evidence.Count != 0 || attribution.IsTruncated)))
        {
            return LocalProcessRiskMappingFailure.InvalidYaraAttribution;
        }

        var acceptedPolicy = policyDecision.Policy;
        var severityBounds = aggregationPolicy.SeverityDeltaBounds
            .ToDictionary(item => item.Severity);
        var matchIds = new HashSet<string>(StringComparer.Ordinal);
        var canonicalInputs = new HashSet<string>(StringComparer.Ordinal);
        DateTime? completedUtc = null;
        string? correlationMethod = null;
        foreach (var item in attribution.Evidence)
        {
            if (item == null || item.Ruleset == null || item.Target == null ||
                item.EvidenceReferences == null || !Required(item.MatchId))
            {
                return LocalProcessRiskMappingFailure.InvalidYaraAttribution;
            }

            if (!matchIds.Add(item.MatchId))
            {
                return LocalProcessRiskMappingFailure.DuplicateYaraEvidence;
            }

            if (!Required(item.ScanId) ||
                !string.Equals(item.ScanId, attribution.ScanId, StringComparison.Ordinal) ||
                !Required(item.RuleNamespace) || !Required(item.RuleId) ||
                !Enum.IsDefined(item.Severity) ||
                item.Severity == AnalysisFindingSeverity.Unknown ||
                !Required(item.PolicyId) || !Required(item.PolicyVersion) ||
                !Required(item.ReviewerId) || !Required(item.ReviewPolicyId) ||
                !Required(item.ReviewPolicyVersion) ||
                item.ReviewedUtc.Kind != DateTimeKind.Utc ||
                item.CompletedUtc.Kind != DateTimeKind.Utc ||
                item.ReviewedUtc > item.CompletedUtc || item.CompletedUtc > evaluatedUtc ||
                !string.Equals(item.PolicyId, acceptedPolicy.PolicyId, StringComparison.Ordinal) ||
                !string.Equals(item.PolicyVersion, acceptedPolicy.PolicyVersion,
                    StringComparison.Ordinal) ||
                !string.Equals(item.ReviewerId, acceptedPolicy.ReviewerId,
                    StringComparison.Ordinal) ||
                !string.Equals(item.ReviewPolicyId, acceptedPolicy.ReviewPolicyId,
                    StringComparison.Ordinal) ||
                !string.Equals(item.ReviewPolicyVersion, acceptedPolicy.ReviewPolicyVersion,
                    StringComparison.Ordinal) ||
                item.ReviewedUtc != acceptedPolicy.ReviewedUtc ||
                item.Ruleset != attribution.Ruleset || item.Target != attribution.Target ||
                !string.Equals(item.ProcessEntityId, attribution.ProcessEntityId,
                    StringComparison.Ordinal) ||
                !string.Equals(item.ProcessKey, attribution.ProcessKey, StringComparison.Ordinal) ||
                item.IsTruncated != attribution.IsTruncated ||
                !Enum.IsDefined(item.CorrelationState) ||
                item.CorrelationState != EvidenceCorrelationState.Exact ||
                item.CorrelationCandidateCount != 1 ||
                !Required(item.CorrelationMethod, MaximumCorrelationMethodLength) ||
                !SameReferenceSet(item.EvidenceReferences, attribution.EvidenceReferences) ||
                !ValidateYaraReferences(item.EvidenceReferences, observation, item.Target))
            {
                return LocalProcessRiskMappingFailure.InvalidYaraAttribution;
            }

            if (completedUtc.HasValue && completedUtc.Value != item.CompletedUtc ||
                correlationMethod != null &&
                !string.Equals(correlationMethod, item.CorrelationMethod, StringComparison.Ordinal))
            {
                return LocalProcessRiskMappingFailure.InvalidYaraAttribution;
            }

            completedUtc = item.CompletedUtc;
            correlationMethod = item.CorrelationMethod;
            var disposition = acceptedPolicy.Rules.SingleOrDefault(rule =>
                string.Equals(rule.RuleNamespace, item.RuleNamespace, StringComparison.Ordinal) &&
                string.Equals(rule.RuleId, item.RuleId, StringComparison.Ordinal));
            var expectedDelta = disposition?.Severity == AnalysisFindingSeverity.Informational
                ? (int?)null
                : disposition?.ScoreDelta;
            if (disposition == null)
            {
                if (item.IsPolicyMatched || item.Severity != AnalysisFindingSeverity.Informational ||
                    item.ScoreDelta.HasValue)
                {
                    return LocalProcessRiskMappingFailure.InvalidYaraAttribution;
                }
            }
            else if (!item.IsPolicyMatched || item.Severity != disposition.Severity ||
                     item.ScoreDelta != expectedDelta)
            {
                return LocalProcessRiskMappingFailure.InvalidYaraAttribution;
            }

            if (item.ScoreDelta is int scoreDelta &&
                (scoreDelta <= 0 ||
                 !severityBounds.TryGetValue(item.Severity, out var bound) ||
                 scoreDelta > bound.MaximumAbsoluteDelta))
            {
                return LocalProcessRiskMappingFailure.InvalidYaraAttribution;
            }

            if (!canonicalInputs.Add(Sha256(
                    YaraEvidenceCanonical(item, observation.Fields, includeMatchId: false))))
            {
                return LocalProcessRiskMappingFailure.DuplicateYaraEvidence;
            }
        }

        return LocalProcessRiskMappingFailure.None;
    }

    private static bool ValidYaraTarget(YaraScanTarget target, EvidenceIdentity scope)
    {
        if (target.EvidenceIdentity == null || target.EvidenceReference == null ||
            !Enum.IsDefined(target.Kind) || target.Kind == YaraScanTargetKind.Unknown ||
            !ValidScope(target.EvidenceIdentity) || !SameScope(target.EvidenceIdentity, scope) ||
            !Required(target.SourceRunId) || !Required(target.EvidenceReference.Id) ||
            !ValidSha256(target.ContentHashSha256) || target.OffsetBytes < 0 ||
            target.LengthBytes <= 0 ||
            target.LengthBytes > YaraAnalysisContractPolicy.MaximumTargetBytes)
        {
            return false;
        }

        return target.Kind switch
        {
            YaraScanTargetKind.FileArtifact =>
                target.EvidenceReference.Kind == EvidenceReferenceKind.FileArtifact &&
                target.OffsetBytes == 0,
            YaraScanTargetKind.MemoryDump =>
                target.EvidenceReference.Kind == EvidenceReferenceKind.MemoryDump &&
                target.OffsetBytes == 0,
            YaraScanTargetKind.MemoryImageRegion =>
                target.EvidenceReference.Kind == EvidenceReferenceKind.MemoryImage &&
                target.OffsetBytes <= long.MaxValue - target.LengthBytes,
            _ => false
        };
    }

    private static bool ValidateYaraReferences(
        IReadOnlyList<EvidenceReference>? references,
        ProcessObservation observation,
        YaraScanTarget target)
    {
        if (references == null || references.Count < 3 ||
            references.Count > MaximumYaraEvidenceReferences)
        {
            return false;
        }

        var identities = new HashSet<EvidenceReference>();
        var processCount = 0;
        var sourceRunCount = 0;
        var targetCount = 0;
        foreach (var reference in references)
        {
            if (reference == null || !Enum.IsDefined(reference.Kind) ||
                !YaraReferenceKinds.Contains(reference.Kind) || !Required(reference.Id) ||
                !identities.Add(reference))
            {
                return false;
            }

            if (reference.Kind == EvidenceReferenceKind.ProcessEntity)
            {
                processCount++;
                if (!string.Equals(reference.Id, observation.ProcessEntityId,
                        StringComparison.Ordinal))
                {
                    return false;
                }
            }
            else if (reference.Kind == EvidenceReferenceKind.ProcessObservation &&
                     !string.Equals(reference.Id, observation.ObservationId,
                         StringComparison.Ordinal))
            {
                return false;
            }
            else if (reference.Kind == EvidenceReferenceKind.SourceRun)
            {
                sourceRunCount++;
                if (!string.Equals(reference.Id, target.SourceRunId, StringComparison.Ordinal))
                {
                    return false;
                }
            }

            if (reference.Kind is EvidenceReferenceKind.FileArtifact or
                EvidenceReferenceKind.MemoryDump or EvidenceReferenceKind.MemoryImage)
            {
                targetCount++;
                if (reference != target.EvidenceReference)
                {
                    return false;
                }
            }
        }

        return processCount == 1 && sourceRunCount == 1 && targetCount == 1;
    }

    private static bool SameReferenceSet(
        IReadOnlyList<EvidenceReference> left,
        IReadOnlyList<EvidenceReference> right) =>
        left.Count == right.Count && left.ToHashSet().SetEquals(right);

    private static LocalProcessRiskMappingFailure ValidateFilesystemEvidence(
        IReadOnlyList<LocalProcessFilesystemEvidence>? evidence,
        ProcessObservation observation,
        DateTime evaluatedUtc)
    {
        if (evidence == null)
        {
            return LocalProcessRiskMappingFailure.InvalidFilesystemEvidence;
        }

        if (evidence.Count > MaximumFilesystemEvidence)
        {
            return LocalProcessRiskMappingFailure.FilesystemInputLimitExceeded;
        }

        var observationScope = ScopeOf(observation.Fields);
        var artifactIds = new HashSet<string>(StringComparer.Ordinal);
        var relationIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in evidence)
        {
            if (item?.Artifact == null || item.Relation == null)
            {
                return LocalProcessRiskMappingFailure.InvalidFilesystemEvidence;
            }

            var artifact = item.Artifact;
            var relation = item.Relation;
            if (!artifactIds.Add(artifact.ArtifactId) || !relationIds.Add(relation.RelationId))
            {
                return LocalProcessRiskMappingFailure.DuplicateFilesystemEvidence;
            }

            if (!Required(artifact.ArtifactId) || !Required(artifact.SourceRunId) ||
                !Required(artifact.Source) || !Enum.IsDefined(artifact.Kind) ||
                artifact.Kind == FilesystemArtifactKind.Unknown ||
                artifact.Status != FilesystemArtifactStatus.Imported ||
                artifact.TimestampUtc.Kind != DateTimeKind.Utc || artifact.TimestampUtc > evaluatedUtc ||
                !ValidOptionalUtc(artifact.CreatedUtc, evaluatedUtc) ||
                !ValidOptionalUtc(artifact.LastModifiedUtc, evaluatedUtc) ||
                !ValidOptionalUtc(artifact.LastRunUtc, evaluatedUtc) ||
                artifact.FileSizeBytes < 0 || !ValidOptionalSha256(artifact.Sha256Hash) ||
                !Bounded(artifact.Name, MaximumIdentityLength) ||
                !Bounded(artifact.SourcePath, MaximumPathLength) ||
                !ValidScope(ScopeOf(artifact)) ||
                !SameInvestigationScope(ScopeOf(artifact), observationScope))
            {
                return LocalProcessRiskMappingFailure.InvalidFilesystemEvidence;
            }

            if (!Required(relation.RelationId) || !Required(relation.SourceRunId) ||
                relation.FromKind != EvidenceReferenceKind.ProcessEntity ||
                relation.ToKind != EvidenceReferenceKind.FileArtifact ||
                !string.Equals(relation.FromId, observation.ProcessEntityId, StringComparison.Ordinal) ||
                !string.Equals(relation.ToId, artifact.ArtifactId, StringComparison.Ordinal) ||
                !Enum.IsDefined(relation.RelationType) ||
                relation.State != EvidenceCorrelationState.Exact ||
                relation.Status != EvidenceRelationStatus.Active ||
                relation.CandidateCount != 1 || relation.Confidence != 1 ||
                !Required(relation.CorrelationMethod) ||
                relation.ObservedFromUtc.Kind != DateTimeKind.Utc ||
                relation.CreatedUtc.Kind != DateTimeKind.Utc ||
                relation.UpdatedUtc.Kind != DateTimeKind.Utc ||
                relation.ObservedFromUtc > evaluatedUtc ||
                relation.CreatedUtc > evaluatedUtc || relation.UpdatedUtc > evaluatedUtc ||
                !ValidOptionalUtc(relation.ObservedToUtc, evaluatedUtc) ||
                !ValidOptionalUtc(relation.ValidFromUtc, evaluatedUtc) ||
                !ValidOptionalUtc(relation.ValidToUtc, evaluatedUtc) ||
                relation.UpdatedUtc < relation.CreatedUtc ||
                relation.ObservedToUtc < relation.ObservedFromUtc ||
                relation.ValidToUtc < relation.ValidFromUtc ||
                !ValidScope(ScopeOf(relation)) ||
                !SameInvestigationScope(ScopeOf(relation), observationScope) ||
                !SameInvestigationScope(ScopeOf(relation), ScopeOf(artifact)))
            {
                return LocalProcessRiskMappingFailure.InvalidFilesystemEvidence;
            }
        }

        return LocalProcessRiskMappingFailure.None;
    }

    private static LocalProcessRiskMappingFailure ValidateMemoryEvidence(
        IReadOnlyList<LocalProcessMemoryEvidence>? evidence,
        ProcessObservation observation,
        DateTime evaluatedUtc)
    {
        if (evidence == null)
        {
            return LocalProcessRiskMappingFailure.InvalidMemoryEvidence;
        }

        if (evidence.Count > MaximumMemoryEvidence)
        {
            return LocalProcessRiskMappingFailure.MemoryInputLimitExceeded;
        }

        var observationScope = ScopeOf(observation.Fields);
        var artifactIds = new HashSet<string>(StringComparer.Ordinal);
        var relationIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in evidence)
        {
            if (item?.MemoryProcess == null || item.Relation == null)
            {
                return LocalProcessRiskMappingFailure.InvalidMemoryEvidence;
            }

            var memoryProcess = item.MemoryProcess;
            var relation = item.Relation;
            if (!artifactIds.Add(memoryProcess.ArtifactId) || !relationIds.Add(relation.RelationId))
            {
                return LocalProcessRiskMappingFailure.DuplicateMemoryEvidence;
            }

            if (!Required(memoryProcess.ArtifactId) || !Required(memoryProcess.ImageId) ||
                !Required(memoryProcess.PluginRunId) || !Required(memoryProcess.PluginName) ||
                !Required(memoryProcess.SourceRunId) || !Required(memoryProcess.Source) ||
                !Optional(memoryProcess.IngestionJobId) ||
                !Enum.IsDefined(memoryProcess.EvidenceKind) ||
                memoryProcess.EvidenceKind == MemoryProcessEvidenceKind.Unknown ||
                !Enum.IsDefined(memoryProcess.CorrelationState) ||
                memoryProcess.CorrelationState != MemoryProcessCorrelationState.Correlated ||
                !double.IsFinite(memoryProcess.CorrelationConfidence) ||
                memoryProcess.CorrelationConfidence <= 0 ||
                memoryProcess.CorrelationConfidence > 1 ||
                !Required(memoryProcess.CorrelationMethod) ||
                memoryProcess.ProcessId <= 0 || memoryProcess.ParentProcessId < 0 ||
                memoryProcess.RowNumber < 0 || memoryProcess.SessionId < 0 ||
                memoryProcess.ThreadCount < 0 || memoryProcess.HandleCount < 0 ||
                !Optional(memoryProcess.ProcessKey) ||
                !Bounded(memoryProcess.ObjectOffset, MaximumIdentityLength) ||
                !Bounded(memoryProcess.ProcessName, MaximumIdentityLength) ||
                !Bounded(memoryProcess.ImagePath, MaximumPathLength) ||
                !Bounded(memoryProcess.CommandLine, MaximumEventDetailsLength) ||
                !Bounded(memoryProcess.Wow64, MaximumIdentityLength) ||
                !ValidOptionalSha256(memoryProcess.RawRowHash) ||
                !Bounded(memoryProcess.RawJson, MaximumEventDetailsLength) ||
                !ValidOptionalUtc(memoryProcess.CreateTimeUtc, evaluatedUtc) ||
                !ValidOptionalUtc(memoryProcess.ExitTimeUtc, evaluatedUtc) ||
                memoryProcess.ExitTimeUtc < memoryProcess.CreateTimeUtc ||
                !ValidScope(ScopeOf(memoryProcess)) ||
                !SameInvestigationScope(ScopeOf(memoryProcess), observationScope) ||
                memoryProcess.ProcessId != observation.Fields.ProcessId ||
                (!string.IsNullOrWhiteSpace(memoryProcess.ProcessKey) &&
                 !string.IsNullOrWhiteSpace(observation.Fields.ProcessKey) &&
                 !string.Equals(memoryProcess.ProcessKey, observation.Fields.ProcessKey,
                     StringComparison.Ordinal)))
            {
                return LocalProcessRiskMappingFailure.InvalidMemoryEvidence;
            }

            if (!Required(relation.RelationId) || !Required(relation.DecisionKey) ||
                !Required(relation.SourceRunId) || !Required(relation.CorrelationMethod) ||
                !Required(relation.ResolverName) || !Required(relation.ResolverVersion) ||
                !Optional(relation.RawInputId) ||
                relation.FromKind != EvidenceReferenceKind.MemoryProcess ||
                relation.ToKind != EvidenceReferenceKind.ProcessEntity ||
                !string.Equals(relation.FromId, memoryProcess.ArtifactId, StringComparison.Ordinal) ||
                !string.Equals(relation.ToId, observation.ProcessEntityId, StringComparison.Ordinal) ||
                relation.RelationType != EvidenceRelationType.CorrelatesWith ||
                relation.State != EvidenceCorrelationState.Exact ||
                relation.Status != EvidenceRelationStatus.Active ||
                !string.IsNullOrEmpty(relation.SupersededByRelationId) ||
                relation.CandidateCount != 1 || relation.Confidence != 1 ||
                relation.ObservedFromUtc.Kind != DateTimeKind.Utc ||
                relation.CreatedUtc.Kind != DateTimeKind.Utc ||
                relation.UpdatedUtc.Kind != DateTimeKind.Utc ||
                relation.ObservedFromUtc > evaluatedUtc ||
                relation.CreatedUtc > evaluatedUtc || relation.UpdatedUtc > evaluatedUtc ||
                !ValidOptionalUtc(relation.ObservedToUtc, evaluatedUtc) ||
                !ValidOptionalUtc(relation.ValidFromUtc, evaluatedUtc) ||
                !ValidOptionalUtc(relation.ValidToUtc, evaluatedUtc) ||
                relation.UpdatedUtc < relation.CreatedUtc ||
                relation.ObservedToUtc < relation.ObservedFromUtc ||
                relation.ValidToUtc < relation.ValidFromUtc ||
                !ValidScope(ScopeOf(relation)) ||
                !SameScope(ScopeOf(relation), ScopeOf(memoryProcess)) ||
                !string.Equals(relation.SourceRunId, memoryProcess.SourceRunId,
                    StringComparison.Ordinal) ||
                (!string.IsNullOrWhiteSpace(memoryProcess.RawRowHash) &&
                 !string.IsNullOrWhiteSpace(relation.RawInputId) &&
                 !string.Equals(memoryProcess.RawRowHash, relation.RawInputId,
                     StringComparison.OrdinalIgnoreCase)))
            {
                return LocalProcessRiskMappingFailure.InvalidMemoryEvidence;
            }
        }

        return LocalProcessRiskMappingFailure.None;
    }

    private static LocalProcessRiskMappingFailure ValidateNetworkEvents(
        IReadOnlyList<TelemetryEventRecord>? events,
        ProcessObservation observation,
        DateTime evaluatedUtc)
    {
        if (events == null)
        {
            return LocalProcessRiskMappingFailure.InvalidNetworkEvent;
        }

        if (events.Count > MaximumNetworkEventRecords)
        {
            return LocalProcessRiskMappingFailure.NetworkInputLimitExceeded;
        }

        var commonFailure = ValidateEvents(events, observation, evaluatedUtc);
        if (commonFailure != LocalProcessRiskMappingFailure.None)
        {
            return commonFailure switch
            {
                LocalProcessRiskMappingFailure.EventInputLimitExceeded =>
                    LocalProcessRiskMappingFailure.NetworkInputLimitExceeded,
                LocalProcessRiskMappingFailure.DuplicateProcessEvent =>
                    LocalProcessRiskMappingFailure.DuplicateNetworkEvent,
                _ => LocalProcessRiskMappingFailure.InvalidNetworkEvent
            };
        }

        return events.Any(item => item.Action is not ProcessEventAction.Connect and
                not ProcessEventAction.DnsQuery)
            ? LocalProcessRiskMappingFailure.InvalidNetworkEvent
            : LocalProcessRiskMappingFailure.None;
    }

    private static LocalProcessRiskMappingFailure ValidateEvents(
        IReadOnlyList<TelemetryEventRecord>? events,
        ProcessObservation observation,
        DateTime evaluatedUtc)
    {
        if (events == null)
        {
            return LocalProcessRiskMappingFailure.InvalidProcessEvent;
        }

        if (events.Count > MaximumEventRecords)
        {
            return LocalProcessRiskMappingFailure.EventInputLimitExceeded;
        }

        var observationScope = ScopeOf(observation.Fields);
        var sequenceIds = new HashSet<long>();
        foreach (var processEvent in events)
        {
            if (processEvent == null)
            {
                return LocalProcessRiskMappingFailure.InvalidProcessEvent;
            }

            if (!sequenceIds.Add(processEvent.SequenceId))
            {
                return LocalProcessRiskMappingFailure.DuplicateProcessEvent;
            }

            if (processEvent.SequenceId <= 0 ||
                !Enum.IsDefined(processEvent.Category) ||
                !Enum.IsDefined(processEvent.Action) ||
                !Enum.IsDefined(processEvent.CorrelationState) ||
                processEvent.CorrelationState != EvidenceCorrelationState.Exact ||
                processEvent.CorrelationCandidateCount != 1 ||
                processEvent.TimestampUtc.Kind != DateTimeKind.Utc ||
                processEvent.TimestampUtc > evaluatedUtc ||
                processEvent.ProcessId < 0 || processEvent.ParentProcessId < 0 ||
                processEvent.RepeatCount <= 0 || processEvent.RepeatCount > 1_000_000 ||
                !Required(processEvent.ProcessEntityId) ||
                !Optional(processEvent.ProcessKey) ||
                !Required(processEvent.SourceRunId) ||
                !Optional(processEvent.IngestionJobId) ||
                !Required(processEvent.Source) ||
                !Required(processEvent.CorrelationMethod) ||
                !Bounded(processEvent.ProcessGuid, MaximumIdentityLength) ||
                !Bounded(processEvent.ProcessName, MaximumIdentityLength) ||
                !Bounded(processEvent.Target, MaximumPathLength) ||
                !Bounded(processEvent.Summary, MaximumEventSummaryLength) ||
                !Bounded(processEvent.Details, MaximumEventDetailsLength) ||
                !Bounded(processEvent.RiskFlags, MaximumEventSummaryLength) ||
                !Bounded(processEvent.RawProvider, MaximumIdentityLength) ||
                !Bounded(processEvent.RawLogName, MaximumIdentityLength) ||
                !Bounded(processEvent.RawRecordId, MaximumIdentityLength) ||
                !Bounded(processEvent.CorrelationDiagnostics, MaximumEventDiagnosticLength) ||
                !ValidScope(ScopeOf(processEvent)) ||
                !SameInvestigationScope(ScopeOf(processEvent), observationScope) ||
                !string.Equals(
                    processEvent.ProcessEntityId,
                    observation.ProcessEntityId,
                    StringComparison.Ordinal) ||
                (!string.IsNullOrWhiteSpace(processEvent.ProcessKey) &&
                 !string.IsNullOrWhiteSpace(observation.Fields.ProcessKey) &&
                 !string.Equals(
                     processEvent.ProcessKey,
                     observation.Fields.ProcessKey,
                     StringComparison.Ordinal)) ||
                processEvent.ProcessStartTimeUtc is { } startUtc &&
                (startUtc.Kind != DateTimeKind.Utc || startUtc > processEvent.TimestampUtc))
            {
                return LocalProcessRiskMappingFailure.InvalidProcessEvent;
            }
        }

        return LocalProcessRiskMappingFailure.None;
    }

    private static LocalProcessRiskMappingFailure ValidatePe(
        PeAnalysisRecord? pe,
        ProcessObservation observation,
        DateTime evaluatedUtc)
    {
        if (pe == null)
        {
            return LocalProcessRiskMappingFailure.None;
        }

        if (!Required(pe.AnalysisId) || !Required(pe.ProcessEntityId) || !Optional(pe.ProcessKey) ||
            !Required(pe.SourceRunId) || !Enum.IsDefined(pe.SourceKind) ||
            pe.SourceKind != PeAnalysisSourceKind.ProcessImage || !Enum.IsDefined(pe.Status) ||
            pe.AnalyzedUtc.Kind != DateTimeKind.Utc || pe.AnalyzedUtc > evaluatedUtc ||
            !Bounded(pe.FilePath, MaximumPathLength) || !ValidOptionalSha256(pe.Sha256Hash))
        {
            return LocalProcessRiskMappingFailure.InvalidPeAnalysis;
        }

        if (!SameScope(ScopeOf(pe), ScopeOf(observation.Fields)) ||
            !string.Equals(pe.ProcessEntityId, observation.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(pe.ProcessKey, observation.Fields.ProcessKey, StringComparison.Ordinal))
        {
            return LocalProcessRiskMappingFailure.ProcessScopeMismatch;
        }

        return LocalProcessRiskMappingFailure.None;
    }

    private static LocalProcessRiskMappingFailure ValidateAuthenticode(
        AuthenticodeVerificationRecord? verification,
        PeAnalysisRecord? pe,
        ProcessObservation observation,
        DateTime evaluatedUtc)
    {
        if (verification == null)
        {
            return LocalProcessRiskMappingFailure.None;
        }

        if (pe == null || !Required(verification.VerificationId) ||
            !Required(verification.AnalysisId) || !Required(verification.ProcessEntityId) ||
            !Optional(verification.ProcessKey) || !Required(verification.SourceRunId) ||
            !Enum.IsDefined(verification.SignatureKind) ||
            !Enum.IsDefined(verification.VerificationStatus) ||
            !Enum.IsDefined(verification.RevocationMode) ||
            !Enum.IsDefined(verification.RevocationStatus) ||
            verification.VerificationTimeUtc.Kind != DateTimeKind.Utc ||
            verification.VerificationTimeUtc > evaluatedUtc ||
            !Bounded(verification.FilePath, MaximumPathLength) ||
            !ValidOptionalSha256(verification.Sha256Hash))
        {
            return LocalProcessRiskMappingFailure.InvalidAuthenticodeVerification;
        }

        if (!SameScope(ScopeOf(verification), ScopeOf(observation.Fields)) ||
            !string.Equals(verification.ProcessEntityId, observation.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(verification.ProcessKey, observation.Fields.ProcessKey, StringComparison.Ordinal) ||
            !string.Equals(verification.AnalysisId, pe.AnalysisId, StringComparison.Ordinal))
        {
            return LocalProcessRiskMappingFailure.ProcessScopeMismatch;
        }

        if (!string.Equals(verification.SourceRunId, pe.SourceRunId, StringComparison.Ordinal))
        {
            return LocalProcessRiskMappingFailure.SourceRunMismatch;
        }

        var peHash = Concrete(pe.Sha256Hash);
        var verificationHash = Concrete(verification.Sha256Hash);
        if (peHash != null && verificationHash != null &&
            !string.Equals(peHash, verificationHash, StringComparison.OrdinalIgnoreCase))
        {
            return LocalProcessRiskMappingFailure.ContradictoryEvidence;
        }

        if ((RequiresSignature(verification.VerificationStatus) &&
             verification.SignatureKind is not AuthenticodeSignatureKind.Embedded and
                 not AuthenticodeSignatureKind.Catalog) ||
            (verification.VerificationStatus == AuthenticodeVerificationStatus.Unsigned &&
             verification.SignatureKind != AuthenticodeSignatureKind.None) ||
            verification.RevocationStatus != ExpectedRevocationStatus(verification.VerificationStatus))
        {
            return LocalProcessRiskMappingFailure.ContradictoryEvidence;
        }

        return LocalProcessRiskMappingFailure.None;
    }

    private static bool RequiresSignature(AuthenticodeVerificationStatus status) => status is
        AuthenticodeVerificationStatus.Valid or
        AuthenticodeVerificationStatus.Invalid or
        AuthenticodeVerificationStatus.Untrusted or
        AuthenticodeVerificationStatus.Expired or
        AuthenticodeVerificationStatus.Revoked or
        AuthenticodeVerificationStatus.RevocationUnavailable;

    private static AuthenticodeRevocationStatus ExpectedRevocationStatus(
        AuthenticodeVerificationStatus status) => status switch
        {
            AuthenticodeVerificationStatus.Valid => AuthenticodeRevocationStatus.Good,
            AuthenticodeVerificationStatus.Revoked => AuthenticodeRevocationStatus.Revoked,
            AuthenticodeVerificationStatus.RevocationUnavailable =>
                AuthenticodeRevocationStatus.Unavailable,
            AuthenticodeVerificationStatus.Unsigned or
                AuthenticodeVerificationStatus.FileMissing or
                AuthenticodeVerificationStatus.Unsupported =>
                AuthenticodeRevocationStatus.NotChecked,
            _ => AuthenticodeRevocationStatus.Unknown
        };

    private static AnalysisSourceAvailability ProcessMetadataFieldAvailability(
        ProcessObservation observation)
    {
        var states = new[]
        {
            FieldState(observation, nameof(ProcessRecord.ProcessName)),
            FieldState(observation, nameof(ProcessRecord.ProcessPath))
        };
        if (states.Any(state => state is ProcessObservationValueState.AccessDenied or
                ProcessObservationValueState.Unavailable))
        {
            return AnalysisSourceAvailability.Unavailable;
        }

        return states.Any(state => state == ProcessObservationValueState.NotCollected)
            ? AnalysisSourceAvailability.NotCollected
            : AnalysisSourceAvailability.Available;
    }

    private static ProcessObservationValueState? FieldState(ProcessObservation observation, string name) =>
        observation.FieldStates.TryGetValue(name, out var state) ? state : null;

    private static LocalMappedSource UnavailableSource(
        ProcessRiskSourceKind sourceKind,
        string sourceId,
        string ruleId,
        AnalysisSourceAvailability availability,
        string diagnostic,
        string sourceRunId,
        DateTime createdUtc,
        string canonicalInput) =>
        new(
            sourceKind,
            sourceId,
            ruleId,
            availability,
            AnalysisFindingSeverity.Unknown,
            0,
            $"The {sourceId} input is {availability}.",
            diagnostic,
            null,
            sourceRunId,
            createdUtc,
            Array.Empty<EvidenceReference>(),
            canonicalInput);

    private static bool IsSupportedPolicy(ProcessRiskAggregationPolicy? policy)
    {
        if (policy == null)
        {
            return false;
        }

        return IsExactPolicy(policy, ProcessRiskAggregationPolicy.LocalFirstVersion1) ||
               IsExactPolicy(policy, ProcessRiskAggregationPolicy.LocalFirstVersion2);
    }

    private static bool IsExactPolicy(
        ProcessRiskAggregationPolicy policy,
        ProcessRiskAggregationPolicy expected) =>
        policy.SchemaVersion == expected.SchemaVersion &&
               string.Equals(policy.PolicyId, expected.PolicyId, StringComparison.Ordinal) &&
               string.Equals(policy.PolicyVersion, expected.PolicyVersion, StringComparison.Ordinal) &&
               policy.MaximumFindings == expected.MaximumFindings &&
               policy.MaximumSignals == expected.MaximumSignals &&
               SequenceEqual(policy.Sources, expected.Sources, item => item.SourceKind) &&
               SequenceEqual(policy.SeverityDeltaBounds, expected.SeverityDeltaBounds, item => item.Severity) &&
               SequenceEqual(policy.BandThresholds, expected.BandThresholds, item => item.Band);

    private static bool SequenceEqual<T, TKey>(
        IReadOnlyList<T>? actual,
        IReadOnlyList<T> expected,
        Func<T, TKey> keySelector)
        where TKey : struct, Enum =>
        actual != null &&
        actual.OrderBy(keySelector).SequenceEqual(expected.OrderBy(keySelector));

    private static EvidenceIdentity ScopeOf(IHasEvidenceIdentity evidence) => new()
    {
        CaseId = evidence.CaseId,
        EvidenceSessionId = evidence.EvidenceSessionId,
        CaptureId = evidence.CaptureId,
        SourceIdentityId = evidence.SourceIdentityId,
        HostId = evidence.HostId,
        ExecutionRootId = evidence.ExecutionRootId
    };

    private static bool ValidScope(EvidenceIdentity scope) =>
        Optional(scope.CaseId) && Required(scope.EvidenceSessionId) && Optional(scope.CaptureId) &&
        Required(scope.SourceIdentityId) && Required(scope.HostId) && Required(scope.ExecutionRootId);

    private static bool SameScope(EvidenceIdentity left, EvidenceIdentity right) =>
        string.Equals(left.CaseId, right.CaseId, StringComparison.Ordinal) &&
        string.Equals(left.EvidenceSessionId, right.EvidenceSessionId, StringComparison.Ordinal) &&
        string.Equals(left.CaptureId, right.CaptureId, StringComparison.Ordinal) &&
        string.Equals(left.SourceIdentityId, right.SourceIdentityId, StringComparison.Ordinal) &&
        string.Equals(left.HostId, right.HostId, StringComparison.Ordinal) &&
        string.Equals(left.ExecutionRootId, right.ExecutionRootId, StringComparison.Ordinal);

    private static bool SameInvestigationScope(EvidenceIdentity left, EvidenceIdentity right) =>
        string.Equals(left.CaseId, right.CaseId, StringComparison.Ordinal) &&
        string.Equals(left.EvidenceSessionId, right.EvidenceSessionId, StringComparison.Ordinal) &&
        string.Equals(left.CaptureId, right.CaptureId, StringComparison.Ordinal) &&
        string.Equals(left.HostId, right.HostId, StringComparison.Ordinal) &&
        string.Equals(left.ExecutionRootId, right.ExecutionRootId, StringComparison.Ordinal);

    private static bool Required(
        string? value,
        int maximumLength = MaximumIdentityLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;

    private static bool Optional(string? value) => value != null && value.Length <= MaximumIdentityLength;

    private static bool Bounded(string? value, int maximumLength) =>
        value != null && value.Length <= maximumLength;

    private static bool ValidOptionalSha256(string? value)
    {
        var concrete = Concrete(value);
        return concrete == null || concrete.Length == 64 && concrete.All(Uri.IsHexDigit);
    }

    private static bool ValidSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static bool ValidOptionalUtc(DateTime? value, DateTime evaluatedUtc) =>
        value is not { } timestamp ||
        timestamp.Kind == DateTimeKind.Utc && timestamp <= evaluatedUtc;

    private static string? Concrete(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed.Equals("<not available>", StringComparison.OrdinalIgnoreCase) ||
               trimmed.Equals("<unknown>", StringComparison.OrdinalIgnoreCase)
            ? null
            : trimmed;
    }

    private static string? FileName(string path)
    {
        var trimmed = path.TrimEnd('\\', '/');
        if (trimmed.Length == 0)
        {
            return null;
        }

        var separator = Math.Max(trimmed.LastIndexOf('\\'), trimmed.LastIndexOf('/'));
        return separator == trimmed.Length - 1 ? null : trimmed[(separator + 1)..];
    }

    private static string ScopeCanonical(EvidenceIdentity scope, string processEntityId, string processKey) =>
        Canonical(
            ("case-id", scope.CaseId),
            ("session-id", scope.EvidenceSessionId),
            ("capture-id", scope.CaptureId),
            ("source-identity-id", scope.SourceIdentityId),
            ("host-id", scope.HostId),
            ("execution-root-id", scope.ExecutionRootId),
            ("process-entity-id", processEntityId),
            ("process-key", processKey));

    private static string StableId(string prefix, string canonical) =>
        $"{prefix}-{Sha256(canonical)[..32]}";

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string Canonical(params (string Name, string Value)[] fields)
    {
        var builder = new StringBuilder();
        foreach (var field in fields)
        {
            builder.Append(field.Name.Length.ToString(CultureInfo.InvariantCulture))
                .Append(':')
                .Append(field.Name)
                .Append('=')
                .Append(field.Value.Length.ToString(CultureInfo.InvariantCulture))
                .Append(':')
                .Append(field.Value)
                .Append(';');
        }

        return builder.ToString();
    }

    private static string Utc(DateTime value) => value.ToString("O", CultureInfo.InvariantCulture);

    private static string ObservationDiagnostic(LocalProcessRiskMappingFailure failure) => failure switch
    {
        LocalProcessRiskMappingFailure.ContradictoryEvidence =>
            "The process observation marks a required field available but carries no concrete value.",
        _ => "The process observation identity, scope, provenance, timestamp, enum, hash, or bounded field is invalid."
    };

    private static string PeDiagnostic(LocalProcessRiskMappingFailure failure) => failure switch
    {
        LocalProcessRiskMappingFailure.ProcessScopeMismatch =>
            "The PE analysis does not target the exact process observation scope and identity.",
        _ => "The PE analysis identity, source kind, provenance, timestamp, enum, hash, or bounded field is invalid."
    };

    private static string AuthenticodeDiagnostic(LocalProcessRiskMappingFailure failure) => failure switch
    {
        LocalProcessRiskMappingFailure.ProcessScopeMismatch =>
            "The Authenticode verification does not target the exact PE analysis and process scope.",
        LocalProcessRiskMappingFailure.SourceRunMismatch =>
            "The Authenticode verification does not preserve the linked PE analysis source-run provenance.",
        LocalProcessRiskMappingFailure.ContradictoryEvidence =>
            "The Authenticode verification contains contradictory signature, revocation, or file-hash evidence.",
        _ => "The Authenticode identity, provenance, timestamp, enum, hash, or bounded field is invalid."
    };

    private static string EventDiagnostic(LocalProcessRiskMappingFailure failure) => failure switch
    {
        LocalProcessRiskMappingFailure.EventInputLimitExceeded =>
            $"The event input exceeds the bounded maximum of {MaximumEventRecords} exact records.",
        LocalProcessRiskMappingFailure.DuplicateProcessEvent =>
            "The event input repeats an immutable event sequence identity.",
        _ =>
            "An event identity, exact correlation, process scope, provenance, timestamp, enum, count, or bounded field is invalid."
    };

    private static string NetworkEventDiagnostic(LocalProcessRiskMappingFailure failure) => failure switch
    {
        LocalProcessRiskMappingFailure.NetworkInputLimitExceeded =>
            $"The network/DNS input exceeds the independent bounded maximum of {MaximumNetworkEventRecords} exact records.",
        LocalProcessRiskMappingFailure.DuplicateNetworkEvent =>
            "The network/DNS input repeats an immutable event sequence identity.",
        _ =>
            "A network/DNS event action, identity, exact correlation, process scope, provenance, timestamp, enum, count, or bounded field is invalid."
    };

    private static string FilesystemDiagnostic(LocalProcessRiskMappingFailure failure) => failure switch
    {
        LocalProcessRiskMappingFailure.FilesystemInputLimitExceeded =>
            $"The filesystem input exceeds the independent bounded maximum of {MaximumFilesystemEvidence} exact records.",
        LocalProcessRiskMappingFailure.DuplicateFilesystemEvidence =>
            "The filesystem input repeats an immutable artifact or relation identity.",
        _ =>
            "A filesystem artifact or its active exact process relation has invalid identity, direction, scope, provenance, timestamp, state, or bounded metadata."
    };

    private static string MemoryDiagnostic(LocalProcessRiskMappingFailure failure) => failure switch
    {
        LocalProcessRiskMappingFailure.MemoryInputLimitExceeded =>
            $"The memory/Volatility input exceeds the independent bounded maximum of {MaximumMemoryEvidence} exact records.",
        LocalProcessRiskMappingFailure.DuplicateMemoryEvidence =>
            "The memory/Volatility input repeats an immutable memory-process artifact or relation identity.",
        _ =>
            "A Volatility memory-process row or its active exact process relation has invalid identity, direction, scope, provenance, timestamp, correlation, state, or bounded metadata."
    };

    private static string SigmaDiagnostic(LocalProcessRiskMappingFailure failure) => failure switch
    {
        LocalProcessRiskMappingFailure.SigmaInputLimitExceeded =>
            $"The Sigma input exceeds the independent bounded maximum of {MaximumSigmaEvidence} exact matches.",
        LocalProcessRiskMappingFailure.DuplicateSigmaEvidence =>
            "The Sigma input repeats a producer match identity or canonical normalized match.",
        _ =>
            "A normalized Sigma match has invalid identity, rule version, scope, exact correlation, provenance, timestamp, hash, or evidence references."
    };

    private static string BaselineDiagnostic(LocalProcessRiskMappingFailure failure) => failure switch
    {
        LocalProcessRiskMappingFailure.BaselineInputLimitExceeded =>
            $"The baseline-comparison input exceeds the independent bounded maximum of {MaximumBaselineComparisonEvidence} exact findings.",
        LocalProcessRiskMappingFailure.DuplicateBaselineComparisonEvidence =>
            "The baseline-comparison input repeats a producer finding identity or canonical normalized finding.",
        _ =>
            "A normalized baseline-comparison finding has invalid identity, version, snapshot/fingerprint hash, verdict shape, scope, exact correlation, timestamp, policy identity, or evidence references."
    };

    private static string YaraDiagnostic(LocalProcessRiskMappingFailure failure) => failure switch
    {
        LocalProcessRiskMappingFailure.YaraInputLimitExceeded =>
            $"The YARA input exceeds the independent bounded maximum of {MaximumYaraEvidence} exact attributed matches.",
        LocalProcessRiskMappingFailure.DuplicateYaraEvidence =>
            "The YARA input repeats a scan/match identity or canonical review-gated attribution.",
        _ =>
            "A YARA attribution has invalid policy/reviewer/ruleset/target/process/source-run/correlation/reference/timestamp or reviewed positive-delta identity."
    };

    private static LocalProcessRiskMappingDecision Reject(
        LocalProcessRiskMappingFailure failure,
        string diagnostic) =>
        new() { Failure = failure, Diagnostic = diagnostic };

    private sealed record LocalMappedSource(
        ProcessRiskSourceKind SourceKind,
        string SourceId,
        string RuleId,
        AnalysisSourceAvailability Availability,
        AnalysisFindingSeverity Severity,
        double Confidence,
        string Summary,
        string Diagnostic,
        int? ScoreDelta,
        string SourceRunId,
        DateTime CreatedUtc,
        IReadOnlyList<EvidenceReference> References,
        string CanonicalInput,
        string RuleVersion = "");

    private sealed record AuthenticodeMapping(
        AnalysisFindingSeverity Severity,
        double Confidence,
        int? ScoreDelta,
        string Summary,
        string Diagnostic);

    private sealed record EventActionRiskRule(
        string RuleId,
        AnalysisFindingSeverity Severity,
        double Confidence,
        int ScoreDelta,
        string Summary,
        string Diagnostic);
}
