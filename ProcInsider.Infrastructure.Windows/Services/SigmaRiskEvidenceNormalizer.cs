using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum SigmaRiskEvidenceNormalizationFailure
{
    None = 0,
    InvalidRequest = 1,
    UnsupportedSourceKind = 2,
    InvalidRuleIdentity = 3,
    UnknownLevel = 4,
    InvalidEvidenceIdentity = 5,
    InvalidEventIdentity = 6,
    InvalidTimestamp = 7,
    WeakCorrelation = 8,
    FindingMismatch = 9,
    SyntheticEvidence = 10,
    InvalidProcessObservation = 11,
    InvalidModuleObservation = 12,
    InvalidHandleObservation = 13
}

public sealed record SigmaRiskEvidenceNormalizationRequest
{
    public SigmaFinding Finding { get; init; } = new();

    public TelemetryEventRecord? Event { get; init; }

    public ProcessObservation? ProcessObservation { get; init; }

    public ModuleObservationRecord? ModuleObservation { get; init; }

    public HandleObservationRecord? HandleObservation { get; init; }

    public string RuleId { get; init; } = string.Empty;

    public string RuleVersion { get; init; } = string.Empty;

    public string RuleContentHashSha256 { get; init; } = string.Empty;

    public DateTime EvaluatedUtc { get; init; }
}

public sealed record SigmaRiskEvidenceNormalizationDecision
{
    public bool Accepted { get; init; }

    public SigmaRiskEvidenceNormalizationFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public LocalProcessSigmaEvidence? Evidence { get; init; }
}

/// <summary>
/// Converts one rich Sigma UI finding into the portable Process Risk input only
/// when it cites one exact persisted event, process observation, module, or handle,
/// source run, and durable process.
/// </summary>
public static class SigmaRiskEvidenceNormalizer
{
    private const int MaximumIdentityLength = 512;
    private const string PersistedEventSourceKind = "Event";
    private const string PersistedProcessSourceKind = "Process";
    private const string PersistedModuleSourceKind = "Module";
    private const string PersistedHandleSourceKind = "Handle";
    private const string ExactProcessFindingCorrelationMethod = "ExactProcessEntityId";
    private const string ExactModuleFindingCorrelationMethod = "ExactModuleProcessEntityId";
    private const string ExactHandleFindingCorrelationMethod = "ExactHandleProcessEntityId";
    private const string SyntheticSourcePrefix = "IndependentArtifact:";
    private const string SyntheticRawProvider = "ProcInsider independent artifact projection";

    public static SigmaRiskEvidenceNormalizationDecision Normalize(
        SigmaRiskEvidenceNormalizationRequest? request)
    {
        if (request?.Finding == null)
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidRequest,
                "A Sigma finding and exactly one supported persisted source are required.");
        }

        var finding = request.Finding;
        var eventSource = string.Equals(finding.SourceKind, PersistedEventSourceKind, StringComparison.Ordinal);
        var processSource = string.Equals(finding.SourceKind, PersistedProcessSourceKind, StringComparison.Ordinal);
        var moduleSource = string.Equals(finding.SourceKind, PersistedModuleSourceKind, StringComparison.Ordinal);
        var handleSource = string.Equals(finding.SourceKind, PersistedHandleSourceKind, StringComparison.Ordinal);
        if (!eventSource && !processSource && !moduleSource && !handleSource)
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.UnsupportedSourceKind,
                "Only persisted Event, Process, Module, and Handle findings can enter this normalizer.");
        }

        var suppliedSourceCount =
            (request.Event == null ? 0 : 1) +
            (request.ProcessObservation == null ? 0 : 1) +
            (request.ModuleObservation == null ? 0 : 1) +
            (request.HandleObservation == null ? 0 : 1);
        if (suppliedSourceCount != 1 ||
            (eventSource && request.Event == null) ||
            (processSource && request.ProcessObservation == null) ||
            (moduleSource && request.ModuleObservation == null) ||
            (handleSource && request.HandleObservation == null))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidRequest,
                "The finding source kind must select exactly one matching persisted source payload.");
        }

        if (!Required(request.RuleId) ||
            !Required(request.RuleVersion) ||
            !ValidSha256(request.RuleContentHashSha256))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidRuleIdentity,
                "Rule ID, explicit version, and SHA-256 content identity are required.");
        }

        if (!string.Equals(finding.RuleId, request.RuleId, StringComparison.Ordinal))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.FindingMismatch,
                "The Sigma finding rule ID does not match the supplied versioned rule identity.");
        }

        if (!TryNormalizeLevel(finding.Level, out var level))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.UnknownLevel,
                "The Sigma level is not a supported normalized severity.");
        }

        if (eventSource)
        {
            return NormalizeEvent(request, finding, request.Event!, level);
        }

        if (processSource)
        {
            return NormalizeProcess(request, finding, request.ProcessObservation!, level);
        }

        return moduleSource
            ? NormalizeModule(request, finding, request.ModuleObservation!, level)
            : NormalizeHandle(request, finding, request.HandleObservation!, level);
    }

    private static SigmaRiskEvidenceNormalizationDecision NormalizeEvent(
        SigmaRiskEvidenceNormalizationRequest request,
        SigmaFinding finding,
        TelemetryEventRecord sourceEvent,
        AnalysisFindingSeverity level)
    {
        if (sourceEvent.Source?.StartsWith(SyntheticSourcePrefix, StringComparison.Ordinal) == true ||
            string.Equals(sourceEvent.RawProvider, SyntheticRawProvider, StringComparison.Ordinal))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.SyntheticEvidence,
                "In-memory independent-artifact projections are not persisted event evidence.");
        }

        if (!ValidScope(sourceEvent))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidEvidenceIdentity,
                "The persisted event must carry complete bounded evidence scope.");
        }

        if (sourceEvent.SequenceId <= 0 ||
            !Required(sourceEvent.ProcessEntityId) ||
            !Optional(sourceEvent.ProcessKey) ||
            !Required(sourceEvent.SourceRunId))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidEventIdentity,
                "The persisted event must carry a positive sequence, durable process, and source run.");
        }

        if (request.EvaluatedUtc.Kind != DateTimeKind.Utc ||
            sourceEvent.TimestampUtc.Kind != DateTimeKind.Utc ||
            sourceEvent.TimestampUtc > request.EvaluatedUtc ||
            finding.TimestampUtc is not { Kind: DateTimeKind.Utc } matchedUtc ||
            matchedUtc > request.EvaluatedUtc)
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidTimestamp,
                "Evaluation and match timestamps must be UTC and the match cannot be in the future.");
        }

        if (sourceEvent.CorrelationState != EvidenceCorrelationState.Exact ||
            sourceEvent.CorrelationCandidateCount != 1 ||
            !Required(sourceEvent.CorrelationMethod))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.WeakCorrelation,
                "Only one-candidate exact durable-process correlation is accepted.");
        }

        if (!string.Equals(finding.ProcessEntityId, sourceEvent.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(finding.ProcessKey, sourceEvent.ProcessKey, StringComparison.Ordinal) ||
            finding.TimestampUtc != sourceEvent.TimestampUtc ||
            finding.CorrelationState != sourceEvent.CorrelationState ||
            finding.CorrelationCandidateCount != sourceEvent.CorrelationCandidateCount ||
            !string.Equals(finding.CorrelationMethod, sourceEvent.CorrelationMethod, StringComparison.Ordinal))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.FindingMismatch,
                "The Sigma finding does not describe the supplied exact event identity.");
        }

        var scope = new EvidenceIdentity
        {
            CaseId = sourceEvent.CaseId,
            EvidenceSessionId = sourceEvent.EvidenceSessionId,
            CaptureId = sourceEvent.CaptureId,
            SourceIdentityId = sourceEvent.SourceIdentityId,
            HostId = sourceEvent.HostId,
            ExecutionRootId = sourceEvent.ExecutionRootId
        };
        var canonical = Canonical(
            ("rule-id", request.RuleId),
            ("rule-version", request.RuleVersion),
            ("rule-content-hash", request.RuleContentHashSha256.ToLowerInvariant()),
            ("level", level.ToString()),
            ("case-id", scope.CaseId),
            ("session-id", scope.EvidenceSessionId),
            ("capture-id", scope.CaptureId),
            ("source-identity-id", scope.SourceIdentityId),
            ("host-id", scope.HostId),
            ("execution-root-id", scope.ExecutionRootId),
            ("event-sequence-id", sourceEvent.SequenceId.ToString(CultureInfo.InvariantCulture)),
            ("process-entity-id", sourceEvent.ProcessEntityId),
            ("process-key", sourceEvent.ProcessKey),
            ("source-run-id", sourceEvent.SourceRunId),
            ("matched-utc", sourceEvent.TimestampUtc.ToString("O", CultureInfo.InvariantCulture)),
            ("correlation-method", sourceEvent.CorrelationMethod),
            ("correlation-candidate-count", sourceEvent.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture)));
        var matchContentHash = Sha256(canonical);
        var evidence = new LocalProcessSigmaEvidence
        {
            MatchId = $"sigma-match-{Sha256(Canonical(("match-content-hash", matchContentHash)))[..32]}",
            RuleId = request.RuleId,
            RuleVersion = request.RuleVersion,
            Level = level,
            MatchContentHashSha256 = matchContentHash,
            EvidenceIdentity = scope,
            ProcessEntityId = sourceEvent.ProcessEntityId,
            ProcessKey = sourceEvent.ProcessKey,
            SourceRunId = sourceEvent.SourceRunId,
            MatchedUtc = sourceEvent.TimestampUtc,
            CorrelationState = sourceEvent.CorrelationState,
            CorrelationMethod = sourceEvent.CorrelationMethod,
            CorrelationCandidateCount = sourceEvent.CorrelationCandidateCount,
            EvidenceReferences =
            [
                new EvidenceReference(EvidenceReferenceKind.ProcessEntity, sourceEvent.ProcessEntityId),
                new EvidenceReference(
                    EvidenceReferenceKind.Event,
                    sourceEvent.SequenceId.ToString(CultureInfo.InvariantCulture)),
                new EvidenceReference(EvidenceReferenceKind.SourceRun, sourceEvent.SourceRunId)
            ]
        };

        return new SigmaRiskEvidenceNormalizationDecision
        {
            Accepted = true,
            Failure = SigmaRiskEvidenceNormalizationFailure.None,
            Diagnostic = "The exact persisted Sigma event was normalized for portable risk mapping.",
            Evidence = evidence
        };
    }

    private static SigmaRiskEvidenceNormalizationDecision NormalizeProcess(
        SigmaRiskEvidenceNormalizationRequest request,
        SigmaFinding finding,
        ProcessObservation observation,
        AnalysisFindingSeverity level)
    {
        if (!ValidProcessObservation(observation))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidProcessObservation,
                "The persisted process observation must carry complete exact identity and provenance.");
        }

        var process = observation.Fields;
        if (request.EvaluatedUtc.Kind != DateTimeKind.Utc ||
            observation.ObservedUtc.Kind != DateTimeKind.Utc ||
            observation.ObservedUtc > request.EvaluatedUtc ||
            process.LastObservedUtc.Kind != DateTimeKind.Utc ||
            process.LastObservedUtc != observation.ObservedUtc ||
            finding.TimestampUtc is not { Kind: DateTimeKind.Utc } matchedUtc ||
            matchedUtc > request.EvaluatedUtc)
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidTimestamp,
                "Evaluation, observation, process, and match timestamps must be the same bounded UTC observation.");
        }

        if (!Enum.IsDefined(observation.CorrelationMethod) ||
            observation.CorrelationMethod == ProcessCorrelationMethod.LegacyCompatibility ||
            observation.CorrelationConfidence != 1d ||
            finding.CorrelationState != EvidenceCorrelationState.Exact ||
            finding.CorrelationCandidateCount != 1 ||
            !string.Equals(
                finding.CorrelationMethod,
                ExactProcessFindingCorrelationMethod,
                StringComparison.Ordinal))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.WeakCorrelation,
                "Only one-candidate exact durable-process finding and observation correlation is accepted.");
        }

        if (!string.Equals(finding.ProcessEntityId, observation.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(finding.ProcessEntityId, process.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(finding.ProcessKey, process.ProcessKey, StringComparison.Ordinal) ||
            finding.TimestampUtc != observation.ObservedUtc)
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.FindingMismatch,
                "The Sigma finding does not describe the supplied exact process observation identity.");
        }

        var scope = ScopeOf(process);
        var observationCorrelationMethod = observation.CorrelationMethod.ToString();
        var canonical = Canonical(
            ("rule-id", request.RuleId),
            ("rule-version", request.RuleVersion),
            ("rule-content-hash", request.RuleContentHashSha256.ToLowerInvariant()),
            ("level", level.ToString()),
            ("case-id", scope.CaseId),
            ("session-id", scope.EvidenceSessionId),
            ("capture-id", scope.CaptureId),
            ("source-identity-id", scope.SourceIdentityId),
            ("host-id", scope.HostId),
            ("execution-root-id", scope.ExecutionRootId),
            ("process-observation-id", observation.ObservationId),
            ("observation-kind", observation.ObservationKind.ToString()),
            ("adapter-id", observation.AdapterId),
            ("parser-version", observation.ParserVersion),
            ("process-entity-id", observation.ProcessEntityId),
            ("process-key", process.ProcessKey),
            ("source-run-id", observation.SourceRunId),
            ("matched-utc", observation.ObservedUtc.ToString("O", CultureInfo.InvariantCulture)),
            ("finding-correlation-method", finding.CorrelationMethod),
            ("observation-correlation-method", observationCorrelationMethod),
            ("correlation-candidate-count", finding.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture)));
        var matchContentHash = Sha256(canonical);
        var evidence = new LocalProcessSigmaEvidence
        {
            MatchId = $"sigma-match-{Sha256(Canonical(("match-content-hash", matchContentHash)))[..32]}",
            RuleId = request.RuleId,
            RuleVersion = request.RuleVersion,
            Level = level,
            MatchContentHashSha256 = matchContentHash,
            EvidenceIdentity = scope,
            ProcessEntityId = observation.ProcessEntityId,
            ProcessKey = process.ProcessKey,
            SourceRunId = observation.SourceRunId,
            MatchedUtc = observation.ObservedUtc,
            CorrelationState = finding.CorrelationState,
            CorrelationMethod = observationCorrelationMethod,
            CorrelationCandidateCount = finding.CorrelationCandidateCount,
            EvidenceReferences =
            [
                new EvidenceReference(EvidenceReferenceKind.ProcessEntity, observation.ProcessEntityId),
                new EvidenceReference(EvidenceReferenceKind.ProcessObservation, observation.ObservationId),
                new EvidenceReference(EvidenceReferenceKind.SourceRun, observation.SourceRunId)
            ]
        };

        return new SigmaRiskEvidenceNormalizationDecision
        {
            Accepted = true,
            Failure = SigmaRiskEvidenceNormalizationFailure.None,
            Diagnostic = "The exact persisted Sigma process observation was normalized for portable risk mapping.",
            Evidence = evidence
        };
    }

    private static SigmaRiskEvidenceNormalizationDecision NormalizeModule(
        SigmaRiskEvidenceNormalizationRequest request,
        SigmaFinding finding,
        ModuleObservationRecord module,
        AnalysisFindingSeverity level)
    {
        if (!ValidModuleObservation(module))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidModuleObservation,
                "The persisted module observation must carry complete exact identity and provenance.");
        }

        if (request.EvaluatedUtc.Kind != DateTimeKind.Utc ||
            module.FirstSeenUtc.Kind != DateTimeKind.Utc ||
            module.LastSeenUtc.Kind != DateTimeKind.Utc ||
            module.FirstSeenUtc > module.LastSeenUtc ||
            module.LastSeenUtc > request.EvaluatedUtc ||
            module.UnloadedUtc is { } unloadedUtc &&
            (unloadedUtc.Kind != DateTimeKind.Utc ||
             unloadedUtc < module.FirstSeenUtc ||
             unloadedUtc > module.LastSeenUtc) ||
            finding.TimestampUtc is not { Kind: DateTimeKind.Utc } matchedUtc ||
            matchedUtc > request.EvaluatedUtc)
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidTimestamp,
                "Evaluation, module observation, and match timestamps must be coherent bounded UTC values.");
        }

        if (finding.CorrelationState != EvidenceCorrelationState.Exact ||
            finding.CorrelationCandidateCount != 1 ||
            !string.Equals(
                finding.CorrelationMethod,
                ExactModuleFindingCorrelationMethod,
                StringComparison.Ordinal))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.WeakCorrelation,
                "Only one-candidate exact durable module-to-process correlation is accepted.");
        }

        if (!string.Equals(finding.ProcessEntityId, module.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(finding.ProcessKey, module.ProcessKey, StringComparison.Ordinal) ||
            !string.Equals(finding.SourceEvidenceId, module.ModuleKey, StringComparison.Ordinal) ||
            !string.Equals(finding.SourceRunId, module.SourceRunId, StringComparison.Ordinal) ||
            finding.TimestampUtc != module.LastSeenUtc)
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.FindingMismatch,
                "The Sigma finding does not describe the supplied exact module observation identity.");
        }

        var scope = ScopeOf(module);
        var canonical = Canonical(
            ("rule-id", request.RuleId),
            ("rule-version", request.RuleVersion),
            ("rule-content-hash", request.RuleContentHashSha256.ToLowerInvariant()),
            ("level", level.ToString()),
            ("case-id", scope.CaseId),
            ("session-id", scope.EvidenceSessionId),
            ("capture-id", scope.CaptureId),
            ("source-identity-id", scope.SourceIdentityId),
            ("host-id", scope.HostId),
            ("execution-root-id", scope.ExecutionRootId),
            ("module-sequence-id", module.SequenceId.ToString(CultureInfo.InvariantCulture)),
            ("module-key", module.ModuleKey),
            ("process-entity-id", module.ProcessEntityId),
            ("process-key", module.ProcessKey),
            ("source-run-id", module.SourceRunId),
            ("matched-utc", module.LastSeenUtc.ToString("O", CultureInfo.InvariantCulture)),
            ("correlation-method", finding.CorrelationMethod),
            ("correlation-candidate-count", finding.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture)));
        var matchContentHash = Sha256(canonical);
        var evidence = new LocalProcessSigmaEvidence
        {
            MatchId = $"sigma-match-{Sha256(Canonical(("match-content-hash", matchContentHash)))[..32]}",
            RuleId = request.RuleId,
            RuleVersion = request.RuleVersion,
            Level = level,
            MatchContentHashSha256 = matchContentHash,
            EvidenceIdentity = scope,
            ProcessEntityId = module.ProcessEntityId,
            ProcessKey = module.ProcessKey,
            SourceRunId = module.SourceRunId,
            MatchedUtc = module.LastSeenUtc,
            CorrelationState = finding.CorrelationState,
            CorrelationMethod = finding.CorrelationMethod,
            CorrelationCandidateCount = finding.CorrelationCandidateCount,
            EvidenceReferences =
            [
                new EvidenceReference(EvidenceReferenceKind.ProcessEntity, module.ProcessEntityId),
                new EvidenceReference(EvidenceReferenceKind.Module, module.ModuleKey),
                new EvidenceReference(EvidenceReferenceKind.SourceRun, module.SourceRunId)
            ]
        };

        return new SigmaRiskEvidenceNormalizationDecision
        {
            Accepted = true,
            Failure = SigmaRiskEvidenceNormalizationFailure.None,
            Diagnostic = "The exact persisted Sigma module observation was normalized for portable risk mapping.",
            Evidence = evidence
        };
    }

    private static SigmaRiskEvidenceNormalizationDecision NormalizeHandle(
        SigmaRiskEvidenceNormalizationRequest request,
        SigmaFinding finding,
        HandleObservationRecord handle,
        AnalysisFindingSeverity level)
    {
        if (!ValidHandleObservation(handle))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidHandleObservation,
                "The persisted handle observation must carry complete exact identity and provenance.");
        }

        if (request.EvaluatedUtc.Kind != DateTimeKind.Utc ||
            handle.FirstSeenUtc.Kind != DateTimeKind.Utc ||
            handle.LastSeenUtc.Kind != DateTimeKind.Utc ||
            handle.FirstSeenUtc > handle.LastSeenUtc ||
            handle.LastSeenUtc > request.EvaluatedUtc ||
            handle.ClosedUtc is { } closedUtc &&
            (closedUtc.Kind != DateTimeKind.Utc ||
             closedUtc < handle.FirstSeenUtc ||
             closedUtc > request.EvaluatedUtc) ||
            finding.TimestampUtc is not { Kind: DateTimeKind.Utc } matchedUtc ||
            matchedUtc > request.EvaluatedUtc)
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.InvalidTimestamp,
                "Evaluation, handle observation, and match timestamps must be coherent bounded UTC values.");
        }

        if (finding.CorrelationState != EvidenceCorrelationState.Exact ||
            finding.CorrelationCandidateCount != 1 ||
            !string.Equals(
                finding.CorrelationMethod,
                ExactHandleFindingCorrelationMethod,
                StringComparison.Ordinal))
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.WeakCorrelation,
                "Only one-candidate exact durable handle-to-process correlation is accepted.");
        }

        if (!string.Equals(finding.ProcessEntityId, handle.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(finding.ProcessKey, handle.ProcessKey, StringComparison.Ordinal) ||
            !string.Equals(finding.SourceEvidenceId, handle.HandleKey, StringComparison.Ordinal) ||
            !string.Equals(finding.SourceRunId, handle.SourceRunId, StringComparison.Ordinal) ||
            finding.TimestampUtc != handle.LastSeenUtc)
        {
            return Fail(
                SigmaRiskEvidenceNormalizationFailure.FindingMismatch,
                "The Sigma finding does not describe the supplied exact handle observation identity.");
        }

        var scope = ScopeOf(handle);
        var canonical = Canonical(
            ("rule-id", request.RuleId),
            ("rule-version", request.RuleVersion),
            ("rule-content-hash", request.RuleContentHashSha256.ToLowerInvariant()),
            ("level", level.ToString()),
            ("case-id", scope.CaseId),
            ("session-id", scope.EvidenceSessionId),
            ("capture-id", scope.CaptureId),
            ("source-identity-id", scope.SourceIdentityId),
            ("host-id", scope.HostId),
            ("execution-root-id", scope.ExecutionRootId),
            ("handle-sequence-id", handle.SequenceId.ToString(CultureInfo.InvariantCulture)),
            ("handle-key", handle.HandleKey),
            ("process-entity-id", handle.ProcessEntityId),
            ("process-key", handle.ProcessKey),
            ("source-run-id", handle.SourceRunId),
            ("matched-utc", handle.LastSeenUtc.ToString("O", CultureInfo.InvariantCulture)),
            ("correlation-method", finding.CorrelationMethod),
            ("correlation-candidate-count", finding.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture)));
        var matchContentHash = Sha256(canonical);
        var evidence = new LocalProcessSigmaEvidence
        {
            MatchId = $"sigma-match-{Sha256(Canonical(("match-content-hash", matchContentHash)))[..32]}",
            RuleId = request.RuleId,
            RuleVersion = request.RuleVersion,
            Level = level,
            MatchContentHashSha256 = matchContentHash,
            EvidenceIdentity = scope,
            ProcessEntityId = handle.ProcessEntityId,
            ProcessKey = handle.ProcessKey,
            SourceRunId = handle.SourceRunId,
            MatchedUtc = handle.LastSeenUtc,
            CorrelationState = finding.CorrelationState,
            CorrelationMethod = finding.CorrelationMethod,
            CorrelationCandidateCount = finding.CorrelationCandidateCount,
            EvidenceReferences =
            [
                new EvidenceReference(EvidenceReferenceKind.ProcessEntity, handle.ProcessEntityId),
                new EvidenceReference(EvidenceReferenceKind.Handle, handle.HandleKey),
                new EvidenceReference(EvidenceReferenceKind.SourceRun, handle.SourceRunId)
            ]
        };

        return new SigmaRiskEvidenceNormalizationDecision
        {
            Accepted = true,
            Failure = SigmaRiskEvidenceNormalizationFailure.None,
            Diagnostic = "The exact persisted Sigma handle observation was normalized for portable risk mapping.",
            Evidence = evidence
        };
    }

    private static bool TryNormalizeLevel(string? value, out AnalysisFindingSeverity severity)
    {
        severity = value?.Trim().ToLowerInvariant() switch
        {
            "informational" or "information" => AnalysisFindingSeverity.Informational,
            "low" => AnalysisFindingSeverity.Low,
            "medium" => AnalysisFindingSeverity.Medium,
            "high" => AnalysisFindingSeverity.High,
            "critical" => AnalysisFindingSeverity.Critical,
            _ => AnalysisFindingSeverity.Unknown
        };
        return severity != AnalysisFindingSeverity.Unknown;
    }

    private static bool ValidProcessObservation(ProcessObservation observation) =>
        observation.Fields != null &&
        Required(observation.ObservationId) &&
        Required(observation.AdapterId) &&
        Enum.IsDefined(observation.ObservationKind) &&
        observation.ObservationKind != ProcessObservationKind.LegacyCompatibility &&
        Enum.IsDefined(observation.StatusAssertion) &&
        Required(observation.ProcessEntityId) &&
        Required(observation.SourceRunId) &&
        Required(observation.ParserVersion) &&
        observation.FieldStates != null &&
        observation.FieldStates.All(pair => Required(pair.Key) && Enum.IsDefined(pair.Value)) &&
        ValidScope(observation.Fields) &&
        Required(observation.Fields.ProcessEntityId) &&
        Required(observation.Fields.ProcessKey) &&
        string.Equals(
            observation.ProcessEntityId,
            observation.Fields.ProcessEntityId,
            StringComparison.Ordinal);

    private static bool ValidModuleObservation(ModuleObservationRecord module) =>
        module.SequenceId > 0 &&
        Required(module.ModuleKey) &&
        Required(module.ProcessEntityId) &&
        Required(module.ProcessKey) &&
        Required(module.SourceRunId) &&
        Enum.IsDefined(module.State) &&
        ValidScope(module);

    private static bool ValidHandleObservation(HandleObservationRecord handle) =>
        handle.SequenceId > 0 &&
        Required(handle.HandleKey) &&
        Required(handle.ProcessEntityId) &&
        Required(handle.ProcessKey) &&
        Required(handle.SourceRunId) &&
        Enum.IsDefined(handle.State) &&
        ValidScope(handle);

    private static EvidenceIdentity ScopeOf(IHasEvidenceIdentity evidence) =>
        new()
        {
            CaseId = evidence.CaseId,
            EvidenceSessionId = evidence.EvidenceSessionId,
            CaptureId = evidence.CaptureId,
            SourceIdentityId = evidence.SourceIdentityId,
            HostId = evidence.HostId,
            ExecutionRootId = evidence.ExecutionRootId
        };

    private static bool ValidScope(IHasEvidenceIdentity evidence) =>
        Required(evidence.CaseId) &&
        Required(evidence.EvidenceSessionId) &&
        Required(evidence.CaptureId) &&
        Required(evidence.SourceIdentityId) &&
        Required(evidence.HostId) &&
        Required(evidence.ExecutionRootId);

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

    private static SigmaRiskEvidenceNormalizationDecision Fail(
        SigmaRiskEvidenceNormalizationFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = diagnostic
        };

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
}
