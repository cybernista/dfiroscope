using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum ReputationProcessAttributionNormalizationFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    AttributionRejected = 2,
    MissingSourceEvidence = 3,
    MultipleSourceEvidence = 4,
    MissingSourceReference = 5,
    MultipleSourceReferences = 6,
    SourceReferenceMismatch = 7,
    InvalidProcessIdentity = 8,
    ProcessIdentityMismatch = 9,
    ProcessKeyMismatch = 10,
    ScopeMismatch = 11,
    SourceRunMismatch = 12,
    InvalidProcessObservation = 13,
    ObservationIdentityMismatch = 14,
    ObservationProcessMismatch = 15,
    ObservationScopeMismatch = 16,
    ObservationSourceRunMismatch = 17,
    ObservationCorrelationMismatch = 18,
    InvalidFileArtifact = 19,
    FileArtifactIdentityMismatch = 20,
    FileArtifactScopeMismatch = 21,
    FileArtifactSourceRunMismatch = 22,
    StoredHashMismatch = 23,
    MissingRelation = 24,
    UnexpectedRelation = 25,
    InvalidRelationIdentity = 26,
    UnsupportedRelationType = 27,
    InvalidRelationState = 28,
    InvalidRelationConfidence = 29,
    InvalidRelationCandidateCount = 30,
    InvalidRelationMethod = 31,
    InvalidRelationLifecycle = 32,
    RelationScopeMismatch = 33,
    RelationSourceRunMismatch = 34,
    RelationEndpointMismatch = 35
}

public sealed record ReputationProcessAttributionNormalizationRequest
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ReputationProcessAttributionResult Attribution { get; init; } = new();

    public ProcessRecord Process { get; init; } = new();

    public ProcessObservation? ProcessObservation { get; init; }

    public FilesystemArtifactRecord? FileArtifact { get; init; }

    public EvidenceRelation? Relation { get; init; }
}

public sealed record ReputationProcessAttributionNormalizationDecision
{
    public bool Accepted { get; init; }

    public ReputationProcessAttributionNormalizationFailure Failure { get; init; }

    public ReputationProcessAttributionFailure AttributionFailure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationProcessAttributionResult? Result { get; init; }
}

/// <summary>
/// Pure persisted-record adapter between one caller-established #416
/// attribution and later durable reputation consumers. It performs no database
/// I/O, provider execution, cache mutation, evidence write, scoring, or UI work.
/// </summary>
public static class ReputationProcessAttributionNormalizer
{
    private const int MaximumIdentityLength = 512;
    private const int MaximumMethodLength = 256;

    private static readonly HashSet<EvidenceRelationType> SupportedRelationTypes =
    [
        EvidenceRelationType.Created,
        EvidenceRelationType.OwnedBy,
        EvidenceRelationType.CorrelatesWith
    ];

    private static readonly HashSet<ProcessCorrelationMethod> ExactObservationMethods =
    [
        ProcessCorrelationMethod.ExactScopedPidStartTime,
        ProcessCorrelationMethod.SourceNativeAlias,
        ProcessCorrelationMethod.SysmonProcessGuid,
        ProcessCorrelationMethod.ExactMemoryPidCreateTime
    ];

    public static ReputationProcessAttributionNormalizationDecision Normalize(
        ReputationProcessAttributionNormalizationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.SchemaVersion !=
            ReputationProcessAttributionNormalizationRequest.CurrentSchemaVersion)
        {
            return Reject(
                ReputationProcessAttributionNormalizationFailure.InvalidSchemaVersion,
                "The reputation persisted-attribution schema version is unsupported.");
        }

        var attributionDecision =
            ReputationProcessAttributionContract.Validate(request.Attribution);
        if (!attributionDecision.Accepted || attributionDecision.Result == null)
        {
            return RejectAttribution(
                attributionDecision.Failure,
                attributionDecision.Diagnostic);
        }

        var attribution = attributionDecision.Result;
        var suppliedSourceCount = (request.ProcessObservation == null ? 0 : 1) +
                                  (request.FileArtifact == null ? 0 : 1);
        if (suppliedSourceCount == 0)
        {
            return Reject(
                ReputationProcessAttributionNormalizationFailure.MissingSourceEvidence,
                "One persisted ProcessObservation or FileArtifact source is required.");
        }

        if (suppliedSourceCount != 1)
        {
            return Reject(
                ReputationProcessAttributionNormalizationFailure.MultipleSourceEvidence,
                "Exactly one persisted reputation source path is allowed.");
        }

        var attributionSourceReferences = attribution.EvidenceReferences
            .Where(IsSourceEvidenceReference)
            .ToArray();
        var targetSourceReferences = attribution.TargetRequest.EvidenceReferences
            .Where(IsSourceEvidenceReference)
            .ToArray();
        if (attributionSourceReferences.Length == 0 || targetSourceReferences.Length == 0)
        {
            return Reject(
                ReputationProcessAttributionNormalizationFailure.MissingSourceReference,
                "The attribution and target request must cite the persisted source evidence.");
        }

        if (attributionSourceReferences.Length != 1 || targetSourceReferences.Length != 1)
        {
            return Reject(
                ReputationProcessAttributionNormalizationFailure.MultipleSourceReferences,
                "The attribution and target request must select one exact persisted source path.");
        }

        var sourceReference = attributionSourceReferences[0];
        if (sourceReference != targetSourceReferences[0])
        {
            return Reject(
                ReputationProcessAttributionNormalizationFailure.SourceReferenceMismatch,
                "The attribution source reference does not match its target request.");
        }

        if (request.Process == null ||
            !Required(request.Process.ProcessEntityId) ||
            !Optional(request.Process.ProcessKey))
        {
            return Reject(
                ReputationProcessAttributionNormalizationFailure.InvalidProcessIdentity,
                "Persisted reputation attribution requires one bounded durable process identity.");
        }

        if (!string.Equals(
                request.Process.ProcessEntityId,
                attribution.ProcessEntityId,
                StringComparison.Ordinal))
        {
            return Reject(
                ReputationProcessAttributionNormalizationFailure.ProcessIdentityMismatch,
                "The persisted process does not match the attributed durable process entity.");
        }

        if (!CompatibilityKeyMatches(attribution.ProcessKey, request.Process.ProcessKey))
        {
            return Reject(
                ReputationProcessAttributionNormalizationFailure.ProcessKeyMismatch,
                "The optional persisted process compatibility key does not match the attribution.");
        }

        if (!SameScope(attribution.TargetRequest.EvidenceIdentity, request.Process))
        {
            return Reject(
                ReputationProcessAttributionNormalizationFailure.ScopeMismatch,
                "The persisted process is outside the exact reputation evidence scope.");
        }

        var references = attribution.EvidenceReferences
            .Select(reference => reference with { })
            .ToList();
        if (request.ProcessObservation != null)
        {
            if (sourceReference.Kind != EvidenceReferenceKind.ProcessObservation)
            {
                return Reject(
                    ReputationProcessAttributionNormalizationFailure.SourceReferenceMismatch,
                    "The supplied ProcessObservation does not match the selected source kind.");
            }

            if (request.Relation != null)
            {
                return Reject(
                    ReputationProcessAttributionNormalizationFailure.UnexpectedRelation,
                    "ProcessObservation attribution is established by the exact observation and accepts no relation.");
            }

            var observationFailure = ValidateObservation(
                request.ProcessObservation,
                request.Process,
                attribution,
                sourceReference);
            if (observationFailure != ReputationProcessAttributionNormalizationFailure.None)
            {
                return Reject(observationFailure, Diagnostic(observationFailure));
            }
        }
        else
        {
            if (sourceReference.Kind != EvidenceReferenceKind.FileArtifact)
            {
                return Reject(
                    ReputationProcessAttributionNormalizationFailure.SourceReferenceMismatch,
                    "The supplied FileArtifact does not match the selected source kind.");
            }

            var artifactFailure = ValidateArtifact(
                request.FileArtifact!,
                attribution,
                sourceReference);
            if (artifactFailure != ReputationProcessAttributionNormalizationFailure.None)
            {
                return Reject(artifactFailure, Diagnostic(artifactFailure));
            }

            if (request.Relation == null)
            {
                return Reject(
                    ReputationProcessAttributionNormalizationFailure.MissingRelation,
                    "FileArtifact attribution requires one exact active persisted process relation.");
            }

            var relationFailure = ValidateRelation(
                request.Relation,
                attribution.TargetRequest.EvidenceIdentity,
                attribution.TargetRequest.SourceRunId,
                sourceReference,
                attribution.ProcessEntityId);
            if (relationFailure != ReputationProcessAttributionNormalizationFailure.None)
            {
                return Reject(relationFailure, Diagnostic(relationFailure));
            }

            var relationReference = new EvidenceReference(
                EvidenceReferenceKind.EvidenceRelation,
                request.Relation.RelationId);
            if (!references.Contains(relationReference))
            {
                references.Add(relationReference);
            }
        }

        var normalized = ReputationProcessAttributionContract.Attribute(
            new ReputationProcessAttributionRequest
            {
                SourceKind = attribution.SourceKind,
                Receipt = attribution.Receipt,
                CacheEvaluation = attribution.CacheEvaluation,
                TargetRequest = attribution.TargetRequest,
                ProcessEntityId = attribution.ProcessEntityId,
                ProcessKey = attribution.ProcessKey,
                CorrelationState = attribution.CorrelationState,
                CorrelationMethod = attribution.CorrelationMethod,
                CorrelationCandidateCount = attribution.CorrelationCandidateCount,
                EvidenceReferences = references
            });
        if (!normalized.Accepted || normalized.Result == null)
        {
            return RejectAttribution(normalized.Failure, normalized.Diagnostic);
        }

        return new ReputationProcessAttributionNormalizationDecision
        {
            Accepted = true,
            Failure = ReputationProcessAttributionNormalizationFailure.None,
            AttributionFailure = ReputationProcessAttributionFailure.None,
            Result = normalized.Result
        };
    }

    private static ReputationProcessAttributionNormalizationFailure ValidateObservation(
        ProcessObservation observation,
        ProcessRecord process,
        ReputationProcessAttributionResult attribution,
        EvidenceReference sourceReference)
    {
        if (!Required(observation.ObservationId) ||
            !Required(observation.AdapterId) ||
            !Required(observation.ProcessEntityId) ||
            !Required(observation.SourceRunId) ||
            observation.Fields == null ||
            !Enum.IsDefined(observation.ObservationKind) ||
            observation.ObservationKind == ProcessObservationKind.LegacyCompatibility ||
            !Utc(observation.ObservedUtc) ||
            !OptionalUtc(observation.ValidFromUtc) ||
            !OptionalUtc(observation.ValidToUtc) ||
            observation.ValidFromUtc.HasValue && observation.ValidToUtc.HasValue &&
            observation.ValidToUtc.Value < observation.ValidFromUtc.Value)
        {
            return ReputationProcessAttributionNormalizationFailure.InvalidProcessObservation;
        }

        if (!string.Equals(observation.ObservationId, sourceReference.Id, StringComparison.Ordinal))
        {
            return ReputationProcessAttributionNormalizationFailure.ObservationIdentityMismatch;
        }

        if (!string.Equals(
                observation.ProcessEntityId,
                attribution.ProcessEntityId,
                StringComparison.Ordinal) ||
            !string.Equals(
                observation.Fields.ProcessEntityId,
                attribution.ProcessEntityId,
                StringComparison.Ordinal) ||
            !CompatibilityKeyMatches(attribution.ProcessKey, observation.Fields.ProcessKey) ||
            !string.Equals(
                observation.Fields.ProcessEntityId,
                process.ProcessEntityId,
                StringComparison.Ordinal))
        {
            return ReputationProcessAttributionNormalizationFailure.ObservationProcessMismatch;
        }

        if (!SameScope(attribution.TargetRequest.EvidenceIdentity, observation.Fields))
        {
            return ReputationProcessAttributionNormalizationFailure.ObservationScopeMismatch;
        }

        if (!string.Equals(
                observation.SourceRunId,
                attribution.TargetRequest.SourceRunId,
                StringComparison.Ordinal))
        {
            return ReputationProcessAttributionNormalizationFailure.ObservationSourceRunMismatch;
        }

        if (!Enum.IsDefined(observation.CorrelationMethod) ||
            !ExactObservationMethods.Contains(observation.CorrelationMethod) ||
            !double.IsFinite(observation.CorrelationConfidence) ||
            observation.CorrelationConfidence != 1d)
        {
            return ReputationProcessAttributionNormalizationFailure.ObservationCorrelationMismatch;
        }

        return StoredHashMatches(
            observation.Fields.Sha256Hash,
            attribution.TargetRequest.Indicator.Value)
            ? ReputationProcessAttributionNormalizationFailure.None
            : ReputationProcessAttributionNormalizationFailure.StoredHashMismatch;
    }

    private static ReputationProcessAttributionNormalizationFailure ValidateArtifact(
        FilesystemArtifactRecord artifact,
        ReputationProcessAttributionResult attribution,
        EvidenceReference sourceReference)
    {
        if (!Required(artifact.ArtifactId) ||
            !Required(artifact.SourceRunId) ||
            !Enum.IsDefined(artifact.Kind) ||
            artifact.Kind == FilesystemArtifactKind.Unknown ||
            !Enum.IsDefined(artifact.Status) ||
            artifact.Status != FilesystemArtifactStatus.Imported ||
            !Utc(artifact.TimestampUtc))
        {
            return ReputationProcessAttributionNormalizationFailure.InvalidFileArtifact;
        }

        if (!string.Equals(artifact.ArtifactId, sourceReference.Id, StringComparison.Ordinal))
        {
            return ReputationProcessAttributionNormalizationFailure.FileArtifactIdentityMismatch;
        }

        if (!SameScope(attribution.TargetRequest.EvidenceIdentity, artifact))
        {
            return ReputationProcessAttributionNormalizationFailure.FileArtifactScopeMismatch;
        }

        if (!string.Equals(
                artifact.SourceRunId,
                attribution.TargetRequest.SourceRunId,
                StringComparison.Ordinal))
        {
            return ReputationProcessAttributionNormalizationFailure.FileArtifactSourceRunMismatch;
        }

        return StoredHashMatches(
            artifact.Sha256Hash,
            attribution.TargetRequest.Indicator.Value)
            ? ReputationProcessAttributionNormalizationFailure.None
            : ReputationProcessAttributionNormalizationFailure.StoredHashMismatch;
    }

    private static ReputationProcessAttributionNormalizationFailure ValidateRelation(
        EvidenceRelation relation,
        EvidenceIdentity identity,
        string sourceRunId,
        EvidenceReference sourceReference,
        string processEntityId)
    {
        if (!Required(relation.RelationId) ||
            !Required(relation.DecisionKey) ||
            !Required(relation.ResolverName) ||
            !Required(relation.ResolverVersion) ||
            !Required(relation.FromId) ||
            !Required(relation.ToId) ||
            !Enum.IsDefined(relation.FromKind) ||
            !Enum.IsDefined(relation.ToKind) ||
            !Enum.IsDefined(relation.RelationType) ||
            !Enum.IsDefined(relation.Status) ||
            relation.Status != EvidenceRelationStatus.Active ||
            !string.IsNullOrEmpty(relation.SupersededByRelationId) ||
            !string.IsNullOrEmpty(relation.AnalystAnnotationId))
        {
            return ReputationProcessAttributionNormalizationFailure.InvalidRelationIdentity;
        }

        if (!SupportedRelationTypes.Contains(relation.RelationType))
        {
            return ReputationProcessAttributionNormalizationFailure.UnsupportedRelationType;
        }

        if (!Enum.IsDefined(relation.State) || relation.State != EvidenceCorrelationState.Exact)
        {
            return ReputationProcessAttributionNormalizationFailure.InvalidRelationState;
        }

        if (!double.IsFinite(relation.Confidence) || relation.Confidence != 1d)
        {
            return ReputationProcessAttributionNormalizationFailure.InvalidRelationConfidence;
        }

        if (relation.CandidateCount != 1)
        {
            return ReputationProcessAttributionNormalizationFailure.InvalidRelationCandidateCount;
        }

        if (!Required(relation.CorrelationMethod, MaximumMethodLength))
        {
            return ReputationProcessAttributionNormalizationFailure.InvalidRelationMethod;
        }

        if (!ValidLifecycle(relation))
        {
            return ReputationProcessAttributionNormalizationFailure.InvalidRelationLifecycle;
        }

        if (!SameScope(identity, relation))
        {
            return ReputationProcessAttributionNormalizationFailure.RelationScopeMismatch;
        }

        if (!string.Equals(relation.SourceRunId, sourceRunId, StringComparison.Ordinal))
        {
            return ReputationProcessAttributionNormalizationFailure.RelationSourceRunMismatch;
        }

        var sourceIsFrom = relation.FromKind == sourceReference.Kind &&
                           string.Equals(relation.FromId, sourceReference.Id, StringComparison.Ordinal);
        var sourceIsTo = relation.ToKind == sourceReference.Kind &&
                         string.Equals(relation.ToId, sourceReference.Id, StringComparison.Ordinal);
        var processIsFrom = relation.FromKind == EvidenceReferenceKind.ProcessEntity &&
                            string.Equals(relation.FromId, processEntityId, StringComparison.Ordinal);
        var processIsTo = relation.ToKind == EvidenceReferenceKind.ProcessEntity &&
                          string.Equals(relation.ToId, processEntityId, StringComparison.Ordinal);
        return sourceIsFrom && processIsTo || processIsFrom && sourceIsTo
            ? ReputationProcessAttributionNormalizationFailure.None
            : ReputationProcessAttributionNormalizationFailure.RelationEndpointMismatch;
    }

    private static bool IsSourceEvidenceReference(EvidenceReference reference) =>
        reference.Kind is EvidenceReferenceKind.ProcessObservation or
            EvidenceReferenceKind.FileArtifact;

    private static bool StoredHashMatches(string? stored, string expected) =>
        LowerSha256(stored) && string.Equals(stored, expected, StringComparison.Ordinal);

    private static bool CompatibilityKeyMatches(string attributed, string persisted) =>
        string.IsNullOrEmpty(attributed) || string.Equals(attributed, persisted, StringComparison.Ordinal);

    private static bool ValidLifecycle(EvidenceRelation relation) =>
        Utc(relation.ObservedFromUtc) &&
        Utc(relation.CreatedUtc) &&
        Utc(relation.UpdatedUtc) &&
        OptionalUtc(relation.ObservedToUtc) &&
        OptionalUtc(relation.ValidFromUtc) &&
        OptionalUtc(relation.ValidToUtc) &&
        relation.UpdatedUtc >= relation.CreatedUtc &&
        (!relation.ObservedToUtc.HasValue ||
         relation.ObservedToUtc.Value >= relation.ObservedFromUtc) &&
        (!relation.ValidFromUtc.HasValue || !relation.ValidToUtc.HasValue ||
         relation.ValidToUtc.Value >= relation.ValidFromUtc.Value);

    private static bool SameScope(EvidenceIdentity identity, IHasEvidenceIdentity candidate) =>
        string.Equals(identity.CaseId, candidate.CaseId, StringComparison.Ordinal) &&
        string.Equals(identity.EvidenceSessionId, candidate.EvidenceSessionId, StringComparison.Ordinal) &&
        string.Equals(identity.CaptureId, candidate.CaptureId, StringComparison.Ordinal) &&
        string.Equals(identity.SourceIdentityId, candidate.SourceIdentityId, StringComparison.Ordinal) &&
        string.Equals(identity.HostId, candidate.HostId, StringComparison.Ordinal) &&
        string.Equals(identity.ExecutionRootId, candidate.ExecutionRootId, StringComparison.Ordinal);

    private static bool Required(string? value, int maximumLength = MaximumIdentityLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;

    private static bool Optional(string? value) =>
        value != null && value.Length <= MaximumIdentityLength;

    private static bool LowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static bool Utc(DateTime value) =>
        value != default && value.Kind == DateTimeKind.Utc;

    private static bool OptionalUtc(DateTime? value) =>
        !value.HasValue || Utc(value.Value);

    private static ReputationProcessAttributionNormalizationDecision RejectAttribution(
        ReputationProcessAttributionFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = ReputationProcessAttributionNormalizationFailure.AttributionRejected,
            AttributionFailure = failure,
            Diagnostic = string.IsNullOrWhiteSpace(diagnostic)
                ? "The caller-established reputation attribution failed canonical revalidation."
                : diagnostic
        };

    private static ReputationProcessAttributionNormalizationDecision Reject(
        ReputationProcessAttributionNormalizationFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = diagnostic
        };

    private static string Diagnostic(
        ReputationProcessAttributionNormalizationFailure failure) => failure switch
    {
        ReputationProcessAttributionNormalizationFailure.InvalidProcessObservation =>
            "The persisted process observation is incomplete, legacy, or malformed.",
        ReputationProcessAttributionNormalizationFailure.ObservationIdentityMismatch =>
            "The persisted process observation identity does not match the cited source reference.",
        ReputationProcessAttributionNormalizationFailure.ObservationProcessMismatch =>
            "The persisted process observation does not identify the exact durable process.",
        ReputationProcessAttributionNormalizationFailure.ObservationScopeMismatch =>
            "The persisted process observation is outside the exact reputation evidence scope.",
        ReputationProcessAttributionNormalizationFailure.ObservationSourceRunMismatch =>
            "The persisted process observation is outside the exact reputation source run.",
        ReputationProcessAttributionNormalizationFailure.ObservationCorrelationMismatch =>
            "The persisted process observation does not carry exact non-legacy correlation.",
        ReputationProcessAttributionNormalizationFailure.InvalidFileArtifact =>
            "The persisted file artifact is incomplete, unsuccessful, or malformed.",
        ReputationProcessAttributionNormalizationFailure.FileArtifactIdentityMismatch =>
            "The persisted file artifact identity does not match the cited source reference.",
        ReputationProcessAttributionNormalizationFailure.FileArtifactScopeMismatch =>
            "The persisted file artifact is outside the exact reputation evidence scope.",
        ReputationProcessAttributionNormalizationFailure.FileArtifactSourceRunMismatch =>
            "The persisted file artifact is outside the exact reputation source run.",
        ReputationProcessAttributionNormalizationFailure.StoredHashMismatch =>
            "The persisted source SHA-256 is noncanonical or does not equal the attributed indicator.",
        ReputationProcessAttributionNormalizationFailure.InvalidRelationIdentity =>
            "The persisted file-to-process relation has invalid identity, status, or provenance.",
        ReputationProcessAttributionNormalizationFailure.UnsupportedRelationType =>
            "The persisted file-to-process relation uses unsupported semantics.",
        ReputationProcessAttributionNormalizationFailure.InvalidRelationState =>
            "Persisted reputation attribution requires one exact active relation.",
        ReputationProcessAttributionNormalizationFailure.InvalidRelationConfidence =>
            "Persisted reputation attribution requires relation confidence 1.0.",
        ReputationProcessAttributionNormalizationFailure.InvalidRelationCandidateCount =>
            "Persisted reputation attribution requires exactly one relation candidate.",
        ReputationProcessAttributionNormalizationFailure.InvalidRelationMethod =>
            "Persisted reputation attribution requires one bounded relation method.",
        ReputationProcessAttributionNormalizationFailure.InvalidRelationLifecycle =>
            "The persisted file-to-process relation lifecycle is malformed or non-UTC.",
        ReputationProcessAttributionNormalizationFailure.RelationScopeMismatch =>
            "The persisted file-to-process relation is outside the exact reputation evidence scope.",
        ReputationProcessAttributionNormalizationFailure.RelationSourceRunMismatch =>
            "The persisted file-to-process relation is outside the exact reputation source run.",
        _ => "The persisted relation does not link the exact file artifact and durable process entity."
    };
}
