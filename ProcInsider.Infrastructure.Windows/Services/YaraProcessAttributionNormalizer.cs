using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum YaraProcessAttributionNormalizationFailure
{
    None = 0,
    InvalidPersistedScan = 1,
    PersistedPayloadHashMismatch = 2,
    UnsupportedTargetKind = 3,
    InvalidProcessIdentity = 4,
    ScopeMismatch = 5,
    InvalidRelationIdentity = 6,
    UnsupportedRelationType = 7,
    InvalidRelationState = 8,
    InvalidRelationConfidence = 9,
    InvalidRelationCandidateCount = 10,
    InvalidRelationMethod = 11,
    InvalidRelationLifecycle = 12,
    RelationScopeMismatch = 13,
    RelationSourceRunMismatch = 14,
    RelationEndpointMismatch = 15,
    AttributionRejected = 16
}

public sealed record YaraProcessAttributionNormalizationRequest
{
    public YaraRiskPolicy Policy { get; init; } = new();

    public YaraPersistedScan PersistedScan { get; init; } = new();

    public ProcessRecord Process { get; init; } = new();

    public EvidenceRelation Relation { get; init; } = new();
}

public sealed record YaraProcessAttributionNormalizationDecision
{
    public bool Accepted { get; init; }

    public YaraProcessAttributionNormalizationFailure Failure { get; init; }

    public YaraProcessAttributionFailure AttributionFailure { get; init; }

    public YaraRiskPolicyFailure RiskPolicyFailure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public YaraProcessAttributionResult? Result { get; init; }
}

/// <summary>
/// Pure persisted-record adapter between migration-029 YARA readback and the
/// package-free #395 process-attribution contract. It performs no database I/O,
/// evidence mutation, execution, scoring, or publication.
/// </summary>
public static class YaraProcessAttributionNormalizer
{
    private const int MaximumIdentityLength = 512;
    private const int MaximumMethodLength = 256;

    private static readonly HashSet<EvidenceRelationType> SupportedRelationTypes =
    [
        EvidenceRelationType.Created,
        EvidenceRelationType.OwnedBy,
        EvidenceRelationType.CorrelatesWith
    ];

    public static YaraProcessAttributionNormalizationDecision Normalize(
        YaraProcessAttributionNormalizationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.PersistedScan == null || request.PersistedScan.Result == null ||
            !Required(request.PersistedScan.RequestId) ||
            !Required(request.PersistedScan.AdmissionProfileId) ||
            !Required(request.PersistedScan.AdmissionProfileVersion) ||
            !Sha256(request.PersistedScan.ScannerArtifactHashSha256) ||
            request.PersistedScan.ScannerAdapterProtocolVersion !=
                YaraTrustAdmissionPolicy.CurrentAdapterProtocolVersion ||
            !Sha256(request.PersistedScan.RulesetManifestHashSha256) ||
            !Sha256(request.PersistedScan.PayloadHashSha256))
        {
            return Reject(
                YaraProcessAttributionNormalizationFailure.InvalidPersistedScan,
                "The persisted YARA scan wrapper is incomplete or malformed.");
        }

        var computedPayloadHash =
            YaraAnalysisPersistencePolicy.ComputePayloadHash(request.PersistedScan);
        if (!string.Equals(
                request.PersistedScan.PayloadHashSha256,
                computedPayloadHash,
                StringComparison.Ordinal))
        {
            return Reject(
                YaraProcessAttributionNormalizationFailure.PersistedPayloadHashMismatch,
                "The persisted YARA payload hash does not match its normalized scan rows.");
        }

        var scanDecision = YaraAnalysisContractPolicy.Validate(request.PersistedScan.Result);
        if (!scanDecision.Accepted || scanDecision.Result == null)
        {
            return Reject(
                YaraProcessAttributionNormalizationFailure.InvalidPersistedScan,
                $"The persisted normalized YARA scan is invalid ({scanDecision.Failure}).");
        }

        var scan = scanDecision.Result;
        if (scan.Target.Kind == YaraScanTargetKind.MemoryImageRegion)
        {
            return Reject(
                YaraProcessAttributionNormalizationFailure.UnsupportedTargetKind,
                "A memory-image range has no persisted exact range-to-process ownership record.");
        }

        if (scan.Target.Kind is not (YaraScanTargetKind.FileArtifact or YaraScanTargetKind.MemoryDump))
        {
            return Reject(
                YaraProcessAttributionNormalizationFailure.UnsupportedTargetKind,
                "The persisted YARA target kind is unsupported for exact process attribution.");
        }

        if (request.Process == null || !Required(request.Process.ProcessEntityId) ||
            !Optional(request.Process.ProcessKey))
        {
            return Reject(
                YaraProcessAttributionNormalizationFailure.InvalidProcessIdentity,
                "Persisted YARA attribution requires one bounded durable process entity identity.");
        }

        if (!SameScope(scan.Target.EvidenceIdentity, request.Process))
        {
            return Reject(
                YaraProcessAttributionNormalizationFailure.ScopeMismatch,
                "The persisted process and YARA target do not share the exact evidence scope.");
        }

        var relationFailure = ValidateRelation(
            request.Relation,
            scan.Target,
            request.Process.ProcessEntityId);
        if (relationFailure != YaraProcessAttributionNormalizationFailure.None)
        {
            return Reject(relationFailure, RelationDiagnostic(relationFailure));
        }

        var attribution = YaraProcessAttributionContract.Attribute(
            new YaraProcessAttributionRequest
            {
                Policy = request.Policy,
                ScanResult = scan,
                ProcessEntityId = request.Process.ProcessEntityId,
                ProcessKey = request.Process.ProcessKey,
                CorrelationState = EvidenceCorrelationState.Exact,
                CorrelationMethod = request.Relation.CorrelationMethod,
                CorrelationCandidateCount = request.Relation.CandidateCount,
                EvidenceReferences =
                [
                    new EvidenceReference(
                        EvidenceReferenceKind.ProcessEntity,
                        request.Process.ProcessEntityId),
                    scan.Target.EvidenceReference with { },
                    new EvidenceReference(
                        EvidenceReferenceKind.SourceRun,
                        scan.Target.SourceRunId),
                    new EvidenceReference(
                        EvidenceReferenceKind.EvidenceRelation,
                        request.Relation.RelationId)
                ]
            });
        if (!attribution.Accepted || attribution.Result == null)
        {
            return new YaraProcessAttributionNormalizationDecision
            {
                Accepted = false,
                Failure = YaraProcessAttributionNormalizationFailure.AttributionRejected,
                AttributionFailure = attribution.Failure,
                RiskPolicyFailure = attribution.RiskPolicyFailure,
                Diagnostic = attribution.Diagnostic
            };
        }

        return new YaraProcessAttributionNormalizationDecision
        {
            Accepted = true,
            Failure = YaraProcessAttributionNormalizationFailure.None,
            AttributionFailure = YaraProcessAttributionFailure.None,
            RiskPolicyFailure = YaraRiskPolicyFailure.None,
            Result = attribution.Result
        };
    }

    private static YaraProcessAttributionNormalizationFailure ValidateRelation(
        EvidenceRelation? relation,
        YaraScanTarget target,
        string processEntityId)
    {
        if (relation == null || !Required(relation.RelationId) ||
            !Required(relation.DecisionKey) || !Required(relation.ResolverName) ||
            !Required(relation.ResolverVersion) || !Enum.IsDefined(relation.FromKind) ||
            !Enum.IsDefined(relation.ToKind) || !Enum.IsDefined(relation.RelationType) ||
            !Enum.IsDefined(relation.Status) || relation.Status != EvidenceRelationStatus.Active ||
            !string.IsNullOrEmpty(relation.SupersededByRelationId) ||
            !string.IsNullOrEmpty(relation.AnalystAnnotationId))
        {
            return YaraProcessAttributionNormalizationFailure.InvalidRelationIdentity;
        }

        if (!SupportedRelationTypes.Contains(relation.RelationType))
        {
            return YaraProcessAttributionNormalizationFailure.UnsupportedRelationType;
        }

        if (!Enum.IsDefined(relation.State) || relation.State != EvidenceCorrelationState.Exact)
        {
            return YaraProcessAttributionNormalizationFailure.InvalidRelationState;
        }

        if (!double.IsFinite(relation.Confidence) || relation.Confidence != 1d)
        {
            return YaraProcessAttributionNormalizationFailure.InvalidRelationConfidence;
        }

        if (relation.CandidateCount != 1)
        {
            return YaraProcessAttributionNormalizationFailure.InvalidRelationCandidateCount;
        }

        if (!Required(relation.CorrelationMethod, MaximumMethodLength))
        {
            return YaraProcessAttributionNormalizationFailure.InvalidRelationMethod;
        }

        if (!ValidLifecycle(relation))
        {
            return YaraProcessAttributionNormalizationFailure.InvalidRelationLifecycle;
        }

        if (!SameScope(target.EvidenceIdentity, relation))
        {
            return YaraProcessAttributionNormalizationFailure.RelationScopeMismatch;
        }

        if (!string.Equals(relation.SourceRunId, target.SourceRunId, StringComparison.Ordinal))
        {
            return YaraProcessAttributionNormalizationFailure.RelationSourceRunMismatch;
        }

        var targetIsFrom = relation.FromKind == target.EvidenceReference.Kind &&
                           string.Equals(
                               relation.FromId,
                               target.EvidenceReference.Id,
                               StringComparison.Ordinal);
        var targetIsTo = relation.ToKind == target.EvidenceReference.Kind &&
                         string.Equals(
                             relation.ToId,
                             target.EvidenceReference.Id,
                             StringComparison.Ordinal);
        var processIsFrom = relation.FromKind == EvidenceReferenceKind.ProcessEntity &&
                            string.Equals(
                                relation.FromId,
                                processEntityId,
                                StringComparison.Ordinal);
        var processIsTo = relation.ToKind == EvidenceReferenceKind.ProcessEntity &&
                          string.Equals(
                              relation.ToId,
                              processEntityId,
                              StringComparison.Ordinal);
        if (!(targetIsFrom && processIsTo || processIsFrom && targetIsTo))
        {
            return YaraProcessAttributionNormalizationFailure.RelationEndpointMismatch;
        }

        return YaraProcessAttributionNormalizationFailure.None;
    }

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

    private static bool Sha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static bool Utc(DateTime value) =>
        value != default && value.Kind == DateTimeKind.Utc;

    private static bool OptionalUtc(DateTime? value) =>
        !value.HasValue || Utc(value.Value);

    private static YaraProcessAttributionNormalizationDecision Reject(
        YaraProcessAttributionNormalizationFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = diagnostic
        };

    private static string RelationDiagnostic(
        YaraProcessAttributionNormalizationFailure failure) => failure switch
    {
        YaraProcessAttributionNormalizationFailure.InvalidRelationIdentity =>
            "The persisted YARA process relation has invalid identity, status, or provenance.",
        YaraProcessAttributionNormalizationFailure.UnsupportedRelationType =>
            "The persisted YARA process relation uses unsupported semantics.",
        YaraProcessAttributionNormalizationFailure.InvalidRelationState =>
            "Persisted YARA process attribution requires an exact active relation.",
        YaraProcessAttributionNormalizationFailure.InvalidRelationConfidence =>
            "Persisted YARA process attribution requires confidence 1.0.",
        YaraProcessAttributionNormalizationFailure.InvalidRelationCandidateCount =>
            "Persisted YARA process attribution requires exactly one relation candidate.",
        YaraProcessAttributionNormalizationFailure.InvalidRelationMethod =>
            "Persisted YARA process attribution requires one bounded correlation method.",
        YaraProcessAttributionNormalizationFailure.InvalidRelationLifecycle =>
            "The persisted YARA process relation lifecycle is malformed or non-UTC.",
        YaraProcessAttributionNormalizationFailure.RelationScopeMismatch =>
            "The persisted YARA process relation is outside the exact target scope.",
        YaraProcessAttributionNormalizationFailure.RelationSourceRunMismatch =>
            "The persisted YARA process relation is outside the exact target source run.",
        _ => "The persisted YARA relation does not link the exact target and process entity."
    };
}
