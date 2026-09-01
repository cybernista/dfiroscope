using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ProcInsider.Models.Analysis;

public enum ReputationProcessAttributionSourceKind
{
    Unknown = 0,
    DirectExecution = 1,
    FreshCacheReuse = 2
}

public enum ReputationProcessAttributionFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    UnknownSourceKind = 2,
    InvalidExecutionReceipt = 3,
    UnexpectedCacheEvaluation = 4,
    InvalidCacheEvaluation = 5,
    CacheEvaluationNotReusable = 6,
    ReceiptMismatch = 7,
    TargetRequestMismatch = 8,
    UnsupportedIndicatorKind = 9,
    InvalidProcessIdentity = 10,
    InvalidCorrelationState = 11,
    InvalidCorrelationMethod = 12,
    InvalidCorrelationCandidateCount = 13,
    ReferenceLimitExceeded = 14,
    InvalidReference = 15,
    UnsupportedReference = 16,
    DuplicateReference = 17,
    MismatchedReference = 18,
    MissingProcessReference = 19,
    MissingSourceRunReference = 20,
    MissingSourceEvidenceReference = 21,
    MissingTargetReference = 22,
    InvalidAttributionHash = 23
}

/// <summary>
/// Caller-established exact process attribution for one canonical reputation
/// receipt. A cache evaluation is present only when the original receipt is
/// reused for a different evidence-scoped request.
/// </summary>
public sealed record ReputationProcessAttributionRequest
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ReputationProcessAttributionSourceKind SourceKind { get; init; }

    public ReputationProviderExecutionReceipt Receipt { get; init; } = new();

    public ReputationCacheEvaluation? CacheEvaluation { get; init; }

    public ReputationLookupRequest TargetRequest { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public EvidenceCorrelationState CorrelationState { get; init; }

    public string CorrelationMethod { get; init; } = string.Empty;

    public int CorrelationCandidateCount { get; init; }

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();
}

/// <summary>
/// Canonical non-scoring result that preserves the original provider receipt,
/// optional fresh-cache decision, exact target request, and durable process
/// correlation as separate provenance layers.
/// </summary>
public sealed record ReputationProcessAttributionResult
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ReputationProcessAttributionSourceKind SourceKind { get; init; }

    public ReputationProviderExecutionReceipt Receipt { get; init; } = new();

    public ReputationCacheEvaluation? CacheEvaluation { get; init; }

    public ReputationLookupRequest TargetRequest { get; init; } = new();

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public EvidenceCorrelationState CorrelationState { get; init; }

    public string CorrelationMethod { get; init; } = string.Empty;

    public int CorrelationCandidateCount { get; init; }

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();

    public string AttributionHashSha256 { get; init; } = string.Empty;
}

public sealed record ReputationProcessAttributionDecision
{
    public bool Accepted { get; init; }

    public ReputationProcessAttributionFailure Failure { get; init; }

    public ReputationProviderExecutionFailure ExecutionFailure { get; init; }

    public ReputationCacheFailure CacheFailure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationProcessAttributionResult? Result { get; init; }
}

/// <summary>
/// Pure fail-closed boundary between one exact provider receipt/cache decision
/// and any later persisted-evidence normalizer. It performs no evidence read,
/// provider execution, persistence, scoring, annotation, Agent, or UI work.
/// </summary>
public static class ReputationProcessAttributionContract
{
    public const int MaximumEvidenceReferences = 64;

    private const int MaximumIdentityLength = 512;
    private const int MaximumCorrelationMethodLength = 256;

    private static readonly HashSet<EvidenceReferenceKind> AllowedReferenceKinds =
    [
        EvidenceReferenceKind.ProcessEntity,
        EvidenceReferenceKind.ProcessObservation,
        EvidenceReferenceKind.FileArtifact,
        EvidenceReferenceKind.SourceRun,
        EvidenceReferenceKind.PeAnalysis,
        EvidenceReferenceKind.AuthenticodeVerification,
        EvidenceReferenceKind.EvidenceRelation
    ];

    private static readonly HashSet<EvidenceReferenceKind> SourceEvidenceKinds =
    [
        EvidenceReferenceKind.ProcessObservation,
        EvidenceReferenceKind.FileArtifact
    ];

    public static ReputationProcessAttributionDecision Attribute(
        ReputationProcessAttributionRequest candidate) =>
        AttributeInternal(candidate);

    public static ReputationProcessAttributionDecision Validate(
        ReputationProcessAttributionResult candidate)
    {
        if (candidate == null ||
            candidate.SchemaVersion != ReputationProcessAttributionResult.CurrentSchemaVersion)
        {
            return Reject(
                ReputationProcessAttributionFailure.InvalidSchemaVersion,
                "The reputation process-attribution schema version is unsupported.");
        }

        var decision = AttributeInternal(new ReputationProcessAttributionRequest
        {
            SchemaVersion = candidate.SchemaVersion,
            SourceKind = candidate.SourceKind,
            Receipt = candidate.Receipt,
            CacheEvaluation = candidate.CacheEvaluation,
            TargetRequest = candidate.TargetRequest,
            ProcessEntityId = candidate.ProcessEntityId,
            ProcessKey = candidate.ProcessKey,
            CorrelationState = candidate.CorrelationState,
            CorrelationMethod = candidate.CorrelationMethod,
            CorrelationCandidateCount = candidate.CorrelationCandidateCount,
            EvidenceReferences = candidate.EvidenceReferences
        });
        if (!decision.Accepted || decision.Result == null)
        {
            return decision;
        }

        if (!IsLowerSha256(candidate.AttributionHashSha256) ||
            !string.Equals(
                candidate.AttributionHashSha256,
                decision.Result.AttributionHashSha256,
                StringComparison.Ordinal))
        {
            return Reject(
                ReputationProcessAttributionFailure.InvalidAttributionHash,
                "The reputation process-attribution identity is missing or mismatched.");
        }

        return decision;
    }

    private static ReputationProcessAttributionDecision AttributeInternal(
        ReputationProcessAttributionRequest? candidate)
    {
        if (candidate == null ||
            candidate.SchemaVersion != ReputationProcessAttributionRequest.CurrentSchemaVersion)
        {
            return Reject(
                ReputationProcessAttributionFailure.InvalidSchemaVersion,
                "The reputation process-attribution schema version is unsupported.");
        }

        if (!Enum.IsDefined(candidate.SourceKind) ||
            candidate.SourceKind == ReputationProcessAttributionSourceKind.Unknown)
        {
            return Reject(
                ReputationProcessAttributionFailure.UnknownSourceKind,
                "The reputation attribution source kind is unknown or unsupported.");
        }

        var receiptDecision = ReputationProviderExecutionPolicy.Validate(candidate.Receipt);
        if (!receiptDecision.Accepted || receiptDecision.Receipt == null)
        {
            return RejectExecution(
                receiptDecision.Failure,
                "The reputation attribution requires one canonical provider execution receipt.");
        }

        if (!ReputationLookupContractPolicy.TryCanonicalizeRequest(
                candidate.TargetRequest,
                out var targetRequest,
                out _))
        {
            return Reject(
                ReputationProcessAttributionFailure.TargetRequestMismatch,
                "The reputation attribution target request is malformed or noncanonical.");
        }

        var receipt = receiptDecision.Receipt;
        ReputationCacheEvaluation? cacheEvaluation = null;
        switch (candidate.SourceKind)
        {
            case ReputationProcessAttributionSourceKind.DirectExecution:
                if (candidate.CacheEvaluation != null)
                {
                    return Reject(
                        ReputationProcessAttributionFailure.UnexpectedCacheEvaluation,
                        "A direct reputation attribution cannot carry a cache evaluation.");
                }

                if (!RequestsEqual(targetRequest, receipt.Result.Request))
                {
                    return Reject(
                        ReputationProcessAttributionFailure.TargetRequestMismatch,
                        "A direct reputation attribution must target the receipt's exact request.");
                }

                break;

            case ReputationProcessAttributionSourceKind.FreshCacheReuse:
                if (candidate.CacheEvaluation == null)
                {
                    return Reject(
                        ReputationProcessAttributionFailure.InvalidCacheEvaluation,
                        "A cache-backed reputation attribution requires one exact cache evaluation.");
                }

                var cacheDecision =
                    ReputationCachePolicy.ValidateEvaluation(candidate.CacheEvaluation);
                if (!cacheDecision.Accepted || cacheDecision.Evaluation == null)
                {
                    return RejectCache(
                        cacheDecision.Failure,
                        "The reputation cache evaluation is invalid.");
                }

                cacheEvaluation = cacheDecision.Evaluation;
                if (cacheEvaluation.Disposition != ReputationCacheDisposition.Fresh ||
                    !cacheEvaluation.CanReuse)
                {
                    return Reject(
                        ReputationProcessAttributionFailure.CacheEvaluationNotReusable,
                        "Only an exact fresh reusable cache evaluation can support attribution.");
                }

                if (!string.Equals(
                        cacheEvaluation.SourceEntry.SourceReceipt.ReceiptHashSha256,
                        receipt.ReceiptHashSha256,
                        StringComparison.Ordinal))
                {
                    return Reject(
                        ReputationProcessAttributionFailure.ReceiptMismatch,
                        "The cache evaluation does not preserve the supplied provider receipt.");
                }

                if (!RequestsEqual(targetRequest, cacheEvaluation.TargetRequest) ||
                    !ProvidersEqual(cacheEvaluation.ExpectedProvider, receipt.Result.Provider) ||
                    !IndicatorsEqual(
                        cacheEvaluation.TargetRequest.Indicator,
                        receipt.Result.Request.Indicator))
                {
                    return Reject(
                        ReputationProcessAttributionFailure.TargetRequestMismatch,
                        "The cache target, provider, or indicator does not match the supplied receipt.");
                }

                break;
        }

        if (targetRequest.Indicator.Kind != ReputationIndicatorKind.Sha256)
        {
            return Reject(
                ReputationProcessAttributionFailure.UnsupportedIndicatorKind,
                "Reputation process attribution version 1 supports only exact SHA-256 indicators.");
        }

        if (!Required(candidate.ProcessEntityId) || !Optional(candidate.ProcessKey))
        {
            return Reject(
                ReputationProcessAttributionFailure.InvalidProcessIdentity,
                "Reputation process attribution requires one bounded durable process identity.");
        }

        if (!Enum.IsDefined(candidate.CorrelationState) ||
            candidate.CorrelationState != EvidenceCorrelationState.Exact)
        {
            return Reject(
                ReputationProcessAttributionFailure.InvalidCorrelationState,
                "Reputation process attribution requires exact correlation.");
        }

        if (!Required(candidate.CorrelationMethod, MaximumCorrelationMethodLength))
        {
            return Reject(
                ReputationProcessAttributionFailure.InvalidCorrelationMethod,
                "Reputation process attribution requires one bounded correlation method.");
        }

        if (candidate.CorrelationCandidateCount != 1)
        {
            return Reject(
                ReputationProcessAttributionFailure.InvalidCorrelationCandidateCount,
                "Reputation process attribution requires exactly one correlation candidate.");
        }

        var referenceFailure = ValidateReferences(
            candidate.EvidenceReferences,
            targetRequest,
            candidate.ProcessEntityId,
            out var references);
        if (referenceFailure != ReputationProcessAttributionFailure.None)
        {
            return Reject(referenceFailure, ReferenceDiagnostic(referenceFailure));
        }

        var result = new ReputationProcessAttributionResult
        {
            SourceKind = candidate.SourceKind,
            Receipt = receipt,
            CacheEvaluation = cacheEvaluation,
            TargetRequest = targetRequest,
            ProcessEntityId = candidate.ProcessEntityId,
            ProcessKey = candidate.ProcessKey,
            CorrelationState = candidate.CorrelationState,
            CorrelationMethod = candidate.CorrelationMethod,
            CorrelationCandidateCount = candidate.CorrelationCandidateCount,
            EvidenceReferences = references
        };
        result = result with
        {
            AttributionHashSha256 = ComputeCanonicalHash(result)
        };

        return new ReputationProcessAttributionDecision
        {
            Accepted = true,
            Failure = ReputationProcessAttributionFailure.None,
            Result = result
        };
    }

    private static ReputationProcessAttributionFailure ValidateReferences(
        IReadOnlyList<EvidenceReference>? candidate,
        ReputationLookupRequest targetRequest,
        string processEntityId,
        out IReadOnlyList<EvidenceReference> references)
    {
        references = Array.Empty<EvidenceReference>();
        if (candidate == null || candidate.Count is 0 or > MaximumEvidenceReferences)
        {
            return ReputationProcessAttributionFailure.ReferenceLimitExceeded;
        }

        var targetKeys = new HashSet<(EvidenceReferenceKind Kind, string Id)>();
        foreach (var targetReference in targetRequest.EvidenceReferences)
        {
            if (!AllowedReferenceKinds.Contains(targetReference.Kind))
            {
                return ReputationProcessAttributionFailure.UnsupportedReference;
            }

            targetKeys.Add((targetReference.Kind, targetReference.Id));
        }

        if (!targetKeys.Any(key => SourceEvidenceKinds.Contains(key.Kind)))
        {
            return ReputationProcessAttributionFailure.MissingSourceEvidenceReference;
        }

        var keys = new HashSet<(EvidenceReferenceKind Kind, string Id)>();
        var canonical = new List<EvidenceReference>(candidate.Count);
        foreach (var reference in candidate)
        {
            if (reference == null || !Enum.IsDefined(reference.Kind) || !Required(reference.Id))
            {
                return ReputationProcessAttributionFailure.InvalidReference;
            }

            if (!AllowedReferenceKinds.Contains(reference.Kind))
            {
                return ReputationProcessAttributionFailure.UnsupportedReference;
            }

            if (reference.Kind == EvidenceReferenceKind.ProcessEntity &&
                !string.Equals(reference.Id, processEntityId, StringComparison.Ordinal) ||
                reference.Kind == EvidenceReferenceKind.SourceRun &&
                !string.Equals(reference.Id, targetRequest.SourceRunId, StringComparison.Ordinal))
            {
                return ReputationProcessAttributionFailure.MismatchedReference;
            }

            if (!keys.Add((reference.Kind, reference.Id)))
            {
                return ReputationProcessAttributionFailure.DuplicateReference;
            }

            canonical.Add(reference with { });
        }

        if (!keys.Contains((EvidenceReferenceKind.ProcessEntity, processEntityId)))
        {
            return ReputationProcessAttributionFailure.MissingProcessReference;
        }

        if (!keys.Contains((EvidenceReferenceKind.SourceRun, targetRequest.SourceRunId)))
        {
            return ReputationProcessAttributionFailure.MissingSourceRunReference;
        }

        if (!keys.Any(key => SourceEvidenceKinds.Contains(key.Kind)))
        {
            return ReputationProcessAttributionFailure.MissingSourceEvidenceReference;
        }

        if (targetKeys.Any(targetKey => !keys.Contains(targetKey)))
        {
            return ReputationProcessAttributionFailure.MissingTargetReference;
        }

        references = new ReadOnlyCollection<EvidenceReference>(canonical
            .OrderBy(reference => reference.Kind)
            .ThenBy(reference => reference.Id, StringComparer.Ordinal)
            .ToArray());
        return ReputationProcessAttributionFailure.None;
    }

    private static string ComputeCanonicalHash(ReputationProcessAttributionResult result)
    {
        var builder = new StringBuilder();
        Append(builder, result.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(builder, ((int)result.SourceKind).ToString(CultureInfo.InvariantCulture));
        Append(builder, result.Receipt.ReceiptHashSha256);
        Append(builder, result.CacheEvaluation?.DecisionHashSha256 ?? string.Empty);
        AppendRequest(builder, result.TargetRequest);
        Append(builder, result.ProcessEntityId);
        Append(builder, result.ProcessKey);
        Append(builder, ((int)result.CorrelationState).ToString(CultureInfo.InvariantCulture));
        Append(builder, result.CorrelationMethod);
        Append(builder, result.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture));
        foreach (var reference in result.EvidenceReferences)
        {
            Append(builder, ((int)reference.Kind).ToString(CultureInfo.InvariantCulture));
            Append(builder, reference.Id);
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())))
            .ToLowerInvariant();
    }

    private static void AppendRequest(StringBuilder builder, ReputationLookupRequest request)
    {
        Append(builder, request.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(builder, request.RequestId);
        Append(builder, ((int)request.Initiation).ToString(CultureInfo.InvariantCulture));
        Append(builder, ((int)request.Indicator.Kind).ToString(CultureInfo.InvariantCulture));
        Append(builder, request.Indicator.Value);
        Append(builder, request.EvidenceIdentity.CaseId);
        Append(builder, request.EvidenceIdentity.EvidenceSessionId);
        Append(builder, request.EvidenceIdentity.CaptureId);
        Append(builder, request.EvidenceIdentity.SourceIdentityId);
        Append(builder, request.EvidenceIdentity.HostId);
        Append(builder, request.EvidenceIdentity.ExecutionRootId);
        Append(builder, request.SourceRunId);
        Append(builder, request.RequestedUtc.ToString("O", CultureInfo.InvariantCulture));
        foreach (var reference in request.EvidenceReferences)
        {
            Append(builder, ((int)reference.Kind).ToString(CultureInfo.InvariantCulture));
            Append(builder, reference.Id);
        }
    }

    private static bool RequestsEqual(
        ReputationLookupRequest left,
        ReputationLookupRequest right) =>
        left.SchemaVersion == right.SchemaVersion &&
        string.Equals(left.RequestId, right.RequestId, StringComparison.Ordinal) &&
        left.Initiation == right.Initiation &&
        IndicatorsEqual(left.Indicator, right.Indicator) &&
        EvidenceIdentitiesEqual(left.EvidenceIdentity, right.EvidenceIdentity) &&
        string.Equals(left.SourceRunId, right.SourceRunId, StringComparison.Ordinal) &&
        left.RequestedUtc == right.RequestedUtc &&
        ReferencesEqual(left.EvidenceReferences, right.EvidenceReferences);

    private static bool IndicatorsEqual(ReputationIndicator left, ReputationIndicator right) =>
        left.Kind == right.Kind &&
        string.Equals(left.Value, right.Value, StringComparison.Ordinal);

    private static bool ProvidersEqual(
        ReputationProviderIdentity left,
        ReputationProviderIdentity right) =>
        string.Equals(left.ProviderId, right.ProviderId, StringComparison.Ordinal) &&
        string.Equals(left.ProviderVersion, right.ProviderVersion, StringComparison.Ordinal) &&
        string.Equals(left.DatasetId, right.DatasetId, StringComparison.Ordinal) &&
        string.Equals(left.DatasetVersion, right.DatasetVersion, StringComparison.Ordinal) &&
        left.QueryMode == right.QueryMode;

    private static bool EvidenceIdentitiesEqual(EvidenceIdentity left, EvidenceIdentity right) =>
        string.Equals(left.CaseId, right.CaseId, StringComparison.Ordinal) &&
        string.Equals(left.EvidenceSessionId, right.EvidenceSessionId, StringComparison.Ordinal) &&
        string.Equals(left.CaptureId, right.CaptureId, StringComparison.Ordinal) &&
        string.Equals(left.SourceIdentityId, right.SourceIdentityId, StringComparison.Ordinal) &&
        string.Equals(left.HostId, right.HostId, StringComparison.Ordinal) &&
        string.Equals(left.ExecutionRootId, right.ExecutionRootId, StringComparison.Ordinal);

    private static bool ReferencesEqual(
        IReadOnlyList<EvidenceReference> left,
        IReadOnlyList<EvidenceReference> right) =>
        left.Count == right.Count &&
        left.Zip(right).All(pair =>
            pair.First.Kind == pair.Second.Kind &&
            string.Equals(pair.First.Id, pair.Second.Id, StringComparison.Ordinal));

    private static bool Required(string? value, int maximumLength = MaximumIdentityLength) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximumLength &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal) &&
        !value.Any(char.IsControl);

    private static bool Optional(string? value) =>
        value != null &&
        value.Length <= MaximumIdentityLength &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal) &&
        !value.Any(char.IsControl);

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static void Append(StringBuilder builder, string value) =>
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture))
            .Append(':')
            .Append(value)
            .Append('\n');

    private static ReputationProcessAttributionDecision RejectExecution(
        ReputationProviderExecutionFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = ReputationProcessAttributionFailure.InvalidExecutionReceipt,
            ExecutionFailure = failure,
            Diagnostic = diagnostic
        };

    private static ReputationProcessAttributionDecision RejectCache(
        ReputationCacheFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = ReputationProcessAttributionFailure.InvalidCacheEvaluation,
            CacheFailure = failure,
            Diagnostic = diagnostic
        };

    private static ReputationProcessAttributionDecision Reject(
        ReputationProcessAttributionFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = diagnostic
        };

    private static string ReferenceDiagnostic(ReputationProcessAttributionFailure failure) =>
        failure switch
        {
            ReputationProcessAttributionFailure.ReferenceLimitExceeded =>
                "The reputation attribution evidence-reference set is empty or exceeds its bound.",
            ReputationProcessAttributionFailure.InvalidReference =>
                "The reputation attribution contains an invalid immutable reference.",
            ReputationProcessAttributionFailure.UnsupportedReference =>
                "The reputation attribution contains an unsupported reference kind.",
            ReputationProcessAttributionFailure.DuplicateReference =>
                "The reputation attribution contains a duplicate immutable reference.",
            ReputationProcessAttributionFailure.MismatchedReference =>
                "The reputation attribution contains a mismatched process or source-run reference.",
            ReputationProcessAttributionFailure.MissingProcessReference =>
                "The reputation attribution requires the exact durable ProcessEntity reference.",
            ReputationProcessAttributionFailure.MissingSourceRunReference =>
                "The reputation attribution requires the exact target SourceRun reference.",
            ReputationProcessAttributionFailure.MissingSourceEvidenceReference =>
                "The reputation attribution requires exact ProcessObservation or FileArtifact evidence.",
            ReputationProcessAttributionFailure.MissingTargetReference =>
                "The reputation attribution must preserve every target-request evidence reference.",
            _ => "The reputation attribution evidence references are invalid."
        };
}
