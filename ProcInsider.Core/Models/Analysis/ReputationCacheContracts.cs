using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ProcInsider.Models.Analysis;

public enum ReputationCacheDisposition
{
    Unknown = 0,
    Fresh = 1,
    Stale = 2,
    Expired = 3,
    KeyMiss = 4
}

public enum ReputationCacheFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    InvalidExecutionReceipt = 2,
    UncacheableSourceAvailability = 3,
    InvalidEntryTimestamp = 4,
    FreshnessLimitExceeded = 5,
    RetentionLimitExceeded = 6,
    InvalidCacheKey = 7,
    InvalidEntryHash = 8,
    InvalidTargetRequest = 9,
    InvalidProviderIdentity = 10,
    InvalidEvaluationTimestamp = 11,
    UnknownDisposition = 12,
    InvalidReuseState = 13,
    InvalidDecisionHash = 14
}

/// <summary>
/// Canonical metadata for one cacheable provider execution. Storage and
/// eviction remain outside this package-free contract.
/// </summary>
public sealed record ReputationCacheEntry
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ReputationProviderExecutionReceipt SourceReceipt { get; init; } = new();

    public DateTime StoredUtc { get; init; }

    public DateTime FreshUntilUtc { get; init; }

    public DateTime RetainUntilUtc { get; init; }

    public string CacheKeySha256 { get; init; } = string.Empty;

    public string EntryHashSha256 { get; init; } = string.Empty;
}

public sealed record ReputationCacheEntryDecision
{
    public bool Accepted { get; init; }

    public ReputationCacheFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationCacheEntry? Entry { get; init; }
}

/// <summary>
/// One exact cache evaluation. It preserves the new evidence-scoped request
/// beside the original provider receipt and never claims a new retrieval.
/// </summary>
public sealed record ReputationCacheEvaluation
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ReputationCacheEntry SourceEntry { get; init; } = new();

    public ReputationLookupRequest TargetRequest { get; init; } = new();

    public ReputationProviderIdentity ExpectedProvider { get; init; } = new();

    public DateTime EvaluatedUtc { get; init; }

    public ReputationCacheDisposition Disposition { get; init; }

    public bool CanReuse { get; init; }

    public string DecisionHashSha256 { get; init; } = string.Empty;
}

public sealed record ReputationCacheEvaluationDecision
{
    public bool Accepted { get; init; }

    public ReputationCacheFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationCacheEvaluation? Evaluation { get; init; }
}

/// <summary>
/// Pure fail-closed cache-entry and reuse evaluation. It performs no storage,
/// provider access, credential loading, persistence, scoring, or UI work.
/// </summary>
public static class ReputationCachePolicy
{
    public const int MaximumFreshnessDays = 30;
    public const int MaximumRetentionDays = 365;

    public static ReputationCacheEntryDecision ValidateEntry(ReputationCacheEntry candidate) =>
        ValidateEntryInternal(candidate, requireHash: true);

    public static string ComputeCacheKey(
        ReputationLookupRequest request,
        ReputationProviderIdentity provider)
    {
        if (!ReputationLookupContractPolicy.TryCanonicalizeRequest(
                request, out var canonicalRequest, out _) ||
            !ReputationLookupContractPolicy.TryCanonicalizeProvider(
                provider, out var canonicalProvider, out _))
        {
            return string.Empty;
        }

        return ComputeCanonicalCacheKey(
            canonicalRequest.Indicator,
            canonicalProvider);
    }

    public static string ComputeEntryHash(ReputationCacheEntry candidate)
    {
        var decision = ValidateEntryInternal(candidate, requireHash: false);
        return decision.Accepted && decision.Entry != null
            ? decision.Entry.EntryHashSha256
            : string.Empty;
    }

    public static ReputationCacheEvaluationDecision Evaluate(
        ReputationCacheEntry entry,
        ReputationLookupRequest targetRequest,
        ReputationProviderIdentity expectedProvider,
        DateTime evaluatedUtc)
    {
        var entryDecision = ValidateEntry(entry);
        if (!entryDecision.Accepted || entryDecision.Entry == null)
        {
            return RejectEvaluation(entryDecision.Failure);
        }

        if (!ReputationLookupContractPolicy.TryCanonicalizeRequest(
                targetRequest, out var request, out _))
        {
            return RejectEvaluation(ReputationCacheFailure.InvalidTargetRequest);
        }

        if (!ReputationLookupContractPolicy.TryCanonicalizeProvider(
                expectedProvider, out var provider, out _))
        {
            return RejectEvaluation(ReputationCacheFailure.InvalidProviderIdentity);
        }

        var canonicalEntry = entryDecision.Entry;
        if (!IsUtc(evaluatedUtc) ||
            evaluatedUtc < canonicalEntry.StoredUtc ||
            evaluatedUtc < request.RequestedUtc)
        {
            return RejectEvaluation(ReputationCacheFailure.InvalidEvaluationTimestamp);
        }

        var targetCacheKey = ComputeCanonicalCacheKey(request.Indicator, provider);
        var keyMatches = string.Equals(
            targetCacheKey,
            canonicalEntry.CacheKeySha256,
            StringComparison.Ordinal);
        var disposition = keyMatches
            ? evaluatedUtc <= canonicalEntry.FreshUntilUtc
                ? ReputationCacheDisposition.Fresh
                : evaluatedUtc <= canonicalEntry.RetainUntilUtc
                    ? ReputationCacheDisposition.Stale
                    : ReputationCacheDisposition.Expired
            : ReputationCacheDisposition.KeyMiss;
        var canReuse = disposition == ReputationCacheDisposition.Fresh;
        var evaluation = new ReputationCacheEvaluation
        {
            SourceEntry = canonicalEntry,
            TargetRequest = request,
            ExpectedProvider = provider,
            EvaluatedUtc = evaluatedUtc,
            Disposition = disposition,
            CanReuse = canReuse
        };
        evaluation = evaluation with
        {
            DecisionHashSha256 = ComputeCanonicalEvaluationHash(evaluation)
        };

        return AcceptEvaluation(evaluation);
    }

    public static ReputationCacheEvaluationDecision ValidateEvaluation(
        ReputationCacheEvaluation candidate)
    {
        if (candidate == null ||
            candidate.SchemaVersion != ReputationCacheEvaluation.CurrentSchemaVersion)
        {
            return RejectEvaluation(ReputationCacheFailure.InvalidSchemaVersion);
        }

        if (!Enum.IsDefined(typeof(ReputationCacheDisposition), candidate.Disposition) ||
            candidate.Disposition == ReputationCacheDisposition.Unknown)
        {
            return RejectEvaluation(ReputationCacheFailure.UnknownDisposition);
        }

        var decision = Evaluate(
            candidate.SourceEntry,
            candidate.TargetRequest,
            candidate.ExpectedProvider,
            candidate.EvaluatedUtc);
        if (!decision.Accepted || decision.Evaluation == null)
        {
            return decision;
        }

        var canonical = decision.Evaluation;
        if (candidate.Disposition != canonical.Disposition ||
            candidate.CanReuse != canonical.CanReuse)
        {
            return RejectEvaluation(ReputationCacheFailure.InvalidReuseState);
        }

        if (!IsLowerSha256(candidate.DecisionHashSha256) ||
            !string.Equals(
                candidate.DecisionHashSha256,
                canonical.DecisionHashSha256,
                StringComparison.Ordinal))
        {
            return RejectEvaluation(ReputationCacheFailure.InvalidDecisionHash);
        }

        return AcceptEvaluation(canonical);
    }

    private static ReputationCacheEntryDecision ValidateEntryInternal(
        ReputationCacheEntry? candidate,
        bool requireHash)
    {
        if (candidate == null ||
            candidate.SchemaVersion != ReputationCacheEntry.CurrentSchemaVersion)
        {
            return RejectEntry(ReputationCacheFailure.InvalidSchemaVersion);
        }

        var receiptDecision =
            ReputationProviderExecutionPolicy.Validate(candidate.SourceReceipt);
        if (!receiptDecision.Accepted || receiptDecision.Receipt == null)
        {
            return RejectEntry(ReputationCacheFailure.InvalidExecutionReceipt);
        }

        var receipt = receiptDecision.Receipt;
        if (receipt.Result.Availability != AnalysisSourceAvailability.Available)
        {
            return RejectEntry(ReputationCacheFailure.UncacheableSourceAvailability);
        }

        if (!IsUtc(candidate.StoredUtc) ||
            !IsUtc(candidate.FreshUntilUtc) ||
            !IsUtc(candidate.RetainUntilUtc) ||
            candidate.StoredUtc < receipt.CompletedUtc ||
            candidate.FreshUntilUtc < candidate.StoredUtc ||
            candidate.RetainUntilUtc < candidate.FreshUntilUtc)
        {
            return RejectEntry(ReputationCacheFailure.InvalidEntryTimestamp);
        }

        if (candidate.FreshUntilUtc - candidate.StoredUtc >
            TimeSpan.FromDays(MaximumFreshnessDays))
        {
            return RejectEntry(ReputationCacheFailure.FreshnessLimitExceeded);
        }

        if (candidate.RetainUntilUtc - candidate.StoredUtc >
            TimeSpan.FromDays(MaximumRetentionDays))
        {
            return RejectEntry(ReputationCacheFailure.RetentionLimitExceeded);
        }

        var expectedCacheKey = ComputeCanonicalCacheKey(
            receipt.Result.Request.Indicator,
            receipt.Result.Provider);
        if (!IsLowerSha256(candidate.CacheKeySha256) ||
            !string.Equals(
                candidate.CacheKeySha256,
                expectedCacheKey,
                StringComparison.Ordinal))
        {
            return RejectEntry(ReputationCacheFailure.InvalidCacheKey);
        }

        var canonical = candidate with
        {
            SourceReceipt = receipt,
            CacheKeySha256 = expectedCacheKey,
            EntryHashSha256 = string.Empty
        };
        var expectedHash = ComputeCanonicalEntryHash(canonical);
        if (requireHash &&
            (!IsLowerSha256(candidate.EntryHashSha256) ||
             !string.Equals(candidate.EntryHashSha256, expectedHash, StringComparison.Ordinal)))
        {
            return RejectEntry(ReputationCacheFailure.InvalidEntryHash);
        }

        return new ReputationCacheEntryDecision
        {
            Accepted = true,
            Failure = ReputationCacheFailure.None,
            Entry = canonical with { EntryHashSha256 = expectedHash }
        };
    }

    private static string ComputeCanonicalCacheKey(
        ReputationIndicator indicator,
        ReputationProviderIdentity provider)
    {
        var builder = new StringBuilder();
        Append(builder, ((int)indicator.Kind).ToString(CultureInfo.InvariantCulture));
        Append(builder, indicator.Value);
        AppendProvider(builder, provider);
        return Hash(builder);
    }

    private static string ComputeCanonicalEntryHash(ReputationCacheEntry entry)
    {
        var builder = new StringBuilder();
        Append(builder, entry.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(builder, entry.SourceReceipt.ReceiptHashSha256);
        Append(builder, entry.CacheKeySha256);
        Append(builder, entry.StoredUtc.ToString("O", CultureInfo.InvariantCulture));
        Append(builder, entry.FreshUntilUtc.ToString("O", CultureInfo.InvariantCulture));
        Append(builder, entry.RetainUntilUtc.ToString("O", CultureInfo.InvariantCulture));
        return Hash(builder);
    }

    private static string ComputeCanonicalEvaluationHash(ReputationCacheEvaluation evaluation)
    {
        var builder = new StringBuilder();
        Append(builder, evaluation.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(builder, evaluation.SourceEntry.EntryHashSha256);
        AppendRequest(builder, evaluation.TargetRequest);
        AppendProvider(builder, evaluation.ExpectedProvider);
        Append(builder, evaluation.EvaluatedUtc.ToString("O", CultureInfo.InvariantCulture));
        Append(builder, ((int)evaluation.Disposition).ToString(CultureInfo.InvariantCulture));
        Append(builder, evaluation.CanReuse ? "1" : "0");
        return Hash(builder);
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

    private static void AppendProvider(
        StringBuilder builder,
        ReputationProviderIdentity provider)
    {
        Append(builder, provider.ProviderId);
        Append(builder, provider.ProviderVersion);
        Append(builder, provider.DatasetId);
        Append(builder, provider.DatasetVersion);
        Append(builder, ((int)provider.QueryMode).ToString(CultureInfo.InvariantCulture));
    }

    private static string Hash(StringBuilder builder) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())))
            .ToLowerInvariant();

    private static void Append(StringBuilder builder, string value) =>
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture))
            .Append(':')
            .Append(value)
            .Append('\n');

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static bool IsUtc(DateTime value) =>
        value != default && value.Kind == DateTimeKind.Utc;

    private static ReputationCacheEntryDecision RejectEntry(
        ReputationCacheFailure failure) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = Diagnostic(failure)
        };

    private static ReputationCacheEvaluationDecision AcceptEvaluation(
        ReputationCacheEvaluation evaluation) =>
        new()
        {
            Accepted = true,
            Failure = ReputationCacheFailure.None,
            Evaluation = evaluation
        };

    private static ReputationCacheEvaluationDecision RejectEvaluation(
        ReputationCacheFailure failure) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = Diagnostic(failure)
        };

    private static string Diagnostic(ReputationCacheFailure failure) =>
        failure switch
        {
            ReputationCacheFailure.InvalidSchemaVersion =>
                "The reputation cache schema version is unsupported.",
            ReputationCacheFailure.InvalidExecutionReceipt =>
                "The reputation cache source does not contain a valid #401 execution receipt.",
            ReputationCacheFailure.UncacheableSourceAvailability =>
                "Only an available reputation provider result can become a reusable cache entry.",
            ReputationCacheFailure.InvalidEntryTimestamp =>
                "The reputation cache entry timestamps are invalid or out of order.",
            ReputationCacheFailure.FreshnessLimitExceeded =>
                "The reputation cache freshness window exceeds the fixed policy ceiling.",
            ReputationCacheFailure.RetentionLimitExceeded =>
                "The reputation cache retention window exceeds the fixed policy ceiling.",
            ReputationCacheFailure.InvalidCacheKey =>
                "The reputation cache key is missing or does not match its source receipt.",
            ReputationCacheFailure.InvalidEntryHash =>
                "The reputation cache entry identity is missing or mismatched.",
            ReputationCacheFailure.InvalidTargetRequest =>
                "The reputation cache target request is invalid.",
            ReputationCacheFailure.InvalidProviderIdentity =>
                "The reputation cache expected provider identity is invalid.",
            ReputationCacheFailure.InvalidEvaluationTimestamp =>
                "The reputation cache evaluation timestamp is invalid or predates its inputs.",
            ReputationCacheFailure.UnknownDisposition =>
                "The reputation cache disposition is unknown or unsupported.",
            ReputationCacheFailure.InvalidReuseState =>
                "The reputation cache disposition and reuse flag do not match the exact policy decision.",
            ReputationCacheFailure.InvalidDecisionHash =>
                "The reputation cache decision identity is missing or mismatched.",
            _ => "The reputation cache input violates the portable policy."
        };
}
