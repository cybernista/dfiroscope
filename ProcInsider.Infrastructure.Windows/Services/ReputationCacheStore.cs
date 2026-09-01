using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum ReputationCacheStoreWriteKind
{
    Unknown = 0,
    Stored = 1,
    Replaced = 2,
    Unchanged = 3,
    Rejected = 4
}

public enum ReputationCacheStoreLookupKind
{
    Unknown = 0,
    Miss = 1,
    Fresh = 2,
    Stale = 3,
    Expired = 4,
    Rejected = 5
}

public enum ReputationCacheStoreFailure
{
    None = 0,
    InvalidEntry = 1,
    InvalidOperationTimestamp = 2,
    OlderEntry = 3,
    ConflictingEntry = 4,
    InvalidLookupInput = 5,
    EvaluationRejected = 6
}

public sealed record ReputationCacheStoreWriteResult
{
    public ReputationCacheStoreWriteKind Kind { get; init; }

    public ReputationCacheStoreFailure Failure { get; init; }

    public ReputationCacheFailure PolicyFailure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public int Count { get; init; }

    public int ExpiredEvictionCount { get; init; }

    public int CapacityEvictionCount { get; init; }

    public bool IsRetained { get; init; }

    public bool Accepted => Kind is
        ReputationCacheStoreWriteKind.Stored or
        ReputationCacheStoreWriteKind.Replaced or
        ReputationCacheStoreWriteKind.Unchanged;
}

public sealed record ReputationCacheStoreLookupResult
{
    public ReputationCacheStoreLookupKind Kind { get; init; }

    public ReputationCacheStoreFailure Failure { get; init; }

    public ReputationCacheFailure PolicyFailure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationCacheEvaluation? Evaluation { get; init; }

    public int Count { get; init; }

    public int ExpiredEvictionCount { get; init; }

    public bool CanReuse =>
        Kind == ReputationCacheStoreLookupKind.Fresh &&
        Evaluation?.CanReuse == true;
}

/// <summary>
/// Process-local bounded storage for canonical #402 reputation cache entries.
/// It performs no provider access, persistence, evidence writes, scoring, or UI work.
/// </summary>
public sealed class ReputationCacheStore
{
    public const int DefaultMaximumEntries = 1_000;
    public const int HardMaximumEntries = 10_000;

    private readonly object _sync = new();
    private readonly Dictionary<string, ReputationCacheEntry> _entries =
        new(StringComparer.Ordinal);
    private readonly int _maximumEntries;

    public ReputationCacheStore(int maximumEntries = DefaultMaximumEntries)
    {
        if (maximumEntries is < 1 or > HardMaximumEntries)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumEntries),
                $"The reputation cache capacity must be between 1 and {HardMaximumEntries} entries.");
        }

        _maximumEntries = maximumEntries;
    }

    public int MaximumEntries => _maximumEntries;

    public int Count
    {
        get
        {
            lock (_sync)
            {
                return _entries.Count;
            }
        }
    }

    public ReputationCacheStoreWriteResult Store(
        ReputationCacheEntry candidate,
        DateTime operationUtc)
    {
        var entryDecision = ReputationCachePolicy.ValidateEntry(candidate);
        if (!entryDecision.Accepted || entryDecision.Entry == null)
        {
            return RejectWrite(
                ReputationCacheStoreFailure.InvalidEntry,
                entryDecision.Failure,
                "The reputation cache store rejected an invalid #402 entry.");
        }

        var entry = entryDecision.Entry;
        if (!IsUtc(operationUtc) || operationUtc < entry.StoredUtc)
        {
            return RejectWrite(
                ReputationCacheStoreFailure.InvalidOperationTimestamp,
                ReputationCacheFailure.InvalidEvaluationTimestamp,
                "The reputation cache store operation time is invalid or predates the entry.");
        }

        lock (_sync)
        {
            var expiredEvictions = PruneExpiredLocked(operationUtc);
            if (_entries.TryGetValue(entry.CacheKeySha256, out var existing))
            {
                if (existing.StoredUtc > entry.StoredUtc)
                {
                    return RejectWriteLocked(
                        ReputationCacheStoreFailure.OlderEntry,
                        "An older reputation cache entry cannot replace the retained exact-key entry.",
                        expiredEvictions);
                }

                if (existing.StoredUtc == entry.StoredUtc)
                {
                    if (string.Equals(
                            existing.EntryHashSha256,
                            entry.EntryHashSha256,
                            StringComparison.Ordinal))
                    {
                        return AcceptWriteLocked(
                            ReputationCacheStoreWriteKind.Unchanged,
                            entry,
                            expiredEvictions,
                            capacityEvictions: 0);
                    }

                    return RejectWriteLocked(
                        ReputationCacheStoreFailure.ConflictingEntry,
                        "A same-time reputation cache entry has a different canonical identity.",
                        expiredEvictions);
                }
            }

            var kind = _entries.ContainsKey(entry.CacheKeySha256)
                ? ReputationCacheStoreWriteKind.Replaced
                : ReputationCacheStoreWriteKind.Stored;
            _entries[entry.CacheKeySha256] = entry;
            var capacityEvictions = EnforceCapacityLocked();
            return AcceptWriteLocked(kind, entry, expiredEvictions, capacityEvictions);
        }
    }

    public ReputationCacheStoreLookupResult Lookup(
        ReputationLookupRequest targetRequest,
        ReputationProviderIdentity expectedProvider,
        DateTime evaluatedUtc)
    {
        if (!IsUtc(evaluatedUtc) ||
            targetRequest == null ||
            evaluatedUtc < targetRequest.RequestedUtc)
        {
            return RejectLookup(
                ReputationCacheStoreFailure.InvalidLookupInput,
                ReputationCacheFailure.InvalidEvaluationTimestamp,
                "The reputation cache lookup time or target request is invalid.");
        }

        var cacheKey = ReputationCachePolicy.ComputeCacheKey(targetRequest, expectedProvider);
        if (cacheKey.Length == 0)
        {
            return RejectLookup(
                ReputationCacheStoreFailure.InvalidLookupInput,
                ReputationCacheFailure.InvalidTargetRequest,
                "The reputation cache lookup request or provider identity is invalid.");
        }

        lock (_sync)
        {
            if (!_entries.TryGetValue(cacheKey, out var entry))
            {
                var missExpiredEvictions = PruneExpiredLocked(evaluatedUtc);
                return new ReputationCacheStoreLookupResult
                {
                    Kind = ReputationCacheStoreLookupKind.Miss,
                    Count = _entries.Count,
                    ExpiredEvictionCount = missExpiredEvictions
                };
            }

            var decision = ReputationCachePolicy.Evaluate(
                entry,
                targetRequest,
                expectedProvider,
                evaluatedUtc);
            if (!decision.Accepted || decision.Evaluation == null)
            {
                return RejectLookupLocked(
                    ReputationCacheStoreFailure.EvaluationRejected,
                    decision.Failure,
                    "The retained reputation cache entry could not be evaluated for this exact request.");
            }

            var evaluation = decision.Evaluation;
            var kind = evaluation.Disposition switch
            {
                ReputationCacheDisposition.Fresh => ReputationCacheStoreLookupKind.Fresh,
                ReputationCacheDisposition.Stale => ReputationCacheStoreLookupKind.Stale,
                ReputationCacheDisposition.Expired => ReputationCacheStoreLookupKind.Expired,
                _ => ReputationCacheStoreLookupKind.Rejected
            };
            if (kind == ReputationCacheStoreLookupKind.Rejected)
            {
                return RejectLookupLocked(
                    ReputationCacheStoreFailure.EvaluationRejected,
                    ReputationCacheFailure.InvalidReuseState,
                    "The retained reputation cache entry produced an unsupported reuse state.");
            }

            var expiredEvictions = 0;
            if (kind == ReputationCacheStoreLookupKind.Expired &&
                _entries.TryGetValue(cacheKey, out var current) &&
                string.Equals(
                    current.EntryHashSha256,
                    entry.EntryHashSha256,
                    StringComparison.Ordinal))
            {
                _entries.Remove(cacheKey);
                expiredEvictions++;
            }
            expiredEvictions += PruneExpiredLocked(evaluatedUtc);

            return new ReputationCacheStoreLookupResult
            {
                Kind = kind,
                Evaluation = evaluation,
                Count = _entries.Count,
                ExpiredEvictionCount = expiredEvictions
            };
        }
    }

    public int PruneExpired(DateTime evaluatedUtc)
    {
        if (!IsUtc(evaluatedUtc))
        {
            throw new ArgumentException(
                "The reputation cache evaluation time must be a non-default UTC value.",
                nameof(evaluatedUtc));
        }

        lock (_sync)
        {
            return PruneExpiredLocked(evaluatedUtc);
        }
    }

    public int Clear()
    {
        lock (_sync)
        {
            var removed = _entries.Count;
            _entries.Clear();
            return removed;
        }
    }

    private int PruneExpiredLocked(DateTime evaluatedUtc)
    {
        var keys = _entries
            .Where(pair => evaluatedUtc > pair.Value.RetainUntilUtc)
            .Select(pair => pair.Key)
            .ToArray();
        foreach (var key in keys)
        {
            _entries.Remove(key);
        }

        return keys.Length;
    }

    private int EnforceCapacityLocked()
    {
        var excess = _entries.Count - _maximumEntries;
        if (excess <= 0)
        {
            return 0;
        }

        var keys = _entries
            .OrderBy(pair => pair.Value.RetainUntilUtc)
            .ThenBy(pair => pair.Value.StoredUtc)
            .ThenBy(pair => pair.Key, StringComparer.Ordinal)
            .Take(excess)
            .Select(pair => pair.Key)
            .ToArray();
        foreach (var key in keys)
        {
            _entries.Remove(key);
        }

        return keys.Length;
    }

    private ReputationCacheStoreWriteResult AcceptWriteLocked(
        ReputationCacheStoreWriteKind kind,
        ReputationCacheEntry entry,
        int expiredEvictions,
        int capacityEvictions) =>
        new()
        {
            Kind = kind,
            Count = _entries.Count,
            ExpiredEvictionCount = expiredEvictions,
            CapacityEvictionCount = capacityEvictions,
            IsRetained = _entries.TryGetValue(entry.CacheKeySha256, out var retained) &&
                string.Equals(
                    retained.EntryHashSha256,
                    entry.EntryHashSha256,
                    StringComparison.Ordinal)
        };

    private ReputationCacheStoreWriteResult RejectWriteLocked(
        ReputationCacheStoreFailure failure,
        string diagnostic,
        int expiredEvictions) =>
        new()
        {
            Kind = ReputationCacheStoreWriteKind.Rejected,
            Failure = failure,
            Diagnostic = diagnostic,
            Count = _entries.Count,
            ExpiredEvictionCount = expiredEvictions
        };

    private static ReputationCacheStoreWriteResult RejectWrite(
        ReputationCacheStoreFailure failure,
        ReputationCacheFailure policyFailure,
        string diagnostic) =>
        new()
        {
            Kind = ReputationCacheStoreWriteKind.Rejected,
            Failure = failure,
            PolicyFailure = policyFailure,
            Diagnostic = diagnostic
        };

    private ReputationCacheStoreLookupResult RejectLookupLocked(
        ReputationCacheStoreFailure failure,
        ReputationCacheFailure policyFailure,
        string diagnostic) =>
        new()
        {
            Kind = ReputationCacheStoreLookupKind.Rejected,
            Failure = failure,
            PolicyFailure = policyFailure,
            Diagnostic = diagnostic,
            Count = _entries.Count
        };

    private static ReputationCacheStoreLookupResult RejectLookup(
        ReputationCacheStoreFailure failure,
        ReputationCacheFailure policyFailure,
        string diagnostic) =>
        new()
        {
            Kind = ReputationCacheStoreLookupKind.Rejected,
            Failure = failure,
            PolicyFailure = policyFailure,
            Diagnostic = diagnostic
        };

    private static bool IsUtc(DateTime value) =>
        value != default && value.Kind == DateTimeKind.Utc;
}
