using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum ReputationProviderExecutionCoordinatorResultKind
{
    Unknown = 0,
    CacheHit = 1,
    Executed = 2,
    RateLimited = 3,
    Rejected = 4,
    Failed = 5,
    Canceled = 6
}

public enum ReputationProviderExecutionCoordinatorFailure
{
    None = 0,
    Disposed = 1,
    InvalidAuthorization = 2,
    AdmissionMismatch = 3,
    InvalidOperationTimestamp = 4,
    CacheLookupRejected = 5,
    MinuteRateLimitExceeded = 6,
    DayRateLimitExceeded = 7,
    AdapterFailure = 8,
    InvalidAdapterResponse = 9,
    InvalidExecutionReceipt = 10,
    CacheStoreRejected = 11
}

/// <summary>
/// Provider-neutral output from one injected adapter attempt. Transport content,
/// endpoints, credentials, evidence bytes and paths are deliberately absent.
/// </summary>
public sealed record ReputationProviderAdapterResponse
{
    public ReputationLookupResult Result { get; init; } = new();

    public int ResponseLength { get; init; }
}

public interface IReputationProviderAdapter
{
    ValueTask<ReputationProviderAdapterResponse> ExecuteAsync(
        ReputationProviderAuthorization authorization,
        CancellationToken cancellationToken);
}

public sealed record ReputationProviderExecutionCoordinatorResult
{
    public ReputationProviderExecutionCoordinatorResultKind Kind { get; init; }

    public ReputationProviderExecutionCoordinatorFailure Failure { get; init; }

    public ReputationProviderAuthorizationFailure AuthorizationFailure { get; init; }

    public ReputationProviderExecutionFailure ExecutionFailure { get; init; }

    public ReputationCacheStoreFailure CacheStoreFailure { get; init; }

    public ReputationCacheFailure CacheFailure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationLookupResult? Result { get; init; }

    public ReputationProviderExecutionReceipt? Receipt { get; init; }

    public ReputationCacheEvaluation? CacheEvaluation { get; init; }

    public ReputationCacheStoreWriteResult? CacheWrite { get; init; }

    public long StartedAttemptCount { get; init; }

    public bool Succeeded => Kind is
        ReputationProviderExecutionCoordinatorResultKind.CacheHit or
        ReputationProviderExecutionCoordinatorResultKind.Executed;
}

/// <summary>
/// Stateful process-local owner for exact cache reuse, provider concurrency/rate
/// admission, one injected adapter attempt, receipt validation and cache publication.
/// It performs no transport, credential loading, persistence, evidence writes,
/// scoring, annotation, Agent IPC or UI work.
/// </summary>
public sealed class ReputationProviderExecutionCoordinator : IAsyncDisposable
{
    private static readonly TimeSpan MinuteWindow = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan DayWindow = TimeSpan.FromDays(1);

    private readonly object _sync = new();
    private readonly ReputationProviderAdmission _admission;
    private readonly IReputationProviderAdapter _adapter;
    private readonly ReputationCacheStore _cacheStore;
    private readonly Func<DateTime> _utcNow;
    private readonly TimeSpan _freshness;
    private readonly TimeSpan _retention;
    private readonly SemaphoreSlim _concurrency;
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly Queue<DateTime> _minuteStarts = new();
    private readonly Queue<DateTime> _dayStarts = new();
    private TaskCompletionSource? _drained;
    private Task? _disposeTask;
    private int _activeOperations;
    private long _startedAttemptCount;
    private DateTime _lastStartedUtc;
    private bool _disposed;

    public ReputationProviderExecutionCoordinator(
        ReputationProviderAdmission admission,
        IReputationProviderAdapter adapter,
        ReputationCacheStore cacheStore,
        Func<DateTime> utcNow,
        TimeSpan freshness,
        TimeSpan retention)
    {
        var admissionDecision =
            ReputationProviderAuthorizationPolicy.ValidateAdmission(admission);
        if (!admissionDecision.Accepted || admissionDecision.Admission == null)
        {
            throw new ArgumentException(
                "The reputation execution coordinator requires a canonical provider admission.",
                nameof(admission));
        }

        if (adapter == null)
        {
            throw new ArgumentNullException(nameof(adapter));
        }

        if (cacheStore == null)
        {
            throw new ArgumentNullException(nameof(cacheStore));
        }

        if (utcNow == null)
        {
            throw new ArgumentNullException(nameof(utcNow));
        }

        if (freshness < TimeSpan.Zero ||
            freshness > TimeSpan.FromDays(ReputationCachePolicy.MaximumFreshnessDays))
        {
            throw new ArgumentOutOfRangeException(nameof(freshness));
        }

        if (retention < freshness ||
            retention > TimeSpan.FromDays(ReputationCachePolicy.MaximumRetentionDays))
        {
            throw new ArgumentOutOfRangeException(nameof(retention));
        }

        _admission = admissionDecision.Admission;
        _adapter = adapter;
        _cacheStore = cacheStore;
        _utcNow = utcNow;
        _freshness = freshness;
        _retention = retention;
        _concurrency = new SemaphoreSlim(
            _admission.Limits.MaximumConcurrency,
            _admission.Limits.MaximumConcurrency);
    }

    public string AdmissionHashSha256 => _admission.AdmissionHashSha256;

    public long StartedAttemptCount
    {
        get
        {
            lock (_sync)
            {
                return _startedAttemptCount;
            }
        }
    }

    public async ValueTask<ReputationProviderExecutionCoordinatorResult> ExecuteAsync(
        ReputationProviderAuthorization candidate,
        CancellationToken cancellationToken = default)
    {
        if (!TryBeginOperation(out var lifetimeToken))
        {
            return Reject(
                ReputationProviderExecutionCoordinatorFailure.Disposed,
                "The reputation execution coordinator is disposed.");
        }

        try
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return Canceled();
            }

            var authorizationDecision =
                ReputationProviderAuthorizationPolicy.ValidateAuthorization(candidate);
            if (!authorizationDecision.Accepted || authorizationDecision.Authorization == null)
            {
                return Reject(
                    ReputationProviderExecutionCoordinatorFailure.InvalidAuthorization,
                    "The reputation provider authorization is invalid.",
                    authorizationFailure: authorizationDecision.Failure);
            }

            var authorization = authorizationDecision.Authorization;
            if (!string.Equals(
                    authorization.Admission.AdmissionHashSha256,
                    _admission.AdmissionHashSha256,
                    StringComparison.Ordinal))
            {
                return Reject(
                    ReputationProviderExecutionCoordinatorFailure.AdmissionMismatch,
                    "The authorization does not belong to this exact provider admission.");
            }

            var evaluatedUtc = _utcNow();
            if (!IsUtc(evaluatedUtc) || evaluatedUtc < authorization.AuthorizedUtc)
            {
                return Reject(
                    ReputationProviderExecutionCoordinatorFailure.InvalidOperationTimestamp,
                    "The reputation cache evaluation time is invalid or predates authorization.");
            }

            var cacheLookup = _cacheStore.Lookup(
                authorization.LookupRequest,
                _admission.Provider,
                evaluatedUtc);
            if (cacheLookup.Kind == ReputationCacheStoreLookupKind.Rejected)
            {
                return Reject(
                    ReputationProviderExecutionCoordinatorFailure.CacheLookupRejected,
                    "The exact reputation cache lookup was rejected.",
                    cacheStoreFailure: cacheLookup.Failure,
                    cacheFailure: cacheLookup.PolicyFailure);
            }

            if (cacheLookup.Kind == ReputationCacheStoreLookupKind.Fresh &&
                cacheLookup.Evaluation is { CanReuse: true } evaluation)
            {
                return Snapshot(new ReputationProviderExecutionCoordinatorResult
                {
                    Kind = ReputationProviderExecutionCoordinatorResultKind.CacheHit,
                    Result = evaluation.SourceEntry.SourceReceipt.Result,
                    Receipt = evaluation.SourceEntry.SourceReceipt,
                    CacheEvaluation = evaluation
                });
            }

            var immediateAdmissionFailure = EvaluateAttemptAdmission(
                evaluatedUtc,
                authorization.AuthorizedUtc,
                commitStart: false);
            if (immediateAdmissionFailure !=
                ReputationProviderExecutionCoordinatorFailure.None)
            {
                return immediateAdmissionFailure switch
                {
                    ReputationProviderExecutionCoordinatorFailure.MinuteRateLimitExceeded =>
                        RateLimited(immediateAdmissionFailure,
                            "The provider minute request ceiling has been reached."),
                    ReputationProviderExecutionCoordinatorFailure.DayRateLimitExceeded =>
                        RateLimited(immediateAdmissionFailure,
                            "The provider daily request ceiling has been reached."),
                    _ => Reject(
                        ReputationProviderExecutionCoordinatorFailure.InvalidOperationTimestamp,
                        "The provider admission time is invalid or regressed.")
                };
            }

            using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                lifetimeToken);
            try
            {
                await _concurrency.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (linkedCancellation.IsCancellationRequested)
            {
                return Canceled();
            }

            try
            {
                if (linkedCancellation.IsCancellationRequested)
                {
                    return Canceled();
                }

                var startedUtc = _utcNow();
                var admissionFailure = EvaluateAttemptAdmission(
                    startedUtc,
                    authorization.AuthorizedUtc,
                    commitStart: true);
                if (admissionFailure != ReputationProviderExecutionCoordinatorFailure.None)
                {
                    return admissionFailure switch
                    {
                        ReputationProviderExecutionCoordinatorFailure.MinuteRateLimitExceeded =>
                            RateLimited(admissionFailure,
                                "The provider minute request ceiling has been reached."),
                        ReputationProviderExecutionCoordinatorFailure.DayRateLimitExceeded =>
                            RateLimited(admissionFailure,
                                "The provider daily request ceiling has been reached."),
                        _ => Reject(
                            ReputationProviderExecutionCoordinatorFailure.InvalidOperationTimestamp,
                            "The provider attempt start time is invalid or regressed.")
                    };
                }

                ReputationProviderAdapterResponse response;
                try
                {
                    response = await _adapter.ExecuteAsync(
                            authorization,
                            linkedCancellation.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (linkedCancellation.IsCancellationRequested)
                {
                    return Canceled();
                }
                catch
                {
                    return Failed(
                        ReputationProviderExecutionCoordinatorFailure.AdapterFailure,
                        "The reputation provider adapter failed without a reusable result.");
                }

                if (linkedCancellation.IsCancellationRequested)
                {
                    return Canceled();
                }

                var completedUtc = _utcNow();
                if (!IsUtc(completedUtc) || completedUtc < startedUtc)
                {
                    return Reject(
                        ReputationProviderExecutionCoordinatorFailure.InvalidOperationTimestamp,
                        "The provider attempt completion time is invalid or precedes its start.");
                }

                if (response?.Result == null)
                {
                    return Reject(
                        ReputationProviderExecutionCoordinatorFailure.InvalidAdapterResponse,
                        "The provider adapter returned no bounded lookup result.");
                }

                var receipt = new ReputationProviderExecutionReceipt
                {
                    Authorization = authorization,
                    Result = response.Result,
                    StartedUtc = startedUtc,
                    CompletedUtc = completedUtc,
                    ResponseLength = response.ResponseLength
                };
                receipt = receipt with
                {
                    ReceiptHashSha256 =
                        ReputationProviderExecutionPolicy.ComputeReceiptHash(receipt)
                };
                var receiptDecision = ReputationProviderExecutionPolicy.Validate(receipt);
                if (!receiptDecision.Accepted || receiptDecision.Receipt == null)
                {
                    return Reject(
                        ReputationProviderExecutionCoordinatorFailure.InvalidExecutionReceipt,
                        "The provider adapter result did not produce a valid execution receipt.",
                        executionFailure: receiptDecision.Failure);
                }

                var canonicalReceipt = receiptDecision.Receipt;
                ReputationCacheStoreWriteResult? cacheWrite = null;
                if (canonicalReceipt.Result.Availability == AnalysisSourceAvailability.Available)
                {
                    var entry = new ReputationCacheEntry
                    {
                        SourceReceipt = canonicalReceipt,
                        StoredUtc = completedUtc,
                        FreshUntilUtc = completedUtc + _freshness,
                        RetainUntilUtc = completedUtc + _retention,
                        CacheKeySha256 = ReputationCachePolicy.ComputeCacheKey(
                            canonicalReceipt.Result.Request,
                            canonicalReceipt.Result.Provider)
                    };
                    entry = entry with
                    {
                        EntryHashSha256 = ReputationCachePolicy.ComputeEntryHash(entry)
                    };
                    cacheWrite = _cacheStore.Store(entry, completedUtc);
                    if (!cacheWrite.Accepted)
                    {
                        return Reject(
                            ReputationProviderExecutionCoordinatorFailure.CacheStoreRejected,
                            "The validated available result could not be published to the exact cache.",
                            cacheStoreFailure: cacheWrite.Failure,
                            cacheFailure: cacheWrite.PolicyFailure);
                    }
                }

                return Snapshot(new ReputationProviderExecutionCoordinatorResult
                {
                    Kind = ReputationProviderExecutionCoordinatorResultKind.Executed,
                    Result = canonicalReceipt.Result,
                    Receipt = canonicalReceipt,
                    CacheWrite = cacheWrite
                });
            }
            finally
            {
                _concurrency.Release();
            }
        }
        finally
        {
            EndOperation();
        }
    }

    public ValueTask DisposeAsync()
    {
        Task disposalTask;
        TaskCompletionSource? completion = null;
        Task drainTask = Task.CompletedTask;
        lock (_sync)
        {
            if (_disposeTask != null)
            {
                return new ValueTask(_disposeTask);
            }

            _disposed = true;
            if (_activeOperations > 0)
            {
                _drained = new TaskCompletionSource(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                drainTask = _drained.Task;
            }

            completion = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            _disposeTask = completion.Task;
            disposalTask = _disposeTask;
        }

        _ = CompleteDisposalAsync(drainTask, completion);
        return new ValueTask(disposalTask);
    }

    private async Task CompleteDisposalAsync(
        Task drainTask,
        TaskCompletionSource completion)
    {
        try
        {
            _lifetimeCancellation.Cancel();
            await drainTask.ConfigureAwait(false);
            _concurrency.Dispose();
            _lifetimeCancellation.Dispose();
            completion.TrySetResult();
        }
        catch (Exception exception)
        {
            completion.TrySetException(exception);
        }
    }

    private bool TryBeginOperation(out CancellationToken lifetimeToken)
    {
        lock (_sync)
        {
            if (_disposed)
            {
                lifetimeToken = new CancellationToken(canceled: true);
                return false;
            }

            _activeOperations++;
            lifetimeToken = _lifetimeCancellation.Token;
            return true;
        }
    }

    private void EndOperation()
    {
        TaskCompletionSource? drained = null;
        lock (_sync)
        {
            _activeOperations--;
            if (_disposed && _activeOperations == 0)
            {
                drained = _drained;
            }
        }

        drained?.TrySetResult();
    }

    private ReputationProviderExecutionCoordinatorFailure EvaluateAttemptAdmission(
        DateTime startedUtc,
        DateTime authorizedUtc,
        bool commitStart)
    {
        lock (_sync)
        {
            if (!IsUtc(startedUtc) || startedUtc < authorizedUtc ||
                _lastStartedUtc != default && startedUtc < _lastStartedUtc)
            {
                return ReputationProviderExecutionCoordinatorFailure.InvalidOperationTimestamp;
            }

            PruneWindow(_minuteStarts, startedUtc - MinuteWindow);
            PruneWindow(_dayStarts, startedUtc - DayWindow);
            if (_dayStarts.Count >= _admission.Limits.MaximumRequestsPerDay)
            {
                return ReputationProviderExecutionCoordinatorFailure.DayRateLimitExceeded;
            }

            if (_minuteStarts.Count >= _admission.Limits.MaximumRequestsPerMinute)
            {
                return ReputationProviderExecutionCoordinatorFailure.MinuteRateLimitExceeded;
            }

            if (!commitStart)
            {
                return ReputationProviderExecutionCoordinatorFailure.None;
            }

            _minuteStarts.Enqueue(startedUtc);
            _dayStarts.Enqueue(startedUtc);
            _lastStartedUtc = startedUtc;
            _startedAttemptCount++;
            return ReputationProviderExecutionCoordinatorFailure.None;
        }
    }

    private static void PruneWindow(Queue<DateTime> starts, DateTime exclusiveCutoff)
    {
        while (starts.TryPeek(out var startedUtc) && startedUtc <= exclusiveCutoff)
        {
            starts.Dequeue();
        }
    }

    private ReputationProviderExecutionCoordinatorResult Snapshot(
        ReputationProviderExecutionCoordinatorResult result)
    {
        lock (_sync)
        {
            return result with { StartedAttemptCount = _startedAttemptCount };
        }
    }

    private ReputationProviderExecutionCoordinatorResult RateLimited(
        ReputationProviderExecutionCoordinatorFailure failure,
        string diagnostic) =>
        Snapshot(new ReputationProviderExecutionCoordinatorResult
        {
            Kind = ReputationProviderExecutionCoordinatorResultKind.RateLimited,
            Failure = failure,
            Diagnostic = diagnostic
        });

    private ReputationProviderExecutionCoordinatorResult Failed(
        ReputationProviderExecutionCoordinatorFailure failure,
        string diagnostic) =>
        Snapshot(new ReputationProviderExecutionCoordinatorResult
        {
            Kind = ReputationProviderExecutionCoordinatorResultKind.Failed,
            Failure = failure,
            Diagnostic = diagnostic
        });

    private ReputationProviderExecutionCoordinatorResult Canceled() =>
        Snapshot(new ReputationProviderExecutionCoordinatorResult
        {
            Kind = ReputationProviderExecutionCoordinatorResultKind.Canceled,
            Diagnostic = "The reputation provider operation was canceled."
        });

    private ReputationProviderExecutionCoordinatorResult Reject(
        ReputationProviderExecutionCoordinatorFailure failure,
        string diagnostic,
        ReputationProviderAuthorizationFailure authorizationFailure =
            ReputationProviderAuthorizationFailure.None,
        ReputationProviderExecutionFailure executionFailure =
            ReputationProviderExecutionFailure.None,
        ReputationCacheStoreFailure cacheStoreFailure = ReputationCacheStoreFailure.None,
        ReputationCacheFailure cacheFailure = ReputationCacheFailure.None) =>
        Snapshot(new ReputationProviderExecutionCoordinatorResult
        {
            Kind = ReputationProviderExecutionCoordinatorResultKind.Rejected,
            Failure = failure,
            AuthorizationFailure = authorizationFailure,
            ExecutionFailure = executionFailure,
            CacheStoreFailure = cacheStoreFailure,
            CacheFailure = cacheFailure,
            Diagnostic = diagnostic
        });

    private static bool IsUtc(DateTime value) =>
        value != default && value.Kind == DateTimeKind.Utc;
}
