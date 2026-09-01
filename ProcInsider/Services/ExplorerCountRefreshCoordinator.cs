using System.Diagnostics;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal enum ExplorerCountRefreshTrigger
{
    WorkspaceActivation,
    SnapshotActivation,
    AnnotationMutation,
    DerivedAnalysisReady,
    ForcedDiagnostic
}

internal enum ExplorerCountRefreshOutcome
{
    Succeeded,
    Cached,
    Failed,
    Disposed
}

internal sealed record ExplorerCountRefreshRequest(
    object QueryBinding,
    long WorkspaceGeneration,
    long InputGeneration,
    ExplorerCountRefreshTrigger Trigger,
    bool Force = false);

internal sealed record ExplorerCountRefreshPayload(
    ExplorerScopeCounts Counts,
    IReadOnlyList<EvidenceRootSummary> EvidenceRoots);

internal sealed record ExplorerCountRefreshDiagnostics(
    long RequestCount,
    long QueryExecutionCount,
    long CacheHitCount,
    long CoalescedRequestCount,
    long FollowUpCount,
    long FailureCount,
    int ActiveExecutionCount,
    int MaximumObservedConcurrency,
    ExplorerCountRefreshTrigger? LastTrigger,
    long LastWorkspaceGeneration,
    long LastInputGeneration,
    double LastElapsedMilliseconds,
    string LastError);

internal sealed record ExplorerCountRefreshResult(
    ExplorerCountRefreshOutcome Outcome,
    ExplorerCountRefreshRequest Request,
    ExplorerCountRefreshPayload? Payload,
    ExplorerCountRefreshDiagnostics Diagnostics,
    string Error = "")
{
    internal bool Succeeded =>
        Outcome is ExplorerCountRefreshOutcome.Succeeded or ExplorerCountRefreshOutcome.Cached;
}

/// <summary>
/// Headless single-flight owner for Explorer badge/evidence-root refreshes. Equivalent
/// requests share one query, newer generations replace intermediate pending work, and
/// only the latest completed generation becomes the retained projection.
/// </summary>
internal sealed class ExplorerCountRefreshCoordinator : IDisposable
{
    private readonly object _gate = new();
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly CancellationToken _lifetimeToken;
    private PendingRefresh? _activeRequest;
    private PendingRefresh? _pendingRequest;
    private CachedRefresh? _cache;
    private Task<ExplorerCountRefreshResult>? _worker;
    private long _requestCount;
    private long _queryExecutionCount;
    private long _cacheHitCount;
    private long _coalescedRequestCount;
    private long _followUpCount;
    private long _failureCount;
    private int _activeExecutionCount;
    private int _maximumObservedConcurrency;
    private ExplorerCountRefreshTrigger? _lastTrigger;
    private long _lastWorkspaceGeneration;
    private long _lastInputGeneration;
    private double _lastElapsedMilliseconds;
    private string _lastError = string.Empty;
    private bool _disposed;

    internal ExplorerCountRefreshCoordinator()
    {
        _lifetimeToken = _lifetimeCts.Token;
    }

    internal ExplorerCountRefreshDiagnostics Diagnostics
    {
        get
        {
            lock (_gate)
            {
                return CreateDiagnosticsLocked();
            }
        }
    }

    internal Task<ExplorerCountRefreshResult> RefreshAsync(
        ExplorerCountRefreshRequest request,
        Func<CancellationToken, Task<ExplorerCountRefreshPayload>> loadAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.QueryBinding);
        ArgumentNullException.ThrowIfNull(loadAsync);
        if (request.WorkspaceGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Workspace generation cannot be negative.");
        }

        if (request.InputGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Input generation cannot be negative.");
        }

        Task<ExplorerCountRefreshResult> task;
        lock (_gate)
        {
            _requestCount++;
            if (_disposed)
            {
                return Task.FromResult(new ExplorerCountRefreshResult(
                    ExplorerCountRefreshOutcome.Disposed,
                    request,
                    null,
                    CreateDiagnosticsLocked(),
                    "Explorer count refresh is disposed."));
            }

            if (!request.Force && CacheMatches(_cache, request))
            {
                _cacheHitCount++;
                return Task.FromResult(new ExplorerCountRefreshResult(
                    ExplorerCountRefreshOutcome.Cached,
                    request,
                    _cache!.Payload,
                    CreateDiagnosticsLocked()));
            }

            var pending = new PendingRefresh(request, loadAsync);
            if (_worker != null)
            {
                _coalescedRequestCount++;
                if (!RequestsMatch(_activeRequest?.Request, request) &&
                    !RequestsMatch(_pendingRequest?.Request, request))
                {
                    _pendingRequest = pending;
                }

                task = _worker;
            }
            else
            {
                StartExecutionLocked(pending);
                _worker = RunWorkerAsync(pending);
                task = _worker;
            }
        }

        return cancellationToken.CanBeCanceled
            ? task.WaitAsync(cancellationToken)
            : task;
    }

    internal bool TryGetCachedPayload(
        object queryBinding,
        long workspaceGeneration,
        long inputGeneration,
        out ExplorerCountRefreshPayload? payload)
    {
        ArgumentNullException.ThrowIfNull(queryBinding);
        lock (_gate)
        {
            var request = new ExplorerCountRefreshRequest(
                queryBinding,
                workspaceGeneration,
                inputGeneration,
                ExplorerCountRefreshTrigger.WorkspaceActivation);
            if (CacheMatches(_cache, request))
            {
                payload = _cache!.Payload;
                return true;
            }

            payload = null;
            return false;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _pendingRequest = null;
            _cache = null;
        }

        _lifetimeCts.Cancel();
        _lifetimeCts.Dispose();
    }

    private async Task<ExplorerCountRefreshResult> RunWorkerAsync(PendingRefresh current)
    {
        await Task.Yield();
        while (true)
        {
            var stopwatch = Stopwatch.StartNew();
            ExplorerCountRefreshPayload payload;
            try
            {
                payload = await current.LoadAsync(_lifetimeToken).ConfigureAwait(false);
                _lifetimeToken.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException) when (_lifetimeToken.IsCancellationRequested)
            {
                stopwatch.Stop();
                lock (_gate)
                {
                    FinishExecutionLocked(current, stopwatch.Elapsed, "Explorer count refresh was disposed.");
                    _worker = null;
                    _activeRequest = null;
                    _pendingRequest = null;
                    return new ExplorerCountRefreshResult(
                        ExplorerCountRefreshOutcome.Disposed,
                        current.Request,
                        null,
                        CreateDiagnosticsLocked(),
                        _lastError);
                }
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                lock (_gate)
                {
                    _failureCount++;
                    FinishExecutionLocked(current, stopwatch.Elapsed, ex.Message);
                    if (_pendingRequest is { } retry)
                    {
                        _pendingRequest = null;
                        _followUpCount++;
                        current = retry;
                        StartExecutionLocked(current);
                        continue;
                    }

                    _worker = null;
                    _activeRequest = null;
                    return new ExplorerCountRefreshResult(
                        ExplorerCountRefreshOutcome.Failed,
                        current.Request,
                        null,
                        CreateDiagnosticsLocked(),
                        ex.Message);
                }
            }

            stopwatch.Stop();
            lock (_gate)
            {
                FinishExecutionLocked(current, stopwatch.Elapsed, string.Empty);
                if (_disposed)
                {
                    _worker = null;
                    _activeRequest = null;
                    _pendingRequest = null;
                    return new ExplorerCountRefreshResult(
                        ExplorerCountRefreshOutcome.Disposed,
                        current.Request,
                        null,
                        CreateDiagnosticsLocked(),
                        "Explorer count refresh is disposed.");
                }

                if (_pendingRequest is { } followUp)
                {
                    _pendingRequest = null;
                    _followUpCount++;
                    current = followUp;
                    StartExecutionLocked(current);
                    continue;
                }

                _cache = new CachedRefresh(current.Request with { Force = false }, payload);
                _worker = null;
                _activeRequest = null;
                return new ExplorerCountRefreshResult(
                    ExplorerCountRefreshOutcome.Succeeded,
                    current.Request,
                    payload,
                    CreateDiagnosticsLocked());
            }
        }
    }

    private void StartExecutionLocked(PendingRefresh request)
    {
        _activeRequest = request;
        _queryExecutionCount++;
        _activeExecutionCount++;
        _maximumObservedConcurrency = Math.Max(
            _maximumObservedConcurrency,
            _activeExecutionCount);
    }

    private void FinishExecutionLocked(
        PendingRefresh request,
        TimeSpan elapsed,
        string error)
    {
        _activeExecutionCount = Math.Max(0, _activeExecutionCount - 1);
        _lastTrigger = request.Request.Trigger;
        _lastWorkspaceGeneration = request.Request.WorkspaceGeneration;
        _lastInputGeneration = request.Request.InputGeneration;
        _lastElapsedMilliseconds = elapsed.TotalMilliseconds;
        _lastError = error ?? string.Empty;
    }

    private ExplorerCountRefreshDiagnostics CreateDiagnosticsLocked() => new(
        _requestCount,
        _queryExecutionCount,
        _cacheHitCount,
        _coalescedRequestCount,
        _followUpCount,
        _failureCount,
        _activeExecutionCount,
        _maximumObservedConcurrency,
        _lastTrigger,
        _lastWorkspaceGeneration,
        _lastInputGeneration,
        _lastElapsedMilliseconds,
        _lastError);

    private static bool CacheMatches(
        CachedRefresh? cache,
        ExplorerCountRefreshRequest request) =>
        cache != null && RequestsMatch(cache.Request, request);

    private static bool RequestsMatch(
        ExplorerCountRefreshRequest? left,
        ExplorerCountRefreshRequest? right) =>
        left != null &&
        right != null &&
        !left.Force &&
        !right.Force &&
        ReferenceEquals(left.QueryBinding, right.QueryBinding) &&
        left.WorkspaceGeneration == right.WorkspaceGeneration &&
        left.InputGeneration == right.InputGeneration;

    private sealed record PendingRefresh(
        ExplorerCountRefreshRequest Request,
        Func<CancellationToken, Task<ExplorerCountRefreshPayload>> LoadAsync);

    private sealed record CachedRefresh(
        ExplorerCountRefreshRequest Request,
        ExplorerCountRefreshPayload Payload);
}
