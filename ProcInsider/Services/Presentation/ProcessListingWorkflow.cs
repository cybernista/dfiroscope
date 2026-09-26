using ProcInsider.Models;
using ProcInsider.ViewModels;

namespace ProcInsider.Services.Presentation;

internal interface IProcessListingRuntime
{
    long CaptureGeneration { get; }
    ProcessListingService? ListingService { get; }
    ProcessListingQuery BuildQuery();
    string? SelectedProcessKey { get; }
    string? SelectedProcessEntityId { get; }
    void Publish(VirtualizedProcessCollection collection, ProcessRowViewModel? selectedRow);
    void ReportError(string message);
}

/// <summary>Owns debouncing, request generations and cancellation for one bounded listing.</summary>
internal sealed class ProcessListingWorkflow : IDisposable
{
    private readonly IProcessListingRuntime _runtime;
    private readonly TimeProvider _time;
    private CancellationTokenSource? _debounce;
    private CancellationTokenSource? _refresh;
    private int _activeRequests;
    private bool _disposed;
    private bool _suspended;
    internal long QueryGeneration;

    public ProcessListingWorkflow(IProcessListingRuntime runtime, TimeProvider? time = null)
    {
        _runtime = runtime;
        _time = time ?? TimeProvider.System;
    }

    public int ActiveRequests => Volatile.Read(ref _activeRequests);

    public void Schedule()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_suspended || _runtime.ListingService == null) return;
        Invalidate();
        CancelDebounce();
        var cancellation = new CancellationTokenSource();
        _debounce = cancellation;
        _ = DebounceAsync(cancellation);
    }

    private async Task DebounceAsync(CancellationTokenSource cancellation)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(300), _time, cancellation.Token);
            if (!_disposed && ReferenceEquals(_debounce, cancellation)) await RefreshAsync();
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        finally
        {
            Interlocked.CompareExchange(ref _debounce, null, cancellation);
            cancellation.Dispose();
        }
    }

    public void CancelDebounce() => Interlocked.Exchange(ref _debounce, null)?.Cancel();

    public void CancelRefresh() => _refresh?.Cancel();

    public void Invalidate()
    {
        Interlocked.Increment(ref QueryGeneration);
        _refresh?.Cancel();
    }

    public async Task RefreshAsync(IProgress<ProcessListingLoadProgress>? progress = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var listing = _runtime.ListingService;
        if (_suspended || listing == null) return;
        var generation = Interlocked.Increment(ref QueryGeneration);
        var capture = _runtime.CaptureGeneration;
        var cancellation = new CancellationTokenSource();
        Interlocked.Exchange(ref _refresh, cancellation)?.Cancel();
        Interlocked.Increment(ref _activeRequests);
        VirtualizedProcessCollection? pending = null;
        bool IsCurrent() => !_disposed && !cancellation.IsCancellationRequested &&
            generation == Volatile.Read(ref QueryGeneration) &&
            capture == _runtime.CaptureGeneration && ReferenceEquals(listing, _runtime.ListingService);
        try
        {
            var query = _runtime.BuildQuery();
            progress?.Report(new ProcessListingLoadProgress(0, query.PageSize, 0,
                "Counting matching processes for the virtualized listing..."));
            pending = new VirtualizedProcessCollection(listing, query, capture,
                ProcessPresentationViewModel.VirtualProcessPageSize,
                ProcessPresentationViewModel.VirtualProcessCachePages,
                SynchronizationContext.Current, generation);
            await pending.InitializeAsync(progress, cancellation.Token);
            if (!IsCurrent()) return;
            var key = _runtime.SelectedProcessKey;
            var entity = _runtime.SelectedProcessEntityId;
            ProcessRowViewModel? selected = null;
            if (!string.IsNullOrWhiteSpace(key) || !string.IsNullOrWhiteSpace(entity))
            {
                var firstPage = new ProcessListingWindow { Rows = pending.GetLoadedRows(), TotalCount = pending.Count, PageSize = query.PageSize };
                var anchor = await new ProcessListingAnchorResolver(listing, query, firstPage)
                    .ResolveAsync(entity ?? string.Empty, key ?? string.Empty, cancellation.Token);
                var index = anchor.Index;
                if (index >= 0)
                {
                    await pending.EnsureRangeAsync(index, 1, cancellation.Token);
                    selected = pending.GetLoadedItem(index);
                }
            }
            if (!IsCurrent()) return;
            if (!string.Equals(entity, _runtime.SelectedProcessEntityId, StringComparison.Ordinal) ||
                !string.Equals(key, _runtime.SelectedProcessKey, StringComparison.Ordinal))
            {
                Schedule();
                return;
            }
            _runtime.Publish(pending, selected);
            pending = null;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception exception)
        {
            if (IsCurrent()) _runtime.ReportError(exception.Message);
        }
        finally
        {
            pending?.Dispose();
            Interlocked.CompareExchange(ref _refresh, null, cancellation);
            cancellation.Dispose();
            Interlocked.Decrement(ref _activeRequests);
        }
    }

    public async Task QuiesceAsync(CancellationToken cancellationToken = default)
    {
        _suspended = true;
        CancelDebounce();
        _refresh?.Cancel();
        while (ActiveRequests != 0) await Task.Delay(25, cancellationToken);
    }

    public void Resume() => _suspended = false;

    public async Task<PreparedProcessListingSnapshot?> PrepareSnapshotAsync(ViewerReadBinding candidate,
        ProcessListingSnapshotRequest request, CancellationToken cancellationToken)
    {
        var listing = candidate.ListingService;
        var count = await listing.CountProcessesAsync(request.Query.Filters, cancellationToken);
        var first = await listing.GetPageAsync(request.Query, cancellationToken);
        var anchors = new ProcessListingAnchorResolver(listing, request.Query, first);
        var selected = await anchors.ResolveAsync(request.SelectedEntityId, request.SelectedKey, cancellationToken);
        var viewport = await anchors.ResolveAsync(request.Viewport?.ProcessEntityId ?? string.Empty,
            request.Viewport?.ProcessKey ?? string.Empty, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return new PreparedProcessListingSnapshot(request, count, first, selected.Index, selected.Page,
            viewport.Index, viewport.Page);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CancelDebounce();
        Invalidate();
    }
}
