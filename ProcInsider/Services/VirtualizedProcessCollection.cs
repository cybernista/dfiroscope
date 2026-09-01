using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;
using ProcInsider.ViewModels;

namespace ProcInsider.Services;

public sealed record VirtualizedProcessListingDiagnostics(
    long WorkspaceGeneration,
    int TotalCount,
    int LoadedRows,
    int CachedPages,
    long CacheHits,
    long CacheMisses,
    long CacheEvictions,
    long CursorQueries,
    long OffsetQueries,
    long CanceledRequests,
    TimeSpan LastQueryDuration,
    TimeSpan LastMaterializationDuration,
    string LastError);

/// <summary>
/// Fixed-size virtual IList for WPF collection views. The Count represents the
/// complete filtered result, while only a small LRU of row view-model pages is
/// materialized. Index access schedules visible/near-visible pages without ever
/// enumerating or constructing all matching rows.
/// </summary>
public sealed class VirtualizedProcessCollection : IList, INotifyCollectionChanged,
    IViewerProcessNavigationCollection,
    INotifyPropertyChanged, IDisposable
{
    private readonly object _gate = new();
    private readonly object _placeholderOwner = new();
    private readonly IProcessListingPageSource _source;
    private readonly ProcessListingQuery _baseQuery;
    private readonly int _pageSize;
    private readonly int _maxCachedPages;
    private readonly SynchronizationContext? _synchronizationContext;
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly CancellationToken _lifetimeToken;
    private readonly Dictionary<int, CachedPage> _pages = new();
    private readonly Dictionary<int, Task> _inflight = new();
    private readonly LinkedList<int> _lru = new();
    private volatile bool _disposed;
    private int _count;
    private int _activeLoads;
    private int? _selectedPageIndex;
    private long _cacheHits;
    private long _cacheMisses;
    private long _cacheEvictions;
    private long _cursorQueries;
    private long _offsetQueries;
    private long _canceledRequests;
    private TimeSpan _lastQueryDuration;
    private TimeSpan _lastMaterializationDuration;
    private string _lastError = string.Empty;

    public VirtualizedProcessCollection(
        IProcessListingPageSource source,
        ProcessListingQuery baseQuery,
        long workspaceGeneration,
        int pageSize = 128,
        int maxCachedPages = 6,
        SynchronizationContext? synchronizationContext = null,
        long queryGeneration = 0)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _pageSize = Math.Clamp(pageSize, 32, 512);
        _maxCachedPages = Math.Clamp(maxCachedPages, 2, 32);
        _baseQuery = CloneQuery(baseQuery, offset: 0, cursor: null, _pageSize);
        WorkspaceGeneration = workspaceGeneration;
        QueryGeneration = queryGeneration;
        _synchronizationContext = synchronizationContext ?? SynchronizationContext.Current;
        _lifetimeToken = _lifetimeCts.Token;
    }

    public event NotifyCollectionChangedEventHandler? CollectionChanged;
    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? CacheChanged;

    public long WorkspaceGeneration { get; }
    public long QueryGeneration { get; }
    public int Count => Volatile.Read(ref _count);
    public bool IsLoading => Volatile.Read(ref _activeLoads) > 0;
    public bool IsFixedSize => true;
    public bool IsReadOnly => true;
    public bool IsSynchronized => false;
    public object SyncRoot => _gate;

    public int LoadedRowCount
    {
        get
        {
            lock (_gate)
            {
                return _pages.Values.Sum(page => page.Window.Rows.Count);
            }
        }
    }

    public string StatusMessage
    {
        get
        {
            var diagnostics = GetDiagnostics();
            if (!string.IsNullOrWhiteSpace(diagnostics.LastError))
            {
                return $"Listing error: {diagnostics.LastError}";
            }

            var loading = IsLoading ? "Loading pages... " : string.Empty;
            return $"{loading}{diagnostics.TotalCount:N0} matches; " +
                   $"{diagnostics.LoadedRows:N0} rows in {diagnostics.CachedPages} cached pages; " +
                   $"hits {diagnostics.CacheHits:N0}, misses {diagnostics.CacheMisses:N0}, " +
                   $"evictions {diagnostics.CacheEvictions:N0}.";
        }
    }

    [System.Diagnostics.CodeAnalysis.AllowNull]
    public object this[int index]
    {
        get
        {
            if ((uint)index >= (uint)Count)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            if (TryGetLoadedItem(index, out var row))
            {
                Interlocked.Increment(ref _cacheHits);
                return row!;
            }

            if (!_disposed)
            {
                RequestRange(index, 1);
            }
            // A view/container may still read its predecessor during a WPF rebind.
            // Disposed collections retain their count but never schedule more I/O.
            return GetDisplayItem(index);
        }
        set => throw new NotSupportedException();
    }

    public async Task InitializeAsync(
        IProgress<ProcessListingLoadProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            _lifetimeToken,
            cancellationToken);
        var totalCount = await _source
            .CountProcessesAsync(_baseQuery.Filters, linked.Token)
            .ConfigureAwait(false);
        linked.Token.ThrowIfCancellationRequested();
        await DispatchAsync(() =>
        {
            linked.Token.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Interlocked.Exchange(ref _count, Math.Max(0, totalCount));
            OnPropertyChanged(nameof(Count));
            CollectionChanged?.Invoke(
                this,
                new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }).ConfigureAwait(false);

        progress?.Report(new ProcessListingLoadProgress(
            0,
            Math.Min(_pageSize, Count),
            Count,
            "Loading the first virtualized process page..."));
        if (Count > 0)
        {
            await GetOrLoadPageAsync(0, linked.Token).ConfigureAwait(false);
        }

        progress?.Report(new ProcessListingLoadProgress(
            Math.Min(_pageSize, Count),
            Math.Min(_pageSize, Count),
            Count,
            "Virtualized process listing is ready."));
    }

    /// <summary>
    /// Seeds a not-yet-published collection with a count and first page that were
    /// prepared against a validated snapshot candidate. No collection notification is
    /// raised because the collection must not be WPF-bound until its owning snapshot
    /// generation is published.
    /// </summary>
    public void InitializePrepared(
        int totalCount,
        ProcessListingWindow? firstPage,
        ProcessListingWindow? selectedPage = null,
        ProcessListingWindow? viewportPage = null)
    {
        ThrowIfDisposed();
        if (totalCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(totalCount));
        }

        ValidatePreparedPage(firstPage, totalCount, requireFirstPage: true);
        ValidatePreparedPage(selectedPage, totalCount, requireFirstPage: false);
        ValidatePreparedPage(viewportPage, totalCount, requireFirstPage: false);

        lock (_gate)
        {
            ThrowIfDisposed();
            if (_count != 0 || _pages.Count != 0 || _inflight.Count != 0)
            {
                throw new InvalidOperationException(
                    "A virtualized process collection can be initialized only once.");
            }

            _count = totalCount;
            foreach (var page in new[] { firstPage, selectedPage, viewportPage }
                         .Where(page => page is { Rows.Count: > 0 })
                         .DistinctBy(page => page!.Offset))
            {
                var pageIndex = page!.Offset / _pageSize;
                var node = _lru.AddLast(pageIndex);
                _pages[pageIndex] = new CachedPage(page, node);
                _lastQueryDuration = page.QueryDuration;
                _lastMaterializationDuration = page.MaterializationDuration;
                if (page.PagingMode == ProcessListingPagingMode.Cursor)
                {
                    _cursorQueries++;
                }
                else
                {
                    _offsetQueries++;
                }
            }
        }
    }

    private void ValidatePreparedPage(
        ProcessListingWindow? page,
        int totalCount,
        bool requireFirstPage)
    {
        if (page == null)
        {
            return;
        }

        if ((requireFirstPage && page.Offset != 0) ||
            page.Offset < 0 ||
            page.Offset % _pageSize != 0 ||
            page.Rows.Count > _pageSize ||
            page.Rows.Any(row => row is null) ||
            page.Rows.Count > Math.Max(0, totalCount - page.Offset))
        {
            throw new ArgumentException(
                requireFirstPage
                    ? "A prepared first page must begin at offset zero and fit within the prepared count."
                    : "A prepared selected page must be aligned to the collection page size and fit within the prepared count.",
                requireFirstPage ? nameof(page) : nameof(page));
        }
    }

    public void RequestRange(int firstIndex, int itemCount)
    {
        var task = EnsureRangeAsync(firstIndex, itemCount, CancellationToken.None);
        _ = task.ContinueWith(
            completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    public async Task EnsureRangeAsync(
        int firstIndex,
        int itemCount,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (Count == 0)
        {
            return;
        }

        var first = Math.Clamp(firstIndex, 0, Count - 1);
        var last = Math.Clamp(first + Math.Max(1, itemCount) - 1, 0, Count - 1);
        var firstPage = Math.Max(0, first / _pageSize - 1);
        var lastPage = Math.Min((Count - 1) / _pageSize, last / _pageSize + 1);
        for (var pageIndex = firstPage; pageIndex <= lastPage; pageIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await GetOrLoadPageAsync(pageIndex, cancellationToken).ConfigureAwait(false);
        }
    }

    public ProcessRowViewModel? GetLoadedItem(int index)
        => TryGetLoadedItem(index, out var row) ? row : null;

    public ProcessRowViewModel? FindLoadedByProcessKey(string processKey)
    {
        if (string.IsNullOrWhiteSpace(processKey))
        {
            return null;
        }

        lock (_gate)
        {
            return _pages.Values
                .SelectMany(page => page.Window.Rows)
                .FirstOrDefault(row => string.Equals(row.ProcessKey, processKey, StringComparison.Ordinal));
        }
    }

    public IReadOnlyList<ProcessRowViewModel> GetLoadedRows()
    {
        lock (_gate)
        {
            return _pages
                .OrderBy(pair => pair.Key)
                .SelectMany(pair => pair.Value.Window.Rows)
                .ToArray();
        }
    }

    public void PreserveSelection(ProcessRowViewModel? row)
    {
        lock (_gate)
        {
            _selectedPageIndex = null;
            if (row == null)
            {
                return;
            }

            foreach (var (pageIndex, page) in _pages)
            {
                if (page.Window.Rows.Any(candidate =>
                        ReferenceEquals(candidate, row) ||
                        string.Equals(candidate.ProcessKey, row.ProcessKey, StringComparison.Ordinal)))
                {
                    _selectedPageIndex = pageIndex;
                    TouchPage(pageIndex, page);
                    break;
                }
            }
        }
    }

    public VirtualizedProcessListingDiagnostics GetDiagnostics()
    {
        lock (_gate)
        {
            return new VirtualizedProcessListingDiagnostics(
                WorkspaceGeneration,
                Count,
                _pages.Values.Sum(page => page.Window.Rows.Count),
                _pages.Count,
                Interlocked.Read(ref _cacheHits),
                Interlocked.Read(ref _cacheMisses),
                Interlocked.Read(ref _cacheEvictions),
                Interlocked.Read(ref _cursorQueries),
                Interlocked.Read(ref _offsetQueries),
                Interlocked.Read(ref _canceledRequests),
                _lastQueryDuration,
                _lastMaterializationDuration,
                _lastError);
        }
    }

    public int IndexOf(object? value)
    {
        if (value is ProcessListingPlaceholder placeholder)
        {
            return placeholder.BelongsTo(_placeholderOwner) &&
                   (uint)placeholder.Index < (uint)Count &&
                   !TryGetLoadedItem(placeholder.Index, out _)
                ? placeholder.Index
                : -1;
        }

        if (value is not ProcessRowViewModel row)
        {
            return -1;
        }

        lock (_gate)
        {
            foreach (var (pageIndex, page) in _pages)
            {
                for (var index = 0; index < page.Window.Rows.Count; index++)
                {
                    var candidate = page.Window.Rows[index];
                    if (ReferenceEquals(candidate, row) ||
                        string.Equals(candidate.ProcessKey, row.ProcessKey, StringComparison.Ordinal))
                    {
                        return pageIndex * _pageSize + index;
                    }
                }
            }
        }

        return -1;
    }

    public bool Contains(object? value) => IndexOf(value) >= 0;

    public IEnumerator GetEnumerator()
    {
        for (var index = 0; index < Count; index++)
        {
            yield return GetDisplayItem(index);
        }
    }

    public void CopyTo(Array array, int index)
    {
        ArgumentNullException.ThrowIfNull(array);
        if (array.Rank != 1 || array.GetLowerBound(0) != 0 || index < 0 ||
            index > array.Length || Count > array.Length - index)
        {
            throw new ArgumentException("The destination must be a zero-based one-dimensional array with enough space.", nameof(array));
        }
        for (var itemIndex = 0; itemIndex < Count; itemIndex++)
        {
            array.SetValue(GetDisplayItem(itemIndex), index + itemIndex);
        }
    }

    public int Add(object? value) => throw new NotSupportedException();
    public void Clear() => throw new NotSupportedException();
    public void Insert(int index, object? value) => throw new NotSupportedException();
    public void Remove(object? value) => throw new NotSupportedException();
    public void RemoveAt(int index) => throw new NotSupportedException();

    private ProcessListingPlaceholder CreatePlaceholder(int index) => new(_placeholderOwner, index);

    // Enumeration/copying must not request every page or allocate a retained slot array.
    private object GetDisplayItem(int index) =>
        TryGetLoadedItem(index, out var row) ? row! : CreatePlaceholder(index);

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        _lifetimeCts.Cancel();
        _lifetimeCts.Dispose();
        lock (_gate)
        {
            _pages.Clear();
            _lru.Clear();
        }
    }

    private bool TryGetLoadedItem(int index, out ProcessRowViewModel? row)
    {
        if ((uint)index >= (uint)Count)
        {
            row = null;
            return false;
        }
        var pageIndex = index / _pageSize;
        var offset = index % _pageSize;
        lock (_gate)
        {
            if (_pages.TryGetValue(pageIndex, out var page) && offset < page.Window.Rows.Count)
            {
                TouchPage(pageIndex, page);
                row = page.Window.Rows[offset];
                return true;
            }
        }

        row = null;
        return false;
    }

    private Task GetOrLoadPageAsync(int pageIndex, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (_pages.TryGetValue(pageIndex, out var cached))
            {
                TouchPage(pageIndex, cached);
                Interlocked.Increment(ref _cacheHits);
                return Task.CompletedTask;
            }

            if (_inflight.TryGetValue(pageIndex, out var inflight))
            {
                return inflight;
            }

            Interlocked.Increment(ref _cacheMisses);
            var task = LoadPageAsync(pageIndex, cancellationToken);
            _inflight[pageIndex] = task;
            _ = task.ContinueWith(
                _ =>
                {
                    lock (_gate)
                    {
                        _inflight.Remove(pageIndex);
                    }
                },
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            return task;
        }
    }

    private async Task LoadPageAsync(int pageIndex, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _activeLoads);
        await DispatchStateChangedAsync().ConfigureAwait(false);
        try
        {
            string? cursor = null;
            lock (_gate)
            {
                if (pageIndex > 0 && _pages.TryGetValue(pageIndex - 1, out var previous))
                {
                    cursor = previous.Window.NextCursor;
                }
            }

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                _lifetimeToken,
                cancellationToken);
            var query = CloneQuery(
                _baseQuery,
                pageIndex * _pageSize,
                cursor,
                _pageSize);
            var window = await _source.GetPageAsync(query, linked.Token).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            await DispatchAsync(() => ApplyPage(pageIndex, window)).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Interlocked.Increment(ref _canceledRequests);
            throw;
        }
        catch (Exception ex)
        {
            lock (_gate)
            {
                _lastError = ex.Message;
            }

            await DispatchStateChangedAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            Interlocked.Decrement(ref _activeLoads);
            await DispatchStateChangedAsync().ConfigureAwait(false);
        }
    }

    private void ApplyPage(int pageIndex, ProcessListingWindow window)
    {
        List<(int Index, ProcessRowViewModel OldItem)> evictedRows = [];
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            ValidatePreparedPage(window, Count, requireFirstPage: false);
            if (window.Offset != pageIndex * _pageSize)
            {
                throw new ArgumentException("A loaded page must match its requested offset.", nameof(window));
            }

            _lastError = string.Empty;
            _lastQueryDuration = window.QueryDuration;
            _lastMaterializationDuration = window.MaterializationDuration;
            if (window.PagingMode == ProcessListingPagingMode.Cursor)
            {
                Interlocked.Increment(ref _cursorQueries);
            }
            else
            {
                Interlocked.Increment(ref _offsetQueries);
            }

            var node = _lru.AddFirst(pageIndex);
            _pages[pageIndex] = new CachedPage(window, node);
            while (_pages.Count > _maxCachedPages)
            {
                var candidate = _lru.Last;
                while (candidate != null && candidate.Value == _selectedPageIndex)
                {
                    candidate = candidate.Previous;
                }

                if (candidate == null)
                {
                    break;
                }

                var evictedPageIndex = candidate.Value;
                var evicted = _pages[evictedPageIndex];
                _lru.Remove(candidate);
                _pages.Remove(evictedPageIndex);
                Interlocked.Increment(ref _cacheEvictions);
                for (var rowIndex = 0; rowIndex < evicted.Window.Rows.Count; rowIndex++)
                {
                    evictedRows.Add((
                        evictedPageIndex * _pageSize + rowIndex,
                        evicted.Window.Rows[rowIndex]));
                }
            }
        }

        foreach (var (index, oldItem) in evictedRows)
        {
            CollectionChanged?.Invoke(
                this,
                new NotifyCollectionChangedEventArgs(
                    NotifyCollectionChangedAction.Replace,
                    CreatePlaceholder(index),
                    oldItem,
                    index));
        }

        for (var rowIndex = 0; rowIndex < window.Rows.Count; rowIndex++)
        {
            var absoluteIndex = pageIndex * _pageSize + rowIndex;
            if (absoluteIndex >= Count)
            {
                break;
            }

            CollectionChanged?.Invoke(
                this,
                new NotifyCollectionChangedEventArgs(
                    NotifyCollectionChangedAction.Replace,
                    window.Rows[rowIndex],
                    CreatePlaceholder(absoluteIndex),
                    absoluteIndex));
        }

        OnPropertyChanged("Item[]");
        OnPropertyChanged(nameof(LoadedRowCount));
        OnPropertyChanged(nameof(StatusMessage));
        CacheChanged?.Invoke(this, EventArgs.Empty);
    }

    private void TouchPage(int pageIndex, CachedPage page)
    {
        if (page.Node.List == null || ReferenceEquals(_lru.First, page.Node))
        {
            return;
        }

        _lru.Remove(page.Node);
        _lru.AddFirst(page.Node);
    }

    private Task DispatchStateChangedAsync()
        => DispatchAsync(() =>
        {
            if (_disposed)
            {
                return;
            }
            OnPropertyChanged(nameof(IsLoading));
            OnPropertyChanged(nameof(StatusMessage));
            CacheChanged?.Invoke(this, EventArgs.Empty);
        });

    private Task DispatchAsync(Action action)
    {
        if (_synchronizationContext == null ||
            ReferenceEquals(SynchronizationContext.Current, _synchronizationContext))
        {
            action();
            return Task.CompletedTask;
        }

        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _synchronizationContext.Post(
            _ =>
            {
                try
                {
                    action();
                    completion.SetResult();
                }
                catch (Exception ex)
                {
                    completion.SetException(ex);
                }
            },
            null);
        return completion.Task;
    }

    private void OnPropertyChanged(string propertyName)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(VirtualizedProcessCollection));
        }
    }

    private static ProcessListingQuery CloneQuery(
        ProcessListingQuery query,
        int offset,
        string? cursor,
        int pageSize)
        => new()
        {
            Filters = query.Filters,
            Sort = query.Sort,
            Offset = offset,
            PageSize = pageSize,
            Cursor = cursor,
            IncludeTotalCount = false
        };

    private sealed record CachedPage(
        ProcessListingWindow Window,
        LinkedListNode<int> Node);
}
