using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Services;

public enum ViewerNavigationPhase
{
    Idle,
    Navigating,
    Disposed
}

public enum ViewerNavigationOutcome
{
    None,
    Succeeded,
    Unavailable,
    NotFound,
    Canceled,
    Superseded,
    Failed,
    Disposed
}

public sealed record ViewerNavigationState(
    FeatureTabDescriptor ExplorerSelection,
    FeatureTabDescriptor? DataSelection,
    bool IncludeNetworkData,
    bool IncludeFilesystemData,
    long Generation,
    ViewerNavigationPhase Phase,
    ViewerNavigationOutcome LastOutcome,
    string StatusMessage,
    string LastError)
{
    public FeatureTabKey ExplorerKey => ExplorerSelection.Key;

    public FeatureTabKey? DataKey => DataSelection?.Key;
}

public sealed record ViewerNavigationResult(
    ViewerNavigationOutcome Outcome,
    ViewerNavigationState State,
    ProcessRowViewModel? ProcessRow = null,
    bool ClearedFilters = false)
{
    public bool Succeeded => Outcome == ViewerNavigationOutcome.Succeeded;
}

public sealed class ViewerNavigationStateChangedEventArgs(ViewerNavigationState state) : EventArgs
{
    public ViewerNavigationState State { get; } = state;
}

/// <summary>
/// Narrow exact-identity and row-index surface used by viewer navigation.
/// </summary>
public interface IViewerProcessNavigationListing
{
    Task<ProcessKeyLookupResult> FindProcessByKeyAsync(
        string processKey,
        CancellationToken cancellationToken = default);

    Task<ProcessEntityLookupResult> FindProcessByEntityIdAsync(
        string processEntityId,
        CancellationToken cancellationToken = default);

    Task<int> GetProcessRowIndexAsync(
        string processKey,
        ProcessListingQuery query,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Narrow bounded page-materialization surface used by viewer navigation.
/// </summary>
public interface IViewerProcessNavigationCollection
{
    long WorkspaceGeneration { get; }

    long QueryGeneration { get; }

    Task EnsureRangeAsync(
        int firstIndex,
        int itemCount,
        CancellationToken cancellationToken = default);

    ProcessRowViewModel? GetLoadedItem(int index);

    IReadOnlyList<ProcessRowViewModel> GetLoadedRows();

    void PreserveSelection(ProcessRowViewModel? row);
}

public sealed record ViewerProcessNavigationContext(
    IViewerProcessNavigationListing Listing,
    IViewerProcessNavigationCollection Collection,
    long WorkspaceGeneration,
    long QueryGeneration);

public sealed record ViewerLegacyProcessNavigationResult(
    bool Succeeded,
    string StatusMessage,
    ProcessRowViewModel? ProcessRow = null,
    bool ClearedFilters = false);

/// <summary>
/// WPF/shell callbacks retained by the composition root. The coordinator does not
/// reference Application, Dispatcher, MainWindow, dialogs, or native processes.
/// </summary>
public interface IViewerNavigationRuntime
{
    ViewerProcessNavigationContext? GetCurrentProcessNavigationContext();

    bool IsCurrentProcessNavigationContext(ViewerProcessNavigationContext context);

    ProcessListingQuery BuildCurrentProcessListingQuery();

    ProcessRowViewModel? FindVisibleProcessRow(TelemetrySearchResult result);

    Task<ViewerProcessNavigationContext?> ClearFiltersAndRebindProcessListingAsync(
        CancellationToken cancellationToken);

    void ApplyProcessNavigationSelection(
        ViewerProcessNavigationContext context,
        ProcessRowViewModel row);

    ViewerLegacyProcessNavigationResult NavigateLegacyProcessResult(TelemetrySearchResult result);
}

/// <summary>
/// Headless owner for stable-key shell navigation and durable process-result
/// navigation. Publication remains in FeatureTabSet/catalog policy, query behavior
/// remains in the listing service, and WPF projection remains in MainViewModel.
/// </summary>
public sealed class ViewerNavigationCoordinator : IDisposable
{
    private readonly object _gate = new();
    private readonly FeatureTabSet _explorerTabs;
    private readonly FeatureTabSet _dataTabs;
    private readonly string _releaseId;
    private readonly IViewerNavigationRuntime _runtime;
    private readonly CancellationTokenSource _lifetimeCts = new();
    private CancellationTokenSource? _activeNavigationCts;
    private ViewerNavigationState _state;
    private bool _disposed;

    public ViewerNavigationCoordinator(
        FeatureTabSet explorerTabs,
        FeatureTabSet dataTabs,
        string releaseId,
        IViewerNavigationRuntime runtime)
    {
        _explorerTabs = explorerTabs ?? throw new ArgumentNullException(nameof(explorerTabs));
        _dataTabs = dataTabs ?? throw new ArgumentNullException(nameof(dataTabs));
        _releaseId = string.IsNullOrWhiteSpace(releaseId)
            ? throw new ArgumentException("Viewer navigation requires a release ID.", nameof(releaseId))
            : releaseId.Trim();
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));

        var explorerFallback = _explorerTabs.SafeFallback ?? throw new InvalidOperationException(
            $"Educational release '{_releaseId}' has no published Explorer fallback.");
        if (!explorerFallback.TryActivate(out _, out var activationException))
        {
            throw new InvalidOperationException(
                $"The published Explorer fallback '{explorerFallback.Key}' could not activate.",
                activationException);
        }

        _state = new ViewerNavigationState(
            explorerFallback,
            GetDataSafeFallback(
                excluded: null,
                includeNetworkData: false,
                includeFilesystemData: false),
            IncludeNetworkData: false,
            IncludeFilesystemData: false,
            Generation: 0,
            ViewerNavigationPhase.Idle,
            ViewerNavigationOutcome.None,
            StatusMessage: string.Empty,
            LastError: string.Empty);

        foreach (var descriptor in _dataTabs.Items)
        {
            descriptor.ActivationFailed += OnDataTabActivationFailed;
        }
    }

    public event EventHandler<ViewerNavigationStateChangedEventArgs>? StateChanged;

    public ViewerNavigationState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    public IReadOnlyList<FeatureTabDescriptor> ExplorerTabs => _explorerTabs.Items;

    public IReadOnlyList<FeatureTabDescriptor> DataTabs
    {
        get
        {
            var state = State;
            return _dataTabs.Items
                .Where(descriptor => IsDataTabContextuallyAvailable(
                    descriptor,
                    state.IncludeNetworkData,
                    state.IncludeFilesystemData))
                .ToArray();
        }
    }

    public ViewerNavigationResult NavigateToExplorerTab(FeatureTabKey tabKey, string actionName)
    {
        if (TryCreateDisposedResult(out var disposed))
        {
            return disposed;
        }

        var generation = BeginSynchronousNavigation();
        if (!_explorerTabs.TryGet(tabKey, out var descriptor) || descriptor == null)
        {
            var fallback = GetExplorerSafeFallback();
            return PublishResult(
                generation,
                ViewerNavigationOutcome.Unavailable,
                explorerSelection: fallback,
                dataSelection: State.DataSelection,
                statusMessage:
                    $"{actionName} is unavailable. Explorer tab '{tabKey}' is not published in educational release '{_releaseId}'.");
        }

        if (!descriptor.TryActivate(out _, out var activationException))
        {
            var fallback = GetExplorerSafeFallback(descriptor);
            return PublishResult(
                generation,
                ViewerNavigationOutcome.Failed,
                explorerSelection: fallback,
                dataSelection: State.DataSelection,
                statusMessage:
                    $"Explorer tab '{descriptor.Key}' could not activate: {activationException?.Message ?? "content unavailable"}. " +
                    $"Selected safe fallback '{fallback.Key}'.",
                lastError: activationException?.Message ?? "content unavailable");
        }

        return PublishResult(
            generation,
            ViewerNavigationOutcome.Succeeded,
            explorerSelection: descriptor,
            dataSelection: State.DataSelection);
    }

    public ViewerNavigationResult NavigateToDataTab(FeatureTabKey tabKey, string actionName)
    {
        if (TryCreateDisposedResult(out var disposed))
        {
            return disposed;
        }

        var generation = BeginSynchronousNavigation();
        var state = State;
        if (!_dataTabs.TryGet(tabKey, out var descriptor) || descriptor == null ||
            !IsDataTabContextuallyAvailable(
                descriptor,
                state.IncludeNetworkData,
                state.IncludeFilesystemData))
        {
            var fallback = GetDataSafeFallback();
            return PublishResult(
                generation,
                ViewerNavigationOutcome.Unavailable,
                explorerSelection: state.ExplorerSelection,
                dataSelection: fallback,
                statusMessage:
                    $"{actionName} is unavailable. Data tab '{tabKey}' is not published or available " +
                    $"in the current scope for educational release '{_releaseId}'.");
        }

        return PublishResult(
            generation,
            ViewerNavigationOutcome.Succeeded,
            explorerSelection: state.ExplorerSelection,
            dataSelection: descriptor);
    }

    public ViewerNavigationResult AcceptExplorerSelection(FeatureTabDescriptor? descriptor)
    {
        if (descriptor != null && _explorerTabs.Contains(descriptor))
        {
            return NavigateToExplorerTab(descriptor.Key, "Select Explorer tab");
        }

        var unavailableKey = descriptor?.Key.ToString() ?? "(none)";
        var generation = BeginSynchronousNavigation();
        var state = State;
        return PublishResult(
            generation,
            ViewerNavigationOutcome.Unavailable,
            explorerSelection: GetExplorerSafeFallback(),
            dataSelection: state.DataSelection,
            statusMessage:
                $"Explorer tab '{unavailableKey}' is unavailable in educational release '{_releaseId}'.");
    }

    public ViewerNavigationResult AcceptDataSelection(FeatureTabDescriptor? descriptor)
    {
        if (descriptor == null && DataTabs.Count == 0)
        {
            var generation = BeginSynchronousNavigation();
            var state = State;
            return PublishResult(
                generation,
                ViewerNavigationOutcome.Succeeded,
                explorerSelection: state.ExplorerSelection,
                dataSelection: null);
        }

        if (descriptor != null && _dataTabs.Contains(descriptor))
        {
            return NavigateToDataTab(descriptor.Key, "Select Data tab");
        }

        var unavailableKey = descriptor?.Key.ToString() ?? "(none)";
        var generationFallback = BeginSynchronousNavigation();
        var fallbackState = State;
        return PublishResult(
            generationFallback,
            ViewerNavigationOutcome.Unavailable,
            explorerSelection: fallbackState.ExplorerSelection,
            dataSelection: GetDataSafeFallback(),
            statusMessage:
                $"Data tab '{unavailableKey}' is unavailable in educational release '{_releaseId}'.");
    }

    public ViewerNavigationResult NavigateForExplorerScope(
        ExplorerScope scope,
        bool includeNetworkData,
        bool includeFilesystemData)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (TryCreateDisposedResult(out var disposed))
        {
            return disposed;
        }

        var generation = BeginSynchronousNavigation();
        var state = State;
        var dataKey = DataTabNavigationPolicy.GetTabKey(scope);
        var dataSelection = _dataTabs.TryGet(dataKey, out var candidate) &&
                            candidate != null &&
                            IsDataTabContextuallyAvailable(
                                candidate,
                                includeNetworkData,
                                includeFilesystemData)
            ? candidate
            : GetDataSafeFallback(
                excluded: null,
                includeNetworkData,
                includeFilesystemData);

        var explorerSelection = state.ExplorerSelection;
        if (includeNetworkData)
        {
            if (_explorerTabs.TryGet(ExplorerTabKeys.Network, out var network) &&
                network != null && network.TryActivate(out _, out _))
            {
                explorerSelection = network;
            }
            else
            {
                explorerSelection = GetExplorerSafeFallback();
            }
        }

        return PublishResult(
            generation,
            ViewerNavigationOutcome.Succeeded,
            explorerSelection,
            dataSelection,
            includeNetworkData,
            includeFilesystemData);
    }

    public ViewerNavigationResult SetDataContext(
        bool includeNetworkData,
        bool includeFilesystemData)
    {
        if (TryCreateDisposedResult(out var disposed))
        {
            return disposed;
        }

        var generation = BeginSynchronousNavigation();
        var state = State;
        var dataSelection = state.DataSelection != null &&
                            IsDataTabContextuallyAvailable(
                                state.DataSelection,
                                includeNetworkData,
                                includeFilesystemData)
            ? state.DataSelection
            : GetDataSafeFallback(
                excluded: null,
                includeNetworkData,
                includeFilesystemData);
        return PublishResult(
            generation,
            ViewerNavigationOutcome.Succeeded,
            state.ExplorerSelection,
            dataSelection,
            includeNetworkData,
            includeFilesystemData);
    }

    public ViewerNavigationResult ResetWorkspaceContext()
    {
        if (TryCreateDisposedResult(out var disposed))
        {
            return disposed;
        }

        var generation = BeginSynchronousNavigation();
        var state = State;
        return PublishResult(
            generation,
            ViewerNavigationOutcome.Succeeded,
            state.ExplorerSelection,
            GetDataSafeFallback(),
            includeNetworkData: false,
            includeFilesystemData: false);
    }

    public ViewerNavigationResult SelectSafeFallbacks(string statusMessage = "")
    {
        if (TryCreateDisposedResult(out var disposed))
        {
            return disposed;
        }

        var generation = BeginSynchronousNavigation();
        var state = State;
        return PublishResult(
            generation,
            ViewerNavigationOutcome.Unavailable,
            GetExplorerSafeFallback(),
            GetDataSafeFallback(
                excluded: null,
                includeNetworkData: state.IncludeNetworkData,
                includeFilesystemData: state.IncludeFilesystemData),
            statusMessage: statusMessage);
    }

    public void InvalidateProcessNavigation()
    {
        if (_disposed)
        {
            return;
        }

        var generation = BeginSynchronousNavigation();
        var state = State;
        PublishResult(
            generation,
            ViewerNavigationOutcome.Superseded,
            state.ExplorerSelection,
            state.DataSelection,
            statusMessage: string.Empty);
    }

    public async Task<ViewerNavigationResult> NavigateToProcessResultAsync(
        TelemetrySearchResult result,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (TryCreateDisposedResult(out var disposed))
        {
            return disposed;
        }

        var operation = BeginProcessNavigation(cancellationToken);
        try
        {
            var visible = _runtime.FindVisibleProcessRow(result);
            if (visible != null)
            {
                var visibleContext = _runtime.GetCurrentProcessNavigationContext();
                if (visibleContext != null && IsOperationCurrent(operation, visibleContext))
                {
                    _runtime.ApplyProcessNavigationSelection(visibleContext, visible);
                }
                else
                {
                    var legacy = _runtime.NavigateLegacyProcessResult(result);
                    return CompleteLegacy(operation, legacy);
                }

                return CompleteProcessSuccess(operation, result, visible, clearedFilters: false);
            }

            var context = _runtime.GetCurrentProcessNavigationContext();
            var processKey = result.ProcessKey;
            if (context != null && !string.IsNullOrWhiteSpace(result.ProcessEntityId))
            {
                var entityLookup = await context.Listing
                    .FindProcessByEntityIdAsync(result.ProcessEntityId, operation.Token);
                if (!IsOperationCurrent(operation, context))
                {
                    return CompleteInterrupted(operation);
                }

                if (!entityLookup.IsFound || entityLookup.Process == null ||
                    string.IsNullOrWhiteSpace(entityLookup.Process.ProcessKey))
                {
                    return CompleteProcessResult(
                        operation,
                        ViewerNavigationOutcome.NotFound,
                        $"The correlated process entity for '{result.ProcessName}' is not in staged data. Refresh and try again.");
                }

                processKey = entityLookup.Process.ProcessKey;
            }

            if (context == null || string.IsNullOrWhiteSpace(processKey))
            {
                var legacy = _runtime.NavigateLegacyProcessResult(result);
                return CompleteLegacy(operation, legacy);
            }

            var lookup = await context.Listing.FindProcessByKeyAsync(processKey, operation.Token);
            if (!IsOperationCurrent(operation, context))
            {
                return CompleteInterrupted(operation);
            }

            if (!lookup.IsFound)
            {
                return CompleteProcessResult(
                    operation,
                    ViewerNavigationOutcome.NotFound,
                    $"Process '{result.ProcessName}' (PID {result.ProcessId}) is not in staged data. Refresh and try again.");
            }

            var baseQuery = _runtime.BuildCurrentProcessListingQuery();
            var rowIndex = await context.Listing
                .GetProcessRowIndexAsync(processKey, baseQuery, operation.Token);
            if (!IsOperationCurrent(operation, context))
            {
                return CompleteInterrupted(operation);
            }

            var clearedFilters = false;
            if (rowIndex < 0)
            {
                context = await _runtime.ClearFiltersAndRebindProcessListingAsync(operation.Token);
                if (context == null || !IsOperationCurrent(operation, context))
                {
                    return CompleteInterrupted(operation);
                }

                baseQuery = _runtime.BuildCurrentProcessListingQuery();
                rowIndex = await context.Listing
                    .GetProcessRowIndexAsync(processKey, baseQuery, operation.Token);
                if (!IsOperationCurrent(operation, context))
                {
                    return CompleteInterrupted(operation);
                }

                clearedFilters = true;
            }

            if (rowIndex < 0)
            {
                return CompleteProcessResult(
                    operation,
                    ViewerNavigationOutcome.NotFound,
                    $"Could not locate '{result.ProcessName}' (PID {result.ProcessId}) in the process listing.");
            }

            await context.Collection.EnsureRangeAsync(rowIndex, 1, operation.Token);
            if (!IsOperationCurrent(operation, context))
            {
                return CompleteInterrupted(operation);
            }

            var row = context.Collection.GetLoadedItem(rowIndex);
            if (row == null)
            {
                return CompleteProcessResult(
                    operation,
                    ViewerNavigationOutcome.Failed,
                    $"Could not materialize '{result.ProcessName}' (PID {result.ProcessId}) in the process listing.");
            }

            context.Collection.PreserveSelection(row);
            _runtime.ApplyProcessNavigationSelection(context, row);
            return CompleteProcessSuccess(operation, result, row, clearedFilters);
        }
        catch (OperationCanceledException)
        {
            return CompleteInterrupted(operation);
        }
        catch (ObjectDisposedException)
        {
            return CompleteInterrupted(operation);
        }
        catch (Exception ex)
        {
            return CompleteProcessResult(
                operation,
                ViewerNavigationOutcome.Failed,
                $"Process navigation failed: {ex.Message}",
                lastError: ex.Message);
        }
        finally
        {
            CompleteOperation(operation);
        }
    }

    public bool TryGetDataTab(FeatureTabKey key, out FeatureTabDescriptor? descriptor) =>
        _dataTabs.TryGet(key, out descriptor);

    public bool TryGetExplorerTab(FeatureTabKey key, out FeatureTabDescriptor? descriptor) =>
        _explorerTabs.TryGet(key, out descriptor);

    public void Dispose()
    {
        ViewerNavigationState disposedState;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _activeNavigationCts?.Cancel();
            _activeNavigationCts?.Dispose();
            _activeNavigationCts = null;
            _lifetimeCts.Cancel();
            _state = _state with
            {
                Generation = _state.Generation + 1,
                Phase = ViewerNavigationPhase.Disposed,
                LastOutcome = ViewerNavigationOutcome.Disposed,
                StatusMessage = string.Empty,
                LastError = string.Empty
            };
            disposedState = _state;
        }

        foreach (var descriptor in _dataTabs.Items)
        {
            descriptor.ActivationFailed -= OnDataTabActivationFailed;
        }

        _lifetimeCts.Dispose();
        StateChanged?.Invoke(this, new ViewerNavigationStateChangedEventArgs(disposedState));
    }

    private void OnDataTabActivationFailed(object? sender, EventArgs e)
    {
        if (sender is not FeatureTabDescriptor descriptor || _disposed)
        {
            return;
        }

        var state = State;
        if (!ReferenceEquals(state.DataSelection, descriptor))
        {
            return;
        }

        var generation = BeginSynchronousNavigation();
        var fallback = GetDataSafeFallback(
            descriptor,
            state.IncludeNetworkData,
            state.IncludeFilesystemData);
        PublishResult(
            generation,
            ViewerNavigationOutcome.Failed,
            state.ExplorerSelection,
            fallback,
            statusMessage:
                $"Data tab '{descriptor.Key}' could not activate: {descriptor.ActivationError}. " +
                $"Selected safe fallback '{fallback?.Key.ToString() ?? "(none)"}'.",
            lastError: descriptor.ActivationError);
    }

    private long BeginSynchronousNavigation()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            _activeNavigationCts?.Cancel();
            return _state.Generation + 1;
        }
    }

    private NavigationOperation BeginProcessNavigation(CancellationToken cancellationToken)
    {
        NavigationOperation operation;
        ViewerNavigationState state;
        lock (_gate)
        {
            ThrowIfDisposed();
            _activeNavigationCts?.Cancel();
            _activeNavigationCts?.Dispose();
            var linked = CancellationTokenSource.CreateLinkedTokenSource(
                _lifetimeCts.Token,
                cancellationToken);
            _activeNavigationCts = linked;
            _state = _state with
            {
                Generation = _state.Generation + 1,
                Phase = ViewerNavigationPhase.Navigating,
                LastOutcome = ViewerNavigationOutcome.None,
                StatusMessage = string.Empty,
                LastError = string.Empty
            };
            operation = new NavigationOperation(_state.Generation, linked, cancellationToken);
            state = _state;
        }

        PublishStateChanged(state);
        return operation;
    }

    private ViewerNavigationResult PublishResult(
        long generation,
        ViewerNavigationOutcome outcome,
        FeatureTabDescriptor explorerSelection,
        FeatureTabDescriptor? dataSelection,
        bool? includeNetworkData = null,
        bool? includeFilesystemData = null,
        string statusMessage = "",
        string lastError = "",
        ProcessRowViewModel? processRow = null,
        bool clearedFilters = false)
    {
        ViewerNavigationState next;
        lock (_gate)
        {
            if (_disposed)
            {
                return CreateDisposedResult();
            }

            if (generation < _state.Generation)
            {
                return new ViewerNavigationResult(ViewerNavigationOutcome.Superseded, _state);
            }

            _state = _state with
            {
                ExplorerSelection = explorerSelection,
                DataSelection = dataSelection,
                IncludeNetworkData = includeNetworkData ?? _state.IncludeNetworkData,
                IncludeFilesystemData = includeFilesystemData ?? _state.IncludeFilesystemData,
                Generation = generation,
                Phase = ViewerNavigationPhase.Idle,
                LastOutcome = outcome,
                StatusMessage = statusMessage,
                LastError = lastError
            };
            next = _state;
        }

        PublishStateChanged(next);
        return new ViewerNavigationResult(outcome, next, processRow, clearedFilters);
    }

    private ViewerNavigationResult CompleteProcessSuccess(
        NavigationOperation operation,
        TelemetrySearchResult result,
        ProcessRowViewModel row,
        bool clearedFilters)
    {
        var status = clearedFilters
            ? $"Cleared filters and selected {result.ProcessName} (PID {result.ProcessId}) from search result."
            : $"Selected {result.ProcessName} (PID {result.ProcessId}) from search result.";
        return CompleteProcessResult(
            operation,
            ViewerNavigationOutcome.Succeeded,
            status,
            processRow: row,
            clearedFilters: clearedFilters);
    }

    private ViewerNavigationResult CompleteLegacy(
        NavigationOperation operation,
        ViewerLegacyProcessNavigationResult legacy)
        => CompleteProcessResult(
            operation,
            legacy.Succeeded ? ViewerNavigationOutcome.Succeeded : ViewerNavigationOutcome.NotFound,
            legacy.StatusMessage,
            processRow: legacy.ProcessRow,
            clearedFilters: legacy.ClearedFilters);

    private ViewerNavigationResult CompleteInterrupted(NavigationOperation operation)
    {
        var outcome = operation.CallerToken.IsCancellationRequested && IsGenerationCurrent(operation.Generation)
            ? ViewerNavigationOutcome.Canceled
            : ViewerNavigationOutcome.Superseded;
        return CompleteProcessResult(operation, outcome, statusMessage: string.Empty);
    }

    private ViewerNavigationResult CompleteProcessResult(
        NavigationOperation operation,
        ViewerNavigationOutcome outcome,
        string statusMessage,
        string lastError = "",
        ProcessRowViewModel? processRow = null,
        bool clearedFilters = false)
    {
        var state = State;
        return PublishResult(
            operation.Generation,
            outcome,
            state.ExplorerSelection,
            state.DataSelection,
            statusMessage: statusMessage,
            lastError: lastError,
            processRow: processRow,
            clearedFilters: clearedFilters);
    }

    private bool IsOperationCurrent(
        NavigationOperation operation,
        ViewerProcessNavigationContext context)
        => !operation.Token.IsCancellationRequested &&
           IsGenerationCurrent(operation.Generation) &&
           context.QueryGeneration == context.Collection.QueryGeneration &&
           context.WorkspaceGeneration == context.Collection.WorkspaceGeneration &&
           _runtime.IsCurrentProcessNavigationContext(context);

    private bool IsGenerationCurrent(long generation)
    {
        lock (_gate)
        {
            return !_disposed && generation == _state.Generation;
        }
    }

    private void CompleteOperation(NavigationOperation operation)
    {
        lock (_gate)
        {
            if (ReferenceEquals(_activeNavigationCts, operation.Cancellation))
            {
                _activeNavigationCts = null;
            }
        }

        operation.Cancellation.Dispose();
    }

    private FeatureTabDescriptor GetExplorerSafeFallback(FeatureTabDescriptor? excluded = null)
    {
        var fallback = _explorerTabs.SafeFallback;
        if (fallback != null && !ReferenceEquals(fallback, excluded) && !fallback.HasActivationFailed &&
            fallback.TryActivate(out _, out _))
        {
            return fallback;
        }

        foreach (var descriptor in _explorerTabs.Items)
        {
            if (!ReferenceEquals(descriptor, excluded) && !descriptor.HasActivationFailed &&
                descriptor.TryActivate(out _, out _))
            {
                return descriptor;
            }
        }

        throw new InvalidOperationException(
            $"Educational release '{_releaseId}' has no usable published Explorer fallback.");
    }

    private FeatureTabDescriptor? GetDataSafeFallback(
        FeatureTabDescriptor? excluded = null,
        bool? includeNetworkData = null,
        bool? includeFilesystemData = null)
    {
        var state = _state;
        var includeNetwork = includeNetworkData ?? state.IncludeNetworkData;
        var includeFilesystem = includeFilesystemData ?? state.IncludeFilesystemData;
        return _dataTabs.Items.FirstOrDefault(descriptor =>
                   descriptor.Key == DataTabKeys.AppInfo &&
                   !ReferenceEquals(descriptor, excluded) &&
                   !descriptor.HasActivationFailed &&
                   IsDataTabContextuallyAvailable(descriptor, includeNetwork, includeFilesystem)) ??
               _dataTabs.Items.FirstOrDefault(descriptor =>
                   !ReferenceEquals(descriptor, excluded) &&
                   !descriptor.HasActivationFailed &&
                   IsDataTabContextuallyAvailable(descriptor, includeNetwork, includeFilesystem));
    }

    private static bool IsDataTabContextuallyAvailable(
        FeatureTabDescriptor descriptor,
        bool includeNetworkData,
        bool includeFilesystemData)
        => DataTabNavigationPolicy.IsContextuallyAvailable(
            descriptor.Key,
            includeNetworkData,
            includeFilesystemData);

    private bool TryCreateDisposedResult(out ViewerNavigationResult result)
    {
        lock (_gate)
        {
            if (!_disposed)
            {
                result = null!;
                return false;
            }

            result = CreateDisposedResult();
            return true;
        }
    }

    private ViewerNavigationResult CreateDisposedResult()
        => new(ViewerNavigationOutcome.Disposed, _state);

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(ViewerNavigationCoordinator));
        }
    }

    private void PublishStateChanged(ViewerNavigationState state)
        => StateChanged?.Invoke(this, new ViewerNavigationStateChangedEventArgs(state));

    private sealed record NavigationOperation(
        long Generation,
        CancellationTokenSource Cancellation,
        CancellationToken CallerToken)
    {
        public CancellationToken Token => Cancellation.Token;
    }
}
