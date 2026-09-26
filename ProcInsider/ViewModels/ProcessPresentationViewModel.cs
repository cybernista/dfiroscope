using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using ProcInsider.Features.BaselineComparison;
using ProcInsider.Features.Infrastructure;
using ProcInsider.Features.Search;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Features;

using ProcInsider.Services.Presentation;

namespace ProcInsider.ViewModels;

/// <summary>Mutable state and selected-row consumers for one Processes presentation.</summary>
public partial class ProcessPresentationViewModel : ViewModelBase, IAppInfoPresentation, IProcessListingPresentation, IViewerNavigationRuntime, ISelectedProcessFanOutConsumerProvider, IProcessListingRuntime
{
    private readonly ProcessPresentationServices _services;
    internal readonly FeatureActivationRegistry _featureModules;
    internal ViewerPresentationRegistrationContext RegistrationContext { get; set; } = null!;
    private readonly TelemetryProjectionService _telemetryProjectionService;
    private AnnotationDatabaseService? _annotationStore => _services.AnnotationStore();
    public FeaturePublicationViewModel FeaturePublication { get; }
    public ListingColumnSettings ListingColumns { get; } = new();
    public SigmaViewModel SigmaViewModel => _services.Sigma();
    public string StatusMessage { get => _services.GetStatus(); set => _services.SetStatus(value); }

    internal ProcessPresentationViewModel(ProcessPresentationServices services)
    {
        _services = services;
        _featureModules = new FeatureActivationRegistry(services.Access);
        _telemetryProjectionService = services.Projection;
        FeaturePublication = services.Publication;
        _filterService = new ProcessFilterService();
        _listingWorkflow = new ProcessListingWorkflow(this);
    }

    private bool RequireFeaturePublished(FeatureId id, string action)
    {
        if (_services.Access.IsPublished(id)) return true;
        StatusMessage = action + " is unavailable in this release.";
        return false;
    }

    internal void NotifySharedStatusChanged() => OnPropertyChanged(nameof(StatusMessage));

    internal void RestoreViewport(ProcessRowViewModel row, double offset) => ProcessViewportAnchorRestoreRequested?.Invoke(row, offset);
    internal void RequestRowNavigation(ProcessRowViewModel row) => ProcessRowNavigationRequested?.Invoke(row);

    private bool _readsSuspended;
    private bool _selectionChangedWhileSuspended;
    private bool _disposed;
    internal ViewerSelectedProcessTarget? CaptureSelectedTarget()
    {
        var context = _selectedProcessFanOutCoordinator.State.CurrentSelection;
        return context == null ? null : new ViewerSelectedProcessTarget(context.ProcessEntityId, context.ProcessKey,
            context.ProcessId, context.ProcessName, context.StartTime, context.WorkspaceGeneration, context.SelectionGeneration);
    }

    internal bool IsSelectedTargetEligible(ViewerSelectedProcessTarget target)
    {
        var current = CaptureSelectedTarget();
        return !_disposed && !_readsSuspended && current == target && target.CaptureGeneration == _services.CaptureGeneration();
    }
    public ViewerSharedActions SharedActions => _services.SharedActions;

    internal async Task QuiesceAsync(CancellationToken cancellationToken)
    {
        if (!_readsSuspended)
        {
            _readsSuspended = true;
            SuspendHeaderQueries();
            _viewerNavigationCoordinator.InvalidateProcessNavigation();
            ProcessDescriptionViewModel.CancelPendingPresentationRequests();
            ProcessStatisticsViewModel.CancelPendingRequests();
            if (_featureModules.TryGetActivated<AiFeatureModule>(FeatureIds.AiAssistance, out var ai))
            {
                ai.InvestigationViewModel.CancelInvestigation();
                ai.DetailsViewModel.CancelInvestigation();
                ai.ChatViewModel.Cancel();
            }
        }
        await _listingWorkflow.QuiesceAsync(cancellationToken);
        await _selectedProcessFanOutCoordinator.QuiesceAsync(cancellationToken);
        await RegistrationContext.QuiesceAsync(cancellationToken);
        if (_virtualizedProcessListing != null)
            await _virtualizedProcessListing.SuspendReadsAsync(cancellationToken);
        while (Volatile.Read(ref _activeHeaderQueryCount) != 0)
            await Task.Delay(25, cancellationToken);
    }

    private sealed record PublicationState(SqliteStagingQueryService? Query, ProcessListingService? Listing,
        VirtualizedProcessCollection? Collection, ObservableCollection<ProcessRowViewModel> Rows,
        ICollectionView? View, int Count, ProcessRowViewModel? Selected, string ListingStatus, long QueryGeneration);
    private PublicationState? _publicationState;
    internal void BeginPublication()
    {
        if (_publicationState != null) throw new InvalidOperationException("A presentation publication is already pending.");
        _publicationState = new(_sqliteStagingQueryService, _processListingService, _virtualizedProcessListing,
            Processes, ProcessesView, TotalProcessCount, SelectedProcess, ProcessListingStatus, Volatile.Read(ref _processListingQueryGeneration));
    }
    internal void CommitPublication()
    {
        var prior = _publicationState;
        _publicationState = null;
        if (prior?.Collection != null && !ReferenceEquals(prior.Collection, _virtualizedProcessListing)) prior.Collection.Dispose();
    }
    internal bool AbortPublication()
    {
        var prior = _publicationState;
        if (prior == null) return false;
        _publicationState = null;
        // Quiescence canceled/drained the old requests; their tokens and navigation epoch stay invalid.
        Interlocked.Exchange(ref _processListingQueryGeneration, prior.QueryGeneration);
        _sqliteStagingQueryService = prior.Query;
        _processListingService = prior.Listing;
        if (!ReferenceEquals(prior.Collection, _virtualizedProcessListing))
        {
            DetachVirtualizedProcessListing()?.Dispose();
            _virtualizedProcessListing = prior.Collection;
            if (prior.Collection != null) prior.Collection.CacheChanged += OnVirtualizedProcessListingChanged;
            Processes = prior.Rows;
            ProcessesView = prior.View;
            TotalProcessCount = prior.Count;
            SelectedProcess = prior.Selected;
            ProcessListingStatus = prior.ListingStatus;
        }
        return true;
    }

    internal void PublishReadBinding(ViewerReadBinding binding)
    {
        _sqliteStagingQueryService = binding.QueryService;
        _processListingService = binding.ListingService;
    }

    internal void DetachReadBinding(long captureGeneration)
    {
        _selectedProcessFanOutCoordinator.InvalidateWorkspace(captureGeneration);
        _sqliteStagingQueryService = null;
        _processListingService = null;
        ProcessDescriptionViewModel.SetAnnotationStore(null);
        ProcessDescriptionViewModel.SetWorkspace(null, captureGeneration);
        NotesViewModel.SetAnnotationStore(null);
        if (_featureModules.TryGetActivated<AiFeatureModule>(FeatureIds.AiAssistance, out var ai)) ai.DetachWorkspace();
        RegistrationContext.BindWorkspace(null);
    }

    internal void BindCapture(ViewerCaptureBinding binding)
    {
        _sqliteStagingQueryService = binding.Query;
        _processListingService = binding.Listing;
        ProcessDescriptionViewModel.SetAnnotationStore(binding.Annotations);
        ProcessDescriptionViewModel.SetWorkspace(binding.Paths, binding.CaptureGeneration);
        NotesViewModel.SetAnnotationStore(binding.Annotations);
        if (_featureModules.TryGetActivated<AiFeatureModule>(FeatureIds.AiAssistance, out var ai))
            ai.SetWorkspace(binding.Paths, binding.Annotations);
        RegistrationContext.BindWorkspace(binding.Paths);
    }

    internal void ApplyExplorerMetadata(ExplorerCountRefreshPayload payload)
    {
        ExplorerViewModel.RefreshCounts(payload.Counts);
        ExplorerViewModel.RefreshEvidenceRoots(payload.EvidenceRoots);
        foreach (var (key, count) in new[] { (ExplorerTabKeys.Search, payload.Counts.SearchResultCount),
                     (ExplorerTabKeys.Sigma, payload.Counts.SigmaFindingCount), (ExplorerTabKeys.Network, payload.Counts.NetworkCaptureCount),
                     (ExplorerTabKeys.Memory, payload.Counts.MemoryImageCount) })
            if (_explorerTabSet.TryGet(key, out var tab)) tab?.UpdateCount(count);
        RefreshDataTabCounts();
    }

    internal void ResetCapture()
    {
        DetachVirtualizedProcessListing()?.Dispose();
        _processViewModels.Clear();
        Processes.Clear();
        ProcessesView = CollectionViewSource.GetDefaultView(Processes);
        SelectedProcess = null;
        ProcessListingStatus = "Process listing is not loaded.";
        IsProcessListingLoading = false;
        TotalProcessCount = RunningProcessCount = ExitedProcessCount = 0;
        ClearSnapshotBackedViews();
        ClearFilters();
        _listingWorkflow.CancelDebounce();
        ClearScopedSelectionState();
        _activeExplorerScope = CreateAllProcessesScope();
        ExplorerViewModel.ResetSelection();
        ExplorerViewModel.ResetCounts();
        foreach (var tab in ExplorerTabs.Concat(DataTabs).Where(tab => tab.Count.HasValue)) tab.UpdateCount(0);
        _viewerNavigationCoordinator.ResetWorkspaceContext();
        if (_featureModules.TryGetActivated<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility, out var memory)) memory.Clear();
        if (_featureModules.TryGetActivated<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry, out var events)) events.SystemActivityViewModel.Clear();
        if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network)) network.ViewModel.Clear();
        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem)) filesystem.Clear();
        InspectorPaneViewModel.Clear("Open a session or select a process to inspect details here.");
        UpdateSelectedProcessBookmarkState();
    }

    internal void ClearSnapshotBackedViews()
    {
        ProcessStatisticsViewModel.Clear();
        if (_featureModules.TryGetActivated<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility, out var memory)) memory.Clear();
        if (_featureModules.TryGetActivated<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry, out var events)) events.SystemActivityViewModel.Clear();
        if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network)) network.ViewModel.Clear();
        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem)) filesystem.Clear();
    }
    internal async Task RefreshSnapshotBackedViewsAsync(CancellationToken token = default)
    {
        await Dispatcher.Yield(DispatcherPriority.Background);
        token.ThrowIfCancellationRequested();
        await ProcessStatisticsViewModel.RefreshStatisticsAsync();
        await Dispatcher.Yield(DispatcherPriority.Background);
        token.ThrowIfCancellationRequested();
        if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network))
        {
            network.ViewModel.RefreshNetworkCaptures();
        }
        await Dispatcher.Yield(DispatcherPriority.Background);
        token.ThrowIfCancellationRequested();
        if (_featureModules.TryGetActivated<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility, out var memory))
        {
            memory.RefreshMemoryInvestigation();
        }
        await Dispatcher.Yield(DispatcherPriority.Background);
        token.ThrowIfCancellationRequested();
        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem))
        {
            filesystem.RefreshArtifacts();
        }
        await Dispatcher.Yield(DispatcherPriority.Background);
        token.ThrowIfCancellationRequested();
        if (_featureModules.TryGetActivated<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry, out var events))
        {
            events.SystemActivityViewModel.RefreshActivities(
                IsSystemActivityScope(_activeExplorerScope) ? _activeExplorerScope : null);
        }
    }

    internal void ResumeReads()
    {
        if (!_readsSuspended || _disposed) return;
        _readsSuspended = false;
        ResumeHeaderQueries();
        _listingWorkflow.Resume();
        _selectedProcessFanOutCoordinator.Resume();
        _virtualizedProcessListing?.ResumeReads();
        if (_selectionChangedWhileSuspended)
        {
            _selectionChangedWhileSuspended = false;
            _ = ObserveSelectedProcessFanOutAsync(_selectedProcessFanOutCoordinator.SelectAsync(SelectedProcess, _services.CaptureGeneration()));
            _services.SelectionChanged(this);
            if (SelectedProcess != null) _services.QueueSelectedDataEnrichment(this);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _featureModules.Activated -= OnFeatureModuleActivated;
        if (_viewerNavigationCoordinator != null) _viewerNavigationCoordinator.StateChanged -= OnViewerNavigationStateChanged;
        if (_selectedProcessFanOutCoordinator != null) _selectedProcessFanOutCoordinator.StateChanged -= OnSelectedProcessFanOutStateChanged;
        CloseHeaderFilters();
        _listingWorkflow.Dispose();
        _virtualizedProcessListing?.Dispose();
        _viewerNavigationCoordinator?.Dispose();
        _selectedProcessFanOutCoordinator?.Dispose();
        ProcessDescriptionViewModel?.Shutdown();
        _featureModules.Dispose();
    }

    public event Action<ProcessRowViewModel>? ProcessRowNavigationRequested;
    public event Func<ViewerProcessViewportAnchor?>? ProcessViewportAnchorCaptureRequested;
    public event Action<ProcessRowViewModel, double>? ProcessViewportAnchorRestoreRequested;

    internal const string ProcessBookmarkKind = "Process";
    internal const string NoProcessScopedSelectionKey = "__procinsider_no_process_scope__";
    internal FeatureTabSet _explorerTabSet = null!;
    internal FeatureTabSet _dataTabSet = null!;
    internal ViewerNavigationCoordinator _viewerNavigationCoordinator = null!;
    internal SelectedProcessFanOutCoordinator _selectedProcessFanOutCoordinator = null!;
    internal bool _isApplyingViewerNavigationState;
    internal ProcessFilterService _filterService;
    internal SqliteStagingQueryService? _sqliteStagingQueryService;
    internal ProcessListingService? _processListingService;
    internal VirtualizedProcessCollection? _virtualizedProcessListing;
    internal readonly ProcessListingWorkflow _listingWorkflow;
    internal ref long _processListingQueryGeneration => ref _listingWorkflow.QueryGeneration;
    internal long _snapshotPresentationInteractionGeneration;
    internal bool _isPublishingSnapshotPresentation;
    internal int _activeDbRefreshCount => _listingWorkflow.ActiveRequests;

    // Debounce timer for DB-backed process grid refreshes (e.g. on every keystroke).
    internal ExplorerScope _activeExplorerScope = new()
    {
        Kind = ExplorerScopeKind.AllProcesses,
        Title = "All Processes",
        Description = "All staged and live process records."
    };
    internal Dictionary<string, ExplorerScope> _includedScopes = new(StringComparer.Ordinal);
    internal Dictionary<string, ExplorerScope> _excludedScopes = new(StringComparer.Ordinal);
    internal HashSet<string> _includedProcessKeys = new(StringComparer.Ordinal);
    internal HashSet<string> _excludedProcessKeys = new(StringComparer.Ordinal);
    internal Dictionary<string, string> _includedProcessLabels = new(StringComparer.Ordinal);
    internal Dictionary<string, string> _excludedProcessLabels = new(StringComparer.Ordinal);

    internal ModulesAndHandlesFeatureModule? ModulesAndHandlesFeature =>
        _featureModules.GetOrActivate<ModulesAndHandlesFeatureModule>(FeatureIds.ModulesAndHandles);
    internal EventTelemetryFeatureModule? EventTelemetryFeature =>
        _featureModules.GetOrActivate<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry);
    internal WindowsSecurityEventsFeatureModule? WindowsSecurityEventsFeature =>
        _featureModules.GetOrActivate<WindowsSecurityEventsFeatureModule>(FeatureIds.WindowsSecurityEvents);
    internal DumpsAndPeFeatureModule? DumpsAndPeFeature =>
        _featureModules.GetOrActivate<DumpsAndPeFeatureModule>(FeatureIds.DumpsAndPeAnalysis);
    internal NetworkAndZeekFeatureModule? NetworkAndZeekFeature =>
        _featureModules.GetOrActivate<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek);
    internal AiFeatureModule? AiFeature =>
        _featureModules.GetOrActivate<AiFeatureModule>(FeatureIds.AiAssistance);

    // Process data
    internal Dictionary<string, ProcessRowViewModel> _processViewModels = new();

    [ObservableProperty]
    private ObservableCollection<ProcessRowViewModel> processes = new();

    [ObservableProperty]
    private ICollectionView? processesView;

    [ObservableProperty]
    private string processListingStatus = "Process listing is not loaded.";

    [ObservableProperty]
    private bool isProcessListingLoading;

    [ObservableProperty]
    private ProcessRowViewModel? selectedProcess;

    // Filter text for each column
    [ObservableProperty]
    private string filterProcessName = string.Empty;

    [ObservableProperty]
    private string filterPid = string.Empty;

    [ObservableProperty]
    private string filterParentPid = string.Empty;

    [ObservableProperty]
    private string filterParentProcessName = string.Empty;

    [ObservableProperty]
    private string filterProcessPath = string.Empty;

    [ObservableProperty]
    private string filterCommandLine = string.Empty;

    [ObservableProperty]
    private string filterUserName = string.Empty;

    [ObservableProperty]
    private string filterSessionId = string.Empty;

    [ObservableProperty]
    private string filterArchitecture = string.Empty;

    [ObservableProperty]
    private string filterStartTime = string.Empty;

    [ObservableProperty]
    private string filterEndTime = string.Empty;

    [ObservableProperty]
    private string filterStatus = string.Empty;

    [ObservableProperty]
    private string filterCpuUsage = string.Empty;

    [ObservableProperty]
    private string filterMemoryUsage = string.Empty;

    [ObservableProperty]
    private string filterCompanyName = string.Empty;

    [ObservableProperty]
    private string filterFileDescription = string.Empty;

    [ObservableProperty]
    private string filterSha256Hash = string.Empty;

    // Sorting state
    internal string _currentSortColumn = "Tree";
    internal bool _sortAscending = true;


    [ObservableProperty]
    private ViewerDetailsTabKey selectedDetailsTabKey = ViewerDetailsTabKey.Object;

    [ObservableProperty]
    private int totalProcessCount;

    [ObservableProperty]
    private int runningProcessCount;

    [ObservableProperty]
    private int exitedProcessCount;

    // Child view models
    public ProcessPropertiesViewModel ProcessPropertiesViewModel { get; internal set; } = null!;
    public ProcessDescriptionViewModel ProcessDescriptionViewModel { get; internal set; } = null!;
    public ProcessNotesViewModel NotesViewModel { get; internal set; } = null!;
    public ModulesViewModel ModulesViewModel => ModulesAndHandlesFeature?.ModulesViewModel!;
    public HandlesViewModel HandlesViewModel => ModulesAndHandlesFeature?.HandlesViewModel!;
    public EventsViewModel EventsViewModel => EventTelemetryFeature?.RuntimeEventsViewModel!;
    public EventsViewModel EtwProviderEventsViewModel => EventTelemetryFeature?.EtwEventsViewModel!;
    public EventsViewModel WindowsAuditLogViewModel => WindowsSecurityEventsFeature?.ViewModel!;
    public EventsViewModel PowerShellLogViewModel => EventTelemetryFeature?.PowerShellEventsViewModel!;
    public EventsViewModel WindowsOtherLogViewModel => EventTelemetryFeature?.OtherWindowsEventsViewModel!;
    public EventsViewModel SysmonEventsViewModel => EventTelemetryFeature?.SysmonEventsViewModel!;
    public MemoryDumpsViewModel MemoryDumpsViewModel => DumpsAndPeFeature?.MemoryDumpsViewModel!;
    public PeAnalysisViewModel PeAnalysisViewModel => DumpsAndPeFeature?.PeAnalysisViewModel!;
    public ProcessStatisticsViewModel ProcessStatisticsViewModel { get; internal set; } = null!;
    public MemoryInvestigationViewModel MemoryInvestigationViewModel =>
        _featureModules.GetOrActivate<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility)!;
    public NetworkCapturesViewModel NetworkCapturesViewModel => NetworkAndZeekFeature?.ViewModel!;
    public FilesystemArtifactsViewModel FilesystemArtifactsViewModel =>
        _featureModules.GetOrActivate<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts)!;
    public SystemActivityViewModel SystemActivityViewModel => EventTelemetryFeature?.SystemActivityViewModel!;
    public ExplorerViewModel ExplorerViewModel { get; internal set; } = null!;
    public InspectorPaneViewModel InspectorPaneViewModel { get; internal set; } = null!;
    public ProcessRiskDetailsViewModel? ProcessRiskDetailsViewModel { get; internal set; } = null!;
    public AiInvestigationViewModel AiInvestigationViewModel => AiFeature?.InvestigationViewModel!;
    public AiDetailsInvestigationViewModel AiDetailsInvestigationViewModel => AiFeature?.DetailsViewModel!;
    public AiChatViewModel AiChatViewModel => AiFeature?.ChatViewModel!;

    public IReadOnlyList<FeatureTabDescriptor> ExplorerTabs => _viewerNavigationCoordinator.ExplorerTabs;
    public IReadOnlyList<FeatureTabDescriptor> DataTabs => _viewerNavigationCoordinator.DataTabs;
    public IReadOnlyList<FeatureTabDescriptor> AppInfoExtensionTabs { get; internal set; } =
        Array.Empty<FeatureTabDescriptor>();

    [ObservableProperty]
    private FeatureTabDescriptor? selectedDataTab;

    [ObservableProperty]
    private FeatureTabDescriptor? selectedExplorerTab;

    [ObservableProperty]
    private ExplorerAiSection selectedExplorerAiSection = ExplorerAiSection.Chat;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DataTabs))]
    private bool isNetworkDataTabVisible;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DataTabs))]
    private bool isFilesystemDataTabVisible;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BookmarkSelectedProcessLabel))]
    private bool isSelectedProcessBookmarked;

    public string BookmarkSelectedProcessLabel => IsSelectedProcessBookmarked ? "Remove Bookmark" : "Bookmark";

    [ObservableProperty]
    private string scopedSelectionStatus = "Green scopes: none active; all evidence visible.";

    [ObservableProperty]
    private string scopedSelectionDetail = "No green scope or exclusion filters are active.";

    public bool TryNavigateToExplorerTab(FeatureTabKey tabKey, string actionName)
        => _viewerNavigationCoordinator.NavigateToExplorerTab(tabKey, actionName).Succeeded;

    public bool TryNavigateToDataTab(FeatureTabKey tabKey, string actionName)
        => _viewerNavigationCoordinator.NavigateToDataTab(tabKey, actionName).Succeeded;

    internal void OnViewerNavigationStateChanged(
        object? sender,
        ViewerNavigationStateChangedEventArgs e)
        => ApplyViewerNavigationState(e.State);

    internal void ApplyViewerNavigationState(ViewerNavigationState state)
    {
        var dataSelectionChanged = !ReferenceEquals(SelectedDataTab, state.DataSelection);
        _isApplyingViewerNavigationState = true;
        try
        {
            IsNetworkDataTabVisible = state.IncludeNetworkData;
            IsFilesystemDataTabVisible = state.IncludeFilesystemData;
            if (!ReferenceEquals(SelectedExplorerTab, state.ExplorerSelection))
            {
                SelectedExplorerTab = state.ExplorerSelection;
            }

            if (!ReferenceEquals(SelectedDataTab, state.DataSelection))
            {
                SelectedDataTab = state.DataSelection;
            }
        }
        finally
        {
            _isApplyingViewerNavigationState = false;
        }

        OnPropertyChanged(nameof(ExplorerTabs));
        OnPropertyChanged(nameof(DataTabs));
        if (!string.IsNullOrWhiteSpace(state.StatusMessage))
        {
            StatusMessage = state.StatusMessage;
        }

        if (dataSelectionChanged)
        {
            _services.QueueSelectedDataEnrichment(this);
        }
    }

    /// <summary>
    /// Updates the process list efficiently.
    /// </summary>
    internal void UpdateProcessList(
        List<ProcessInfo> allProcesses,
        IReadOnlyDictionary<string, ProcessSourceEventCounts>? eventCountsByProcess = null,
        IReadOnlyDictionary<string, int>? moduleCountsByProcess = null,
        IReadOnlyDictionary<string, int>? handleCountsByProcess = null)
    {
        var selectedKey = SelectedProcess?.ProcessKey;
        var selectedProcessId = SelectedProcess?.ProcessId ?? 0;
        var selectedProcessName = SelectedProcess?.ProcessName;
        const bool refreshEventCounts = true;
        var currentKeys = new HashSet<string>();
        eventCountsByProcess ??= _telemetryProjectionService.GetEventCountsByProcess();
        moduleCountsByProcess ??= _telemetryProjectionService.GetModuleCountsByProcess();
        handleCountsByProcess ??= _telemetryProjectionService.GetHandleCountsByProcess();

        // Apply tree-aware ordering when the Tree column is active. Other column sorts are
        // handled by the ICollectionView so live row counters can be sorted too.
        var sortedProcesses = _filterService.SortProcesses(allProcesses, _currentSortColumn, _sortAscending);

        var orderedRows = new List<ProcessRowViewModel>(sortedProcesses.Count);

        // Update or add processes
        foreach (var proc in sortedProcesses)
        {
            var key = proc.GetUniqueKey();
            currentKeys.Add(key);

            if (_processViewModels.TryGetValue(key, out var existingVm))
            {
                // Update existing
                existingVm.UpdateFrom(proc);
                UpdateProcessRowCounts(existingVm, includeEventCounts: refreshEventCounts, eventCountsByProcess, moduleCountsByProcess, handleCountsByProcess);
                orderedRows.Add(existingVm);

                if (ReferenceEquals(existingVm, SelectedProcess))
                {
                    ProcessPropertiesViewModel.LoadProcess(existingVm);
                }
            }
            else
            {
                // Add new
                var vm = new ProcessRowViewModel(proc);
                UpdateProcessRowCounts(vm, includeEventCounts: true, eventCountsByProcess, moduleCountsByProcess, handleCountsByProcess);
                _processViewModels[key] = vm;
                orderedRows.Add(vm);
            }
        }

        // Remove processes that no longer exist (shouldn't happen, but safety check)
        var toRemove = _processViewModels.Keys.Where(k => !currentKeys.Contains(k)).ToList();
        foreach (var key in toRemove)
        {
            _processViewModels.Remove(key);
        }

        ReplaceProcessRows(orderedRows);

        // Update counts
        TotalProcessCount = allProcesses.Count;
        RunningProcessCount = allProcesses.Count(p => p.Status == ProcessStatus.Running);
        ExitedProcessCount = allProcesses.Count(p => p.Status == ProcessStatus.Exited);
        ExplorerViewModel.RefreshCounts(_services.BuildExplorerScopeCounts(allProcesses));

        RestoreSelectedProcess(selectedKey, selectedProcessId, selectedProcessName);
    }

    internal List<ProcessInfo> GetProjectedProcesses()
    {
        return _telemetryProjectionService
            .GetProcessList(new ProcessProjectionQuery
            {
                IncludeExited = true,
                MaxCount = 10000
            })
            .ToList();
    }

    internal void ReplaceProcessRows(List<ProcessRowViewModel> orderedRows)
    {
        Processes = new ObservableCollection<ProcessRowViewModel>(orderedRows);
        ProcessesView = CollectionViewSource.GetDefaultView(Processes);
        ProcessesView.Filter = FilterProcess;

        if (!string.Equals(_currentSortColumn, "Tree", StringComparison.OrdinalIgnoreCase))
        {
            ProcessesView.SortDescriptions.Add(new SortDescription(
                _currentSortColumn,
                _sortAscending ? ListSortDirection.Ascending : ListSortDirection.Descending));
        }

        ProcessesView.Refresh();
    }

    /// <summary>
    /// Filter predicate for the collection view.
    /// </summary>
    internal bool FilterProcess(object obj) => FilterProcess(obj, null);

    internal bool FilterProcess(object obj, string? excludedHeader)
    {
        if (obj is not ProcessRowViewModel vm)
            return false;

        // Check each filter
        if (!ColumnTextFilter.Matches(vm.ProcessName, FilterProcessName))
            return false;

        if (!ColumnTextFilter.Matches(vm.ProcessId.ToString(), FilterPid))
            return false;

        if (!ColumnTextFilter.Matches(vm.ParentProcessId.ToString(), FilterParentPid))
            return false;

        if (!ColumnTextFilter.Matches(vm.ParentProcessName, FilterParentProcessName))
            return false;

        if (!ColumnTextFilter.Matches(vm.ProcessPath, FilterProcessPath))
            return false;

        if (!ColumnTextFilter.Matches(vm.CommandLine, FilterCommandLine))
            return false;

        if (!ColumnTextFilter.Matches(vm.UserName, FilterUserName))
            return false;

        if (!ColumnTextFilter.Matches(vm.SessionId.ToString(), FilterSessionId))
            return false;

        if (!ColumnTextFilter.Matches(vm.Architecture, FilterArchitecture))
            return false;

        if (!ColumnTextFilter.Matches(vm.StartTimeDisplay, FilterStartTime))
            return false;

        if (!ColumnTextFilter.Matches(vm.EndTimeDisplay, FilterEndTime))
            return false;

        if (!ColumnTextFilter.Matches(vm.StatusDisplay, FilterStatus))
            return false;

        if (!ColumnTextFilter.Matches(vm.CpuUsage, FilterCpuUsage))
            return false;

        if (!ColumnTextFilter.Matches(vm.MemoryUsage, FilterMemoryUsage))
            return false;

        if (!ColumnTextFilter.Matches(vm.CompanyName, FilterCompanyName))
            return false;

        if (!ColumnTextFilter.Matches(vm.FileDescription, FilterFileDescription))
            return false;

        if (!ColumnTextFilter.Matches(vm.Sha256Hash, FilterSha256Hash))
            return false;

        return IsProcessInActiveExplorerScope(vm) && IsProcessInScopedSelection(vm) && MatchesHeaderFilters(vm, excludedHeader);
    }

    /// <summary>
    /// Clears Listing column filters without changing Explorer scope or green/exclude selection.
    /// </summary>
    [RelayCommand]
    public void ClearFilters()
    {
        if (_headerFilters != null) foreach (var filter in _headerFilters.Values) filter.Reset(false);
        if (_processListingService == null) ProcessesView?.Refresh();
        FilterProcessName = string.Empty;
        FilterPid = string.Empty;
        FilterParentPid = string.Empty;
        FilterParentProcessName = string.Empty;
        FilterProcessPath = string.Empty;
        FilterCommandLine = string.Empty;
        FilterUserName = string.Empty;
        FilterSessionId = string.Empty;
        FilterArchitecture = string.Empty;
        FilterStartTime = string.Empty;
        FilterEndTime = string.Empty;
        FilterStatus = string.Empty;
        FilterCpuUsage = string.Empty;
        FilterMemoryUsage = string.Empty;
        FilterCompanyName = string.Empty;
        FilterFileDescription = string.Empty;
        FilterSha256Hash = string.Empty;

        // On the DB path a single ScheduleDbRefresh covers all cleared fields.
        // On the fallback path ProcessesView?.Refresh() is already triggered by
        // each OnFilter*Changed partial above; no extra call needed here.
        if (_processListingService != null)
        {
            ScheduleDbRefresh();
        }

        StatusMessage = "Cleared Listing column filters. Explorer green selection was unchanged.";
    }

    internal void RestoreSelectedProcess(string? selectedKey, int selectedProcessId, string? selectedProcessName)
    {
        if (string.IsNullOrWhiteSpace(selectedKey) && selectedProcessId <= 0)
        {
            return;
        }

        var restored = !string.IsNullOrWhiteSpace(selectedKey)
            ? SingleTarget(Processes.Where(process => process.ProcessKey == selectedKey))
            : SingleTarget(Processes.Where(process => process.ProcessId == selectedProcessId)
                .Where(process => string.IsNullOrWhiteSpace(selectedProcessName) ||
                    string.Equals(process.ProcessName, selectedProcessName, StringComparison.OrdinalIgnoreCase)));

        if (restored == null || ReferenceEquals(restored, SelectedProcess))
        {
            return;
        }

        SelectedProcess = restored;
    }

    internal void NavigateToSearchResult(TelemetrySearchResult result)
    {
        if (string.Equals(result.Kind, "Correlation", StringComparison.OrdinalIgnoreCase))
        {
            LoadCorrelationResultIntoInspector(result);
            return;
        }

        if ((string.Equals(result.Kind, "Sigma", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(result.Kind, "Event", StringComparison.OrdinalIgnoreCase)) &&
            result.CorrelationState is EvidenceCorrelationState.Unresolved or EvidenceCorrelationState.Ambiguous &&
            string.IsNullOrWhiteSpace(result.ProcessEntityId))
        {
            LoadCorrelationResultIntoInspector(result);
            return;
        }

        if (TryNavigateToIndependentArtifactResult(result))
        {
            return;
        }

        _ = _viewerNavigationCoordinator.NavigateToProcessResultAsync(result);
    }

    internal bool TryNavigateToIndependentArtifactResult(TelemetrySearchResult result)
    {
        InspectorPayload? payload = null;
        var kind = result.Kind;
        if (string.Equals(kind, "NetworkCapture", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetNetworkCaptures(10000)
                .FirstOrDefault(item => string.Equals(item.CaptureId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new NetworkCaptureRowViewModel(record).ToInspectorPayload();
            TryNavigateToExplorerTab(ExplorerTabKeys.Network, "Open network capture search result");
        }
        else if (string.Equals(kind, "Zeek", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetZeekNetworkArtifacts(10000)
                .FirstOrDefault(item => string.Equals(item.ArtifactId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new ZeekNetworkArtifactRowViewModel(record).ToInspectorPayload();
            TryNavigateToExplorerTab(ExplorerTabKeys.Network, "Open Zeek search result");
        }
        else if (string.Equals(kind, "FilesystemArtifact", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetFilesystemArtifacts(10000)
                .FirstOrDefault(item => string.Equals(item.ArtifactId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new FilesystemArtifactRowViewModel(record).ToInspectorPayload();
            TryNavigateToDataTab(DataTabKeys.Filesystem, "Open filesystem search result");
        }
        else if (string.Equals(kind, "MemoryImage", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetMemoryImages(10000)
                .FirstOrDefault(item => string.Equals(item.ImageId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new MemoryImageRowViewModel(record).ToInspectorPayload();
            TryNavigateToExplorerTab(ExplorerTabKeys.Memory, "Open memory image search result");
        }
        else if (string.Equals(kind, "VolatilityRun", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetVolatilityPluginRuns(maxCount: 10000)
                .FirstOrDefault(item => string.Equals(item.RunId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new VolatilityPluginRunRowViewModel(record).ToInspectorPayload();
            TryNavigateToExplorerTab(ExplorerTabKeys.Memory, "Open Volatility run search result");
        }
        else if (string.Equals(kind, "MemoryProcess", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetMemoryProcesses(maxCount: 10000)
                .FirstOrDefault(item => string.Equals(item.ArtifactId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new MemoryProcessRowViewModel(record).ToInspectorPayload();
            TryNavigateToExplorerTab(ExplorerTabKeys.Memory, "Open memory process search result");
        }
        else
        {
            return false;
        }

        if (payload == null)
        {
            StatusMessage = $"The {kind} search result is no longer present in staged evidence. Refresh and try again.";
            return true;
        }

        InspectorPaneViewModel.Load(payload);
        StatusMessage = $"Opened {kind} evidence from search: {result.Title}.";
        return true;
    }

    internal ViewerLegacyProcessNavigationResult NavigateToSearchResultLegacy(TelemetrySearchResult result)
    {
        if (_virtualizedProcessListing != null && string.IsNullOrWhiteSpace(result.ProcessEntityId) &&
            string.IsNullOrWhiteSpace(result.ProcessKey))
        {
            return new ViewerLegacyProcessNavigationResult(false,
                "Search result has no exact process identity for this bounded listing. Refresh staged data and try again.");
        }
        if (Processes.Count == 0 && _virtualizedProcessListing == null)
        {
            UpdateProcessList(GetProjectedProcesses());
        }

        var target = FindVisibleProcessRow(result) ?? AddSearchResultProcessRow(result);
        if (target == null)
        {
            return new ViewerLegacyProcessNavigationResult(
                false,
                $"Search result process is not visible: {result.ProcessName} (PID {result.ProcessId}). Refresh staged data and try again.");
        }

        var clearedFilters = false;
        if (ProcessesView?.Contains(target) == false)
        {
            ClearFilters();
            clearedFilters = true;
        }

        SelectedProcess = target;
        _virtualizedProcessListing?.PreserveSelection(target);
        ProcessesView?.MoveCurrentTo(target);
        ProcessRowNavigationRequested?.Invoke(target);
        var statusMessage = clearedFilters
            ? $"Cleared filters and selected {target.ProcessName} (PID {target.ProcessId}) from search result."
            : $"Selected {target.ProcessName} (PID {target.ProcessId}) from search result.";
        return new ViewerLegacyProcessNavigationResult(
            true,
            statusMessage,
            target,
            clearedFilters);
    }

    ViewerProcessNavigationContext? IViewerNavigationRuntime.GetCurrentProcessNavigationContext()
    {
        var listingService = _processListingService;
        var collection = _virtualizedProcessListing;
        if (listingService == null || collection == null)
        {
            return null;
        }

        return new ViewerProcessNavigationContext(
            listingService,
            collection,
            _services.CaptureGeneration(),
            Volatile.Read(ref _processListingQueryGeneration));
    }

    bool IViewerNavigationRuntime.IsCurrentProcessNavigationContext(
        ViewerProcessNavigationContext context)
        => ReferenceEquals(context.Listing, _processListingService) &&
           ReferenceEquals(context.Collection, _virtualizedProcessListing) &&
           context.WorkspaceGeneration == _services.CaptureGeneration() &&
           context.QueryGeneration == Volatile.Read(ref _processListingQueryGeneration) &&
           context.QueryGeneration == context.Collection.QueryGeneration &&
           context.WorkspaceGeneration == context.Collection.WorkspaceGeneration;

    ProcessListingQuery IViewerNavigationRuntime.BuildCurrentProcessListingQuery()
        => BuildCurrentListingQuery();

    ProcessRowViewModel? IViewerNavigationRuntime.FindVisibleProcessRow(TelemetrySearchResult result)
        => FindVisibleProcessRow(result);

    async Task<ViewerProcessNavigationContext?> IViewerNavigationRuntime.ClearFiltersAndRebindProcessListingAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher != null && !dispatcher.CheckAccess())
        {
            dispatcher.Invoke(ClearFilters);
        }
        else
        {
            ClearFilters();
        }

        _listingWorkflow.CancelDebounce();
        await ExecuteDbRefreshAsync();
        cancellationToken.ThrowIfCancellationRequested();
        return ((IViewerNavigationRuntime)this).GetCurrentProcessNavigationContext();
    }

    void IViewerNavigationRuntime.ApplyProcessNavigationSelection(
        ViewerProcessNavigationContext context,
        ProcessRowViewModel row)
    {
        void Apply()
        {
            if (!((IViewerNavigationRuntime)this).IsCurrentProcessNavigationContext(context))
            {
                return;
            }

            SelectedProcess = row;
            context.Collection.PreserveSelection(row);
            ProcessesView?.MoveCurrentTo(row);
            ProcessRowNavigationRequested?.Invoke(row);
        }

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher != null && !dispatcher.CheckAccess())
        {
            dispatcher.Invoke(Apply);
        }
        else
        {
            Apply();
        }
    }

    ViewerLegacyProcessNavigationResult IViewerNavigationRuntime.NavigateLegacyProcessResult(
        TelemetrySearchResult result)
        => NavigateToSearchResultLegacy(result);

    internal void LoadCorrelationResultIntoInspector(TelemetrySearchResult result)
    {
        InspectorPaneViewModel.Load(new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.CorrelationEvidence,
            TargetKind = result.EvidenceKind,
            TargetId = result.RecordKey,
            ArtifactId = result.RecordKey,
            ProcessId = result.ProcessId,
            ProcessName = result.ProcessName,
            Header = result.Title,
            Subtitle = result.CorrelationDiagnostics,
            EmptyStateMessage = "Select correlation evidence to inspect its decision diagnostics.",
            Properties = new List<PropertyItemViewModel>
            {
                new("Evidence", "Reference", result.RecordKey),
                new("Evidence", "Kind", result.EvidenceKind),
                new("Evidence", "Source", result.Source),
                new("Correlation", "State", result.CorrelationState?.ToString() ?? "Unresolved"),
                new("Correlation", "Method", result.CorrelationMethod),
                new("Correlation", "Candidate Count", result.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture)),
                new("Correlation", "Resolver Version", result.ResolverVersion),
                new("Process Hint", "PID", result.ProcessId > 0 ? result.ProcessId.ToString(CultureInfo.InvariantCulture) : string.Empty),
                new("Process Hint", "Name", result.ProcessName)
            },
            RawText = result.CorrelationDiagnostics
        });
        StatusMessage = $"Correlation evidence: {result.CorrelationState?.ToString() ?? "Unresolved"}; {result.CorrelationCandidateCount} candidate(s).";
    }

    internal void OnExplorerScopeSelected(ExplorerScope scope)
    {
        MarkSnapshotPresentationInteraction();
        var requiredFeature = FeatureNavigationPolicy.GetFeatureForExplorerScope(scope);
        if (requiredFeature.HasValue &&
            !RequireFeaturePublished(requiredFeature.Value, $"Explorer scope '{scope.Title}'"))
        {
            _viewerNavigationCoordinator.SelectSafeFallbacks(StatusMessage);
            return;
        }

        _activeExplorerScope = scope;
        var isNetworkScope = IsNetworkScope(scope);
        var isFilesystemScope = IsFilesystemScope(scope);
        _viewerNavigationCoordinator.NavigateForExplorerScope(
            scope,
            isNetworkScope,
            isFilesystemScope);
        ProcessStatisticsViewModel.ApplyActiveScope(scope);

        SelectedProcess = null;
        RefreshDataForExplorerScope(scope);
        InspectorPaneViewModel.Clear(
            "Select a row in Data to inspect its additional properties.");

        if (_processListingService != null)
        {
            ScheduleDbRefresh();
        }
        else
        {
            ProcessesView?.Refresh();
        }

        StatusMessage = $"Explorer scope: {scope.Title}.";
    }


    internal void RefreshDataForExplorerScope(ExplorerScope scope)
    {
        switch (scope.Kind)
        {
            case ExplorerScopeKind.NetworkRoot:
            case ExplorerScopeKind.NetworkCaptures:
            case ExplorerScopeKind.NetworkCapture:
            case ExplorerScopeKind.ZeekArtifacts:
                NetworkAndZeekFeature?.ViewModel.RefreshNetworkCaptures();
                break;
            case ExplorerScopeKind.FilesystemRoot:
            case ExplorerScopeKind.FilesystemEvidenceRoots:
            case ExplorerScopeKind.FilesystemArtifacts:
            case ExplorerScopeKind.FilesystemFolder:
                _featureModules.GetOrActivate<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts)
                    ?.RefreshArtifacts(scope);
                break;
            case ExplorerScopeKind.SystemActivityRoot:
            case ExplorerScopeKind.ActivityAuthentication:
            case ExplorerScopeKind.ActivitySuccessfulLogons:
            case ExplorerScopeKind.ActivityFailedLogons:
            case ExplorerScopeKind.ActivityRemoteInteractive:
            case ExplorerScopeKind.ActivityExplicitCredentialUse:
            case ExplorerScopeKind.ActivityPrivilegedLogons:
            case ExplorerScopeKind.ActivityAccounts:
            case ExplorerScopeKind.ActivityCreatedUsers:
            case ExplorerScopeKind.ActivityDisabledDeletedUsers:
            case ExplorerScopeKind.ActivityPasswordChanges:
            case ExplorerScopeKind.ActivityGroups:
            case ExplorerScopeKind.ActivityLocalAdministratorsChanges:
            case ExplorerScopeKind.ActivitySecurityGroupMembershipChanges:
            case ExplorerScopeKind.ActivityPolicyAudit:
            case ExplorerScopeKind.ActivityAuditPolicyChanged:
            case ExplorerScopeKind.ActivityLogIntegrity:
            case ExplorerScopeKind.ActivitySecurityLogCleared:
            case ExplorerScopeKind.ActivityServicesTasks:
            case ExplorerScopeKind.ActivityServicesInstalled:
            case ExplorerScopeKind.ActivityScheduledTasksChanged:
            case ExplorerScopeKind.UsersRoot:
            case ExplorerScopeKind.UserAccount:
                EventTelemetryFeature?.SystemActivityViewModel.RefreshActivities(scope);
                break;
            case ExplorerScopeKind.SearchResults:
                if (_services.SharedModules.TryGetActivated<SearchFeatureModule>(FeatureIds.SearchAndSigma, out var search))
                {
                    search.ViewModel.SearchCommand.NotifyCanExecuteChanged();
                }
                break;
            case ExplorerScopeKind.SigmaFindings:
                if (_services.SharedModules.TryGetActivated<SigmaViewModel>(FeatureIds.SearchAndSigma, out var sigma))
                {
                    sigma.RunRuleCommand.NotifyCanExecuteChanged();
                }
                break;
            case ExplorerScopeKind.UnresolvedEvidence:
            case ExplorerScopeKind.AmbiguousEvidence:
            case ExplorerScopeKind.CorrelationEvidenceGroup:
                _ = _services.LoadCorrelationEvidence(scope);
                break;
        }
    }

    [RelayCommand]
    internal void IncludeCurrentExplorerScope()
    {
        var scopes = GetCurrentExplorerScopeSet().ToList();
        if (scopes.Count == 0)
        {
            StatusMessage = "Select an evidence scope before changing green selection.";
            return;
        }

        foreach (var scope in scopes)
        {
            _excludedScopes.Remove(scope.StableId);
            _includedScopes[scope.StableId] = scope;
        }

        RefreshScopedSelection($"Green-selected {FormatScopeActionCount(scopes.Count)}.");
    }

    [RelayCommand]
    internal void ExcludeCurrentExplorerScope()
    {
        var scopes = GetCurrentExplorerScopeSet().ToList();
        if (scopes.Count == 0)
        {
            StatusMessage = "Select an evidence scope before changing green selection.";
            return;
        }

        foreach (var scope in scopes)
        {
            _includedScopes.Remove(scope.StableId);
            _excludedScopes[scope.StableId] = scope;
        }

        RefreshScopedSelection($"Excluded {FormatScopeActionCount(scopes.Count)}.");
    }

    [RelayCommand]
    internal void ToggleExplorerGreenScope(ExplorerNodeViewModel? node)
    {
        if (node is not { IsPlaceholder: false } || !IsSelectableExplorerScope(node.Scope))
        {
            return;
        }

        var scopes = GetNodeAndLoadedDescendantScopes(node).ToArray();
        if (scopes.Length == 0)
        {
            return;
        }

        var removeGreen = node.SelectionState == ExplorerScopeSelectionState.GreenIncluded;
        var hasIncludedAncestor = removeGreen && HasGreenIncludedAncestor(node);
        foreach (var scope in scopes)
        {
            if (removeGreen)
            {
                _includedScopes.Remove(scope.StableId);
                if (hasIncludedAncestor)
                {
                    _excludedScopes[scope.StableId] = scope;
                }
                else
                {
                    _excludedScopes.Remove(scope.StableId);
                }
            }
            else
            {
                _excludedScopes.Remove(scope.StableId);
                _includedScopes[scope.StableId] = scope;
            }
        }

        RefreshScopedSelection(removeGreen
            ? $"Removed green selection from {FormatScopeActionCount(scopes.Length)}."
            : $"Green-selected {FormatScopeActionCount(scopes.Length)}.");
    }

    internal static IEnumerable<ExplorerScope> GetNodeAndLoadedDescendantScopes(ExplorerNodeViewModel node)
    {
        foreach (var current in FlattenExplorerNode(node))
        {
            if (current is { IsPlaceholder: false } && IsSelectableExplorerScope(current.Scope))
            {
                yield return current.Scope;
            }
        }
    }

    internal static IEnumerable<ExplorerNodeViewModel> FlattenExplorerNode(ExplorerNodeViewModel node)
    {
        yield return node;
        foreach (var child in node.Children)
        {
            foreach (var descendant in FlattenExplorerNode(child))
            {
                yield return descendant;
            }
        }
    }

    internal bool HasGreenIncludedAncestor(ExplorerNodeViewModel target)
    {
        foreach (var root in ExplorerViewModel.RootNodes)
        {
            if (HasGreenIncludedAncestor(root, target, inheritedIncluded: false))
            {
                return true;
            }
        }

        return false;
    }

    internal bool HasGreenIncludedAncestor(
        ExplorerNodeViewModel current,
        ExplorerNodeViewModel target,
        bool inheritedIncluded)
    {
        if (ReferenceEquals(current, target))
        {
            return inheritedIncluded;
        }

        var scopeId = current.Scope.StableId;
        var currentIncluded = inheritedIncluded ||
                              (_includedScopes.ContainsKey(scopeId) && !_excludedScopes.ContainsKey(scopeId));
        if (_excludedScopes.ContainsKey(scopeId))
        {
            currentIncluded = false;
        }

        foreach (var child in current.Children)
        {
            if (HasGreenIncludedAncestor(child, target, currentIncluded))
            {
                return true;
            }
        }

        return false;
    }

    [RelayCommand(CanExecute = nameof(CanChangeSelectedProcessScope))]
    internal void IncludeSelectedProcess()
    {
        if (SelectedProcess == null)
        {
            return;
        }

        var label = FormatProcessLabel(SelectedProcess);
        _excludedProcessKeys.Remove(SelectedProcess.ProcessKey);
        _excludedProcessLabels.Remove(SelectedProcess.ProcessKey);
        _includedProcessKeys.Add(SelectedProcess.ProcessKey);
        _includedProcessLabels[SelectedProcess.ProcessKey] = label;
        RefreshScopedSelection($"Included {label}.");
    }

    [RelayCommand(CanExecute = nameof(CanChangeSelectedProcessScope))]
    internal void ExcludeSelectedProcess()
    {
        if (SelectedProcess == null)
        {
            return;
        }

        var label = FormatProcessLabel(SelectedProcess);
        _includedProcessKeys.Remove(SelectedProcess.ProcessKey);
        _includedProcessLabels.Remove(SelectedProcess.ProcessKey);
        _excludedProcessKeys.Add(SelectedProcess.ProcessKey);
        _excludedProcessLabels[SelectedProcess.ProcessKey] = label;
        RefreshScopedSelection($"Excluded {label}.");
    }

    [RelayCommand(CanExecute = nameof(CanClearScopedSelection))]
    internal void ClearScopedSelection()
    {
        _includedScopes.Clear();
        _excludedScopes.Clear();
        _includedProcessKeys.Clear();
        _excludedProcessKeys.Clear();
        _includedProcessLabels.Clear();
        _excludedProcessLabels.Clear();
        RefreshScopedSelection("Cleared include/exclude selection.");
    }

    internal IEnumerable<ExplorerScope> GetCurrentExplorerScopeSet()
    {
        var scopes = ExplorerViewModel.SelectedScopes
            .Where(scope => IsSelectableExplorerScope(scope))
            .GroupBy(scope => scope.StableId, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToList();

        if (scopes.Count == 0 && IsSelectableExplorerScope(_activeExplorerScope))
        {
            scopes.Add(_activeExplorerScope);
        }

        return scopes;
    }

    internal static bool IsSelectableExplorerScope(ExplorerScope scope)
    {
        return scope.Kind != ExplorerScopeKind.Placeholder &&
               scope.Kind != ExplorerScopeKind.Branch;
    }

    internal bool CanChangeSelectedProcessScope()
    {
        return SelectedProcess != null && !string.IsNullOrWhiteSpace(SelectedProcess.ProcessKey);
    }

    internal bool CanClearScopedSelection()
    {
        return HasScopedSelection();
    }

    internal void RefreshScopedSelection(string statusMessage)
    {
        ApplyScopedSelectionStateToViews();
        UpdateScopedSelectionStatus();
        ClearScopedSelectionCommand.NotifyCanExecuteChanged();

        if (_processListingService != null)
        {
            ScheduleDbRefresh();
        }
        else
        {
            ProcessesView?.Refresh();
            if (SelectedProcess != null && !FilterProcess(SelectedProcess))
            {
                SelectedProcess = null;
            }
        }

        StatusMessage = statusMessage;
    }

    internal void UpdateScopedSelectionStatus()
    {
        if (!HasScopedSelection())
        {
            ScopedSelectionStatus = "Green scopes: none active; all evidence visible.";
            ScopedSelectionDetail = "No green scope or exclusion filters are active.";
            return;
        }

        var greenCount = _includedScopes.Count + _includedProcessKeys.Count;
        var excludeCount = _excludedScopes.Count + _excludedProcessKeys.Count;
        ScopedSelectionStatus = $"Green scopes: {greenCount} active, {excludeCount} excluded.";
        ScopedSelectionDetail = BuildScopedSelectionDetail();
    }

    internal bool HasScopedSelection()
    {
        return _includedScopes.Count > 0 ||
               _excludedScopes.Count > 0 ||
               _includedProcessKeys.Count > 0 ||
               _excludedProcessKeys.Count > 0;
    }

    internal void ClearScopedSelectionState()
    {
        _includedScopes.Clear();
        _excludedScopes.Clear();
        _includedProcessKeys.Clear();
        _excludedProcessKeys.Clear();
        _includedProcessLabels.Clear();
        _excludedProcessLabels.Clear();
        ApplyScopedSelectionStateToViews();
        UpdateScopedSelectionStatus();
        ClearScopedSelectionCommand.NotifyCanExecuteChanged();
    }

    internal void ApplyScopedSelectionStateToViews()
    {
        var includedScopes = _includedScopes.Values.ToList();
        var excludedScopes = _excludedScopes.Values.ToList();
        var hasGreenSelection = _includedScopes.Count > 0 || _includedProcessKeys.Count > 0;

        ExplorerViewModel.ApplyScopeSelectionState(_includedScopes.Keys, _excludedScopes.Keys);
        ProcessStatisticsViewModel.ApplyScopedSelection(
            includedScopes,
            excludedScopes,
            _includedProcessKeys,
            _excludedProcessKeys,
            hasGreenSelection);
        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem))
        {
            filesystem.ApplyScopedSelection(includedScopes, excludedScopes, hasGreenSelection);
        }

        if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network))
        {
            network.ViewModel.ApplyScopedSelection(includedScopes, excludedScopes, hasGreenSelection);
        }

        if (_featureModules.TryGetActivated<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry, out var events))
        {
            events.SystemActivityViewModel.ApplyScopedSelection(includedScopes, excludedScopes, hasGreenSelection);
        }
    }

    internal string BuildScopedSelectionDetail()
    {
        var included = BuildScopedSelectionItems(_includedScopes.Values, _includedProcessLabels.Values);
        var excluded = BuildScopedSelectionItems(_excludedScopes.Values, _excludedProcessLabels.Values);

        return $"Green-selected: {FormatScopedSelectionList(included)}. Excluded: {FormatScopedSelectionList(excluded)}.";
    }

    internal static IEnumerable<string> BuildScopedSelectionItems(
        IEnumerable<ExplorerScope> scopes,
        IEnumerable<string> processLabels)
    {
        foreach (var scope in scopes.OrderBy(scope => scope.Title, StringComparer.OrdinalIgnoreCase))
        {
            yield return $"scope {scope.Title}";
        }

        foreach (var label in processLabels.OrderBy(label => label, StringComparer.OrdinalIgnoreCase))
        {
            yield return label;
        }
    }

    internal static string FormatScopedSelectionList(IEnumerable<string> items)
    {
        var list = items.ToList();
        return list.Count == 0 ? "none" : string.Join("; ", list);
    }

    internal static string FormatCount(int count, string noun)
    {
        return count == 1 ? $"1 {noun}" : $"{count} {noun}s";
    }

    internal static string FormatScopeActionCount(int count)
    {
        return count == 1 ? "1 Explorer scope" : $"{count} Explorer scopes";
    }

    internal static string FormatProcessLabel(ProcessRowViewModel process)
    {
        return $"{process.ProcessName} (PID {process.ProcessId})";
    }

    internal static ExplorerScope CreateAllProcessesScope()
    {
        return new ExplorerScope
        {
            Kind = ExplorerScopeKind.AllProcesses,
            ScopeId = "process:all",
            Title = "All Processes",
            Description = "All staged and live process records."
        };
    }

    internal static FeatureTabKey GetDataTabForScope(ExplorerScope scope) =>
        DataTabNavigationPolicy.GetTabKey(scope);

    internal static bool IsNetworkScope(ExplorerScope scope)
    {
        return scope.Kind is ExplorerScopeKind.NetworkRoot or
            ExplorerScopeKind.NetworkCaptures or
            ExplorerScopeKind.NetworkCapture or
            ExplorerScopeKind.ZeekArtifacts;
    }

    internal static bool IsFilesystemScope(ExplorerScope scope)
    {
        return scope.Kind is ExplorerScopeKind.FilesystemRoot or
            ExplorerScopeKind.FilesystemEvidenceRoots or
            ExplorerScopeKind.FilesystemArtifacts or
            ExplorerScopeKind.FilesystemFolder;
    }

    internal static bool IsSystemActivityScope(ExplorerScope scope)
    {
        return scope.Kind is ExplorerScopeKind.SystemActivityRoot or
            ExplorerScopeKind.ActivityAuthentication or
            ExplorerScopeKind.ActivitySuccessfulLogons or
            ExplorerScopeKind.ActivityFailedLogons or
            ExplorerScopeKind.ActivityRemoteInteractive or
            ExplorerScopeKind.ActivityExplicitCredentialUse or
            ExplorerScopeKind.ActivityPrivilegedLogons or
            ExplorerScopeKind.ActivityAccounts or
            ExplorerScopeKind.ActivityCreatedUsers or
            ExplorerScopeKind.ActivityDisabledDeletedUsers or
            ExplorerScopeKind.ActivityPasswordChanges or
            ExplorerScopeKind.ActivityGroups or
            ExplorerScopeKind.ActivityLocalAdministratorsChanges or
            ExplorerScopeKind.ActivitySecurityGroupMembershipChanges or
            ExplorerScopeKind.ActivityPolicyAudit or
            ExplorerScopeKind.ActivityAuditPolicyChanged or
            ExplorerScopeKind.ActivityLogIntegrity or
            ExplorerScopeKind.ActivitySecurityLogCleared or
            ExplorerScopeKind.ActivityServicesTasks or
            ExplorerScopeKind.ActivityServicesInstalled or
            ExplorerScopeKind.ActivityScheduledTasksChanged or
            ExplorerScopeKind.UsersRoot or
            ExplorerScopeKind.UserAccount;
    }

    internal bool IsProcessInActiveExplorerScope(ProcessRowViewModel process)
    {
        return DoesProcessMatchScope(process, _activeExplorerScope);
    }

    internal bool IsProcessInScopedSelection(ProcessRowViewModel process)
    {
        var includedScopes = GetProcessListingIncludedScopes();
        var hasAnyGreenSelection = _includedProcessKeys.Count > 0 ||
                                   _includedScopes.Count > 0 ||
                                   ExplorerViewModel.VisibleIncludedScopes.Count > 0;
        if (hasAnyGreenSelection)
        {
            if (_includedProcessKeys.Count == 0 && includedScopes.Count == 0)
            {
                return false;
            }

            if (_includedProcessKeys.Count > 0 && !_includedProcessKeys.Contains(process.ProcessKey))
            {
                return false;
            }

            foreach (var scopeGroup in includedScopes.GroupBy(GetScopedSelectionGroupKey))
            {
                if (!scopeGroup.Any(scope => DoesProcessMatchScope(process, scope)))
                {
                    return false;
                }
            }
        }

        if (_excludedProcessKeys.Contains(process.ProcessKey))
        {
            return false;
        }

        return !GetProcessListingExcludedScopes()
            .Any(scope => DoesProcessMatchScope(process, scope));
    }

    internal bool DoesProcessMatchScope(ProcessRowViewModel process, ExplorerScope scope)
    {
        if (!MatchesIdentityScope(process, scope))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(scope.ProcessKey) &&
            !IsProcessInSubtree(process.ProcessKey, scope.ProcessKey))
        {
            return false;
        }

        if (scope.Status.HasValue && process.ProcessInfo.Status != scope.Status.Value)
        {
            return false;
        }

        if (scope.ArtifactScope == ExplorerArtifactScope.Modules && process.ModuleCount <= 0)
        {
            return false;
        }

        if (scope.ArtifactScope == ExplorerArtifactScope.Handles && process.HandleCount <= 0)
        {
            return false;
        }

        if (scope.Kind == ExplorerScopeKind.Bookmarked && !IsProcessBookmarked(process.ProcessKey))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(scope.OwnerKey) &&
            !string.Equals(NormalizeProcessOwnerKey(process.UserName), scope.OwnerKey, StringComparison.Ordinal))
        {
            return false;
        }

        return scope.EventSource switch
        {
            "Runtime" => process.RuntimeEventCount > 0,
            "ETW" => process.EtwEventCount > 0,
            "Security" => process.SecurityEventCount > 0,
            "PowerShell" => process.PowerShellEventCount > 0,
            "WindowsOther" => process.OtherWindowsEventCount > 0,
            "Sysmon" => process.SysmonEventCount > 0,
            _ => true
        };
    }

    internal void UpdateDataTabCount(FeatureTabKey key, int count)
    {
        if (_dataTabSet.TryGet(key, out var descriptor))
        {
            descriptor?.UpdateCount(count);
        }
    }

    internal void RefreshDataTabCounts()
    {
        if (_featureModules.TryGetActivated<ModulesAndHandlesFeatureModule>(FeatureIds.ModulesAndHandles, out var artifacts))
        {
            UpdateDataTabCount(DataTabKeys.Modules, artifacts.ModulesViewModel.Modules.Count);
            UpdateDataTabCount(DataTabKeys.Handles, artifacts.HandlesViewModel.Handles.Count);
        }

        if (_featureModules.TryGetActivated<DumpsAndPeFeatureModule>(FeatureIds.DumpsAndPeAnalysis, out var dumpsAndPe))
        {
            UpdateDataTabCount(DataTabKeys.MemoryDumps, dumpsAndPe.MemoryDumpsViewModel.MemoryDumps.Count);
            UpdateDataTabCount(DataTabKeys.PeAnalysis, dumpsAndPe.PeAnalysisViewModel.PeAnalyses.Count);
        }

        if (_featureModules.TryGetActivated<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility, out var memory))
        {
            UpdateDataTabCount(DataTabKeys.SystemMemory, memory.MemoryImages.Count);
        }

        if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network))
        {
            UpdateDataTabCount(DataTabKeys.Network, network.ViewModel.NetworkCaptures.Count);
        }

        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem))
        {
            UpdateDataTabCount(DataTabKeys.Filesystem, filesystem.Artifacts.Count);
        }

        if (_featureModules.TryGetActivated<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry, out var events))
        {
            UpdateDataTabCount(DataTabKeys.SystemActivity, events.SystemActivityViewModel.VisibleActivityCount);
            UpdateDataTabCount(DataTabKeys.RuntimeEvents, events.RuntimeEventsViewModel.VisibleEventCount);
            UpdateDataTabCount(DataTabKeys.EtwEvents, events.EtwEventsViewModel.VisibleEventCount);
            UpdateDataTabCount(DataTabKeys.PowerShellEvents, events.PowerShellEventsViewModel.VisibleEventCount);
            UpdateDataTabCount(DataTabKeys.WindowsOtherEvents, events.OtherWindowsEventsViewModel.VisibleEventCount);
            UpdateDataTabCount(DataTabKeys.SysmonEvents, events.SysmonEventsViewModel.VisibleEventCount);
        }

        if (_featureModules.TryGetActivated<WindowsSecurityEventsFeatureModule>(
                FeatureIds.WindowsSecurityEvents,
                out var windowsSecurity))
        {
            UpdateDataTabCount(DataTabKeys.SecurityEvents, windowsSecurity.ViewModel.VisibleEventCount);
        }
    }

    internal ProcessRowViewModel? FindFallbackParent(ProcessRowViewModel child)
    {
        if (child.ProcessInfo.ParentProcessId <= 0)
        {
            return null;
        }

        return _processViewModels.Values
            .Where(parent => parent.ProcessId == child.ProcessInfo.ParentProcessId)
            .Where(parent => !string.Equals(parent.ProcessKey, child.ProcessKey, StringComparison.Ordinal))
            .Where(parent => HasSameEvidenceIdentity(child, parent))
            .Where(parent => IsPlausibleParentStart(child, parent))
            .OrderByDescending(parent => parent.ProcessInfo.StartTime ?? DateTime.MinValue)
            .FirstOrDefault();
    }

    internal static bool HasSameEvidenceIdentity(ProcessRowViewModel child, ProcessRowViewModel parent)
    {
        return string.Equals(child.ProcessInfo.CaseId, parent.ProcessInfo.CaseId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.EvidenceSessionId, parent.ProcessInfo.EvidenceSessionId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.CaptureId, parent.ProcessInfo.CaptureId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.SourceIdentityId, parent.ProcessInfo.SourceIdentityId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.HostId, parent.ProcessInfo.HostId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.ExecutionRootId, parent.ProcessInfo.ExecutionRootId, StringComparison.Ordinal);
    }

    internal static bool IsPlausibleParentStart(ProcessRowViewModel child, ProcessRowViewModel parent)
    {
        return child.ProcessInfo.StartTime == null ||
               parent.ProcessInfo.StartTime == null ||
               child.ProcessInfo.StartTime >= parent.ProcessInfo.StartTime;
    }

    internal static string NormalizeProcessOwnerKey(string? userName)
    {
        var trimmed = userName?.Trim();
        return IsUnknownProcessOwner(trimmed)
            ? UnknownProcessOwnerKey
            : trimmed!.ToLowerInvariant();
    }

    [RelayCommand(CanExecute = nameof(CanToggleSelectedProcessBookmark))]
    internal void ToggleSelectedProcessBookmark()
    {
        if (SelectedProcess == null || _annotationStore == null)
        {
            StatusMessage = "Select a staged process before changing bookmarks.";
            return;
        }

        var row = SelectedProcess;
        if (IsSelectedProcessBookmarked)
        {
            _annotationStore.DeleteBookmark(ProcessBookmarkKind, row.ProcessKey);
            IsSelectedProcessBookmarked = false;
            StatusMessage = $"Removed bookmark for {row.ProcessName} (PID {row.ProcessId}).";
        }
        else
        {
            var now = DateTime.UtcNow;
            var target = CreateProcessAnnotationTarget(row);
            var bookmark = new BookmarkRecord
            {
                BookmarkId = Guid.NewGuid().ToString("N"),
                TargetKind = target.TargetKind,
                TargetTable = target.TargetTable,
                TargetId = target.TargetId,
                ArtifactId = target.ArtifactId,
                CaseId = target.CaseId,
                EvidenceSessionId = target.EvidenceSessionId,
                CaptureId = target.CaptureId,
                SourceIdentityId = target.SourceIdentityId,
                HostId = target.HostId,
                ProcessKey = target.ProcessKey,
                ProcessId = target.ProcessId,
                ProcessName = target.ProcessName,
                Label = target.Label,
                DisplayPath = target.DisplayPath,
                CreatedUtc = now,
                UpdatedUtc = now
            };
            _annotationStore.UpsertBookmark(bookmark);
            IsSelectedProcessBookmarked = true;
            StatusMessage = $"Bookmarked {row.ProcessName} (PID {row.ProcessId}).";
        }

        _ = _services.RefreshExplorerCounts(
            ExplorerCountRefreshTrigger.AnnotationMutation);
        if (_activeExplorerScope.Kind == ExplorerScopeKind.Bookmarked)
        {
            ScheduleDbRefresh();
        }
    }

    internal bool CanToggleSelectedProcessBookmark()
    {
        return SelectedProcess != null &&
               _annotationStore != null &&
               !string.IsNullOrWhiteSpace(SelectedProcess.ProcessKey);
    }

    internal void UpdateSelectedProcessBookmarkState()
    {
        IsSelectedProcessBookmarked = SelectedProcess != null && IsProcessBookmarked(SelectedProcess.ProcessKey);
        ToggleSelectedProcessBookmarkCommand.NotifyCanExecuteChanged();
    }

    internal bool IsProcessBookmarked(string processKey)
    {
        if (_annotationStore == null || string.IsNullOrWhiteSpace(processKey))
        {
            return false;
        }

        try
        {
            return _annotationStore.IsBookmarked(ProcessBookmarkKind, processKey);
        }
        catch
        {
            return false;
        }
    }

    internal static AnnotationTarget CreateProcessAnnotationTarget(ProcessRowViewModel row)
    {
        var process = row.ProcessInfo;
        return new AnnotationTarget
        {
            TargetKind = ProcessBookmarkKind,
            TargetTable = "Processes",
            TargetId = row.ProcessKey,
            ProcessKey = row.ProcessKey,
            ProcessId = row.ProcessId,
            ProcessName = row.ProcessName,
            Label = $"{row.ProcessName} (PID {row.ProcessId})",
            DisplayPath = row.ProcessPath,
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId
        };
    }

    internal ProcessRowViewModel? FindVisibleProcessRow(TelemetrySearchResult result)
    {
        var candidates = _virtualizedProcessListing?.GetLoadedRows() ?? Processes;
        if (!string.IsNullOrWhiteSpace(result.ProcessEntityId))
            return SingleTarget(candidates.Where(process => string.Equals(process.ProcessInfo.ProcessEntityId,
                result.ProcessEntityId, StringComparison.Ordinal)));
        if (!string.IsNullOrWhiteSpace(result.ProcessKey))
            return SingleTarget(candidates.Where(process => process.ProcessKey == result.ProcessKey));
        if (_virtualizedProcessListing != null) return null;
        return SingleTarget(candidates.Where(process => process.ProcessId == result.ProcessId)
            .Where(process => string.IsNullOrWhiteSpace(result.ProcessName) ||
                string.Equals(process.ProcessName, result.ProcessName, StringComparison.OrdinalIgnoreCase)));
    }

    private static ProcessRowViewModel? SingleTarget(IEnumerable<ProcessRowViewModel> candidates)
    {
        var matches = candidates.Take(2).ToArray();
        return matches.Length == 1 ? matches[0] : null;
    }

    internal ProcessRowViewModel? AddSearchResultProcessRow(TelemetrySearchResult result)
    {
        var process = _telemetryProjectionService.GetProcessForSearchResult(result);
        if (process == null)
        {
            return null;
        }

        var processKey = process.GetUniqueKey();
        if (_processViewModels.TryGetValue(processKey, out var row) &&
            !string.Equals(row.ProcessInfo.ProcessEntityId, process.ProcessEntityId, StringComparison.Ordinal))
        {
            return null;
        }
        if (row == null)
        {
            row = new ProcessRowViewModel(process);
            UpdateProcessRowCounts(row, includeEventCounts: true);
            _processViewModels[processKey] = row;
        }

        if (!Processes.Contains(row))
        {
            Processes.Add(row);
            ProcessesView?.Refresh();
        }

        var stats = _telemetryProjectionService.GetStats();
        TotalProcessCount = stats.ProcessCount;
        RunningProcessCount = stats.RunningProcessCount;
        ExitedProcessCount = stats.ExitedProcessCount;
        return row;
    }

    internal void UpdateProcessRowCounts(
        ProcessRowViewModel row,
        bool includeEventCounts,
        IReadOnlyDictionary<string, ProcessSourceEventCounts>? eventCountsByProcess = null,
        IReadOnlyDictionary<string, int>? moduleCountsByProcess = null,
        IReadOnlyDictionary<string, int>? handleCountsByProcess = null)
    {
        UpdateProcessRowArtifactCounts(row, moduleCountsByProcess, handleCountsByProcess);

        if (includeEventCounts)
        {
            var counts = eventCountsByProcess != null && eventCountsByProcess.TryGetValue(row.ProcessKey, out var groupedCounts)
                ? groupedCounts
                : _telemetryProjectionService.GetEventCounts(row.ProcessKey, row.ProcessInfo.ProcessEntityId);

            row.RuntimeEventCount = counts.RuntimeEventCount;
            row.EtwEventCount = counts.EtwEventCount;
            row.SecurityEventCount = counts.SecurityEventCount;
            row.PowerShellEventCount = counts.PowerShellEventCount;
            row.OtherWindowsEventCount = counts.OtherWindowsEventCount;
            row.SysmonEventCount = counts.SysmonEventCount;
        }
    }

    internal void UpdateProcessRowArtifactCounts(
        ProcessRowViewModel row,
        IReadOnlyDictionary<string, int>? moduleCountsByProcess = null,
        IReadOnlyDictionary<string, int>? handleCountsByProcess = null)
    {
        var stagedModuleCount = moduleCountsByProcess != null && moduleCountsByProcess.TryGetValue(row.ProcessKey, out var moduleCount)
            ? moduleCount
            : _telemetryProjectionService.GetArtifactCounts(row.ProcessKey, row.ProcessInfo.ProcessEntityId).ModuleCount;
        var stagedHandleCount = handleCountsByProcess != null && handleCountsByProcess.TryGetValue(row.ProcessKey, out var handleCount)
            ? handleCount
            : _telemetryProjectionService.GetArtifactCounts(row.ProcessKey, row.ProcessInfo.ProcessEntityId).HandleCount;
        row.ModuleCount = stagedModuleCount > 0 ? stagedModuleCount : Math.Max(row.ProcessInfo.ModuleCount, row.ProcessInfo.CachedModules.Count);
        row.HandleCount = stagedHandleCount > 0 ? stagedHandleCount : Math.Max(row.ProcessInfo.HandleCount, row.ProcessInfo.CachedHandles.Count);
        row.ProcessInfo.ModuleCount = row.ModuleCount;
        row.ProcessInfo.HandleCount = row.HandleCount;
    }

    internal void UpdateSelectedProcessArtifactCounts()
    {
        if (SelectedProcess == null)
        {
            return;
        }

        SelectedProcess.ModuleCount = ModulesViewModel.Modules.Count;
        SelectedProcess.HandleCount = HandlesViewModel.Handles.Count;
        SelectedProcess.ProcessInfo.ModuleCount = SelectedProcess.ModuleCount;
        SelectedProcess.ProcessInfo.HandleCount = SelectedProcess.HandleCount;
        SelectedProcess.RefreshDisplay();
    }

    internal void RefreshSelectedProcessRow()
    {
        if (SelectedProcess == null)
        {
            return;
        }

        SelectedProcess.ModuleCount = Math.Max(SelectedProcess.ProcessInfo.ModuleCount, ModulesViewModel.Modules.Count);
        SelectedProcess.HandleCount = Math.Max(SelectedProcess.ProcessInfo.HandleCount, HandlesViewModel.Handles.Count);
        SelectedProcess.RefreshDisplay();
        ProcessPropertiesViewModel.LoadProcess(SelectedProcess);
    }

    internal bool TryGetVisibleProcessRow(string processKey, out ProcessRowViewModel row)
    {
        if (_processViewModels.TryGetValue(processKey, out row!))
        {
            return true;
        }

        row = Processes.FirstOrDefault(process =>
            string.Equals(process.ProcessKey, processKey, StringComparison.Ordinal))!;
        return row != null;
    }

    internal ViewerProcessViewportAnchor? CaptureProcessViewportAnchor()
    {
        var handlers = ProcessViewportAnchorCaptureRequested;
        if (handlers == null)
        {
            return null;
        }

        foreach (Func<ViewerProcessViewportAnchor?> handler in handlers.GetInvocationList())
        {
            try
            {
                var anchor = handler();
                if (anchor != null)
                {
                    return anchor;
                }
            }
            catch
            {
                // WPF virtualization may be between container generations. Logical
                // selection still survives; visual anchoring degrades gracefully.
            }
        }

        return null;
    }

    public void NotifyProcessViewportChanged()
    {
        MarkSnapshotPresentationInteraction();
    }

    internal void MarkSnapshotPresentationInteraction()
    {
        if (!_isPublishingSnapshotPresentation)
        {
            Interlocked.Increment(ref _snapshotPresentationInteractionGeneration);
        }
    }

    /// <summary>
    /// Sorts the currently visible process rows by a row view-model property.
    /// </summary>
    public void SortVisibleProcessRows(string columnName)
    {
        MarkSnapshotPresentationInteraction();
        if (_currentSortColumn == columnName)
        {
            _sortAscending = !_sortAscending;
        }
        else
        {
            _currentSortColumn = columnName;
            _sortAscending = true;
        }

        if (_processListingService != null)
        {
            // DB path: sort is pushed into the next SQLite query.
            ScheduleDbRefresh();
            return;
        }

        if (RequiresTreeAwareCompatibilityRebuild(columnName, hasProcessListingService: false))
        {
            UpdateProcessList(GetProjectedProcesses());
            return;
        }

        ProcessesView?.SortDescriptions.Clear();
        ProcessesView?.SortDescriptions.Add(new SortDescription(
            columnName,
            _sortAscending ? ListSortDirection.Ascending : ListSortDirection.Descending));
        ProcessesView?.Refresh();
    }

    internal static bool RequiresTreeAwareCompatibilityRebuild(
        string columnName,
        bool hasProcessListingService)
        => !hasProcessListingService &&
           string.Equals(columnName, "Tree", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Gets the current sort direction for a column (for UI indicators).
    /// </summary>
    public ListSortDirection? GetSortDirection(string columnName)
    {
        if (_currentSortColumn != columnName)
            return null;
        return _sortAscending ? ListSortDirection.Ascending : ListSortDirection.Descending;
    }

    // Partial methods for filter property changes
    // DB path: route through ScheduleDbRefresh (debounced, SQLite-backed).
    // Fallback path: ProcessesView.Refresh() applies the in-memory FilterProcess predicate.
    partial void OnFilterProcessNameChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterPidChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterParentPidChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterParentProcessNameChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterProcessPathChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterCommandLineChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterUserNameChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterSessionIdChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterArchitectureChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterStartTimeChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterEndTimeChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterStatusChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterCpuUsageChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterMemoryUsageChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterCompanyNameChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterFileDescriptionChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterSha256HashChanged(string value) => ScheduleDbRefresh();

    /// <summary>
    /// Handles selection change - updates detail tabs.
    /// </summary>
    partial void OnSelectedProcessChanged(ProcessRowViewModel? oldValue, ProcessRowViewModel? newValue)
    {
        MarkSnapshotPresentationInteraction();
        _virtualizedProcessListing?.PreserveSelection(newValue);
        _selectionChangedWhileSuspended |= _readsSuspended;
        var fanOut = _selectedProcessFanOutCoordinator.SelectAsync(
            newValue,
            _services.CaptureGeneration());
        if (!fanOut.IsCompletedSuccessfully)
        {
            _ = ObserveSelectedProcessFanOutAsync(fanOut);
        }

        UpdateSelectedProcessBookmarkState();
        IncludeSelectedProcessCommand.NotifyCanExecuteChanged();
        ExcludeSelectedProcessCommand.NotifyCanExecuteChanged();
        _services.SelectionChanged(this);


        if (newValue != null && !_readsSuspended)
        {
            _services.QueueSelectedDataEnrichment(this);
        }

        RefreshDataTabCounts();
    }

    internal async Task ObserveSelectedProcessFanOutAsync(
        Task<SelectedProcessFanOutResult> fanOut)
    {
        try
        {
            await fanOut;
        }
        catch (Exception ex)
        {
            StatusMessage = $"Selected-process detail fan-out failed unexpectedly: {ex.Message}";
        }
    }

    internal void OnSelectedProcessFanOutStateChanged(
        object? sender,
        SelectedProcessFanOutStateChangedEventArgs e)
    {
        if (e.State.LastOutcome == SelectedProcessFanOutOutcome.PartialFailure &&
            !string.IsNullOrWhiteSpace(e.State.LastError))
        {
            StatusMessage = $"Selected-process details loaded with partial failures: {e.State.LastError}";
        }

        if (e.State.Phase is SelectedProcessFanOutPhase.Active or SelectedProcessFanOutPhase.Empty)
        {
            RefreshDataTabCounts();
        }
    }

    internal void OnFeatureModuleActivated(object? sender, FeatureActivatedEventArgs e)
    {
        var lateBinding = _selectedProcessFanOutCoordinator.BindActivatedConsumersAsync(e.FeatureId);
        if (!lateBinding.IsCompletedSuccessfully)
        {
            _ = ObserveSelectedProcessFanOutAsync(lateBinding);
        }
    }

    IReadOnlyList<ISelectedProcessFanOutConsumer>
        ISelectedProcessFanOutConsumerProvider.GetCoreConsumers()
    {
        var queryService = _sqliteStagingQueryService;
        var consumers = new List<ISelectedProcessFanOutConsumer>
        {
            CreateSelectedProcessConsumer(
                "process-properties",
                (context, cancellationToken) =>
                {
                    var provenance = context == null || queryService == null
                        ? null
                        : queryService.GetProcessProjectionProvenance(
                            context.ProcessEntityId);
                    cancellationToken.ThrowIfCancellationRequested();
                    ProcessPropertiesViewModel.LoadProcess(context?.Row, provenance);
                }),
            CreateSelectedProcessConsumer(
                "process-statistics",
                (context, _) => ProcessStatisticsViewModel.SetSelectedProcess(context?.Row)),
            CreateSelectedProcessConsumer(
                "application-info",
                (context, cancellationToken) =>
                    ProcessDescriptionViewModel.LoadForProcessSelectionAsync(
                        context?.Row,
                        cancellationToken)),
            CreateSelectedProcessConsumer(
                "process-notes",
                (context, cancellationToken) =>
                    NotesViewModel.LoadNotesForSelectionAsync(
                        context == null ? null : CreateProcessAnnotationTarget(context.Row),
                        cancellationToken)),
            CreateSelectedProcessConsumer(
                "details-object-inspector-clear",
                (_, _) => InspectorPaneViewModel.Clear(
                    "Select a row in Data to inspect its additional properties."))
        };

        var riskDetails = ProcessRiskDetailsViewModel;
        if (riskDetails != null)
        {
            consumers.Add(CreateSelectedProcessConsumer(
                "process-risk-details",
                (context, cancellationToken) =>
                    riskDetails.LoadAsync(
                        queryService?.ProcessRiskProjectionQueries,
                        context?.ProcessEntityId ?? string.Empty,
                        context?.ProcessKey ?? string.Empty,
                        context == null
                            ? string.Empty
                            : $"{context.ProcessName} (PID {context.ProcessId})",
                        cancellationToken)));
        }

        return CaptureConsumerReads(consumers);
    }

    IReadOnlyList<ISelectedProcessFanOutConsumer>
        ISelectedProcessFanOutConsumerProvider.GetActivatedOptionalConsumers() =>
        GetActivatedSelectedProcessConsumers(featureId: null);

    IReadOnlyList<ISelectedProcessFanOutConsumer>
        ISelectedProcessFanOutConsumerProvider.GetActivatedOptionalConsumers(
            FeatureId featureId) =>
        GetActivatedSelectedProcessConsumers(featureId);

    internal IReadOnlyList<ISelectedProcessFanOutConsumer> GetActivatedSelectedProcessConsumers(
        FeatureId? featureId)
    {
        var consumers = new List<ISelectedProcessFanOutConsumer>();
        if ((!featureId.HasValue || featureId.Value == FeatureIds.ModulesAndHandles) &&
            _featureModules.TryGetActivated<ModulesAndHandlesFeatureModule>(
                FeatureIds.ModulesAndHandles,
                out var artifacts))
        {
            consumers.Add(CreateSelectedProcessConsumer(
                "modules",
                async (context, cancellationToken) =>
                {
                    if (context == null)
                    {
                        artifacts.ModulesViewModel.Clear();
                        return;
                    }

                    await artifacts.ModulesViewModel.LoadModulesForProcessAsync(context.Row.ProcessInfo);
                    cancellationToken.ThrowIfCancellationRequested();
                }));
            consumers.Add(CreateSelectedProcessConsumer(
                "handles",
                async (context, cancellationToken) =>
                {
                    if (context == null)
                    {
                        artifacts.HandlesViewModel.Clear();
                        return;
                    }

                    await artifacts.HandlesViewModel.LoadHandlesForProcessAsync(context.Row.ProcessInfo);
                    cancellationToken.ThrowIfCancellationRequested();
                }));
        }

        if ((!featureId.HasValue || featureId.Value == FeatureIds.DumpsAndPeAnalysis) &&
            _featureModules.TryGetActivated<DumpsAndPeFeatureModule>(
                FeatureIds.DumpsAndPeAnalysis,
                out var dumpsAndPe))
        {
            consumers.Add(CreateSelectedProcessConsumer(
                "memory-dumps",
                (context, _) =>
                {
                    if (context == null)
                    {
                        dumpsAndPe.MemoryDumpsViewModel.Clear();
                        return;
                    }

                    dumpsAndPe.MemoryDumpsViewModel.SetSelectedProcessEntityId(context.ProcessEntityId);
                    dumpsAndPe.MemoryDumpsViewModel.LoadMemoryDumpsForProcess(
                        (context.ProcessKey, context.ProcessId, context.ProcessName));
                }));
            consumers.Add(CreateSelectedProcessConsumer(
                "pe-analysis",
                (context, _) =>
                {
                    if (context == null)
                    {
                        dumpsAndPe.PeAnalysisViewModel.Clear();
                        return;
                    }

                    dumpsAndPe.PeAnalysisViewModel.SetSelectedProcessEntityId(context.ProcessEntityId);
                    dumpsAndPe.PeAnalysisViewModel.LoadPeAnalysesForProcess(
                        (context.ProcessKey, context.ProcessId, context.ProcessName));
                }));
        }

        if ((!featureId.HasValue || featureId.Value == FeatureIds.AiAssistance) &&
            _featureModules.TryGetActivated<AiFeatureModule>(
                FeatureIds.AiAssistance,
                out var ai))
        {
            consumers.Add(CreateSelectedProcessConsumer(
                "ai-details-context",
                (context, _) => ai.DetailsViewModel.SetSelectedProcessContext(context?.Row)));
            consumers.Add(CreateSelectedProcessConsumer(
                "ai-investigation",
                (context, cancellationToken) =>
                    ai.InvestigationViewModel.LoadForProcessSelectionAsync(
                        context?.Row,
                        cancellationToken)));
        }

        if ((!featureId.HasValue || featureId.Value == FeatureIds.EventTelemetry) &&
            _featureModules.TryGetActivated<EventTelemetryFeatureModule>(
                FeatureIds.EventTelemetry,
                out var events))
        {
            AddSelectedProcessEventConsumer(consumers, "runtime-events", events.RuntimeEventsViewModel);
            AddSelectedProcessEventConsumer(consumers, "etw-events", events.EtwEventsViewModel);
            AddSelectedProcessEventConsumer(consumers, "powershell-events", events.PowerShellEventsViewModel);
            AddSelectedProcessEventConsumer(consumers, "windows-other-events", events.OtherWindowsEventsViewModel);
            AddSelectedProcessEventConsumer(consumers, "sysmon-events", events.SysmonEventsViewModel);
        }


        if ((!featureId.HasValue || featureId.Value == FeatureIds.WindowsSecurityEvents) &&
            _featureModules.TryGetActivated<WindowsSecurityEventsFeatureModule>(
                FeatureIds.WindowsSecurityEvents,
                out var windowsSecurity))
        {
            AddSelectedProcessEventConsumer(consumers, "security-events", windowsSecurity.ViewModel);
        }

        RegistrationContext.AddConsumers(featureId, consumers);

        return CaptureConsumerReads(consumers);
    }

    private IReadOnlyList<ISelectedProcessFanOutConsumer> CaptureConsumerReads(IEnumerable<ISelectedProcessFanOutConsumer> consumers)
        => consumers.Select(consumer => (ISelectedProcessFanOutConsumer)new DelegateSelectedProcessFanOutConsumer(consumer.Key, async (context, token) =>
        {
            using var readScope = _telemetryProjectionService.BeginReadScope();
            return await consumer.ApplyAsync(context, token);
        })).ToArray();

    internal static void AddSelectedProcessEventConsumer(
        ICollection<ISelectedProcessFanOutConsumer> consumers,
        string key,
        EventsViewModel viewModel)
    {
        consumers.Add(CreateSelectedProcessConsumer(
            key,
            (context, _) =>
            {
                if (context == null)
                {
                    viewModel.Clear();
                    return;
                }

                viewModel.SetSelectedProcessEntityId(context.ProcessEntityId);
                viewModel.LoadEventsForProcess(
                    (context.ProcessKey, context.ProcessId, context.ProcessName));
            }));
    }

    internal static ISelectedProcessFanOutConsumer CreateSelectedProcessConsumer(
        string key,
        Action<SelectedProcessContext?, CancellationToken> apply) =>
        new DelegateSelectedProcessFanOutConsumer(
            key,
            (context, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                apply(context, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                return Task.FromResult(SelectedProcessConsumerResult.Success);
            });

    internal static ISelectedProcessFanOutConsumer CreateSelectedProcessConsumer(
        string key,
        Func<SelectedProcessContext?, CancellationToken, Task> apply) =>
        new DelegateSelectedProcessFanOutConsumer(
            key,
            async (context, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                await apply(context, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                return SelectedProcessConsumerResult.Success;
            });

    partial void OnSelectedDataTabChanged(FeatureTabDescriptor? value)
    {
        if (_isApplyingViewerNavigationState)
        {
            return;
        }

        MarkSnapshotPresentationInteraction();
        var result = _viewerNavigationCoordinator.AcceptDataSelection(value);
        if (result.Succeeded)
        {
            _services.QueueSelectedDataEnrichment(this);
        }
    }

    partial void OnSelectedExplorerTabChanged(FeatureTabDescriptor? value)
    {
        if (_isApplyingViewerNavigationState)
        {
            return;
        }

        MarkSnapshotPresentationInteraction();
        _viewerNavigationCoordinator.AcceptExplorerSelection(value);
    }

    partial void OnSelectedDetailsTabKeyChanged(ViewerDetailsTabKey value) =>
        MarkSnapshotPresentationInteraction();

    // ── DB-backed process grid helpers (Phase 3F / 3G) ────────────────────────

    internal const int VirtualProcessPageSize = 128;
    internal const int VirtualProcessCachePages = 6;

    /// <summary>
    /// Schedules a DB-backed grid refresh, debounced to 300 ms so rapid filter
    /// keystrokes do not trigger a SQLite query on every character.
    /// Invalidates the active virtual collection so filter changes return to the
    /// first page of a new query generation.
    /// Leaves the viewer unchanged when no SQLite projection is active.
    /// </summary>
    internal void ScheduleDbRefresh()
    {
        CloseHeaderFilters();
        MarkSnapshotPresentationInteraction();
        _listingWorkflow.Schedule();
    }

    internal Task ExecuteDbRefreshAsync(IProgress<ProcessListingLoadProgress>? progress = null)
        => _listingWorkflow.RefreshAsync(progress);

    internal ProcessListingQuery BuildCurrentListingQuery()
    {
        var filters = BuildFilterSet();
        ApplyExplorerScope(filters);

        if (!HasGreenIncludedSelection() &&
            HasExplorerSelectionWithoutProcessListingScope(filters.SelectedScopes))
        {
            filters.IncludedProcessKeys = [NoProcessScopedSelectionKey];
        }

        return new ProcessListingQuery
        {
            Filters = filters,
            Sort = new ProcessListingSortDescriptor
            {
                Column = MapSortColumn(_currentSortColumn),
                Direction = _sortAscending
                    ? ProcessListingSortDirection.Ascending
                    : ProcessListingSortDirection.Descending
            },
            Offset = 0,
            PageSize = VirtualProcessPageSize,
            IncludeTotalCount = false
        };
    }

    internal void ApplyExplorerScope(ProcessListingFilterSet filters)
    {
        if (!HasGreenIncludedSelection())
        {
            filters.SelectedScopes = GetProcessListingSelectedScopes();
            filters.SelectedDirectChildScopes = GetSelectedDirectChildScopes();
        }
    }

    internal bool HasExplorerSelectionWithoutProcessListingScope(IReadOnlyCollection<ExplorerScope> selectedScopes)
    {
        return ExplorerViewModel.SelectedNode is { IsPlaceholder: false } &&
               selectedScopes.Count == 0 &&
               ExplorerViewModel.SelectedNode.Scope.ProcessKey is null or "";
    }

    internal static bool UsesProcessListingScope(ExplorerScope scope)
    {
        return scope.Kind switch
        {
            ExplorerScopeKind.FilesystemRoot or
            ExplorerScopeKind.FilesystemEvidenceRoots or
            ExplorerScopeKind.FilesystemArtifacts or
            ExplorerScopeKind.FilesystemFolder or
            ExplorerScopeKind.NetworkRoot or
            ExplorerScopeKind.NetworkCaptures or
            ExplorerScopeKind.NetworkCapture or
            ExplorerScopeKind.ZeekArtifacts or
            ExplorerScopeKind.AnalysisRoot or
            ExplorerScopeKind.SearchResults or
            ExplorerScopeKind.SigmaFindings or
            ExplorerScopeKind.CorrelationEvidence or
            ExplorerScopeKind.UnresolvedEvidence or
            ExplorerScopeKind.AmbiguousEvidence or
            ExplorerScopeKind.CorrelationEvidenceGroup or
            ExplorerScopeKind.ArtifactRoot or
            ExplorerScopeKind.MemoryDumps or
            ExplorerScopeKind.SystemActivityRoot or
            ExplorerScopeKind.ActivityAuthentication or
            ExplorerScopeKind.ActivitySuccessfulLogons or
            ExplorerScopeKind.ActivityFailedLogons or
            ExplorerScopeKind.ActivityRemoteInteractive or
            ExplorerScopeKind.ActivityExplicitCredentialUse or
            ExplorerScopeKind.ActivityPrivilegedLogons or
            ExplorerScopeKind.ActivityAccounts or
            ExplorerScopeKind.ActivityCreatedUsers or
            ExplorerScopeKind.ActivityDisabledDeletedUsers or
            ExplorerScopeKind.ActivityPasswordChanges or
            ExplorerScopeKind.ActivityGroups or
            ExplorerScopeKind.ActivityLocalAdministratorsChanges or
            ExplorerScopeKind.ActivitySecurityGroupMembershipChanges or
            ExplorerScopeKind.ActivityPolicyAudit or
            ExplorerScopeKind.ActivityAuditPolicyChanged or
            ExplorerScopeKind.ActivityLogIntegrity or
            ExplorerScopeKind.ActivitySecurityLogCleared or
            ExplorerScopeKind.ActivityServicesTasks or
            ExplorerScopeKind.ActivityServicesInstalled or
            ExplorerScopeKind.ActivityScheduledTasksChanged or
            ExplorerScopeKind.UsersRoot or
            ExplorerScopeKind.UserAccount => false,
            _ => true
        };
    }

    internal static bool CanScopeFilterProcessListing(ExplorerScope scope)
    {
        return IsSelectableExplorerScope(scope) &&
               (UsesProcessListingScope(scope) || CanAccountScopeFilterProcessListing(scope));
    }

    internal static bool CanAccountScopeFilterProcessListing(ExplorerScope scope)
    {
        return !string.IsNullOrWhiteSpace(scope.OwnerKey) &&
               scope.Kind is ExplorerScopeKind.UserAccount or
                   ExplorerScopeKind.ActivityAuthentication or
                   ExplorerScopeKind.ActivitySuccessfulLogons or
                   ExplorerScopeKind.ActivityFailedLogons or
                   ExplorerScopeKind.ActivityRemoteInteractive or
                   ExplorerScopeKind.ActivityExplicitCredentialUse or
                   ExplorerScopeKind.ActivityPrivilegedLogons or
                   ExplorerScopeKind.ActivityAccounts or
                   ExplorerScopeKind.ActivityCreatedUsers or
                   ExplorerScopeKind.ActivityDisabledDeletedUsers or
                   ExplorerScopeKind.ActivityPasswordChanges or
                   ExplorerScopeKind.ActivityGroups or
                   ExplorerScopeKind.ActivityLocalAdministratorsChanges or
                   ExplorerScopeKind.ActivitySecurityGroupMembershipChanges or
                   ExplorerScopeKind.ActivityPolicyAudit or
                   ExplorerScopeKind.ActivityAuditPolicyChanged or
                   ExplorerScopeKind.ActivityLogIntegrity or
                   ExplorerScopeKind.ActivitySecurityLogCleared or
                   ExplorerScopeKind.ActivityServicesTasks or
                   ExplorerScopeKind.ActivityServicesInstalled or
                   ExplorerScopeKind.ActivityScheduledTasksChanged;
    }

    internal bool MatchesIdentityScope(ProcessRowViewModel process, ExplorerScope scope)
    {
        return MatchesIdentityValue(process.ProcessInfo.CaseId, scope.CaseId) &&
               MatchesIdentityValue(process.ProcessInfo.EvidenceSessionId, scope.EvidenceSessionId) &&
               MatchesIdentityValue(process.ProcessInfo.CaptureId, scope.CaptureId) &&
               MatchesIdentityValue(process.ProcessInfo.SourceIdentityId, scope.SourceIdentityId) &&
               MatchesIdentityValue(process.ProcessInfo.HostId, scope.HostId) &&
               MatchesIdentityValue(process.ProcessInfo.ExecutionRootId, scope.ExecutionRootId);
    }

    internal static bool MatchesIdentityValue(string actual, string? expected)
    {
        return string.IsNullOrWhiteSpace(expected) ||
               string.Equals(actual, expected, StringComparison.Ordinal);
    }

    internal bool IsProcessInSubtree(string processKey, string rootProcessKey)
    {
        if (string.IsNullOrWhiteSpace(processKey) || string.IsNullOrWhiteSpace(rootProcessKey))
        {
            return false;
        }

        var currentKey = processKey;
        var visited = new HashSet<string>(StringComparer.Ordinal);
        while (!string.IsNullOrWhiteSpace(currentKey) && visited.Add(currentKey))
        {
            if (string.Equals(currentKey, rootProcessKey, StringComparison.Ordinal))
            {
                return true;
            }

            if (!_processViewModels.TryGetValue(currentKey, out var row))
            {
                return false;
            }

            currentKey = !string.IsNullOrWhiteSpace(row.ProcessInfo.ParentProcessKey)
                ? row.ProcessInfo.ParentProcessKey
                : FindFallbackParent(row)?.ProcessKey ?? string.Empty;
        }

        return false;
    }

    internal ProcessListingFilterSet BuildFilterSet()
    {
        var includedScopes = GetProcessListingIncludedScopes();
        var excludedScopes = GetProcessListingExcludedScopes();
        var includedProcessKeys = _includedProcessKeys.ToList();
        if ((_includedScopes.Count > 0 || _includedProcessKeys.Count > 0) &&
            includedScopes.Count == 0 &&
            includedProcessKeys.Count == 0)
        {
            includedProcessKeys.Add(NoProcessScopedSelectionKey);
        }

        var f = new ProcessListingFilterSet
        {
            ColumnFilters = GetAppliedHeaderFilters(),
            ProcessNameContains    = NullIfEmpty(FilterProcessName),
            ProcessIdContains      = NullIfEmpty(FilterPid),
            ParentProcessIdContains = NullIfEmpty(FilterParentPid),
            ParentProcessNameContains = NullIfEmpty(FilterParentProcessName),
            ProcessPathContains    = NullIfEmpty(FilterProcessPath),
            CommandLineContains    = NullIfEmpty(FilterCommandLine),
            UserNameContains       = NullIfEmpty(FilterUserName),
            ArchitectureContains   = NullIfEmpty(FilterArchitecture),
            CompanyNameContains    = NullIfEmpty(FilterCompanyName),
            FileDescriptionContains = NullIfEmpty(FilterFileDescription),
            Sha256HashContains     = NullIfEmpty(FilterSha256Hash),
            StatusContains         = NullIfEmpty(FilterStatus),
            IncludedScopes         = includedScopes,
            ExcludedScopes         = excludedScopes,
            IncludedProcessKeys    = includedProcessKeys,
            ExcludedProcessKeys    = _excludedProcessKeys.ToList(),
            SelectedScopes         = GetProcessListingSelectedScopes()
        };

        if (int.TryParse(FilterSessionId, out var sid))
            f.SessionIdEquals = sid;

        return f;

        static string? NullIfEmpty(string s) =>
            ColumnTextFilter.Normalize(s);
    }

    internal List<ExplorerScope> GetProcessListingIncludedScopes()
    {
        // A selected whole category already covers its children. Combining inherited
        // status/annotation/branch families again would accidentally narrow that scope.
        var covered = ExplorerViewModel.RootNodes.SelectMany(FlattenExplorerNode)
            .Where(node => node.Scope.StableId is "branch:Process Status" or "branch:Execution Roots" &&
                node.IsGreenIncludedDirectly)
            .SelectMany(node => node.Children.SelectMany(FlattenExplorerNode))
            .Select(node => node.Scope.StableId).ToHashSet(StringComparer.Ordinal);
        return _includedScopes.Values
            .Concat(ExplorerViewModel.VisibleIncludedScopes)
            .Where(scope => !covered.Contains(scope.StableId))
            .GroupBy(scope => scope.StableId, StringComparer.Ordinal)
            .Select(group => group.First())
            .Where(CanScopeFilterProcessListing)
            .ToList();
    }

    internal List<ExplorerScope> GetProcessListingSelectedScopes()
    {
        return HasGreenIncludedSelection()
            ? []
            : ExplorerViewModel.SelectedNodeAndLoadedDescendantScopes
                .Where(scope => string.IsNullOrWhiteSpace(scope.ProcessKey))
                .Where(CanScopeFilterProcessListing)
                .ToList();
    }

    internal List<ExplorerScope> GetSelectedDirectChildScopes()
    {
        return HasGreenIncludedSelection()
            ? []
            : ExplorerViewModel.SelectedScopes
                .Where(scope => !string.IsNullOrWhiteSpace(scope.ProcessKey))
                .ToList();
    }

    internal bool HasGreenIncludedSelection()
    {
        return _includedProcessKeys.Count > 0 ||
               _includedScopes.Count > 0 ||
               ExplorerViewModel.VisibleIncludedScopes.Count > 0;
    }

    internal static string GetScopedSelectionGroupKey(ExplorerScope scope)
    {
        if (scope.Status.HasValue)
        {
            return "status";
        }

        if (!string.IsNullOrWhiteSpace(scope.OwnerKey))
        {
            return "owner";
        }

        if (!string.IsNullOrWhiteSpace(scope.ProcessKey))
        {
            return "process-tree";
        }

        if (scope.ArtifactScope != ExplorerArtifactScope.None)
        {
            return "artifact";
        }

        if (!string.IsNullOrWhiteSpace(scope.EventSource))
        {
            return "event-source";
        }

        if (scope.Kind == ExplorerScopeKind.Bookmarked)
        {
            return "annotation";
        }

        if (!string.IsNullOrWhiteSpace(scope.CaseId) ||
            !string.IsNullOrWhiteSpace(scope.EvidenceSessionId) ||
            !string.IsNullOrWhiteSpace(scope.CaptureId) ||
            !string.IsNullOrWhiteSpace(scope.SourceIdentityId) ||
            !string.IsNullOrWhiteSpace(scope.HostId) ||
            !string.IsNullOrWhiteSpace(scope.ExecutionRootId))
        {
            return "identity";
        }

        return scope.Kind.ToString();
    }

    internal List<ExplorerScope> GetProcessListingExcludedScopes()
    {
        return _excludedScopes.Values
            .Concat(ExplorerViewModel.VisibleExcludedScopes)
            .GroupBy(scope => scope.StableId, StringComparer.Ordinal)
            .Select(group => group.First())
            .Where(CanScopeFilterProcessListing)
            .ToList();
    }

    internal static ProcessListingSortColumn MapSortColumn(string column) => column switch
    {
        "Tree"              => ProcessListingSortColumn.Tree,
        "ProcessName"       => ProcessListingSortColumn.ProcessName,
        "ProcessId"         => ProcessListingSortColumn.ProcessId,
        "ParentProcessId"   => ProcessListingSortColumn.ParentProcessId,
        "ParentProcessName" => ProcessListingSortColumn.ParentProcessName,
        "ProcessPath"       => ProcessListingSortColumn.ProcessPath,
        "CommandLine"       => ProcessListingSortColumn.CommandLine,
        "UserName"          => ProcessListingSortColumn.UserName,
        "SessionId"         => ProcessListingSortColumn.SessionId,
        "Architecture"      => ProcessListingSortColumn.Architecture,
        "StartTime" or "StartTimeDisplay" => ProcessListingSortColumn.StartTime,
        "EndTime" or "EndTimeDisplay" => ProcessListingSortColumn.EndTime,
        "Status" or "StatusDisplay" => ProcessListingSortColumn.Status,
        "CpuUsage"          => ProcessListingSortColumn.CpuUsage,
        "TotalProcessorTimeTicks" => ProcessListingSortColumn.TotalProcessorTime,
        "ReadBytes"         => ProcessListingSortColumn.ReadBytes,
        "WrittenBytes"      => ProcessListingSortColumn.WrittenBytes,
        "MemoryUsage" or "MemoryUsageBytes" => ProcessListingSortColumn.MemoryUsage,
        "ModuleCount"       => ProcessListingSortColumn.ModuleCount,
        "HandleCount"       => ProcessListingSortColumn.HandleCount,
        "RuntimeEventCount" => ProcessListingSortColumn.RuntimeEventCount,
        "EtwEventCount"     => ProcessListingSortColumn.EtwEventCount,
        "SecurityEventCount" => ProcessListingSortColumn.SecurityEventCount,
        "PowerShellEventCount" => ProcessListingSortColumn.PowerShellEventCount,
        "OtherWindowsEventCount" => ProcessListingSortColumn.OtherWindowsEventCount,
        "SysmonEventCount"  => ProcessListingSortColumn.SysmonEventCount,
        "CompanyName"       => ProcessListingSortColumn.CompanyName,
        "FileDescription"   => ProcessListingSortColumn.FileDescription,
        "Sha256Hash"        => ProcessListingSortColumn.Sha256Hash,
        "RiskScore"         => ProcessListingSortColumn.ProcessRisk,
        _ => throw new ArgumentOutOfRangeException(
            nameof(column),
            column,
            "The process Listing column does not have a typed database sort mapping.")
    };

    public void RequestProcessListingRange(int firstIndex, int itemCount = 1)
        => _virtualizedProcessListing?.RequestRange(firstIndex, itemCount);

    internal void AttachVirtualizedProcessListing(
        VirtualizedProcessCollection collection,
        ProcessRowViewModel? selectedRow,
        bool navigateToSelection = true)
    {
        var previous = DetachVirtualizedProcessListing();
        _virtualizedProcessListing = collection;
        collection.CacheChanged += OnVirtualizedProcessListingChanged;
        Processes = new ObservableCollection<ProcessRowViewModel>();
        ProcessesView = CollectionViewSource.GetDefaultView(collection);
        TotalProcessCount = collection.Count;
        SelectedProcess = selectedRow;
        collection.PreserveSelection(selectedRow);
        OnVirtualizedProcessListingChanged(collection, EventArgs.Empty);
        if (selectedRow != null && navigateToSelection)
        {
            ProcessesView?.MoveCurrentTo(selectedRow);
            ProcessRowNavigationRequested?.Invoke(selectedRow);
        }

        if (!ReferenceEquals(previous, _publicationState?.Collection)) previous?.Dispose();
    }

    internal VirtualizedProcessCollection? DetachVirtualizedProcessListing()
    {
        var previous = _virtualizedProcessListing;
        if (previous != null)
        {
            previous.CacheChanged -= OnVirtualizedProcessListingChanged;
            _virtualizedProcessListing = null;
        }

        return previous;
    }

    internal void OnVirtualizedProcessListingChanged(object? sender, EventArgs e)
    {
        if (sender is not VirtualizedProcessCollection collection ||
            !ReferenceEquals(collection, _virtualizedProcessListing))
        {
            return;
        }

        var loadedRows = collection.GetLoadedRows();
        _processViewModels.Clear();
        foreach (var row in loadedRows)
        {
            _processViewModels[row.ProcessKey] = row;
        }

        TotalProcessCount = collection.Count;
        RunningProcessCount = loadedRows.Count(row => !row.IsExited);
        ExitedProcessCount = loadedRows.Count(row => row.IsExited);
        IsProcessListingLoading = collection.IsLoading;
        ProcessListingStatus = collection.StatusMessage;
    }

    internal const string UnknownProcessOwnerKey = "unknown";

    internal static bool IsUnknownProcessOwner(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ||
               string.Equals(value, "<not available>", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(value, "<access denied>", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(value, "<unknown>", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(value, "unknown", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(value, "n/a", StringComparison.OrdinalIgnoreCase);
    }

    long IProcessListingRuntime.CaptureGeneration => _services.CaptureGeneration();
    ProcessListingService? IProcessListingRuntime.ListingService => _processListingService;
    ProcessListingQuery IProcessListingRuntime.BuildQuery() => BuildCurrentListingQuery();
    string? IProcessListingRuntime.SelectedProcessKey => SelectedProcess?.ProcessKey;
    string? IProcessListingRuntime.SelectedProcessEntityId => SelectedProcess?.ProcessInfo.ProcessEntityId;
    void IProcessListingRuntime.Publish(VirtualizedProcessCollection collection, ProcessRowViewModel? selectedRow) => AttachVirtualizedProcessListing(collection, selectedRow);
    void IProcessListingRuntime.ReportError(string message)
    {
        ProcessListingStatus = "Listing error: " + message;
        StatusMessage = "Process grid refresh error: " + message;
    }
}
