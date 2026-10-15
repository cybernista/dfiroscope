using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text.Json;
using System.Windows.Data;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Features.PersistenceWorkspace;
using ProcInsider.Models;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Models.Persistence;
using ProcInsider.Services;
using ProcInsider.Services.Ai;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed record PersistenceScopeChoice(EvidenceIdentity Scope)
{
    public string Display => $"Host {Scope.HostId} · Capture {Scope.CaptureId} · Source {Scope.SourceIdentityId}";
}

internal sealed class PersistenceWorkspaceViewModel : WorkspaceInstanceViewModel
{
    private readonly PersistenceWorkspaceReadSession _session;
    private readonly PersistenceWorkspaceActionService? _actions;
    private readonly Func<WorkspaceInstanceViewModel, ProcessConversationViewModel>? _createObjectConversation;
    private ProcessConversationViewModel? _objectConversation;
    private PersistenceObjectReference? _exactObject;
    public bool IsAiAvailable => _createObjectConversation != null;
    public ProcessConversationViewModel? ObjectConversationViewModel
    {
        get
        {
            if (_createObjectConversation == null || IsDisposed) return null;
            if (_objectConversation == null)
            {
                _objectConversation = _createObjectConversation(this);
                _objectConversation.SelectObject(SelectedRow is { } row ? EvidenceObjectAgentTools.PersistenceContext(row) : null);
            }
            return _objectConversation;
        }
    }
    public IAsyncRelayCommand<PersistenceWorkspaceRow> ReviewRecordCommand { get; }
    public IAsyncRelayCommand<PersistenceWorkspaceRow> ChatAboutCommand { get; }
    public IAsyncRelayCommand<PersistenceWorkspaceRow> FindRelatedActivityCommand { get; }
    private int _detailsTabIndex;
    public int DetailsTabIndex { get => _detailsTabIndex; set => SetProperty(ref _detailsTabIndex, value); }
    private readonly Func<Task<bool>> _confirmRebaseline;
    private CancellationTokenSource _actionRequest = new();
    private Guid? _job;
    private ProcInsider.Services.AgentIpc.ViewerAgentCaptureActionTarget? _actionTarget;
    private EvidenceIdentity? _actionScope;
    private WorkspaceContext? _actionContext;
    private long _actionRevision;
    private bool _collecting;
    private Guid? _completedJob;
    private EvidenceIdentity? _completedScope;
    private string? _completedBaselinePeriod;
    private long _completedRevision = -1;
    private bool _completedJobSucceeded;
    private ProcInsider.Services.AgentIpc.ViewerAgentCaptureActionTarget? _completedTarget;
    private readonly HashSet<(EvidenceIdentity Scope, string Period)> _closedActionPeriods = [];
    private const string NeutralActionStatus = "Collection is Agent-owned; view refresh does not examine Windows.";
    private string _actionStatus = NeutralActionStatus;
    private CancellationTokenSource _request = new(), _detail = new();
    private CancellationTokenSource _historyRequest = new();
    private long _historyGeneration, _historyMatching;
    private readonly HashSet<Task> _work = [];
    private bool _suspended, _loaded, _busy, _projectingScopes;
    private long _generation, _selectionGeneration, _historyOffset, _matching;
    private PersistenceView _view;
    private sealed class ViewState
    {
        internal string? Category;
        internal long Offset;
        internal PersistenceColumn Sort = PersistenceColumn.Name;
        internal bool Descending;
        internal List<PersistenceSelector> Selectors { get; } = [];
        internal IReadOnlyDictionary<string, ColumnFilterViewModel> Filters { get; set; } = null!;
    }
    private readonly Dictionary<(EvidenceIdentity? Scope, string? Period, PersistenceView View), ViewState> _views = [];
    private string? _periodId;
    private bool _periodActive;
    private long _periodRevision = -1;
    internal string? PeriodId => _periodId;
    internal void ObservePeriods(EvidenceIdentity scope, IReadOnlyList<PersistencePeriod> periods, long revision)
    {
        if (SelectedScope?.Scope != scope || revision != _session.Revision) return;
        _periodActive = periods.FirstOrDefault(period => period.PeriodId == PeriodId)?.Active == true;
        _periodRevision = revision; NotifyActions();
    }
    private ViewState ActiveView => State(SelectedScope?.Scope, PeriodId, View);
    private ViewState State(EvidenceIdentity? scope, string? period, PersistenceView view)
    {
        var key = (scope, period, view);
        if (_views.TryGetValue(key, out var state)) return state;
        state = new ViewState(); _views.Add(key, state);
        state.Filters = Enum.GetValues<PersistenceColumn>().ToDictionary(c => c.ToString(), c => new ColumnFilterViewModel(c.ToString(), c.ToString().EndsWith("Utc", StringComparison.Ordinal) ? ColumnFilterKind.Timestamp : ColumnFilterKind.Values,
            (search, sort, token) => ListingChoicesAsync(scope, period, view, c, search, sort, token),
            () => { state.Offset = 0; if (SelectedScope?.Scope == scope && PeriodId == period && View == view) Changed(); else Refreshed?.Invoke(); }));
        return state;
    }
    private long _offset { get => ActiveView.Offset; set => ActiveView.Offset = value; }
    private string? _category { get => ActiveView.Category; set => ActiveView.Category = value; }
    private string _status = "No assessed Persistence read binding.";
    private PersistenceScopeChoice? _scope;
    private PersistenceWorkspaceRow? _selected, _historySelected;
    private PropertyItemViewModel? _propertySelected;
    private string? _retainedSelection;
    private PersistenceObjectReference? _retainedObject;
    private PersistenceWorkspacePage? _page;
    internal IReadOnlyList<PersistenceSelector> Selectors => _views.Values.SelectMany(state => state.Selectors).ToArray();
    internal bool ReadsSuspended => _suspended || _session.Suspended;
    internal event Action? InvestigationChanged;
    internal event Action? Refreshed;
    public ObservableCollection<PersistenceScopeChoice> Scopes { get; } = [];
    public ObservableCollection<PersistenceWorkspaceRow> Rows { get; } = [];
    public ObservableCollection<PersistenceWorkspaceRow> History { get; } = [];
    public ObservableCollection<PropertyItemViewModel> NativeProperties { get; } = [];
    public InspectorPaneViewModel InspectorPaneViewModel { get; } = new();
    public ICollectionView PropertiesView { get; }
    public ICollectionView HistoryView { get; }
    public IReadOnlyDictionary<string, ColumnFilterViewModel> HeaderFilters => ActiveView.Filters;
    public IReadOnlyDictionary<string, ColumnFilterViewModel> PropertyFilters { get; }
    public IReadOnlyDictionary<string, ColumnFilterViewModel> HistoryFilters { get; }
    public PersistenceColumn Sort { get => ActiveView.Sort; set => ActiveView.Sort = value; }
    public bool Descending { get => ActiveView.Descending; set => ActiveView.Descending = value; }
    public ListSortDirection PropertySortDirection { get; set; } = ListSortDirection.Ascending;
    public string PropertySort { get; set; } = "Name";
    internal void ApplyPropertySort()
    {
        using (PropertiesView.DeferRefresh())
        {
            PropertiesView.SortDescriptions.Clear(); PropertiesView.SortDescriptions.Add(new(PropertySort, PropertySortDirection));
        }
    }
    public ListSortDirection HistorySortDirection { get; set; } = ListSortDirection.Descending;
    public string HistorySort { get; set; } = "ObservedUtc";
    public string Status { get => _status; private set { SetProperty(ref _status, value); OnPropertyChanged(nameof(StatusHeadline)); } }
    public string StatusHeadline => !Status.StartsWith($"{(_page?.MatchingRows ?? MatchingRows):N0} matching records.", StringComparison.Ordinal) ? Status : _page == null ?
        "Retained Persistence read; full status and coverage diagnostics below." :
        $"{_page.MatchingRows:N0} matching records. Declared coverage: {string.Join(", ", _page.Coverage.Select(item => $"{item.Result.Status}/{item.Result.Coverage.SourceAvailability}").Distinct(StringComparer.Ordinal))}. Full recorded diagnostics below.";
    public bool IsBusy { get => _busy; private set => SetProperty(ref _busy, value); }
    public long MatchingRows { get => _matching; private set => SetProperty(ref _matching, value); }
    public long MatchingHistory { get => _historyMatching; private set => SetProperty(ref _historyMatching, value); }
    public PersistenceView View { get => _view; set { if (_view != value) { SwitchView(value); NavigationDescription = value.ToString(); Changed(false); } } }
    public bool IsCurrent => View == PersistenceView.Current;
    public bool IsChanges => !IsCurrent;
    public Array Views => Enum.GetValues<PersistenceView>();
    public PersistenceScopeChoice? SelectedScope { get => _scope; set { if (SetProperty(ref _scope, value) && !_projectingScopes) { _periodId = null; _periodActive = false; ClearScopeSelection(); Changed(); NotifyActions(); } } }
    internal void SelectPeriod(EvidenceIdentity scope, string? periodId)
    {
        _exactObject = null;
        if (SelectedScope?.Scope == scope && PeriodId == periodId) return;
        foreach (var filter in HeaderFilters.Values) filter.Close();
        _scope = Scopes.FirstOrDefault(choice => choice.Scope == scope) ?? new(scope);
        _periodId = periodId; _periodActive = false;
        ClearScopeSelection(); OnPropertyChanged(nameof(SelectedScope)); OnPropertyChanged(nameof(HeaderFilters));
        _loaded = false; NotifyActions();
    }
    public PersistenceWorkspaceRow? SelectedRow { get => _selected; set { if (value != null && (IsDisposed || ReadsSuspended || value.Scope != SelectedScope?.Scope || !Rows.Contains(value))) return; if (SetProperty(ref _selected, value)) { _objectConversation?.SelectObject(value is { } row ? EvidenceObjectAgentTools.PersistenceContext(row) : null); _selectionGeneration++; _ = LoadDetailsAsync(value); } } }
    public PersistenceWorkspaceRow? SelectedHistory { get => _historySelected; set { if (IsDisposed || ReadsSuspended || value != null && (value.Scope != SelectedScope?.Scope || !History.Contains(value))) return; if (SetProperty(ref _historySelected, value)) { if (value != null) { PopulateProperties(value, value.Version?.Before, value.Version?.After); InspectorPaneViewModel.Load(Payload(value, NativeProperties.ToArray())); } else InspectorPaneViewModel.Clear("Select a row inside Data to inspect its recorded values."); } } }
    public PropertyItemViewModel? SelectedProperty { get => _propertySelected; set { if (IsDisposed || ReadsSuspended || value != null && !NativeProperties.Contains(value)) return; if (SetProperty(ref _propertySelected, value)) { if (value == null || SelectedRow == null) InspectorPaneViewModel.Clear("Select a Data row to inspect its exact recorded values."); else InspectorPaneViewModel.Load(Payload(SelectedHistory ?? SelectedRow, [value])); } } }
    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand NextCommand { get; }
    public IAsyncRelayCommand PreviousCommand { get; }
    public IAsyncRelayCommand NextHistoryCommand { get; }
    public IAsyncRelayCommand PreviousHistoryCommand { get; }
    public IRelayCommand CancelCommand { get; }
    public IRelayCommand ClearFiltersCommand { get; }
    public IRelayCommand ClearPropertiesCommand { get; }
    public IRelayCommand ClearHistoryCommand { get; }
    public IAsyncRelayCommand CollectCommand { get; }
    public IAsyncRelayCommand RebaselineCommand { get; }
    public IAsyncRelayCommand CancelCollectionCommand { get; }
    public string ActionStatus { get => _actionStatus; private set => SetProperty(ref _actionStatus, value); }
    internal PersistenceWorkspacePage? Page => _page;
    internal PersistenceWorkspaceViewModel(WorkspaceTypeMetadata type, int ordinal, PersistenceWorkspaceReadSession session,
        PersistenceWorkspaceActionService? actions = null, Func<Task<bool>>? confirmRebaseline = null,
        Func<WorkspaceInstanceViewModel, ProcessConversationViewModel>? createObjectConversation = null) : base(type, ordinal)
    {
        _session = session; NavigationDescription = "Current";
        _actions = actions;
        _createObjectConversation = createObjectConversation;
        ReviewRecordCommand = new AsyncRelayCommand<PersistenceWorkspaceRow>(row => RunObjectActionAsync(row, ProcessConversationAction.ReviewRecord), CanRunObjectAction);
        ChatAboutCommand = new AsyncRelayCommand<PersistenceWorkspaceRow>(row => RunObjectActionAsync(row, ProcessConversationAction.ChatAbout), CanRunObjectAction);
        FindRelatedActivityCommand = new AsyncRelayCommand<PersistenceWorkspaceRow>(row => RunObjectActionAsync(row, ProcessConversationAction.FindRelatedActivity), CanRunObjectAction);
        _confirmRebaseline = confirmRebaseline ?? (() => Task.FromResult(System.Windows.MessageBox.Show("A baseline snapshot closes the current period with one final differential and seeds a new baseline from that accepted inventory. Prior evidence is retained. Continue?", "Baseline snapshot", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question) == System.Windows.MessageBoxResult.Yes));
        CollectCommand = new AsyncRelayCommand(() => CollectAsync(false), CanCollect);
        RebaselineCommand = new AsyncRelayCommand(() => CollectAsync(true), CanCollect);
        CancelCollectionCommand = new AsyncRelayCommand(CancelCollectionAsync, CanCancelCollection);
        PropertiesView = new ListCollectionView(NativeProperties);
        PropertyFilters = new[] { "Group", "Name", "Value" }.ToDictionary(c => c, c => new ColumnFilterViewModel(c, ColumnFilterKind.Values,
            (search, sort, token) => { token.ThrowIfCancellationRequested(); return Task.FromResult(ColumnFilterValuePage.FromValues(NativeProperties.Where(row => PropertyFilters!.Where(f => f.Key != c).All(f => f.Value.Criteria.Matches(PropertyValue(row, f.Key)))).Select(row => PropertyValue(row, c)).Where(value => ColumnTextFilter.Matches(value, search)), sort)); }, () => PropertiesView.Refresh()));
        PropertiesView.Filter = row => row is PropertyItemViewModel property && PropertyFilters.All(f => f.Value.Criteria.Matches(PropertyValue(property, f.Key)));
        PropertiesView.SortDescriptions.Add(new(PropertySort, PropertySortDirection));
        HistoryView = new ListCollectionView(History);
        HistoryFilters = new[] { "ObservedUtc", "Change", "Type", "Name", "Location", "TargetCommand", "Principal", "Generation" }.ToDictionary(c => c, c => new ColumnFilterViewModel(c, c == "ObservedUtc" ? ColumnFilterKind.Timestamp : ColumnFilterKind.Values,
            (search, sort, token) => HistoryChoicesAsync(c, search, sort, token), () => { _historyOffset = 0; _ = LoadHistoryAsync(); }));
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        NextCommand = new AsyncRelayCommand(() => { if (_offset + 128 < MatchingRows) _offset += 128; return RefreshAsync(); });
        PreviousCommand = new AsyncRelayCommand(() => { _offset = Math.Max(0, _offset - 128); return RefreshAsync(); });
        NextHistoryCommand = new AsyncRelayCommand(() => { if (_historyOffset + 128 < MatchingHistory) _historyOffset += 128; return LoadHistoryAsync(); });
        PreviousHistoryCommand = new AsyncRelayCommand(() => { _historyOffset = Math.Max(0, _historyOffset - 128); return LoadHistoryAsync(); });
        CancelCommand = new RelayCommand(() => { _request.Cancel(); _detail.Cancel(); _historyRequest.Cancel(); });
        ClearFiltersCommand = new RelayCommand(() => { foreach (var filter in HeaderFilters.Values) filter.Reset(false); Changed(); });
        ClearPropertiesCommand = new RelayCommand(() => { foreach (var filter in PropertyFilters.Values) filter.Reset(false); PropertiesView.Refresh(); });
        ClearHistoryCommand = new RelayCommand(() => { foreach (var filter in HistoryFilters.Values) filter.Reset(false); _historyOffset = 0; _ = LoadHistoryAsync(); });
    }
    private static string PropertyValue(PropertyItemViewModel row, string column) => column switch { "Group" => row.Group, "Name" => row.Name, "Value" => row.Value, _ => throw new ArgumentOutOfRangeException(nameof(column)) };
    private static string? HistoryValue(PersistenceWorkspaceRow row, string column) => column switch { "ObservedUtc" => row.ObservedUtc.ToString("O"), "Change" => row.Change, "Type" => row.Type, "Name" => row.Name, "Location" => row.Location, "TargetCommand" => row.TargetCommand, "Principal" => row.Principal, "Generation" => row.Generation, _ => throw new ArgumentOutOfRangeException(nameof(column)) };
    internal PersistenceWorkspaceQuery? CaptureQuery() => CaptureQuery(View);
    internal PersistenceWorkspaceQuery? CaptureQuery(PersistenceView view)
        => SelectedScope == null ? null : CaptureQuery(SelectedScope.Scope, PeriodId, view);
    internal PersistenceWorkspaceQuery CaptureQuery(EvidenceIdentity scope, string? period, PersistenceView view)
    {
        var state = State(scope, period, view);
        return new(scope, view, state.Category, state.Selectors.ToArray(), state.Filters.Where(f => f.Value.IsActive).Select(f => new PersistenceColumnFilter(Enum.Parse<PersistenceColumn>(f.Key), f.Value.Criteria)).ToArray(), state.Sort, state.Descending, state.Offset, PeriodId: period,
            ExactObject: view == PersistenceView.Changes ? _exactObject : null);
    }
    internal bool MatchesQuery(PersistenceWorkspaceQuery query) => JsonSerializer.Serialize(query) == JsonSerializer.Serialize(CaptureQuery());
    private void Changed() => Changed(true);
    private void Changed(bool resetOffset) { _exactObject = null; _loaded = false; if (resetOffset) _offset = 0; OnPropertyChanged(nameof(IsCurrent)); OnPropertyChanged(nameof(IsChanges)); InvestigationChanged?.Invoke(); if (!ReadsSuspended && Context != null) _ = RefreshAsync(); }
    private void SwitchView(PersistenceView view)
    {
        if (!Enum.IsDefined(view)) throw new ArgumentOutOfRangeException(nameof(view));
        if (_view != view) foreach (var filter in HeaderFilters.Values) filter.Close();
        _view = view;
        OnPropertyChanged(nameof(View)); OnPropertyChanged(nameof(HeaderFilters)); OnPropertyChanged(nameof(Sort)); OnPropertyChanged(nameof(Descending));
    }
    internal void Navigate(PersistenceView view, string? category) { if (_loaded && View == view && _category == category) return; SwitchView(view); _category = category; NavigationDescription = category == null ? view.ToString() : $"{view}: {category}"; Changed(); }
    internal void Toggle(PersistenceSelector selector, bool excluded = false)
    {
        if (selector.Scope != null) SelectPeriod(selector.Scope, selector.PeriodId);
        SwitchView(selector.View ?? View);
        var selectors = ActiveView.Selectors;
        var exact = selector with { View = View, Excluded = excluded, Scope = SelectedScope?.Scope, PeriodId = PeriodId }; var existing = selectors.FindIndex(s => s.View == exact.View && s.Category == exact.Category);
        _category = null;
        NavigationDescription = "Green Persistence selection";
        OnPropertyChanged(nameof(View));
        if (existing < 0 && selector.Category != null && !excluded && selectors.Any(s => !s.Excluded && s.Category == null))
            exact = exact with { Excluded = true };
        if (existing >= 0) { if (selectors[existing] == exact) selectors.RemoveAt(existing); else selectors[existing] = exact; } else selectors.Add(exact);
        if (selector.Category == null) selectors.RemoveAll(s => s != exact && s.Category != null);
        Changed();
    }
    internal Task LoadAsync() => _loaded ? Task.CompletedTask : RefreshAsync();
    internal Task RefreshAsync()
    {
        if (IsDisposed || ReadsSuspended) return Task.CompletedTask;
        _retainedSelection = SelectedRow?.Identity ?? _retainedSelection;
        _retainedObject = SelectedRow == null ? _retainedObject : Reference(SelectedRow);
        _request.Cancel(); _request.Dispose(); _request = new();
        var token = _request.Token; var generation = ++_generation; var revision = _session.Revision; var context = Context;
        return Track(RunAsync());
        async Task RunAsync()
        {
            IsBusy = true; Status = "Loading assessed Persistence evidence…";
            try
            {
                var scopes = await _session.ScopesAsync(token);
                if (!Current()) return;
                var oldScope = SelectedScope?.Scope;
                _projectingScopes = true;
                try
                {
                    // Preserve WPF selector containers and choice identities when a snapshot
                    // retains the same scope directory. Internal projection is not navigation.
                    foreach (var removed in Scopes.Where(choice => !scopes.Contains(choice.Scope)).ToArray()) Scopes.Remove(removed);
                    foreach (var scope in scopes.Where(scope => !Scopes.Any(choice => choice.Scope == scope))) Scopes.Add(new(scope));
                    _scope = Scopes.FirstOrDefault(s => s.Scope == oldScope) ?? (Scopes.Count == 1 ? Scopes[0] : null);
                    if (_scope?.Scope != oldScope) { _periodId = null; _periodActive = false; ClearScopeSelection(); }
                    OnPropertyChanged(nameof(SelectedScope));
                }
                finally { _projectingScopes = false; }
                if (SelectedScope is { } selectedScope)
                {
                    var periods = await _session.AllPeriodsAsync(selectedScope.Scope, token);
                    if (!Current()) return;
                    // Only a new, unscoped investigation follows the latest period.
                    if (_periodId == null) _periodId = periods.FirstOrDefault()?.PeriodId;
                    ObservePeriods(selectedScope.Scope, periods, revision);
                    OnPropertyChanged(nameof(HeaderFilters));
                }
                var query = CaptureQuery();
                if (query == null)
                {
                    Rows.Clear(); ClearDetails(); MatchingRows = 0; _page = Scopes.Count == 0 ? new([], 0, new Dictionary<string, long> { ["Run"] = 0, ["RunOnce"] = 0, ["ScheduledTasks"] = 0, ["Services"] = 0, ["Drivers"] = 0, ["Startup"] = 0, ["WMI"] = 0, ["Winlogon"] = 0, ["IFEO"] = 0, ["AppInit"] = 0, ["LSA"] = 0 }, new Dictionary<PersistenceView, long> { [PersistenceView.Current] = 0, [PersistenceView.Changes] = 0 }, [], "No accepted collection yet.") : null;
                    Status = Scopes.Count == 0 ? "No accepted collection yet." : "Select a recorded host/source context; scopes are never merged.";
                }
                else
                {
                    if (!_collecting && _completedJob is { } pendingJob && _completedScope == query.Scope && _completedTarget is { } pendingTarget && _actions != null)
                    {
                        var outcome = await _actions.StatusAsync(pendingTarget, pendingJob, query.Scope, token);
                        if (!Current()) return;
                        ObserveActionOutcome(pendingJob, query.Scope, outcome);
                        ActionStatus = outcome.Response?.Job is { } jobStatus
                            ? $"Persistence snapshot job {jobStatus.State}; committed evidence must be assessed before another snapshot action."
                            : "Persistence snapshot outcome unavailable: " + outcome.Diagnostic;
                    }
                    var page = await _session.QueryAsync(query, token);
                    if (!Current() || query.Scope != SelectedScope?.Scope || query.View != View) return;
                    Apply(page);
                    if (_completedJobSucceeded && _completedJob is { } completedJob && _completedScope == query.Scope && revision > _completedRevision && _periodActive &&
                        (_completedBaselinePeriod == null || PeriodId != _completedBaselinePeriod) &&
                        await _session.IsJobAcceptedAsync(query.Scope, completedJob, token))
                    {
                        if (!Current()) return;
                        _completedJob = null;
                    }
                }
                _loaded = true; Refreshed?.Invoke();
                NotifyActions();
            }
            catch (OperationCanceledException) { if (Current()) Status = "Persistence read cancelled; retained rows belong to the previous accepted read."; }
            catch (Exception error) { if (Current()) { _page = null; Status = "Persistence unavailable: " + error.Message; Refreshed?.Invoke(); } }
            finally { if (generation == _generation) IsBusy = false; }
            bool Current() => !IsDisposed && !ReadsSuspended && !token.IsCancellationRequested && generation == _generation && revision == _session.Revision && context == Context;
        }
    }
    private bool CanCollect() => !_collecting && !_completedJob.HasValue && !IsDisposed && !ReadsSuspended && Context != null && _periodActive && _periodRevision == _session.Revision && SelectedScope is { } choice &&
        (PeriodId == null || !_closedActionPeriods.Contains((choice.Scope, PeriodId))) && _actions?.CanCollect(choice.Scope) == true;
    private bool CanCancelCollection() => _job.HasValue && _actionScope != null && _actionScope == SelectedScope?.Scope &&
        _actionContext == Context && _actionRevision == _session.Revision && !_actionRequest.IsCancellationRequested &&
        !IsDisposed && !ReadsSuspended && _actions?.Available == true && _actionTarget == _actions.CaptureTarget();
    internal void NotifyActions() { CollectCommand.NotifyCanExecuteChanged(); RebaselineCommand.NotifyCanExecuteChanged(); CancelCollectionCommand.NotifyCanExecuteChanged(); }
    private void ObserveActionOutcome(Guid jobId, EvidenceIdentity scope, ProcInsider.Services.AgentIpc.ViewerAgentCaptureActionResult outcome)
    {
        if (_completedJob != jobId || _completedScope != scope || outcome.Outcome is not (ProcInsider.Services.AgentIpc.ViewerAgentCaptureActionOutcome.Succeeded or
            ProcInsider.Services.AgentIpc.ViewerAgentCaptureActionOutcome.JobFailed or ProcInsider.Services.AgentIpc.ViewerAgentCaptureActionOutcome.JobCanceled)) return;
        var job = outcome.Job?.JobId == jobId ? outcome.Job : outcome.Jobs.SingleOrDefault(item => item.JobId == jobId);
        if (job == null) return;
        if (job.State is ProcInsider.Models.Agent.JobState.Failed or ProcInsider.Models.Agent.JobState.Cancelled)
        {
            _completedJob = null; _completedJobSucceeded = false;
        }
        else if (job.State == ProcInsider.Models.Agent.JobState.Completed)
        {
            _completedJobSucceeded = true;
            if (_completedBaselinePeriod is { } closedPeriod) _closedActionPeriods.Add((scope, closedPeriod));
        }
    }
    private Task CollectAsync(bool rebaseline)
    {
        if (!CanCollect()) return Task.CompletedTask;
        var scope = SelectedScope!.Scope; var context = Context; var revision = _session.Revision; var actionPeriod = PeriodId;
        var target = _actions!.CaptureTarget(); if (target == null) return Task.CompletedTask;
        _actionRequest.Cancel(); _actionRequest.Dispose(); _actionRequest = new(); var token = _actionRequest.Token;
        return Track(RunAsync());
        async Task RunAsync()
        {
            _collecting = true; NotifyActions();
            try
            {
                if (rebaseline && !await _confirmRebaseline()) return;
                if (!Current()) return;
                var submitted = await _actions!.SubmitAsync(target, scope, rebaseline ? "Analyst requested an on-demand persistence baseline snapshot; close the current period and preserve prior evidence." : null, token);
                var job = submitted.Succeeded ? ProcInsider.Models.Agent.AgentIpcResponseJobProjection.GetAcceptedJobs(submitted.Response!).SingleOrDefault() : null;
                if (job != null && context == Context && !IsDisposed)
                {
                    // Admission survives presentation cancellation. Only terminal Agent state
                    // and an assessed exact-job read can resolve the pending evidence fence.
                    _completedJob = job.JobId; _completedScope = scope; _completedRevision = revision;
                    _completedTarget = target; _completedJobSucceeded = false; _completedBaselinePeriod = rebaseline ? actionPeriod : null;
                }
                if (!Current()) return;
                ActionStatus = submitted.Diagnostic;
                if (!submitted.Succeeded) return;
                if (job == null) { ActionStatus = "The Agent accepted no exact finite collection job; durable completion is unverified."; return; }
                _job = job.JobId; _actionTarget = target; _actionScope = scope; _actionContext = context; _actionRevision = revision; NotifyActions();
                var completed = await _actions.WaitAsync(target, job.JobId, scope, token);
                ObserveActionOutcome(job.JobId, scope, completed);
                if (Current())
                {
                    ActionStatus = completed.Succeeded ? "Persistence collection durably completed. Use Refresh from DB to view accepted evidence before another snapshot action." : completed.Diagnostic;
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception error) { if (Current()) ActionStatus = "Persistence action unavailable: " + error.Message; }
            finally { if (context == Context && SelectedScope?.Scope == scope && _actions?.CaptureTarget() != target) ActionStatus = NeutralActionStatus; _job = null; _actionTarget = null; _actionScope = null; _actionContext = null; _collecting = false; NotifyActions(); }
            bool Current() => !IsDisposed && !ReadsSuspended && !token.IsCancellationRequested && context == Context && revision == _session.Revision && SelectedScope?.Scope == scope && _actions?.CaptureTarget() == target;
        }
    }
    private Task CancelCollectionAsync()
    {
        if (!CanCancelCollection()) return Task.CompletedTask;
        var job = _job!.Value; var target = _actionTarget!; var scope = _actionScope!; var context = _actionContext; var revision = _actionRevision; var token = _actionRequest.Token;
        return Track(RunAsync());
        async Task RunAsync()
        {
            try
            {
                var result = await _actions!.CancelAsync(target, job, scope, token);
                if (!IsDisposed && !ReadsSuspended && !token.IsCancellationRequested && context == Context && revision == _session.Revision && SelectedScope?.Scope == scope && _actions.CaptureTarget() == target) ActionStatus = result.Diagnostic;
            }
            catch (OperationCanceledException) { }
        }
    }
    internal void Apply(PersistenceWorkspacePage page)
    {
        // Prepared snapshot publication also enters here, before Refresh captures selection.
        _retainedSelection = SelectedRow?.Identity ?? _retainedSelection;
        _retainedObject = SelectedRow == null ? _retainedObject : Reference(SelectedRow);
        _page = page; MatchingRows = page.MatchingRows; Rows.Clear(); foreach (var row in page.Rows) Rows.Add(row);
        var selected = Rows.FirstOrDefault(row => row.Identity == _retainedSelection || View == PersistenceView.Current && _retainedObject is { } retained && row.Scope == retained.Scope && row.PartitionKey == retained.PartitionKey && row.ArtifactKey == retained.ArtifactKey);
        _detail.Cancel(); _selectionGeneration++; _selected = selected;
        _objectConversation?.SelectObject(selected is { } current ? EvidenceObjectAgentTools.PersistenceContext(current) : null);
        ClearDetails();
        if (selected != null && !ReadsSuspended) _ = LoadDetailsAsync(selected);
        OnPropertyChanged(nameof(SelectedRow));
        var coverage = string.Join("; ", page.Coverage.Select(c => $"{c.Result.CollectorId} / {c.Result.Coverage.PartitionId}: {c.Result.Status}, {c.Result.Coverage.SourceAvailability}. {c.Result.DiagnosticSummary}"));
        Status = $"{MatchingRows:N0} matching records. {page.Diagnostic} {coverage}";
    }
    private Task LoadDetailsAsync(PersistenceWorkspaceRow? row)
    {
        _detail.Cancel(); _detail.Dispose(); _detail = new(); var token = _detail.Token;
        ClearDetails(); if (row == null || row.Scope != SelectedScope?.Scope || IsDisposed || ReadsSuspended) return Task.CompletedTask;
        _historyOffset = 0; var generation = _selectionGeneration; var revision = _session.Revision; var context = Context;
        return Track(RunAsync());
        async Task RunAsync()
        {
            try
            {
                var reference = Reference(row); var detail = await _session.DetailAsync(reference, token);
                if (IsDisposed || ReadsSuspended || token.IsCancellationRequested || row.Scope != SelectedScope?.Scope || generation != _selectionGeneration || revision != _session.Revision || context != Context || !ReferenceEquals(row, SelectedRow)) return;
                PopulateProperties(row, detail.Before, detail.After); await LoadHistoryAsync();
            }
            catch (OperationCanceledException) { }
            catch (Exception error) { if (!token.IsCancellationRequested && generation == _selectionGeneration) Status = "Persistence details unavailable: " + error.Message; }
        }
    }
    private void ClearScopeSelection()
    {
        _actionRequest.Cancel(); ActionStatus = NeutralActionStatus;
        _detail.Cancel(); _historyRequest.Cancel(); _selectionGeneration++; _historyGeneration++;
        foreach (var filter in _views.Values.SelectMany(state => state.Filters.Values).Concat(PropertyFilters.Values).Concat(HistoryFilters.Values)) filter.Close();
        _selected = null; _objectConversation?.SelectObject(null); _retainedSelection = null; _retainedObject = null; Rows.Clear(); _page = null; ClearDetails(); OnPropertyChanged(nameof(SelectedRow));
    }
    private async Task<ColumnFilterValuePage> ListingChoicesAsync(EvidenceIdentity? scope, string? period, PersistenceView view, PersistenceColumn column, string? search, ColumnFilterValueSort sort, CancellationToken token)
    {
        var query = CaptureQuery(view); if (query == null || scope != SelectedScope?.Scope || period != PeriodId || View != view || IsDisposed || ReadsSuspended) return new([], false);
        var generation = _generation; var revision = _session.Revision;
        var values = await _session.ValuesAsync(query, column, search, sort, token);
        if (generation != _generation || revision != _session.Revision || !MatchesQuery(query) || IsDisposed || ReadsSuspended) throw new OperationCanceledException(token);
        return values;
    }
    private PersistenceHistoryQuery? CaptureHistoryQuery() => SelectedRow == null || SelectedRow.Scope != SelectedScope?.Scope ? null : new(Reference(SelectedRow), HistoryFilters.Where(f => f.Value.IsActive).Select(f => new PersistenceColumnFilter(Enum.Parse<PersistenceColumn>(f.Key), f.Value.Criteria)).ToArray(), Enum.Parse<PersistenceColumn>(HistorySort), HistorySortDirection == ListSortDirection.Descending, _historyOffset);
    private async Task<ColumnFilterValuePage> HistoryChoicesAsync(string column, string? search, ColumnFilterValueSort sort, CancellationToken token)
    {
        var query = CaptureHistoryQuery(); if (query == null || ReadsSuspended || IsDisposed) return new([], false);
        var generation = _historyGeneration; var selection = _selectionGeneration; var revision = _session.Revision;
        var values = await _session.HistoryValuesAsync(query, Enum.Parse<PersistenceColumn>(column), search, sort, token);
        if (generation != _historyGeneration || selection != _selectionGeneration || revision != _session.Revision || IsDisposed || ReadsSuspended) throw new OperationCanceledException(token);
        return values;
    }
    internal Task SortHistoryAsync(string column, ListSortDirection direction) { HistorySort = column; HistorySortDirection = direction; _historyOffset = 0; return LoadHistoryAsync(); }
    private Task LoadHistoryAsync()
    {
        var query = CaptureHistoryQuery(); if (query == null || ReadsSuspended || IsDisposed) return Task.CompletedTask;
        _historyRequest.Cancel(); _historyRequest.Dispose(); _historyRequest = new(); var token = _historyRequest.Token;
        var revision = _session.Revision; var selection = _selectionGeneration; var generation = ++_historyGeneration; var context = Context;
        return Track(RunAsync());
        async Task RunAsync()
        {
            try
            {
                var page = await _session.HistoryAsync(query, token);
                if (token.IsCancellationRequested || revision != _session.Revision || selection != _selectionGeneration || generation != _historyGeneration || context != Context || IsDisposed || ReadsSuspended) return;
                History.Clear(); foreach (var item in page.Rows) History.Add(item); MatchingHistory = page.MatchingRows;
            }
            catch (OperationCanceledException) { }
            catch (Exception error) { if (!token.IsCancellationRequested && generation == _historyGeneration && !IsDisposed) Status = "Persistence history unavailable: " + error.Message; }
        }
    }
    private PersistenceObjectReference Reference(PersistenceWorkspaceRow row) => new(row.Scope, row.PartitionKey, row.ArtifactKey, row.Collection.CollectionId, PeriodId);
    private void ClearDetails() { _historyRequest.Cancel(); _historyGeneration++; NativeProperties.Clear(); History.Clear(); MatchingHistory = 0; _propertySelected = null; _historySelected = null; OnPropertyChanged(nameof(SelectedProperty)); OnPropertyChanged(nameof(SelectedHistory)); InspectorPaneViewModel.Clear("Select a row inside Data to inspect its recorded values."); }
    private void PopulateProperties(PersistenceWorkspaceRow row, PersistenceArtifact? before, PersistenceArtifact? after)
    {
        NativeProperties.Clear();
        void Add(string group, string name, object? value) => NativeProperties.Add(new(group, name, value?.ToString() ?? "Unknown / not recorded"));
        Add("Observation", "Started UTC", row.Collection.StartedUtc.ToString("O")); Add("Observation", "Completed UTC", row.Collection.CompletedUtc.ToString("O"));
        Add("Observation", "First observed UTC", row.FirstObservedUtc?.ToString("O")); Add("Observation", "Last changed observed UTC", row.LastChangedUtc?.ToString("O")); Add("Observation", "Last confirmed UTC", row.LastConfirmedUtc?.ToString("O"));
        Add("Continuity", "Generation", row.Generation); Add("Continuity", "Reason", row.Collection.Reason); Add("Continuity", "Reset explanation", row.Collection.ResetReason); Add("Continuity", "Freshness", row.Freshness);
        Add("Provenance", "Collection", row.Collection.CollectionId); Add("Provenance", "Source run", row.Collection.SourceRunId); Add("Provenance", "Job", row.Collection.IngestionJobId);
        Add("Scope", "Case", row.Scope.CaseId); Add("Scope", "Session", row.Scope.EvidenceSessionId); Add("Scope", "Capture", row.Scope.CaptureId); Add("Scope", "Source", row.Scope.SourceIdentityId); Add("Scope", "Host", row.Scope.HostId); Add("Scope", "Execution root", row.Scope.ExecutionRootId);
        Add("Coverage", "Partition", row.Artifact.Coverage.PartitionId); Add("Coverage", "User SID", row.Artifact.Coverage.UserSid); Add("Coverage", "Registry view", row.Artifact.Coverage.RegistryView); Add("Coverage", "Profile scope", row.Artifact.Coverage.ProfileScope);
        foreach (var result in row.Collection.Results.Where(result => PersistenceComparisonPolicy.PartitionKey(result.CollectorId, result.Coverage) == row.PartitionKey))
        {
            Add("Observation coverage", "Status", result.Status); Add("Observation coverage", "Source availability", result.Coverage.SourceAvailability); Add("Observation coverage", "Diagnostic", result.DiagnosticSummary);
        }
        if (View == PersistenceView.Current && _page?.Coverage.FirstOrDefault() is { } latest)
        {
            Add("Latest collection", "Collection", latest.Collection.CollectionId); Add("Latest collection", "Generation", latest.Collection.StateGenerationId);
            Add("Latest collection", "Reason", latest.Collection.Reason); Add("Latest collection", "Reset explanation", latest.Collection.ResetReason);
            var declared = _page.Coverage.FirstOrDefault(coverage => PersistenceComparisonPolicy.PartitionKey(coverage.Result.CollectorId, coverage.Result.Coverage) == row.PartitionKey);
            Add("Latest collection", "Partition outcome", declared == null ? "Not declared in latest accepted coverage" : declared.Result.Status);
            if (declared != null) { Add("Latest collection", "Source availability", declared.Result.Coverage.SourceAvailability); Add("Latest collection", "Diagnostic", declared.Result.DiagnosticSummary); }
        }
        if (before != null) Artifact("Before", before); if (after != null) Artifact("After", after);
        void Artifact(string group, PersistenceArtifact artifact)
        {
            Add(group, "Type", artifact.Category); Add(group, "Name", artifact.NativeName); Add(group, "Location", artifact.NativeLocation); Add(group, "Target", artifact.Target); Add(group, "Command", artifact.Command); Add(group, "Arguments", artifact.Arguments); Add(group, "Principal", artifact.Principal); Add(group, "Enabled", artifact.Enabled); Add(group, "Source schema", artifact.SourceSchemaVersion);
            foreach (var entry in artifact.Configuration.OrderBy(c => c.Key, StringComparer.Ordinal))
            {
                Add(group, entry.Key + " native type", entry.Value.NativeType);
                if (entry.Value.State == PersistenceValueState.Unknown) { Add(group, entry.Key, "Unknown"); continue; }
                using var json = JsonDocument.Parse(entry.Value.Json);
                if (json.RootElement.ValueKind == JsonValueKind.Array) { var i = 0; foreach (var value in json.RootElement.EnumerateArray()) Add(group, $"{entry.Key}[{i++}]", value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText()); if (i == 0) Add(group, entry.Key, "[] (recorded empty)"); }
                else Add(group, entry.Key, json.RootElement.ValueKind == JsonValueKind.String ? json.RootElement.GetString() : json.RootElement.GetRawText());
            }
        }
    }
    private static InspectorPayload Payload(PersistenceWorkspaceRow row, IReadOnlyList<PropertyItemViewModel> properties) => new() { TargetKind = "Persistence observation", TargetTable = "PersistenceVersions", TargetId = row.Identity, Header = row.Name, Subtitle = row.Change + " · accepted observation " + row.ObservedUtc.ToString("O"), Properties = properties, CaseId = row.Scope.CaseId, EvidenceSessionId = row.Scope.EvidenceSessionId, CaptureId = row.Scope.CaptureId, SourceIdentityId = row.Scope.SourceIdentityId, HostId = row.Scope.HostId, ExecutionRootId = row.Scope.ExecutionRootId, SourceRunId = row.Collection.SourceRunId, IngestionJobId = row.Collection.IngestionJobId };
    private async Task Track(Task task) { _work.Add(task); try { await task; } finally { _work.Remove(task); } }
    internal sealed record RetainedState(PersistenceWorkspaceRow[] Rows, PersistenceWorkspacePage? Page, string Status, string? Selection, bool Loaded,
        PersistenceWorkspaceRow[] History, PropertyItemViewModel[] Properties, long MatchingRows, long MatchingHistory, InspectorPayload? Inspector, PersistenceObjectReference? Object,
        string? PeriodId, bool PeriodActive, long PeriodRevision, PersistenceObjectReference? ExactObject);
    private bool CanRunObjectAction(PersistenceWorkspaceRow? row) => _createObjectConversation != null &&
        !IsDisposed && !ReadsSuspended && row != null && row.Scope == SelectedScope?.Scope && Rows.Contains(row);
    private async Task RunObjectActionAsync(PersistenceWorkspaceRow? row, ProcessConversationAction action)
    {
        if (!CanRunObjectAction(row)) return;
        SelectedRow = row;
        DetailsTabIndex = 2;
        if (ObjectConversationViewModel is { } conversation) await conversation.RunActionAsync(action);
    }
    internal void ShowObjectConversation() { if (IsAiAvailable && !IsDisposed) DetailsTabIndex = 2; }
    internal async Task<bool> OpenAiOriginalAsync(PersistenceObjectReference locator, CancellationToken token)
    {
        if (IsDisposed || ReadsSuspended || Context == null ||
            locator.Scope.EvidenceSessionId != _session.Capture?.Paths.SessionId) return false;
        var context = Context;
        var revision = _session.Revision;
        _request.Cancel();
        var generation = ++_generation;
        PersistenceObjectDetail detail;
        try { detail = await _session.DetailAsync(locator, token); }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) { if (generation == _generation && context == Context) Status = "Exact persistence original unavailable: " + error.Message; return false; }
        if (IsDisposed || ReadsSuspended || context != Context || revision != _session.Revision || generation != _generation) return false;
        var original = detail.Row;
        if (original.Scope != locator.Scope || original.PartitionKey != locator.PartitionKey ||
            original.ArtifactKey != locator.ArtifactKey || original.Collection.CollectionId != locator.CollectionId)
            return false;

        SelectPeriod(locator.Scope, original.Generation);
        SwitchView(PersistenceView.Changes);
        var state = ActiveView;
        state.Category = null; state.Selectors.Clear(); state.Offset = 0;
        foreach (var filter in state.Filters.Values) filter.Reset(false);
        _request.Cancel();
        generation = ++_generation;
        _exactObject = locator with { PeriodId = original.Generation };
        NavigationDescription = "Exact persistence observation";
        var query = CaptureQuery()! with { PageSize = 1 };
        try
        {
            var page = await _session.QueryAsync(query, token);
            if (IsDisposed || ReadsSuspended || context != Context || revision != _session.Revision || generation != _generation ||
                _exactObject != query.ExactObject || SelectedScope?.Scope != locator.Scope) return false;
            if (page.Rows.Count != 1 || page.Rows[0].Identity != original.Identity)
            {
                _exactObject = null;
                Status = "Exact persistence original is unavailable in this read binding.";
                return false;
            }
            Apply(page);
            SelectedRow = Rows[0];
            ShowObjectConversation();
            return true;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) { if (generation == _generation && context == Context) { _exactObject = null; Status = "Exact persistence original unavailable: " + error.Message; } return false; }
    }
    internal RetainedState Retain() => new(Rows.ToArray(), _page, Status, SelectedRow?.Identity ?? _retainedSelection, _loaded, History.ToArray(), NativeProperties.ToArray(), MatchingRows, MatchingHistory, InspectorPaneViewModel.CurrentPayload, SelectedRow == null ? _retainedObject : Reference(SelectedRow), PeriodId, _periodActive, _periodRevision, _exactObject);
    internal void Restore(RetainedState state) { _periodId = state.PeriodId; _periodActive = state.PeriodActive; _periodRevision = state.PeriodRevision; _exactObject = state.ExactObject; Rows.Clear(); foreach (var row in state.Rows) Rows.Add(row); _page = state.Page; Status = state.Status; _retainedSelection = state.Selection; _retainedObject = state.Object; _loaded = state.Loaded; _selected = Rows.FirstOrDefault(row => row.Identity == state.Selection); _objectConversation?.SelectObject(_selected is { } selected ? EvidenceObjectAgentTools.PersistenceContext(selected) : null); History.Clear(); foreach (var row in state.History) History.Add(row); NativeProperties.Clear(); foreach (var property in state.Properties) NativeProperties.Add(property); MatchingRows = state.MatchingRows; MatchingHistory = state.MatchingHistory; if (state.Inspector != null) InspectorPaneViewModel.Load(state.Inspector); else InspectorPaneViewModel.Clear(); OnPropertyChanged(nameof(SelectedRow)); }
    internal void Invalidate(bool captureChanged)
    {
        _request.Cancel(); _detail.Cancel(); _historyRequest.Cancel(); _objectConversation?.SelectObject(null); _generation++; _selectionGeneration++; _loaded = false; _page = null;
        if (captureChanged) _exactObject = null;
        OnPropertyChanged(nameof(StatusHeadline));
        if (captureChanged)
        {
            _completedJob = null; _completedScope = null; _completedBaselinePeriod = null; _completedRevision = -1;
            _completedJobSucceeded = false; _completedTarget = null;
            _closedActionPeriods.Clear();
            foreach (var state in _views.Values) { state.Selectors.Clear(); state.Category = null; state.Offset = 0; state.Sort = PersistenceColumn.Name; state.Descending = false; }
            foreach (var filter in _views.Values.SelectMany(state => state.Filters.Values).Concat(PropertyFilters.Values).Concat(HistoryFilters.Values)) filter.Reset(false);
            _scope = null; _periodId = null; _periodActive = false; Scopes.Clear(); _offset = _historyOffset = 0; _retainedSelection = null; _retainedObject = null; _category = null;
            _view = PersistenceView.Current; _selected = null; Rows.Clear(); ClearDetails(); NavigationDescription = "Current";
            OnPropertyChanged(nameof(SelectedScope)); OnPropertyChanged(nameof(SelectedRow)); OnPropertyChanged(nameof(View)); OnPropertyChanged(nameof(HeaderFilters));
            OnPropertyChanged(nameof(IsCurrent)); OnPropertyChanged(nameof(IsChanges));
            Status = "Persistence capture changed; refresh the assessed read binding.";
            ActionStatus = NeutralActionStatus;
        }
        else _retainedSelection = SelectedRow?.Identity ?? _retainedSelection;
        _actionRequest.Cancel(); NotifyActions();
        Refreshed?.Invoke();
    }
    internal async Task QuiesceAsync(CancellationToken token) { _suspended = true; _objectConversation?.SelectObject(null); _request.Cancel(); _detail.Cancel(); _historyRequest.Cancel(); _actionRequest.Cancel(); NotifyActions(); foreach (var filter in _views.Values.SelectMany(state => state.Filters.Values).Concat(PropertyFilters.Values).Concat(HistoryFilters.Values)) filter.Close(); await Task.WhenAll(_work.ToArray()).WaitAsync(token); while (_objectConversation?.IsBusy == true) await Task.Delay(10, token); }
    internal void Resume() { _suspended = false; if (Context != null && SelectedRow is { } selected) _objectConversation?.SelectObject(EvidenceObjectAgentTools.PersistenceContext(selected)); NotifyActions(); if (!ReadsSuspended && SelectedRow != null && NativeProperties.Count == 0) _ = LoadDetailsAsync(SelectedRow); }
    public override void Dispose() { if (IsDisposed) return; IsDisposed = true; _suspended = true; _request.Cancel(); _detail.Cancel(); _historyRequest.Cancel(); _actionRequest.Cancel(); ActionStatus = NeutralActionStatus; NotifyActions(); foreach (var filter in _views.Values.SelectMany(state => state.Filters.Values).Concat(PropertyFilters.Values).Concat(HistoryFilters.Values)) filter.Close(); _selected = null; Rows.Clear(); ClearDetails(); _objectConversation?.Dispose(); }
}
