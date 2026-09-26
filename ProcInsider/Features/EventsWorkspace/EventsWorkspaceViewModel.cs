using ProcInsider.Features.NativeEventProfiles;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Features.WindowsSecurityDetails;
using ProcInsider.Models;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services;
using ProcInsider.Services.Features;
using ProcInsider.Services.Presentation;
using ProcInsider.Services.Events;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed partial class EventsWorkspaceViewModel : WorkspaceInstanceViewModel
{
    private readonly EventsWorkspaceReadSession _session;
    private readonly SecurityDetailsStore? _definitions;
    private readonly Lazy<NativeEventProfileStore> _profiles;
    private readonly Func<InspectorPaneViewModel, AiDetailsInvestigationViewModel>? _createAi;
    private AiDetailsInvestigationViewModel? _ai;
    private AnnotationDatabaseService? _annotations;
    private string? _aiPrompt;
    private CancellationTokenSource _request = new(), _format = new();
    private readonly HashSet<Task> _work = [];
    private long _revision;
    private bool _suspended, _needsLoad = true;
    private EventsReadBinding? _loadedBinding;
    private EventReference? _retainedSelection;
    private EventsWorkspaceRowViewModel? _selected;
    private string _status = "Open a capture or refresh its recorded evidence.";
    private bool _busy;
    private long _matching;
    private EventsFilter _filter = new();
    private readonly Dictionary<EventGreenSelector, EventAggregate> _greenAggregates = [];
    private string _identityLabel = "All identities";
    private EventSort _sort = EventSort.Timestamp;
    private bool _descending = true;
    private long _offset;
    private long _displayOffset;
    internal bool LastRefreshSucceeded { get; private set; }
    private readonly System.Windows.Threading.Dispatcher _dispatcher = System.Windows.Threading.Dispatcher.CurrentDispatcher;
    internal event Action? InvestigationChanged;
    internal event Action? FiltersChanged;
    internal event Action? RefreshSucceeded;
    public const int PageSize = 128;
    public ObservableCollection<EventsWorkspaceRowViewModel> Rows { get; } = [];
    public InspectorPaneViewModel InspectorPaneViewModel { get; } = new();
    public FeaturePublicationViewModel FeaturePublication { get; }
    public ListingColumnSettings ListingColumns { get; } = new();
    public ViewerSharedActions SharedActions { get; internal set; } = new();
    public AiDetailsInvestigationViewModel? AiDetailsInvestigationViewModel
    {
        get
        {
            if (!FeaturePublication.AiAssistance || _createAi == null || IsDisposed) return null;
            if (_ai == null)
            {
                // A presenter's inspector subject never changes. Retired work cannot publish into a newer subject.
                var subject = new InspectorPaneViewModel();
                _ai = _createAi(subject);
                _ai.SetAnnotationStore(_annotations);
                if (_aiPrompt != null) _ai.ArtifactPrompt = _aiPrompt;
                if (InspectorPaneViewModel.CurrentPayload is { } payload) subject.Load(payload);
            }
            return _ai;
        }
    }
    public ViewerDetailsTabKey SelectedDetailsTabKey { get; set; } = ViewerDetailsTabKey.Object;
    public int SelectedDataTabIndex { get; set; }
    public double VerticalOffset { get; set; }
    public double HorizontalOffset { get; set; }
    public double InspectorOffset { get; set; }
    public EventsFilter Filter => _filter;
    public EventsReadBinding? LoadedBinding => _loadedBinding;
    public EventSort Sort { get => _sort; set { if (_extractedSort != null || _sort != value) { _sort = value; _extractedSort = null; OnPropertyChanged(); OnPropertyChanged(nameof(ExtractedSort)); _offset = 0; InvestigationChanged?.Invoke(); StartRefresh(); } } }
    public bool Descending { get => _descending; set { if (SetProperty(ref _descending, value)) { _offset = 0; InvestigationChanged?.Invoke(); StartRefresh(); } } }
    public Array SortOptions => Enum.GetValues<EventSort>();
    public IReadOnlyDictionary<string, ColumnFilterViewModel> HeaderFilters { get; }
    public string ProviderFilter { get; set; } = "";
    public string ChannelFilter { get; set; } = "";
    public string EventIdFilter { get; set; } = "";
    public string IdentityFilterDisplay => (_filter.GreenSelectors.Count > 0 || _filter.GreenSysmonEventIds.Count > 0 ? GreenSelectionDescription : _identityLabel) + (_filter.MissingEventId ? "; Event ID: Unknown" : "") +
        (_filter.Provider == "" ? "; Provider: Unknown" : "") + (_filter.Channel == "" ? "; Channel: Unknown" : "");
    private string GreenSelectionDescription
    {
        get
        {
            var selections = _filter.GreenSelectors.GroupBy(s => s.Dimension)
                .Select(g => $"{(g.Key == EventAggregateDimension.EventId ? "Event ID" : g.Key)} ({(g.Any(s => s.AllValues) ? $"all; {g.Count(s => s.IsExcluded)} excluded" : g.Count().ToString())})")
                .Concat(_filter.GreenSysmonEventIds.Count > 0 ? [$"Sysmon ({_filter.GreenSysmonEventIds.Count})"] : []);
            return "Green: " + string.Join(" AND ", selections) + "; OR within each category";
        }
    }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public bool IsBusy { get => _busy; private set { if (SetProperty(ref _busy, value)) OnPropertyChanged(nameof(IsLoading)); } }
    private int _preparing;
    public bool IsLoading => IsBusy || _preparing > 0;
    private void BeginPreparing() { _preparing++; OnPropertyChanged(nameof(IsLoading)); }
    private void EndPreparing() { _preparing--; OnPropertyChanged(nameof(IsLoading)); }
    public long MatchingEvents { get => _matching; private set => SetProperty(ref _matching, value); }
    public string PageDisplay => $"{(_matching == 0 ? 0 : _displayOffset + 1)}–{Math.Min(_displayOffset + Rows.Count, _matching)} of {_matching:N0}";
    public EventsWorkspaceRowViewModel? SelectedEvent
    {
        get => _selected;
        set
        {
            if (value != null && (!Rows.Contains(value) || _loadedBinding != _session.Binding)) return;
            if (!SetProperty(ref _selected, value)) return;
            RetireAi();
            _retainedSelection = value?.Reference;
            InvestigationChanged?.Invoke();
            if (value == null) InspectorPaneViewModel.Clear("Select an event; unresolved events can also be inspected.");
            else InspectorPaneViewModel.Load(value.CreatePayload());
            RefreshContextualFields();
            StartComparison();
            OnPropertyChanged(nameof(AiDetailsInvestigationViewModel));
        }
    }
    public IRelayCommand ApplyFiltersCommand { get; }
    public IRelayCommand ClearFiltersCommand { get; }
    public IRelayCommand RefreshCommand { get; }
    public IRelayCommand CancelCommand { get; }
    public IRelayCommand PreviousPageCommand { get; }
    public IRelayCommand NextPageCommand { get; }

    internal EventsWorkspaceViewModel(WorkspaceTypeMetadata type, int ordinal, EventsWorkspaceReadSession session,
        SecurityDetailsStore? definitions, FeatureAccessService access,
        Func<InspectorPaneViewModel, AiDetailsInvestigationViewModel>? createAi = null,
        Lazy<NativeEventProfileStore>? profiles = null, Lazy<NativeEventPresetStore>? presets = null) : base(type, ordinal)
    {
        _session = session; _definitions = definitions; _createAi = createAi;
        foreach (var column in Enum.GetValues<EventSort>().Where(c => c != EventSort.Sequence))
            ListingColumns.GetColumn(column.ToString()).IsVisible = column is EventSort.Timestamp or EventSort.EventId or EventSort.Description;
        _profiles = profiles ?? new(() => new NativeEventProfileStore(SessionPathService.GetNativeEventProfilesPath()));
        _presets = presets ?? new(() => new NativeEventPresetStore(SessionPathService.GetNativeEventPresetsPath()));
        HeaderFilters = Enum.GetValues<EventSort>().Where(c => c != EventSort.Sequence).ToDictionary(c => c.ToString(), c =>
            new ColumnFilterViewModel(c.ToString(), c == EventSort.Timestamp ? ColumnFilterKind.Timestamp :
                c == EventSort.Details ? ColumnFilterKind.Text : ColumnFilterKind.Values,
                (search, sort, token) => _session.Reader.ColumnValuesAsync(_filter, c, search, token, sort), ApplyColumnFilters));
        FeaturePublication = new(access);
        _filter = _filter with { TextProjection = new EventsTextProjection([]) };
        if (FeaturePublication.IsPublished(EventsWorkspaceFeatureComposition.Id) &&
            (FeaturePublication.WindowsSecurityEvents || FeaturePublication.EventTelemetry))
        {
            _filter = _filter with { TextProjection = new EventsTextProjection(_profiles.Value.Snapshot(), _detailsProfiles) };
            _profiles.Value.Changed += ProfilesChanged;
        }
        NavigationDescription = "All Events";
        InitializeComparison();
        InitializeStatistics();
        ApplyFiltersCommand = new RelayCommand(ApplyFilters);
        ClearFiltersCommand = new RelayCommand(() => { foreach (var header in HeaderFilters.Values) header.Reset(false); CloseExtractedHeaders(true); SetFilter(new(), "All Events"); StartRefresh(); });
        RefreshCommand = new RelayCommand(StartRefresh);
        CancelCommand = new RelayCommand(() =>
        {
            _request.Cancel(); _format.Cancel(); CancelExtraction();
            foreach (var row in Rows) row.MarkPresentationUnavailable("Profile Details canceled; refresh to retry");
            PublishFormattedSelection();
            ExtractedFieldsStatus = "Extraction canceled; completed field values retained.";
        });
        PreviousPageCommand = new RelayCommand(() => { if (_offset > 0) { _offset = Math.Max(0, _offset - PageSize); InvestigationChanged?.Invoke(); StartRefresh(); } });
        NextPageCommand = new RelayCommand(() => { if (_offset + PageSize < _matching) { _offset += PageSize; InvestigationChanged?.Invoke(); StartRefresh(); } });
    }
    internal void SetFilter(EventsFilter filter, string description, bool explicitTypeFilter = false)
    {
        InvalidateStatistics();
        var activatePreset = explicitTypeFilter && TypeScopeChanged(_filter, filter);
        foreach (var removed in _greenAggregates.Keys.Where(k => !filter.GreenSelectors.Any(s => k.Covers(s) || k == (s with { IsExcluded = false }))).ToArray()) _greenAggregates.Remove(removed);
        if (filter.IdentityKey == null) _identityLabel = "All identities";
        else if (filter.IdentityKey != _filter.IdentityKey || filter.IdentityRole != _filter.IdentityRole || filter.IdentitySessionKey != _filter.IdentitySessionKey) _identityLabel = description;
        _filter = filter with { TextProjection = _filter.TextProjection }; _offset = 0; _needsLoad = true;
        NavigationDescription = description;
        ProviderFilter = filter.Provider ?? ""; ChannelFilter = filter.Channel ?? ""; EventIdFilter = filter.EventId?.ToString() ?? "";
        OnPropertyChanged(nameof(ProviderFilter)); OnPropertyChanged(nameof(ChannelFilter)); OnPropertyChanged(nameof(EventIdFilter));
        OnPropertyChanged(nameof(IdentityFilterDisplay));
        InvestigationChanged?.Invoke();
        FiltersChanged?.Invoke();
        if (activatePreset) ActivateAssociatedPreset();
    }
    internal void ToggleGreen(EventsPivot pivot)
    {
        var selector = pivot.Selector;
        _greenAggregates[selector] = pivot.Aggregate;
        if (pivot.Parent is { } parent) _greenAggregates[parent.Selector] = parent.Aggregate;
        var selectors = _filter.GreenSelectors.ToList();
        var wasIncluded = EventGreenSelection.Includes(selectors, selector);
        selectors.RemoveAll(s => selector.Covers(s));
        var inherited = EventGreenSelection.Includes(selectors, selector);
        if (!wasIncluded != inherited)
        {
            var changed = selector with { IsExcluded = wasIncluded };
            selectors.Add(changed); _greenAggregates[changed] = pivot.Aggregate;
        }
        // Green selection replaces ordinary pivot scope; column criteria remain independent.
        SetFilter(_filter with { GreenSelectors = selectors, IdentityKey = null, IdentitySessionKey = null, Provider = null,
            Channel = null, EventId = null, Source = null, EventIds = [], MissingEventId = false, ExactEvent = null, AuditCategoryKey = null, AuditSubcategoryKey = null },
            selectors.Count == 0 && _filter.GreenSysmonEventIds.Count == 0 ? "All Events" : "Green selection");
    }
    internal static bool IsSysmonGreenSelected(EventsFilter filter, SysmonExplorerNode node) =>
        node.CanGreenSelect && node.EventIds.All(filter.GreenSysmonEventIds.Contains);
    internal void ToggleSysmonGreen(SysmonExplorerNode node)
    {
        if (!node.CanGreenSelect) return;
        var selected = IsSysmonGreenSelected(_filter, node);
        var eventIds = _filter.GreenSysmonEventIds.ToHashSet();
        if (selected) eventIds.ExceptWith(node.EventIds);
        else eventIds.UnionWith(node.EventIds);
        SetFilter(_filter with
        {
            IdentityKey = null,
            IdentitySessionKey = null,
            Provider = null,
            Channel = null,
            EventId = null,
            Source = null,
            EventIds = [],
            GreenSysmonEventIds = SysmonEventTaxonomy.EventIds.Where(eventIds.Contains).ToArray(),
            MissingEventId = false,
            ExactEvent = null,
            AuditCategoryKey = null,
            AuditSubcategoryKey = null
        }, eventIds.Count == 0 && _filter.GreenSelectors.Count == 0 ? "All Events" : "Green selection");
    }
    internal IEnumerable<EventsPivot> GreenPivots(EventAggregateDimension dimension, EventIdentityRole role, EventsReadBinding? binding)
    {
        if (binding == null) yield break;
        var child = dimension is EventAggregateDimension.IdentitySession or EventAggregateDimension.AuditSubcategory;
        var family = EventsPivot.Family(dimension);
        var seen = new HashSet<EventGreenSelector>();
        foreach (var selected in _filter.GreenSelectors.Where(s => !s.AllValues && s.Dimension == family &&
            (family != EventAggregateDimension.Identity || s.Role == role)))
        {
            if (child && selected.ChildKey == null) continue;
            var selector = child ? selected with { IsExcluded = false } : selected with { ChildKey = null, IsExcluded = false };
            if (!seen.Add(selector)) continue;
            var aggregate = _greenAggregates.GetValueOrDefault(selector) ?? _greenAggregates.GetValueOrDefault(selector with { IsExcluded = true }) ??
                new(child ? selector.ChildKey! : selector.Key, 0, null, child ? selector.Key : null);
            yield return new(dimension, aggregate with { EventCount = 0 }, role, binding)
            {
                IsGreenIncludedDirectly = EventGreenSelection.Includes(_filter.GreenSelectors, selector),
                HasGreenIncludedDescendant = EventGreenSelection.HasDescendant(_filter.GreenSelectors, selector)
            };
        }
    }
    private void ApplyFilters()
    {
        if (EventIdFilter.Length != 0 && (!int.TryParse(EventIdFilter, out var id) || id < 0)) { Status = "Event ID must be a nonnegative integer; displayed results are unchanged."; return; }
        SetFilter(_filter with
        {
            Provider = ProviderFilter.Length == 0 && _filter.Provider == "" ? "" : Empty(ProviderFilter),
            Channel = ChannelFilter.Length == 0 && _filter.Channel == "" ? "" : Empty(ChannelFilter),
            EventId = EventIdFilter.Length == 0 ? null : int.Parse(EventIdFilter),
            Source = null,
            EventIds = [],
            MissingEventId = EventIdFilter.Length == 0 && _filter.MissingEventId
        }, NavigationDescription, explicitTypeFilter: true);
        StartRefresh();
    }
    private static string? Empty(string value) => value.Length == 0 ? null : value;
    private void ApplyColumnFilters()
    {
        SetFilter(_filter with
        {
            Columns = HeaderFilters.Values.Where(f => f.IsActive).ToDictionary(f => Enum.Parse<EventSort>(f.Key), f => f.Criteria),
            ExtractedColumns = _nativeHeaders.Values.Where(h => h.Filter.IsActive).Select(h => new ExtractedEventColumnFilter(h.Identity, h.Filter.Criteria)).ToArray()
        }, NavigationDescription, explicitTypeFilter: true);
        StartRefresh();
    }
    internal void SortColumn(EventSort column)
    {
        var descending = _extractedSort == null && column == _sort ? !_descending : false;
        _extractedSort = null; OnPropertyChanged(nameof(ExtractedSort));
        _sort = column; _descending = descending; _offset = 0;
        OnPropertyChanged(nameof(Sort)); OnPropertyChanged(nameof(Descending));
        InvestigationChanged?.Invoke(); StartRefresh();
    }
    private void StartRefresh() => Track(RefreshAsync());
    private async void Track(Task task)
    {
        _work.Add(task);
        try { await task; }
        finally { _work.Remove(task); }
    }
    internal Task LoadAsync() => _needsLoad ? RefreshAsync() : Task.CompletedTask;
    internal EventsQuery CaptureQuery() => new() { Filter = _filter, Sort = _sort, ExtractedSort = _extractedSort, Descending = _descending, Offset = _offset, PageSize = PageSize };
    internal void ApplyPrepared(EventsPage page)
    {
        if (_statisticsResult != null && _statisticsResult.Binding != page.Binding) InvalidateStatistics();
        ValidateComparisonBinding(page.Binding);
        var selected = _retainedSelection;
        var rows = page.Rows.Select(row => new EventsWorkspaceRowViewModel(row)).ToArray();
        _format.Cancel();
        SelectedEvent = null; Rows.Clear(); foreach (var row in rows) Rows.Add(row);
        _loadedBinding = page.Binding; MatchingEvents = page.MatchingEvents; _displayOffset = _offset;
        OnPropertyChanged(nameof(LoadedBinding));
        SelectedEvent = rows.FirstOrDefault(row => row.Reference == selected);
        _needsLoad = false; LastRefreshSucceeded = true;
        Status = $"{page.MatchingEvents:N0} matching stored events. Acquisition coverage: {page.Completeness.AcquisitionCoverage}. " +
            $"Identity unavailable: {page.Completeness.IdentityUnavailableEvents:N0}; missing source run: {page.Completeness.MissingSourceRunEvents:N0}; " +
            $"authorized sources observed: {page.Completeness.ObservedAuthorizedSources?.ToString("N0") ?? "unavailable"}; " +
            $"sources without healthy status: {page.Completeness.SourcesWithoutHealthyStatus?.ToString("N0") ?? "unavailable"}." +
            (selected != null && SelectedEvent == null ? " Previous selection is outside this page, missing or filtered out; no replacement selected." : "");
        OnPropertyChanged(nameof(PageDisplay));
        BeginFormatting();
        BeginExtraction();
    }
    internal async Task RefreshAsync()
    {
        if (_suspended || IsDisposed) return;
        _request.Cancel(); _request.Dispose(); _request = new();
        var token = _request.Token;
        var revision = ++_revision;
        var binding = _session.Binding;
        var filter = _filter;
        var offset = _offset;
        IsBusy = true;
        LastRefreshSucceeded = false;
        Status = "Reading recorded evidence from published event sources…";
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _work.Add(completion.Task);
        try
        {
            var page = await _session.Reader.QueryAsync(new() { Filter = filter, Sort = _sort, ExtractedSort = _extractedSort, Descending = _descending, Offset = offset, PageSize = PageSize }, token);
            token.ThrowIfCancellationRequested();
            if (revision != _revision || binding != _session.Binding || IsDisposed) return;
            ApplyPrepared(page);
            RefreshSucceeded?.Invoke();
        }
        catch (OperationCanceledException) { if (revision == _revision && !IsDisposed) Status = "Read canceled; previous displayed page retained."; }
        catch (Exception ex) { if (revision == _revision && !IsDisposed) Status = $"Events read failed; previous displayed page retained: {ex.Message}"; }
        finally { if (revision == _revision) IsBusy = false; completion.SetResult(); _work.Remove(completion.Task); }
    }
    private void BeginFormatting()
    {
        if (_suspended || IsDisposed || Rows.Count == 0) return;
        _format.Cancel(); _format.Dispose(); _format = new();
        Track(FormatAsync(Rows.ToArray(), _loadedBinding, (EventsTextProjection)_filter.TextProjection!, _format.Token));
    }
    private async Task FormatAsync(EventsWorkspaceRowViewModel[] rows, EventsReadBinding? binding,
        EventsTextProjection projection, CancellationToken token)
    {
        BeginPreparing();
        try
        {
            var summaries = await Task.Run(() =>
            {
                return rows.Select(row =>
                {
                    token.ThrowIfCancellationRequested();
                    return projection.Project(row.ExtractNativeFields(token), token);
                }).ToArray();
            }, token);
            if (token.IsCancellationRequested || IsDisposed || _suspended || binding != _session.Binding || binding != _loadedBinding ||
                !ReferenceEquals(projection, _filter.TextProjection) || !Rows.SequenceEqual(rows)) return;
            for (var i = 0; i < rows.Length; i++) rows[i].ApplyPresentation(summaries[i]);
            PublishFieldChoices([]);
            PublishFormattedSelection();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!token.IsCancellationRequested && !IsDisposed)
            {
                Status = $"Details formatting unavailable: {ex.Message}";
                foreach (var row in rows) row.MarkPresentationUnavailable("Profile Details unavailable; refresh to retry");
                PublishFormattedSelection();
            }
        }
        finally { EndPreparing(); }
    }
    private void PublishFormattedSelection()
    {
        RefreshContextualFields();
        if (_selected == null) return;
        RetireAi();
        InspectorPaneViewModel.Load(_selected.CreatePayload());
        OnPropertyChanged(nameof(AiDetailsInvestigationViewModel));
    }
    internal void Invalidate(bool captureChanged)
    {
        InvalidateStatistics();
        if (captureChanged) ClearComparison("Comparison cleared as stale: capture changed.");
        else ValidateComparisonBinding(_session.Binding);
        CancelExtraction();
        ++_revision; _request.Cancel(); _format.Cancel();
        IsBusy = false;
        var retained = _retainedSelection;
        SelectedEvent = null; Rows.Clear(); _loadedBinding = null; _needsLoad = true; MatchingEvents = 0;
        OnPropertyChanged(nameof(LoadedBinding));
        PublishFieldChoices([]); ExtractedFieldsStatus = "No displayed events.";
        RefreshContextualFields();
        _retainedSelection = captureChanged ? null : retained;
        if (captureChanged) { SetFilter(new(), "All Events"); VerticalOffset = HorizontalOffset = InspectorOffset = 0; }
        foreach (var header in HeaderFilters.Values) { if (captureChanged) header.Reset(false); else header.Close(); }
        CloseExtractedHeaders(captureChanged);
        if (captureChanged) BindAnnotations(null);
        Status = "Evidence generation changed; activate or refresh this investigation.";
        OnPropertyChanged(nameof(PageDisplay));
    }
    internal sealed record RetainedState(EventsWorkspaceRowViewModel[] Rows, EventsWorkspaceRowViewModel? Selected,
        EventReference? Selection, EventsReadBinding? Binding, bool NeedsLoad, long Matching, string Status, IEventsTextProjection? Projection);
    internal RetainedState Retain() => new(Rows.ToArray(), _selected, _retainedSelection, _loadedBinding, _needsLoad, _matching, Status, _filter.TextProjection);
    internal void Restore(RetainedState state)
    {
        InvalidateStatistics();
        ValidateComparisonBinding(state.Binding);
        if (!ReferenceEquals(state.Projection, _filter.TextProjection)) { Invalidate(false); return; }
        CancelExtraction();
        Rows.Clear(); foreach (var row in state.Rows) Rows.Add(row);
        _loadedBinding = state.Binding; _needsLoad = state.NeedsLoad; MatchingEvents = state.Matching;
        OnPropertyChanged(nameof(LoadedBinding));
        SelectedEvent = state.Selected; _retainedSelection = state.Selection; Status = state.Status;
        OnPropertyChanged(nameof(PageDisplay));
        BeginExtraction();
    }
    internal void BindAnnotations(AnnotationDatabaseService? annotations)
    {
        if (ReferenceEquals(_annotations, annotations)) return;
        RetireAi();
        _annotations = annotations;
        OnPropertyChanged(nameof(AiDetailsInvestigationViewModel));
    }
    private void RetireAi()
    {
        if (_ai is not { } prior) return;
        _aiPrompt = prior.ArtifactPrompt;
        _ai = null;
        prior.CancelInvestigation();
        Track(DrainAiAsync(prior));
    }
    private static async Task DrainAiAsync(AiDetailsInvestigationViewModel prior)
    {
        try { while (prior.IsBusy) await Task.Delay(10); }
        finally { prior.Dispose(); }
    }
    internal NativeEventProfileEditorViewModel CreateProfileEditor() => new(_profiles.Value, SelectedEvent?.Extraction,
        _definitions?.Snapshot().FirstOrDefault(d => d.EventId == SelectedEvent?.EventCode), _definitions?.LoadError ?? "");
    internal void ShowProfiles(System.Windows.Window? owner)
    {
        if (IsDisposed || !FeaturePublication.IsPublished(EventsWorkspaceFeatureComposition.Id) ||
            (!FeaturePublication.WindowsSecurityEvents && !FeaturePublication.EventTelemetry)) return;
        var window = new NativeEventProfileEditorWindow { Owner = owner, DataContext = CreateProfileEditor() };
        window.ShowDialog();
    }
    internal async Task QuiesceAsync(CancellationToken token)
    {
        FieldChooser.Close();
        CloseExtractedHeaders();
        foreach (var header in HeaderFilters.Values) header.Close();
        _suspended = true; _request.Cancel(); _format.Cancel();
        InvalidateStatistics("Statistics paused for evidence transition; calculate after resuming.");
        CancelComparison("Comparison paused for evidence transition; selections retained until binding validation.");
        _comparisonAdds.Cancel();
        CancelExtraction();
        _ai?.CancelInvestigation();
        while (_ai?.IsBusy == true) await Task.Delay(10, token);
        while (_work.Where(task => !task.IsCompleted).ToArray() is { Length: > 0 } pending) await Task.WhenAll(pending).WaitAsync(token);
    }
    internal void Resume() { _suspended = false; BeginFormatting(); BeginExtraction(); StartComparison(); }
    public override void Dispose()
    {
        if (IsDisposed) return;
        IsDisposed = true; ++_revision;
        FieldChooser.Close();
        CloseExtractedHeaders();
        InvalidateStatistics("Statistics closed."); _statistics.Dispose();
        ClearComparison("Comparison closed."); _comparison.Dispose(); _comparisonAdds.Dispose();
        CancelExtraction(); _extraction.Dispose();
        foreach (var header in HeaderFilters.Values) header.Close();
        if (_profiles.IsValueCreated) _profiles.Value.Changed -= ProfilesChanged;
        _request.Cancel(); _format.Cancel(); _request.Dispose(); _format.Dispose(); _ai?.Dispose();
    }
}
