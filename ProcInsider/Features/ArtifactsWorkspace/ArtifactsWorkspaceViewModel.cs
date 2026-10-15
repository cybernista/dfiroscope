using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text.Json;
using System.IO;
using System.Windows.Data;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

/// <summary>Generic, snapshot-backed browser for retained forensic results; source-specific fields stay in the Data surface.</summary>
internal sealed class ArtifactsWorkspaceViewModel : WorkspaceInstanceViewModel
{
    private readonly ArtifactsWorkspaceReadSession _session;
    private readonly ArtifactsWorkspaceActionService? _actions;
    private CancellationTokenSource _request = new(), _detail = new(), _action = new();
    private readonly HashSet<Task> _work = [];
    private bool _suspended, _loaded, _busy, _collecting, _lastRefreshSucceeded;
    private long _generation, _selectionGeneration, _offset, _matching;
    private string _status = "No assessed Artifacts read binding.", _actionStatus = "For live Prefetch results, connect an Agent, use Collect Prefetch, then Refresh from DB.";
    private ForensicArtifactResultRow? _selected;
    private string? _retainedSelection;
    private Guid? _job;
    private ProcInsider.Services.AgentIpc.ViewerAgentCaptureActionTarget? _actionTarget;
    private WorkspaceContext? _actionContext;
    private long _actionRevision;
    private IReadOnlyList<ForensicArtifactResultColumnFilter> _explorerFilters = [];
    private IReadOnlyList<ForensicArtifactResultGreenSelector> _explorerSelectors = [];
    internal List<ForensicArtifactResultGreenSelector> GreenSelectors { get; } = [];
    internal event Action? QueryChanged;
    public ObservableCollection<ForensicArtifactResultRow> Rows { get; } = [];
    public ObservableCollection<PropertyItemViewModel> Properties { get; } = [];
    public ObservableCollection<PropertyItemViewModel> ReadOccurrences { get; } = [];
    private PrefetchPresentation? _prefetch;
    private int _dataTabIndex = 4;
    public PrefetchPresentation? Prefetch { get => _prefetch; private set { if (SetProperty(ref _prefetch, value)) OnPropertyChanged(nameof(HasPrefetchPresentation)); } }
    public bool HasPrefetchPresentation => Prefetch != null;
    public int DataTabIndex { get => _dataTabIndex; set => SetProperty(ref _dataTabIndex, value); }
    public InspectorPaneViewModel InspectorPaneViewModel { get; } = new();
    public IReadOnlyDictionary<string, ColumnFilterViewModel> HeaderFilters { get; }
    public IReadOnlyDictionary<string, ColumnFilterViewModel> PropertyFilters { get; }
    public IReadOnlyDictionary<string, ColumnFilterViewModel> ReadOccurrenceFilters { get; }
    public ICollectionView PropertiesView { get; }
    public ICollectionView ReadOccurrencesView { get; }
    public ForensicArtifactResultColumn Sort { get; set; } = ForensicArtifactResultColumn.ObservedUtc;
    public bool Descending { get; set; } = true;
    public string PropertySort { get; set; } = "Name";
    public ListSortDirection PropertySortDirection { get; set; } = ListSortDirection.Ascending;
    public string ReadOccurrenceSort { get; set; } = "Name";
    public ListSortDirection ReadOccurrenceSortDirection { get; set; } = ListSortDirection.Ascending;
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public string ActionStatus { get => _actionStatus; private set => SetProperty(ref _actionStatus, value); }
    public bool IsBusy { get => _busy; private set => SetProperty(ref _busy, value); }
    public long MatchingRows { get => _matching; private set => SetProperty(ref _matching, value); }
    public bool LastRefreshSucceeded { get => _lastRefreshSucceeded; private set => SetProperty(ref _lastRefreshSucceeded, value); }
    public bool ReadsSuspended => _suspended || _session.Suspended;
    public ForensicArtifactResultRow? SelectedRow
    {
        get => _selected;
        set
        {
            if (value != null && (IsDisposed || ReadsSuspended || !Rows.Contains(value))) return;
            if (SetProperty(ref _selected, value)) { _retainedSelection = value?.ArtifactId; _selectionGeneration++; _ = LoadDetailsAsync(value); }
        }
    }
    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand NextCommand { get; }
    public IAsyncRelayCommand PreviousCommand { get; }
    public IRelayCommand CancelCommand { get; }
    public IRelayCommand ClearFiltersCommand { get; }
    public IRelayCommand ClearPropertiesCommand { get; }
    public IRelayCommand ClearReadOccurrencesCommand { get; }
    public IAsyncRelayCommand CollectPrefetchCommand { get; }
    public IAsyncRelayCommand CancelCollectionCommand { get; }
    internal ArtifactsWorkspaceViewModel(WorkspaceTypeMetadata type, int ordinal, ArtifactsWorkspaceReadSession session, ArtifactsWorkspaceActionService? actions = null) : base(type, ordinal)
    {
        _session = session; _actions = actions; NavigationDescription = "Forensic artifacts";
        HeaderFilters = Enum.GetValues<ForensicArtifactResultColumn>().ToDictionary(column => column.ToString(), column => new ColumnFilterViewModel(column.ToString(), column == ForensicArtifactResultColumn.ObservedUtc ? ColumnFilterKind.Timestamp : ColumnFilterKind.Values, (search, sort, token) => ValuesAsync(column, search, sort, token), Changed));
        PropertiesView = new ListCollectionView(Properties);
        var propertyFilters = new Dictionary<string, ColumnFilterViewModel>(StringComparer.Ordinal);
        foreach (var column in new[] { "Group", "Name", "Value" })
            propertyFilters[column] = new ColumnFilterViewModel(column, ColumnFilterKind.Values, (search, sort, token) => Task.FromResult(ColumnFilterValuePage.FromValues(Properties.Where(row => propertyFilters.Where(filter => filter.Key != column).All(filter => filter.Value.Criteria.Matches(PropertyValue(row, filter.Key)))).Select(row => PropertyValue(row, column)).Where(value => ColumnTextFilter.Matches(value, search)), sort)), () => PropertiesView.Refresh());
        PropertyFilters = propertyFilters;
        PropertiesView.Filter = row => row is PropertyItemViewModel property && PropertyFilters.All(filter => filter.Value.Criteria.Matches(PropertyValue(property, filter.Key)));
        ReadOccurrencesView = new ListCollectionView(ReadOccurrences);
        var occurrenceFilters = new Dictionary<string, ColumnFilterViewModel>(StringComparer.Ordinal);
        foreach (var column in new[] { "Group", "Name", "Value" })
            occurrenceFilters[column] = new ColumnFilterViewModel(column, ColumnFilterKind.Values, (search, sort, token) => Task.FromResult(ColumnFilterValuePage.FromValues(ReadOccurrences.Where(row => occurrenceFilters.Where(filter => filter.Key != column).All(filter => filter.Value.Criteria.Matches(PropertyValue(row, filter.Key)))).Select(row => PropertyValue(row, column)).Where(value => ColumnTextFilter.Matches(value, search)), sort)), () => ReadOccurrencesView.Refresh());
        ReadOccurrenceFilters = occurrenceFilters;
        ReadOccurrencesView.Filter = row => row is PropertyItemViewModel occurrence && ReadOccurrenceFilters.All(filter => filter.Value.Criteria.Matches(PropertyValue(occurrence, filter.Key)));
        ApplyPropertySort();
        ApplyReadOccurrenceSort();
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        NextCommand = new AsyncRelayCommand(() => { if (_offset + 128 < MatchingRows) _offset += 128; return RefreshAsync(); });
        PreviousCommand = new AsyncRelayCommand(() => { _offset = Math.Max(0, _offset - 128); return RefreshAsync(); });
        CancelCommand = new RelayCommand(() => { _request.Cancel(); _detail.Cancel(); });
        ClearFiltersCommand = new RelayCommand(() => { foreach (var filter in HeaderFilters.Values) filter.Reset(false); GreenSelectors.Clear(); Changed(); });
        ClearPropertiesCommand = new RelayCommand(() => { foreach (var filter in PropertyFilters.Values) filter.Reset(false); PropertiesView.Refresh(); });
        ClearReadOccurrencesCommand = new RelayCommand(() => { foreach (var filter in ReadOccurrenceFilters.Values) filter.Reset(false); ReadOccurrencesView.Refresh(); });
        CollectPrefetchCommand = new AsyncRelayCommand(CollectPrefetchAsync, CanCollect);
        CancelCollectionCommand = new AsyncRelayCommand(CancelCollectionAsync, CanCancelCollection);
    }
    internal ForensicArtifactResultQuery CaptureQuery() => new(_explorerSelectors.Concat(GreenSelectors).ToArray(), CaptureFilters(_explorerFilters), Sort, Descending, _offset);
    private ForensicArtifactResultColumnFilter[] CaptureFilters(IEnumerable<ForensicArtifactResultColumnFilter> routeFilters, ForensicArtifactResultColumn? omitHeader = null)
    {
        var filters = HeaderFilters.Where(filter => filter.Value.IsActive && Enum.Parse<ForensicArtifactResultColumn>(filter.Key) != omitHeader)
            .ToDictionary(filter => Enum.Parse<ForensicArtifactResultColumn>(filter.Key), filter => filter.Value.Criteria);
        // Navigation routes are finite exact inclusions; intersect them before applying the one-filter-per-column query contract.
        foreach (var group in routeFilters.GroupBy(filter => filter.Column))
        {
            var routes = group.ToArray();
            if (routes.Any(route => route.Criteria.AllValues)) throw new InvalidOperationException("Artifacts navigation requires explicit included values.");
            filters.TryGetValue(group.Key, out var header);
            var values = routes[0].Criteria.Values.Where(value => routes.All(route => route.Criteria.Matches(value)) && (header?.Matches(value) ?? true)).ToArray();
            filters[group.Key] = new ColumnFilterCriteria { AllValues = false, Values = values };
        }
        return filters.Select(filter => new ForensicArtifactResultColumnFilter(filter.Key, filter.Value)).ToArray();
    }
    internal ForensicArtifactResultQuery CaptureCountQuery(ForensicArtifactResultScopeFacet facet, IReadOnlyList<ForensicArtifactResultColumnFilter>? pivotFilters = null)
    {
        ForensicArtifactResultColumn? ownColumn = facet switch { ForensicArtifactResultScopeFacet.Host => ForensicArtifactResultColumn.Host, ForensicArtifactResultScopeFacet.ArtifactType => ForensicArtifactResultColumn.ArtifactType, ForensicArtifactResultScopeFacet.Category => ForensicArtifactResultColumn.Category, _ => null };
        return CaptureQuery() with
        {
            GreenSelectors = _explorerSelectors.Concat(GreenSelectors).Where(selector => selector.Facet != facet).ToArray(),
            Filters = CaptureFilters(_explorerFilters.Where(filter => filter.Column != ownColumn).Concat(pivotFilters ?? [])),
            Offset = 0
        };
    }
    internal Task LoadAsync() => _loaded ? Task.CompletedTask : RefreshAsync();
    private void Changed() { _loaded = false; _offset = 0; QueryChanged?.Invoke(); if (!ReadsSuspended && Context != null) _ = RefreshAsync(); }
    internal void ToggleGreen(ForensicArtifactResultGreenSelector selector)
    {
        if (GreenSelectors.Count == 0) { _explorerFilters = []; _explorerSelectors = []; }
        var index = GreenSelectors.FindIndex(current => current.Facet == selector.Facet && current.Value == selector.Value && current.IsExcluded == selector.IsExcluded);
        if (index >= 0) GreenSelectors.RemoveAt(index); else GreenSelectors.Add(selector);
        Changed();
    }
    internal void SetExplorerScope(IReadOnlyList<ForensicArtifactResultColumnFilter> filters,
        IReadOnlyList<ForensicArtifactResultGreenSelector> selectors, string title)
    {
        if (_loaded && GreenSelectors.Count == 0 && JsonSerializer.Serialize(_explorerFilters) == JsonSerializer.Serialize(filters) && JsonSerializer.Serialize(_explorerSelectors) == JsonSerializer.Serialize(selectors))
        { NavigationDescription = title; return; }
        _explorerFilters = filters.ToArray(); _explorerSelectors = selectors.ToArray(); GreenSelectors.Clear();
        NavigationDescription = title; Changed();
    }
    internal async Task RefreshAsync()
    {
        if (IsDisposed || ReadsSuspended) return;
        _retainedSelection = SelectedRow?.ArtifactId ?? _retainedSelection;
        _request.Cancel(); _request.Dispose(); _request = new();
        var token = _request.Token; var generation = ++_generation; var revision = _session.Revision; var context = Context; var query = CaptureQuery();
        await Track(RunAsync());
        async Task RunAsync()
        {
            IsBusy = true; Status = "Loading assessed Artifacts evidence…"; LastRefreshSucceeded = false;
            try
            {
                var page = await _session.QueryAsync(query, token);
                if (!Current()) return;
                Rows.Clear(); foreach (var row in page.Rows) Rows.Add(row);
                MatchingRows = page.ViewCount; SelectedRow = Rows.FirstOrDefault(row => row.ArtifactId == _retainedSelection);
                Status = page.Availability == ForensicArtifactResultAvailability.Available ? $"{page.ViewCount:N0} matching retained results. {page.Diagnostic}" : page.Diagnostic;
                LastRefreshSucceeded = page.Availability == ForensicArtifactResultAvailability.Available; _loaded = true;
            }
            catch (OperationCanceledException) { if (OwnsRequest()) Status = "Artifacts read cancelled; retained results belong to the prior assessed snapshot."; }
            catch (Exception error) { if (Current()) Status = "Artifacts unavailable: " + error.Message; }
            finally { if (generation == _generation) IsBusy = false; }
        }
        bool OwnsRequest() => !IsDisposed && !ReadsSuspended && generation == _generation && revision == _session.Revision && context == Context;
        bool Current() => OwnsRequest() && !token.IsCancellationRequested;
    }
    private async Task LoadDetailsAsync(ForensicArtifactResultRow? row)
    {
        _detail.Cancel(); _detail.Dispose(); _detail = new(); var token = _detail.Token; Properties.Clear(); ReadOccurrences.Clear(); Prefetch = null; DataTabIndex = 4; InspectorPaneViewModel.Clear();
        if (row == null || IsDisposed || ReadsSuspended) return;
        var selection = _selectionGeneration; var revision = _session.Revision; var context = Context;
        await Track(RunAsync());
        async Task RunAsync()
        {
            try
            {
                var detail = await _session.DetailAsync(row.ArtifactId, token);
                var properties = await _session.PropertiesAsync(row.ArtifactId, new(), token);
                var native = new List<ForensicArtifactResultProperty>(properties.Rows);
                while (properties.Availability == ForensicArtifactResultAvailability.Available && native.Count < properties.MatchingRows)
                {
                    var next = await _session.PropertiesAsync(row.ArtifactId, new(Offset: native.Count), token);
                    if (next.Availability != ForensicArtifactResultAvailability.Available || next.MatchingRows != properties.MatchingRows || next.Rows.Count == 0)
                    { properties = next with { Availability = ForensicArtifactResultAvailability.Failed }; break; }
                    native.AddRange(next.Rows);
                }
                var presentation = await Task.Run(() => (Native: ExpandNative(native, token), Prefetch: PrefetchPresentation.Project(row, native, token)), token);
                if (token.IsCancellationRequested || IsDisposed || ReadsSuspended || selection != _selectionGeneration || revision != _session.Revision || context != Context || !ReferenceEquals(row, SelectedRow)) return;
                if (detail.Availability != ForensicArtifactResultAvailability.Available || detail.Result?.ArtifactId != row.ArtifactId || properties.Availability != ForensicArtifactResultAvailability.Available)
                {
                    Status = "Artifacts Details unavailable: " + (detail.Availability != ForensicArtifactResultAvailability.Available || detail.Result == null ? detail.Diagnostic : properties.Diagnostic);
                    return;
                }
                Add("Result", "Original source file", detail.Result?.OriginalFileRetained == true ? "Retained" : "Not retained — stored analysis results remain readable, but the original cannot be downloaded or reprocessed.");
                Add("Result", "Artifact ID", row.ArtifactId); Add("Result", "Artifact type", row.ArtifactType); Add("Result", "Category", row.Category); Add("Result", "Source path", row.SourcePath); Add("Result", "Input SHA-256", row.InputSha256); Add("Result", "Input size", row.InputByteCount?.ToString() ?? "Unknown");
                Add("Provenance", "Source run", row.SourceRunId); Add("Provenance", "Job", row.IngestionJobId); Add("Provenance", "Parser", row.ParserId + " / " + row.ParserVersion);
                Add("Scope", "Case", row.Scope.CaseId); Add("Scope", "Session", row.Scope.EvidenceSessionId); Add("Scope", "Capture", row.Scope.CaptureId); Add("Scope", "Source", row.Scope.SourceIdentityId); Add("Scope", "Host", row.Scope.HostId); Add("Scope", "Execution root", row.Scope.ExecutionRootId);
                foreach (var property in presentation.Native) Properties.Add(property);
                if (presentation.Prefetch is { } prefetch) { Prefetch = new(prefetch); DataTabIndex = 0; }
                foreach (var occurrence in detail.ReadOccurrences)
                {
                    var read = occurrence.ReadMetadata;
                    var coverage = "Not recorded";
                    try
                    {
                        using var metadata = JsonDocument.Parse(ForensicArtifactContract.CanonicalJson(occurrence.SourceRunMetadataJson));
                        if (metadata.RootElement.ValueKind == JsonValueKind.Object && metadata.RootElement.TryGetProperty("coverage", out var recorded)) coverage = recorded.GetRawText();
                    }
                    catch (Exception error) when (error is JsonException or InvalidDataException) { coverage = "Unavailable: malformed source-run coverage metadata"; }
                    var description = $"Source run {occurrence.SourceRunId}; job {occurrence.IngestionJobId}; receipt {occurrence.ReceiptSha256}; " +
                        $"read interval {read?.ReadStartedUtc.ToString("O") ?? "Unknown"} — {occurrence.ReadCompletedUtc:O}; source created {read?.SourceCreatedUtc?.ToString("O") ?? "Unknown"}; source modified {read?.SourceLastModifiedUtc?.ToString("O") ?? "Unknown"}; " +
                        $"consistency {read?.Consistency.ToString() ?? "Unknown"}; read {read?.Status.ToString() ?? "Unknown"}; parser {read?.ParserStatus.ToString() ?? "Unknown"}; run {occurrence.SourceRunStatus}; diagnostic {read?.DiagnosticCode}: {read?.Diagnostic}; coverage {coverage}";
                    ReadOccurrences.Add(new("Read occurrence", occurrence.ReadCompletedUtc.ToString("O"), description));
                    Add("Source read " + occurrence.SourceRunId, "Read started UTC", read?.ReadStartedUtc.ToString("O") ?? "Unknown");
                    Add("Source read " + occurrence.SourceRunId, "Read completed UTC", occurrence.ReadCompletedUtc.ToString("O"));
                    Add("Source read " + occurrence.SourceRunId, "Source created UTC", read?.SourceCreatedUtc?.ToString("O") ?? "Unknown");
                    Add("Source read " + occurrence.SourceRunId, "Source modified UTC", read?.SourceLastModifiedUtc?.ToString("O") ?? "Unknown");
                    Add("Source read " + occurrence.SourceRunId, "Consistency / read / parser / run status", $"{read?.Consistency} / {read?.Status} / {read?.ParserStatus} / {occurrence.SourceRunStatus}");
                    Add("Source read " + occurrence.SourceRunId, "Coverage", coverage);
                    Add("Source read " + occurrence.SourceRunId, "Diagnostic", string.IsNullOrEmpty(read?.Diagnostic) ? "None recorded" : read.Diagnostic);
                }
                if (detail.ReadOccurrenceCount > detail.ReadOccurrences.Count) ReadOccurrences.Add(new("Read occurrence", "Additional retained lineage", $"{detail.ReadOccurrenceCount - detail.ReadOccurrences.Count:N0} more receipt links are retained."));
                InspectorPaneViewModel.Load(new() { TargetKind = "Forensic artifact result", TargetTable = "Artifacts", TargetId = row.ArtifactId, Header = row.Name, Subtitle = row.ArtifactType + " · " + row.Category, Properties = Properties.ToArray(), CaseId = row.Scope.CaseId, EvidenceSessionId = row.Scope.EvidenceSessionId, CaptureId = row.Scope.CaptureId, SourceIdentityId = row.Scope.SourceIdentityId, HostId = row.Scope.HostId, ExecutionRootId = row.Scope.ExecutionRootId, SourceRunId = row.SourceRunId, IngestionJobId = row.IngestionJobId });
            }
            catch (OperationCanceledException) { }
            catch (Exception error) { if (!token.IsCancellationRequested && selection == _selectionGeneration) Status = "Artifacts details unavailable: " + error.Message; }
        }
        void Add(string group, string name, string value, string? type = null) => Properties.Add(new(group, type == null ? name : name + " (" + type + ")", value));
    }
    private static IReadOnlyList<PropertyItemViewModel> ExpandNative(IEnumerable<ForensicArtifactResultProperty> native, CancellationToken token)
    {
        var rows = new List<PropertyItemViewModel>();
        foreach (var property in native)
        {
            token.ThrowIfCancellationRequested();
            if (property.ValueType is "Object" or "Array" && property.Value != null)
            {
                using var document = JsonDocument.Parse(property.Value, new JsonDocumentOptions { MaxDepth = 32 });
                Expand(property.Name, document.RootElement);
            }
            else Add(property.Name, property.Value ?? "null", property.ValueType);
        }
        return rows;
        void Add(string name, string value, string type) => rows.Add(new("Native artifact property", name + " (" + type + ")", value));
        void Expand(string path, JsonElement value)
        {
            token.ThrowIfCancellationRequested();
            if (value.ValueKind == JsonValueKind.Object)
            {
                var count = 0;
                foreach (var child in value.EnumerateObject()) { count++; Expand(path + "." + child.Name, child.Value); }
                if (count == 0) Add(path, "{}", "Object");
            }
            else if (value.ValueKind == JsonValueKind.Array)
            {
                var index = 0;
                foreach (var child in value.EnumerateArray()) Expand(path + "[" + index++ + "]", child);
                if (index == 0) Add(path, "[]", "Array");
            }
            else Add(path, value.ValueKind == JsonValueKind.String ? value.GetString() ?? "null" : value.GetRawText(), value.ValueKind.ToString());
        }
    }
    private static string? PropertyValue(PropertyItemViewModel row, string column) => column switch { "Group" => row.Group, "Name" => row.Name, "Value" => row.Value, _ => throw new ArgumentOutOfRangeException(nameof(column)) };
    internal void ApplyPropertySort() { using (PropertiesView.DeferRefresh()) { PropertiesView.SortDescriptions.Clear(); PropertiesView.SortDescriptions.Add(new(PropertySort, PropertySortDirection)); } }
    internal void ApplyReadOccurrenceSort() { using (ReadOccurrencesView.DeferRefresh()) { ReadOccurrencesView.SortDescriptions.Clear(); ReadOccurrencesView.SortDescriptions.Add(new(ReadOccurrenceSort, ReadOccurrenceSortDirection)); } }
    private async Task<ColumnFilterValuePage> ValuesAsync(ForensicArtifactResultColumn column, string search, ColumnFilterValueSort sort, CancellationToken token)
    {
        var query = CaptureQuery() with { Filters = CaptureFilters(_explorerFilters, column) };
        return await _session.ValuesAsync(query, column, search, sort, token);
    }
    private bool CanCollect() => !_collecting && !IsDisposed && !ReadsSuspended && Context != null && _actions?.CaptureTarget() != null;
    private bool CanCancelCollection() => _job.HasValue && _actionTarget != null && _actionContext == Context && _actionRevision == _session.Revision && !IsDisposed && !ReadsSuspended;
    internal void NotifyActions() { CollectPrefetchCommand.NotifyCanExecuteChanged(); CancelCollectionCommand.NotifyCanExecuteChanged(); }
    private async Task CollectPrefetchAsync()
    {
        if (!CanCollect()) return; var target = _actions!.CaptureTarget()!; var context = Context; var revision = _session.Revision;
        _action.Cancel(); _action.Dispose(); _action = new(); var token = _action.Token; _collecting = true; NotifyActions();
        try
        {
            var accepted = await _actions.CollectPrefetchAsync(target, token);
            if (!Current()) return; ActionStatus = accepted.Diagnostic;
            if (!accepted.Succeeded || accepted.AcceptedJobId is not { } job) return;
            _job = job; _actionTarget = target; _actionContext = context; _actionRevision = revision; NotifyActions();
            var finished = await _actions.WaitAsync(target, job, token);
            if (Current()) ActionStatus = finished.Succeeded ? "Prefetch analysis durably completed. Use Refresh from DB to view the assessed snapshot." : finished.Diagnostic;
        }
        catch (OperationCanceledException) { }
        catch (Exception error) { if (Current()) ActionStatus = "Collect Prefetch unavailable: " + error.Message; }
        finally { _job = null; _actionTarget = null; _actionContext = null; _collecting = false; NotifyActions(); }
        bool Current() => !IsDisposed && !ReadsSuspended && !token.IsCancellationRequested && context == Context && revision == _session.Revision && _actions.CaptureTarget() == target;
    }
    private async Task CancelCollectionAsync()
    {
        if (!CanCancelCollection()) return;
        var target = _actionTarget!; var job = _job!.Value; var context = _actionContext; var revision = _actionRevision; var token = _action.Token;
        try
        {
            var result = await _actions!.CancelAsync(target, job, token);
            if (!IsDisposed && !ReadsSuspended && !token.IsCancellationRequested && Context == context && revision == _session.Revision && _actions.CaptureTarget() == target)
                ActionStatus = result.Diagnostic;
        }
        catch (OperationCanceledException) { }
    }
    private async Task Track(Task task) { _work.Add(task); try { await task; } finally { _work.Remove(task); } }
    internal sealed record RetainedState(ForensicArtifactResultRow[] Rows, PropertyItemViewModel[] Properties, PropertyItemViewModel[] Occurrences, string Status, string? Selection, bool Loaded, long Matching, ForensicArtifactResultColumnFilter[] ExplorerFilters, ForensicArtifactResultGreenSelector[] ExplorerSelectors, PrefetchPresentation? Prefetch, int DataTabIndex);
    internal RetainedState Retain() => new(Rows.ToArray(), Properties.ToArray(), ReadOccurrences.ToArray(), Status, SelectedRow?.ArtifactId ?? _retainedSelection, _loaded, MatchingRows, _explorerFilters.ToArray(), _explorerSelectors.ToArray(), Prefetch, DataTabIndex);
    internal void Restore(RetainedState state) { Rows.Clear(); foreach (var row in state.Rows) Rows.Add(row); Properties.Clear(); foreach (var property in state.Properties) Properties.Add(property); ReadOccurrences.Clear(); foreach (var occurrence in state.Occurrences) ReadOccurrences.Add(occurrence); Status = state.Status; _retainedSelection = state.Selection; _loaded = state.Loaded; MatchingRows = state.Matching; _explorerFilters = state.ExplorerFilters; _explorerSelectors = state.ExplorerSelectors; _selected = Rows.FirstOrDefault(row => row.ArtifactId == state.Selection); Prefetch = state.Prefetch; DataTabIndex = state.DataTabIndex; OnPropertyChanged(nameof(SelectedRow)); }
    internal void Invalidate(bool captureChanged) { _request.Cancel(); _detail.Cancel(); _action.Cancel(); _generation++; _selectionGeneration++; _loaded = false; LastRefreshSucceeded = false; if (captureChanged) { foreach (var filter in HeaderFilters.Values.Concat(PropertyFilters.Values).Concat(ReadOccurrenceFilters.Values)) filter.Reset(false); GreenSelectors.Clear(); _explorerFilters = []; _explorerSelectors = []; _offset = 0; _retainedSelection = null; _selected = null; Rows.Clear(); Properties.Clear(); ReadOccurrences.Clear(); Prefetch = null; DataTabIndex = 4; InspectorPaneViewModel.Clear(); MatchingRows = 0; Status = "Artifacts capture changed; refresh the assessed read binding."; OnPropertyChanged(nameof(SelectedRow)); } NotifyActions(); }
    internal async Task QuiesceAsync(CancellationToken token) { _suspended = true; _request.Cancel(); _detail.Cancel(); _action.Cancel(); NotifyActions(); foreach (var filter in HeaderFilters.Values.Concat(PropertyFilters.Values).Concat(ReadOccurrenceFilters.Values)) filter.Close(); await Task.WhenAll(_work.ToArray()).WaitAsync(token); }
    internal void Resume() { _suspended = false; NotifyActions(); }
    public override void Dispose() { if (IsDisposed) return; IsDisposed = true; _suspended = true; _request.Cancel(); _detail.Cancel(); _action.Cancel(); foreach (var filter in HeaderFilters.Values.Concat(PropertyFilters.Values).Concat(ReadOccurrenceFilters.Values)) filter.Close(); Rows.Clear(); Properties.Clear(); ReadOccurrences.Clear(); Prefetch = null; }
}
