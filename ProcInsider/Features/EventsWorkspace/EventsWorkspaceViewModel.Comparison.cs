using CommunityToolkit.Mvvm.Input;
using ProcInsider.Services.Events;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed partial class EventsWorkspaceViewModel
{
    private CancellationTokenSource _comparison = new();
    private CancellationTokenSource _comparisonAdds = new();
    private EventsReadBinding? _comparisonBinding;
    private EventsComparisonEvent[] _comparisonEvents = [];
    private EventsComparisonRow[] _comparisonRows = [];
    private EventsComparisonFieldChoice[] _comparisonFields = [];
    private EventsComparisonEvent? _comparisonReference;
    private EventsComparisonMode _comparisonMode;
    private bool _comparisonDifferencesOnly;
    private string _comparisonStatus = "Select an event; use its context menu to pin events for comparison.";
    public IReadOnlyList<EventsComparisonEvent> ComparisonEvents => _comparisonEvents;
    public IReadOnlyList<EventsComparisonEvent> ComparisonColumns => _comparisonReference == null ? _comparisonEvents : [_comparisonReference, .. _comparisonEvents];
    public IReadOnlyList<EventsComparisonRow> ComparisonRows => _comparisonRows;
    public IReadOnlyList<EventsComparisonFieldChoice> ComparisonFields => _comparisonFields;
    public Array ComparisonModes => Enum.GetValues<EventsComparisonMode>();
    public EventsComparisonMode ComparisonMode { get => _comparisonMode; set { if (SetProperty(ref _comparisonMode, value)) StartComparison(); } }
    public bool ComparisonDifferencesOnly { get => _comparisonDifferencesOnly; set { if (SetProperty(ref _comparisonDifferencesOnly, value)) StartComparison(); } }
    public EventsComparisonEvent? ComparisonReference => _comparisonReference;
    public string ComparisonStatus { get => _comparisonStatus; private set => SetProperty(ref _comparisonStatus, value); }
    public IAsyncRelayCommand<EventsWorkspaceRowViewModel> AddComparisonCommand { get; private set; } = null!;
    public IRelayCommand<EventsComparisonEvent> RemoveComparisonCommand { get; private set; } = null!;
    public IRelayCommand<EventsComparisonEvent> InspectComparisonCommand { get; private set; } = null!;
    public IRelayCommand ClearComparisonCommand { get; private set; } = null!;
    public IRelayCommand CancelComparisonCommand { get; private set; } = null!;
    public IRelayCommand RefreshComparisonCommand { get; private set; } = null!;
    private bool CanCompare => !IsDisposed && !_suspended && FeaturePublication.IsPublished(EventsWorkspaceFeatureComposition.Id) &&
        (FeaturePublication.WindowsSecurityEvents || FeaturePublication.EventTelemetry);
    private void InitializeComparison()
    {
        AddComparisonCommand = new AsyncRelayCommand<EventsWorkspaceRowViewModel>(async row => { var task = AddComparisonAsync(row); Track(task); await task; });
        RemoveComparisonCommand = new RelayCommand<EventsComparisonEvent>(item =>
        {
            if (!CanCompare || item == null) return;
            _comparisonEvents = _comparisonEvents.Where(e => e != item).ToArray();
            PublishComparisonEvents(); StartComparison();
        });
        InspectComparisonCommand = new RelayCommand<EventsComparisonEvent>(item =>
        {
            if (!CanCompare || _comparisonBinding != _session.Binding || item == null || !_comparisonEvents.Contains(item)) return;
            SetFilter(new() { ExactEvent = item.Reference }, "Comparison source event");
            _retainedSelection = item.Reference; StartRefresh();
        });
        ClearComparisonCommand = new RelayCommand(() => { ClearComparison("Comparison cleared."); StartComparison(); });
        CancelComparisonCommand = new RelayCommand(() => { _comparisonAdds.Cancel(); CancelComparison("Comparison canceled; selections retained. Recompute to retry."); });
        RefreshComparisonCommand = new RelayCommand(StartComparison);
    }
    internal async Task AddComparisonAsync(EventsWorkspaceRowViewModel? target = null)
    {
        if (!CanCompare || (target ?? SelectedEvent) is not { } row || !Rows.Contains(row) || _loadedBinding == null || _loadedBinding != _session.Binding) return;
        if (_comparisonEvents.Any(e => e.Reference == row.Reference)) return;
        if (_comparisonAdds.IsCancellationRequested) { _comparisonAdds.Dispose(); _comparisonAdds = new(); }
        var token = _comparisonAdds.Token;
        var binding = _loadedBinding;
        try
        {
            var extraction = await Task.Run(() => row.ExtractNativeFields(token), token);
            token.ThrowIfCancellationRequested();
            if (!CanCompare || binding != _session.Binding) return;
            var item = new EventsComparisonEvent(row, extraction);
            _comparisonBinding = binding;
            _comparisonEvents = [.. _comparisonEvents, item];
            PublishComparisonEvents(); StartComparison();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { if (!token.IsCancellationRequested) ComparisonStatus = $"Cannot add event: {ex.Message}. Remove events or retry; no sampled result shown."; }
    }
    private void PublishComparisonEvents()
    {
        OnPropertyChanged(nameof(ComparisonEvents)); OnPropertyChanged(nameof(ComparisonReference)); OnPropertyChanged(nameof(ComparisonColumns));
    }
    private void CancelComparison(string status)
    {
        _comparison.Cancel(); _comparisonRows = []; OnPropertyChanged(nameof(ComparisonRows)); ComparisonStatus = status;
    }
    private void ClearComparison(string status)
    {
        _comparisonAdds.Cancel();
        CancelComparison(status); _comparisonEvents = []; _comparisonReference = null; _comparisonBinding = null; _comparisonFields = [];
        PublishComparisonEvents(); OnPropertyChanged(nameof(ComparisonFields));
    }
    private void ValidateComparisonBinding(EventsReadBinding? binding)
    {
        if (_comparisonEvents.Length > 0 && _comparisonBinding != binding)
            ClearComparison("Comparison cleared as stale: evidence snapshot/capture changed. Add events from the current evidence binding.");
    }
    private void StartComparison()
    {
        if (!CanCompare) return;
        ValidateComparisonBinding(_session.Binding);
        _comparisonReference = null;
        PublishComparisonEvents();
        if (SelectedEvent == null || _loadedBinding != _session.Binding)
        {
            // Keep an explicit stale/capture diagnostic until a current selection exists.
            _comparison.Cancel(); _comparisonRows = []; OnPropertyChanged(nameof(ComparisonRows));
            if (_comparisonEvents.Length > 0)
                ComparisonStatus = "Select a listing event for the first column; pinned events are retained.";
            return;
        }
        CancelComparison("Comparing all selected events…");
        _comparison.Dispose(); _comparison = new();
        Track(BuildComparisonAsync(_comparison.Token));
    }
    private async Task BuildComparisonAsync(CancellationToken token)
    {
        var pinned = _comparisonEvents;
        var selectedRow = SelectedEvent!;
        const int reference = 0;
        var binding = _loadedBinding;
        var mode = ComparisonMode; var differences = ComparisonDifferencesOnly;
        var selected = _comparisonFields.Where(f => f.IsSelected).Select(f => f.Field).ToHashSet();
        var preset = _presetColumns.ToArray();
        try
        {
            var result = await Task.Run(() =>
            {
                var current = new EventsComparisonEvent(selectedRow, selectedRow.Extraction ?? NativeEventFieldExtractor.Extract(
                    selectedRow.Details, selectedRow.EventCode, selectedRow.Provider, selectedRow.Channel, token));
                EventsComparisonEvent[] events = [current, .. pinned];
                var fields = new HashSet<EventsComparisonField>(selected);
                foreach (var item in events)
                {
                    token.ThrowIfCancellationRequested();
                    if (item.Extraction.EventType is not { } type) continue;
                    foreach (var field in item.Extraction.Fields) { token.ThrowIfCancellationRequested(); fields.Add(new(type, field.Path)); }
                    foreach (var column in preset.Where(c => c.Identity.BuiltIn == null && (c.Identity.EventType == null || c.Identity.EventType == type)))
                        fields.Add(new(type, column.Identity.Path!));
                }
                foreach (var column in preset.Where(c => c.Identity.BuiltIn == null && c.Identity.EventType != null))
                    fields.Add(new(column.Identity.EventType!, column.Identity.Path!));
                var ordered = fields.OrderBy(f => f.Type.Provider, StringComparer.Ordinal).ThenBy(f => f.Type.Channel, StringComparer.Ordinal)
                    .ThenBy(f => f.Type.EventId).ThenBy(f => f.Type.Version).ThenBy(f => f.Path, StringComparer.Ordinal).ToArray();
                var rows = new List<EventsComparisonRow>();
                foreach (var field in ordered)
                {
                    token.ThrowIfCancellationRequested();
                    if (mode == EventsComparisonMode.Manual && !selected.Contains(field) || mode == EventsComparisonMode.Preset &&
                        !preset.Any(c => c.Identity.BuiltIn == null && c.Identity.Path == field.Path && (c.Identity.EventType == null || c.Identity.EventType == field.Type))) continue;
                    var baseline = events[reference].Get(field); var different = false;
                    foreach (var item in events) { token.ThrowIfCancellationRequested(); if (item.Get(field) != baseline) different = true; }
                    if (!differences || different) rows.Add(new(field, events, reference, different));
                }
                return (ordered, rows: rows.ToArray(), current);
            }, token);
            token.ThrowIfCancellationRequested();
            if (!CanCompare || binding != _session.Binding || selectedRow != SelectedEvent) return;
            _comparisonReference = result.current;
            _comparisonBinding = binding;
            PublishComparisonEvents();
            _comparisonFields = result.ordered.Select(f => new EventsComparisonFieldChoice(f, selected.Contains(f), StartComparison)).ToArray();
            _comparisonRows = result.rows;
            OnPropertyChanged(nameof(ComparisonFields)); OnPropertyChanged(nameof(ComparisonRows));
            ComparisonStatus = $"Current selection + {pinned.Length:N0} pinned events; {result.rows.Length:N0} displayed qualified fields. Exact original strings; no sampling. " +
                $"{ComparisonColumns.Count(e => e.Extraction.Status != EventFieldExtractionStatus.Available):N0} partial/unavailable extractions; see event headers. " +
                (mode == EventsComparisonMode.Preset ? "Uses native columns of the active saved preset; unscoped paths expand per schema." : "");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { if (!token.IsCancellationRequested) ComparisonStatus = $"Comparison unavailable: {ex.Message}. Remove events or fields, then recompute; no partial matrix shown."; }
    }
}
