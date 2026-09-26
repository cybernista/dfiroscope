using CommunityToolkit.Mvvm.Input;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed partial class EventsWorkspaceViewModel
{
    private CancellationTokenSource _statistics = new();
    private long _statisticsRevision;
    private EventsStatisticsScope _statisticsScope;
    private EventsFieldStatistics? _statisticsResult;
    private EventFieldStatistics? _selectedStatisticsField;
    private bool _statisticsBusy;
    private string _statisticsStatus = "Choose a scope and calculate exact native field statistics across published event sources.";
    public EventsStatisticsScope StatisticsScope
    {
        get => _statisticsScope;
        set { if (SetProperty(ref _statisticsScope, value)) { OnPropertyChanged(nameof(StatisticsScopeIndex)); InvalidateStatistics("Statistics scope changed; calculate to read this scope."); } }
    }
    public int StatisticsScopeIndex { get => (int)StatisticsScope; set { if (value is 0 or 1) StatisticsScope = (EventsStatisticsScope)value; } }
    public EventsFieldStatistics? StatisticsResult => _statisticsResult;
    public IReadOnlyList<EventFieldStatistics> StatisticsFields => _statisticsResult?.Fields ?? [];
    public EventFieldStatistics? SelectedStatisticsField
    {
        get => _selectedStatisticsField;
        set { if (SetProperty(ref _selectedStatisticsField, value)) OnPropertyChanged(nameof(StatisticsTopValues)); }
    }
    public IReadOnlyList<EventFieldFrequency> StatisticsTopValues => SelectedStatisticsField?.TopValues ?? [];
    public bool StatisticsBusy { get => _statisticsBusy; private set => SetProperty(ref _statisticsBusy, value); }
    public string StatisticsStatus { get => _statisticsStatus; private set => SetProperty(ref _statisticsStatus, value); }
    public IAsyncRelayCommand CalculateStatisticsCommand { get; private set; } = null!;
    public IRelayCommand CancelStatisticsCommand { get; private set; } = null!;
    public IRelayCommand AddStatisticsColumnCommand { get; private set; } = null!;

    private void InitializeStatistics()
    {
        CalculateStatisticsCommand = new AsyncRelayCommand(async () => { var task = CalculateStatisticsAsync(); Track(task); await task; });
        CancelStatisticsCommand = new RelayCommand(() => InvalidateStatistics("Statistics canceled; no incomplete result presented as complete."));
        AddStatisticsColumnCommand = new RelayCommand(() =>
        {
            if (_statisticsResult?.Binding != _session.Binding || SelectedStatisticsField is not { } field) return;
            PublishFieldChoices(ExtractedFields.Select(f => f.Path).Append(field.Path));
            var choice = ExtractedFields.FirstOrDefault(f => f.Path == field.Path && f.Identity.EventType == field.EventType)
                ?? ExtractedFields.Single(f => f.Path == field.Path && f.Identity.EventType == null);
            choice.IsVisible = true;
        });
    }

    private void InvalidateStatistics(string message = "Statistics inputs changed; calculate against the current snapshot and filters.")
    {
        ++_statisticsRevision; _statistics.Cancel();
        _statisticsResult = null; SelectedStatisticsField = null; StatisticsBusy = false;
        StatisticsStatus = message;
        OnPropertyChanged(nameof(StatisticsResult)); OnPropertyChanged(nameof(StatisticsFields));
    }

    internal async Task CalculateStatisticsAsync()
    {
        if (IsDisposed || _suspended || !FeaturePublication.IsPublished(EventsWorkspaceFeatureComposition.Id) ||
            (!FeaturePublication.WindowsSecurityEvents && !FeaturePublication.EventTelemetry) || _session.Binding is not { } binding) return;
        InvalidateStatistics();
        _statistics.Dispose(); _statistics = new();
        var token = _statistics.Token; var revision = _statisticsRevision;
        var filter = _filter; var scope = StatisticsScope;
        var label = scope == EventsStatisticsScope.EntireCapture ? "Entire capture" : "Current filtered dataset (all pages)";
        var context = $"{label}; recorded published event sources; session {binding.EvidenceSessionId}; capture generation {binding.CaptureGeneration}, snapshot {binding.SnapshotGeneration}";
        StatisticsBusy = true; StatisticsStatus = context + "; preparing exact query…";
        bool Current() => !token.IsCancellationRequested && !IsDisposed && !_suspended && revision == _statisticsRevision && binding == _session.Binding;
        try
        {
            var progress = new Progress<EventsStatisticsProgress>(p =>
            {
                if (Current() && StatisticsBusy) StatisticsStatus = $"{context}; extracted {p.ProcessedEvents:N0} / {p.EligibleEvents:N0} eligible events…";
            });
            var result = await _session.Reader.FieldStatisticsAsync(filter, scope, progress, token);
            if (!Current() || result.Binding != binding) return;
            _statisticsResult = result;
            OnPropertyChanged(nameof(StatisticsResult)); OnPropertyChanged(nameof(StatisticsFields));
            PublishFieldChoices(ExtractedFields.Select(f => f.Path));
            SelectedStatisticsField = StatisticsFields.FirstOrDefault();
            StatisticsStatus = $"{context}; scan complete: {result.EligibleEvents:N0} eligible events, {result.Fields.Count:N0} qualified fields; " +
                $"{result.AvailableEvents:N0} fully extracted, {result.PartialEvents:N0} partial, {result.FailedEvents:N0} failed. " +
                "Counts cover observed extracted fields; partial/failed extraction is not field absence. Unknown versions remain unqualified schema observations. " +
                $"Exact strings; top ten counts events, ties use ordinal value order. {result.Elapsed.TotalSeconds:F2}s; {result.DerivedBytes:N0} disposable bytes. " +
                $"Extractor {result.ExtractorVersion}. Acquisition coverage unknown.";
        }
        catch (OperationCanceledException) { if (Current()) StatisticsStatus = context + "; canceled."; }
        catch (Exception ex) { if (Current()) StatisticsStatus = context + "; statistics unavailable: " + ex.Message; }
        finally { if (revision == _statisticsRevision) StatisticsBusy = false; }
    }
}
