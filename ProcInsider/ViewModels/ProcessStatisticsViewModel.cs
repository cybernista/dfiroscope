using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class ProcessStatisticsViewModel : ViewModelBase
{
    private const int MaxVisibleStatistics = 100000;
    private const int MaxTrendSamples = 100000;
    private const int MaxTrendBuckets = 240;
    private const double TrendCanvasWidth = 240;
    private const double TrendCanvasHeight = 80;

    private readonly TelemetryProjectionService _projectionService;
    private readonly InspectorPaneViewModel _inspectorPaneViewModel;
    private readonly HashSet<string> _includedProcessKeys = new(StringComparer.Ordinal);
    private readonly HashSet<string> _excludedProcessKeys = new(StringComparer.Ordinal);
    private IReadOnlyList<ExplorerScope> _includedScopes = [];
    private IReadOnlyList<ExplorerScope> _excludedScopes = [];
    private ExplorerScope? _activeScope;
    private bool _hasGreenSelection;
    private ProcessRowViewModel? _selectedProcess;
    private string _selectedProcessKey = string.Empty;
    private string _selectedProcessEntityId = string.Empty;
    private string _selectedProcessLabel = string.Empty;
    private int _trendRefreshVersion;

    [ObservableProperty]
    private ObservableCollection<ProcessStatisticsRowViewModel> statistics = new();

    [ObservableProperty]
    private ICollectionView? statisticsView;

    [ObservableProperty]
    private ProcessStatisticsRowViewModel? selectedStatistic;

    [ObservableProperty]
    private string statusMessage = "Refresh from db to load process statistics.";

    [ObservableProperty]
    private int visibleProcessCount;

    [ObservableProperty]
    private string totalReadBytes = "0 B";

    [ObservableProperty]
    private string totalWrittenBytes = "0 B";

    [ObservableProperty]
    private string totalCpuTime = "0.0s";

    [ObservableProperty]
    private string selectedProcessHeader = "No process selected.";

    [ObservableProperty]
    private bool isTrendLoading;

    [ObservableProperty]
    private bool hasTrendData;

    [ObservableProperty]
    private string trendStatusMessage = "Select a process with at least two persisted samples to show trends.";

    [ObservableProperty]
    private string trendWindow = string.Empty;

    [ObservableProperty]
    private string cpuTrendPeak = "Peak: <not available>";

    [ObservableProperty]
    private string readTrendPeak = "Peak: <not available>";

    [ObservableProperty]
    private string writtenTrendPeak = "Peak: <not available>";

    [ObservableProperty]
    private PointCollection cpuTrendPoints = new();

    [ObservableProperty]
    private PointCollection readTrendPoints = new();

    [ObservableProperty]
    private PointCollection writtenTrendPoints = new();

    public ProcessStatisticsViewModel(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel)
    {
        _projectionService = projectionService;
        _inspectorPaneViewModel = inspectorPaneViewModel;
        StatisticsView = CollectionViewSource.GetDefaultView(Statistics);
        StatisticsView.Filter = FilterStatistic;
    }

    [RelayCommand]
    public async Task RefreshStatisticsAsync()
    {
        var rows = await Task.Run(() => PrepareSnapshotRows(
            _projectionService.GetLatestProcessStatistics(MaxVisibleStatistics)));
        ApplyPreparedSnapshot(rows, refreshTrend: false);
        await RefreshSelectedTrendAsync();
    }

    public void ApplySnapshot(IReadOnlyList<ProcessStatisticsRecord> samples)
    {
        ApplyPreparedSnapshot(PrepareSnapshotRows(samples), refreshTrend: true);
    }

    internal static IReadOnlyList<ProcessStatisticsRowViewModel> PrepareSnapshotRows(
        IReadOnlyList<ProcessStatisticsRecord> samples) =>
        samples
            .Select(sample => new ProcessStatisticsRowViewModel(sample))
            .ToArray();

    internal void ApplyPreparedSnapshot(
        IReadOnlyList<ProcessStatisticsRowViewModel> rows,
        bool refreshTrend = true)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var previouslySelectedKey = SelectedStatistic?.ProcessKey;

        SelectedStatistic = null;
        Statistics = new ObservableCollection<ProcessStatisticsRowViewModel>(rows);
        StatisticsView = CollectionViewSource.GetDefaultView(Statistics);
        StatisticsView.Filter = FilterStatistic;

        var targetKey = FirstNonEmpty(_selectedProcessKey, previouslySelectedKey);
        if (!string.IsNullOrWhiteSpace(targetKey))
        {
            SelectedStatistic = Statistics.FirstOrDefault(row =>
                !string.IsNullOrWhiteSpace(_selectedProcessEntityId)
                    ? string.Equals(row.ProcessEntityId, _selectedProcessEntityId, StringComparison.Ordinal)
                    : string.Equals(row.ProcessKey, targetKey, StringComparison.Ordinal));
        }

        StatisticsView.Refresh();
        UpdateSummary();
        UpdateSelectedProcessDetails();
        if (refreshTrend)
        {
            _ = RefreshSelectedTrendAsync();
        }
    }

    public void SetSelectedProcess(ProcessRowViewModel? process)
    {
        _selectedProcess = process;
        _selectedProcessKey = process?.ProcessKey ?? string.Empty;
        _selectedProcessEntityId = process?.ProcessInfo.ProcessEntityId ?? string.Empty;
        _selectedProcessLabel = process == null
            ? string.Empty
            : $"{process.ProcessName} (PID {process.ProcessId})";

        if (!string.IsNullOrWhiteSpace(_selectedProcessKey))
        {
            var matchingRow = Statistics.FirstOrDefault(row =>
                !string.IsNullOrWhiteSpace(_selectedProcessEntityId)
                    ? string.Equals(row.ProcessEntityId, _selectedProcessEntityId, StringComparison.Ordinal)
                    : string.Equals(row.ProcessKey, _selectedProcessKey, StringComparison.Ordinal));
            if (matchingRow != null)
            {
                SelectedStatistic = matchingRow;
                UpdateSummary();
                return;
            }
        }

        UpdateSummary();
        UpdateSelectedProcessDetails();
        _ = RefreshSelectedTrendAsync();
    }

    public void ApplyActiveScope(ExplorerScope? activeScope)
    {
        _activeScope = IsProcessScope(activeScope) ? activeScope : null;
        StatisticsView?.Refresh();
        UpdateSummary();
        UpdateSelectedProcessDetails();
    }

    public void ApplyScopedSelection(
        IReadOnlyList<ExplorerScope> includedScopes,
        IReadOnlyList<ExplorerScope> excludedScopes,
        IEnumerable<string> includedProcessKeys,
        IEnumerable<string> excludedProcessKeys,
        bool hasGreenSelection)
    {
        _includedScopes = includedScopes.Where(IsProcessScope).ToList();
        _excludedScopes = excludedScopes.Where(IsProcessScope).ToList();
        _includedProcessKeys.Clear();
        _excludedProcessKeys.Clear();
        foreach (var key in includedProcessKeys.Where(key => !string.IsNullOrWhiteSpace(key)))
        {
            _includedProcessKeys.Add(key);
        }

        foreach (var key in excludedProcessKeys.Where(key => !string.IsNullOrWhiteSpace(key)))
        {
            _excludedProcessKeys.Add(key);
        }

        _hasGreenSelection = hasGreenSelection;
        StatisticsView?.Refresh();
        UpdateSummary();
        UpdateSelectedProcessDetails();
    }

    public void Clear()
    {
        _selectedProcess = null;
        SelectedStatistic = null;
        Statistics.Clear();
        VisibleProcessCount = 0;
        TotalReadBytes = "0 B";
        TotalWrittenBytes = "0 B";
        TotalCpuTime = "0.0s";
        StatusMessage = "Refresh from db to load process statistics.";
        UpdateSelectedProcessDetails();
        ClearTrend("Select a process with at least two persisted samples to show trends.");
    }

    partial void OnSelectedStatisticChanged(ProcessStatisticsRowViewModel? value)
    {
        UpdateSelectedProcessDetails();
        _ = RefreshSelectedTrendAsync();
        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a process statistic row to inspect it here.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }

    private async Task RefreshSelectedTrendAsync()
    {
        var processKey = FirstNonEmpty(SelectedStatistic?.ProcessKey, _selectedProcessKey);
        var processLabel = FirstNonEmpty(SelectedStatistic?.ProcessDisplay, _selectedProcessLabel);
        var version = ++_trendRefreshVersion;
        if (string.IsNullOrWhiteSpace(processKey))
        {
            ClearTrend("Select a process with at least two persisted samples to show trends.");
            return;
        }

        IsTrendLoading = true;
        TrendStatusMessage = $"Loading trend samples for {processLabel}...";

        try
        {
            var snapshot = await Task.Run(() => BuildTrendSnapshot(processKey, processLabel));
            if (version != _trendRefreshVersion)
            {
                return;
            }

            HasTrendData = snapshot.HasData;
            TrendStatusMessage = snapshot.StatusMessage;
            TrendWindow = snapshot.WindowDisplay;
            CpuTrendPeak = snapshot.CpuPeakDisplay;
            ReadTrendPeak = snapshot.ReadPeakDisplay;
            WrittenTrendPeak = snapshot.WrittenPeakDisplay;
            CpuTrendPoints = ToPointCollection(snapshot.CpuPoints);
            ReadTrendPoints = ToPointCollection(snapshot.ReadPoints);
            WrittenTrendPoints = ToPointCollection(snapshot.WrittenPoints);
        }
        catch (Exception ex)
        {
            if (version == _trendRefreshVersion)
            {
                ClearTrend($"Trend data unavailable: {ex.Message}");
            }
        }
        finally
        {
            if (version == _trendRefreshVersion)
            {
                IsTrendLoading = false;
            }
        }
    }

    private TrendSnapshot BuildTrendSnapshot(string processKey, string processLabel)
    {
        var samples = _projectionService
            .GetProcessStatisticsSamples(processKey, MaxTrendSamples, _selectedProcessEntityId)
            .Where(sample => sample.ObservedUtc != default)
            .OrderBy(sample => sample.ObservedUtc)
            .ToList();
        if (samples.Count < 2)
        {
            return TrendSnapshot.Empty($"Not enough persisted samples for {processLabel}.");
        }

        var buckets = new SortedDictionary<DateTime, TrendBucket>();
        ProcessStatisticsRecord? previous = null;
        foreach (var sample in samples)
        {
            if (previous != null)
            {
                var bucketStart = TruncateToMinute(sample.ObservedUtc);
                if (!buckets.TryGetValue(bucketStart, out var bucket))
                {
                    bucket = new TrendBucket(bucketStart);
                    buckets[bucketStart] = bucket;
                }

                var cpuDeltaTicks = PositiveDelta(sample.TotalProcessorTimeTicks, previous.TotalProcessorTimeTicks);
                if (cpuDeltaTicks.HasValue)
                {
                    bucket.CpuSeconds += TimeSpan.FromTicks(cpuDeltaTicks.Value).TotalSeconds;
                    bucket.HasCpu = true;
                }

                var readDelta = PositiveDelta(sample.ReadBytes, previous.ReadBytes);
                if (readDelta.HasValue)
                {
                    bucket.ReadBytes += readDelta.Value;
                    bucket.HasRead = true;
                }

                var writtenDelta = PositiveDelta(sample.WrittenBytes, previous.WrittenBytes);
                if (writtenDelta.HasValue)
                {
                    bucket.WrittenBytes += writtenDelta.Value;
                    bucket.HasWritten = true;
                }
            }

            previous = sample;
        }

        var minuteBuckets = buckets.Values
            .Where(bucket => bucket.HasAny)
            .OrderBy(bucket => bucket.StartUtc)
            .ToList();
        if (minuteBuckets.Count < 2)
        {
            return TrendSnapshot.Empty($"Not enough counter deltas for {processLabel}.");
        }

        var downsampled = DownsampleBuckets(minuteBuckets);
        var cpuValues = downsampled.Select(bucket => bucket.CpuSecondsPerMinute).ToList();
        var readValues = downsampled.Select(bucket => bucket.ReadBytesPerMinute).ToList();
        var writtenValues = downsampled.Select(bucket => bucket.WrittenBytesPerMinute).ToList();
        var cpuPeak = cpuValues.Count == 0 ? 0 : cpuValues.Max();
        var readPeak = readValues.Count == 0 ? 0 : readValues.Max();
        var writtenPeak = writtenValues.Count == 0 ? 0 : writtenValues.Max();
        var first = minuteBuckets.First().StartUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        var last = minuteBuckets.Last().StartUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");

        return new TrendSnapshot(
            HasData: true,
            StatusMessage: $"Showing {downsampled.Count} bounded minute bucket(s) for {processLabel}.",
            WindowDisplay: $"{first} to {last}",
            CpuPeakDisplay: $"Peak: {cpuPeak:F1} CPU s/min",
            ReadPeakDisplay: $"Peak: {ProcessStatisticsRowViewModel.FormatBytes((long)Math.Round(readPeak))}/min",
            WrittenPeakDisplay: $"Peak: {ProcessStatisticsRowViewModel.FormatBytes((long)Math.Round(writtenPeak))}/min",
            CpuPoints: BuildTrendPoints(cpuValues, cpuPeak),
            ReadPoints: BuildTrendPoints(readValues, readPeak),
            WrittenPoints: BuildTrendPoints(writtenValues, writtenPeak));
    }

    private void ClearTrend(string message)
    {
        IsTrendLoading = false;
        HasTrendData = false;
        TrendStatusMessage = message;
        TrendWindow = string.Empty;
        CpuTrendPeak = "Peak: <not available>";
        ReadTrendPeak = "Peak: <not available>";
        WrittenTrendPeak = "Peak: <not available>";
        CpuTrendPoints = new PointCollection();
        ReadTrendPoints = new PointCollection();
        WrittenTrendPoints = new PointCollection();
    }

    private bool FilterStatistic(object item)
    {
        if (item is not ProcessStatisticsRowViewModel statistic)
        {
            return false;
        }

        if (_activeScope != null && !statistic.MatchesScope(_activeScope))
        {
            return false;
        }

        if (_hasGreenSelection)
        {
            var included = _includedProcessKeys.Contains(statistic.ProcessKey) ||
                           _includedScopes.Any(statistic.MatchesScope);
            if (!included)
            {
                return false;
            }
        }

        if (_excludedProcessKeys.Contains(statistic.ProcessKey))
        {
            return false;
        }

        return !_excludedScopes.Any(statistic.MatchesScope);
    }

    private void UpdateSummary()
    {
        var statistic = SelectedStatistic;
        if (statistic == null && !string.IsNullOrWhiteSpace(_selectedProcessKey))
        {
            statistic = Statistics.FirstOrDefault(row =>
                string.Equals(row.ProcessKey, _selectedProcessKey, StringComparison.Ordinal));
        }

        VisibleProcessCount = _selectedProcess == null ? 0 : 1;
        TotalCpuTime = statistic?.CpuTimeDisplay ?? "<not available>";
        TotalReadBytes = statistic?.ReadBytesDisplay ?? "<not available>";
        TotalWrittenBytes = statistic?.WrittenBytesDisplay ?? "<not available>";
        StatusMessage = _selectedProcess == null
            ? "Select a process in the list to view its persisted statistics."
            : $"Showing persisted statistics for {_selectedProcess.ProcessName} (PID {_selectedProcess.ProcessId}).";
    }

    private void UpdateSelectedProcessDetails()
    {
        var detail = SelectedStatistic;
        if (detail == null && !string.IsNullOrWhiteSpace(_selectedProcessKey))
        {
            detail = Statistics.FirstOrDefault(row =>
                string.Equals(row.ProcessKey, _selectedProcessKey, StringComparison.Ordinal));
        }

        if (detail == null)
        {
            SelectedProcessHeader = string.IsNullOrWhiteSpace(_selectedProcessLabel)
                ? "No process selected."
                : $"{_selectedProcessLabel}: no statistics sample";
            return;
        }

        SelectedProcessHeader = detail.ProcessDisplay;
    }

    private static long? SumNullableBytes(IEnumerable<long?> values)
    {
        long total = 0;
        var hasValue = false;
        foreach (var value in values)
        {
            if (!value.HasValue)
            {
                continue;
            }

            hasValue = true;
            total = checked(total + value.Value);
        }

        return hasValue ? total : null;
    }

    private static TimeSpan? SumNullableTicks(IEnumerable<long?> ticks)
    {
        long total = 0;
        var hasValue = false;
        foreach (var value in ticks)
        {
            if (!value.HasValue)
            {
                continue;
            }

            hasValue = true;
            total = checked(total + value.Value);
        }

        return hasValue ? TimeSpan.FromTicks(total) : null;
    }

    private static IReadOnlyList<TrendBucket> DownsampleBuckets(IReadOnlyList<TrendBucket> buckets)
    {
        if (buckets.Count <= MaxTrendBuckets)
        {
            return buckets;
        }

        var groupSize = (int)Math.Ceiling(buckets.Count / (double)MaxTrendBuckets);
        var downsampled = new List<TrendBucket>(MaxTrendBuckets);
        for (var index = 0; index < buckets.Count; index += groupSize)
        {
            var group = buckets.Skip(index).Take(groupSize).ToList();
            var merged = new TrendBucket(group[0].StartUtc)
            {
                MinuteCount = group.Sum(bucket => bucket.MinuteCount),
                CpuSeconds = group.Sum(bucket => bucket.CpuSeconds),
                ReadBytes = group.Sum(bucket => bucket.ReadBytes),
                WrittenBytes = group.Sum(bucket => bucket.WrittenBytes),
                HasCpu = group.Any(bucket => bucket.HasCpu),
                HasRead = group.Any(bucket => bucket.HasRead),
                HasWritten = group.Any(bucket => bucket.HasWritten)
            };
            downsampled.Add(merged);
        }

        return downsampled;
    }

    private static IReadOnlyList<Point> BuildTrendPoints(IReadOnlyList<double> values, double maxValue)
    {
        if (values.Count < 2)
        {
            return [];
        }

        var denominator = maxValue > 0 ? maxValue : 1;
        var xStep = TrendCanvasWidth / (values.Count - 1);
        var points = new List<Point>(values.Count);
        for (var index = 0; index < values.Count; index++)
        {
            var normalized = Math.Clamp(values[index] / denominator, 0, 1);
            points.Add(new Point(index * xStep, TrendCanvasHeight - (normalized * TrendCanvasHeight)));
        }

        return points;
    }

    private static PointCollection ToPointCollection(IEnumerable<Point> points)
    {
        var collection = new PointCollection();
        foreach (var point in points)
        {
            collection.Add(point);
        }

        return collection;
    }

    private static DateTime TruncateToMinute(DateTime value)
    {
        var utc = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
        return new DateTime(utc.Year, utc.Month, utc.Day, utc.Hour, utc.Minute, 0, DateTimeKind.Utc);
    }

    private static long? PositiveDelta(long? current, long? previous)
    {
        if (!current.HasValue || !previous.HasValue)
        {
            return null;
        }

        var delta = current.Value - previous.Value;
        return delta >= 0 ? delta : null;
    }

    private static bool IsProcessScope(ExplorerScope? scope)
    {
        return scope?.Kind is ExplorerScopeKind.AllProcesses or
            ExplorerScopeKind.RunningProcesses or
            ExplorerScopeKind.ExitedProcesses or
            ExplorerScopeKind.NotFoundProcesses or
            ExplorerScopeKind.ProcessTrees or
            ExplorerScopeKind.ProcessBranch or
            ExplorerScopeKind.ProcessExecutionRoot or
            ExplorerScopeKind.ProcessOwners or
            ExplorerScopeKind.ProcessOwner or
            ExplorerScopeKind.Bookmarked or
            ExplorerScopeKind.CaseSessionRoot or
            ExplorerScopeKind.EvidenceRoot;
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
    }

    private sealed class TrendBucket
    {
        public TrendBucket(DateTime startUtc)
        {
            StartUtc = startUtc;
        }

        public DateTime StartUtc { get; }
        public int MinuteCount { get; set; } = 1;
        public double CpuSeconds { get; set; }
        public double ReadBytes { get; set; }
        public double WrittenBytes { get; set; }
        public bool HasCpu { get; set; }
        public bool HasRead { get; set; }
        public bool HasWritten { get; set; }
        public bool HasAny => HasCpu || HasRead || HasWritten;
        public double CpuSecondsPerMinute => MinuteCount <= 0 ? CpuSeconds : CpuSeconds / MinuteCount;
        public double ReadBytesPerMinute => MinuteCount <= 0 ? ReadBytes : ReadBytes / MinuteCount;
        public double WrittenBytesPerMinute => MinuteCount <= 0 ? WrittenBytes : WrittenBytes / MinuteCount;
    }

    private sealed record TrendSnapshot(
        bool HasData,
        string StatusMessage,
        string WindowDisplay,
        string CpuPeakDisplay,
        string ReadPeakDisplay,
        string WrittenPeakDisplay,
        IReadOnlyList<Point> CpuPoints,
        IReadOnlyList<Point> ReadPoints,
        IReadOnlyList<Point> WrittenPoints)
    {
        public static TrendSnapshot Empty(string message)
        {
            return new TrendSnapshot(
                HasData: false,
                StatusMessage: message,
                WindowDisplay: string.Empty,
                CpuPeakDisplay: "Peak: <not available>",
                ReadPeakDisplay: "Peak: <not available>",
                WrittenPeakDisplay: "Peak: <not available>",
                CpuPoints: [],
                ReadPoints: [],
                WrittenPoints: []);
        }
    }
}
