using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed class AgentLiveCaptureHealthTracker
{
    private readonly object _sync = new();
    private readonly Dictionary<string, SourceCaptureCounters> _sourceCounters = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _runStartedUtc = DateTime.UtcNow;

    public void BeginRun(DateTime startedUtc)
    {
        lock (_sync)
        {
            _sourceCounters.Clear();
            _runStartedUtc = startedUtc;
        }
    }

    public void AddRecordsWritten(string source, long count)
    {
        if (count > 0)
        {
            Interlocked.Add(ref GetOrCreateSourceCounters(source).RecordsWritten, count);
        }
    }

    public void AddRecordsQueued(string source, long count)
    {
        if (count == 0)
        {
            return;
        }

        var counters = GetOrCreateSourceCounters(source);
        var queued = Interlocked.Add(ref counters.RecordsQueued, count);
        if (queued < 0)
        {
            Interlocked.Exchange(ref counters.RecordsQueued, 0);
        }
    }

    public void AddRecordsDropped(string source, long count)
    {
        if (count > 0)
        {
            Interlocked.Add(ref GetOrCreateSourceCounters(source).RecordsDropped, count);
        }
    }

    public void AddWriteFailure(string source)
    {
        Interlocked.Increment(ref GetOrCreateSourceCounters(source).WriteFailures);
    }

    public IReadOnlyList<CaptureSourceHealthReport> BuildReports(
        IReadOnlyList<EventSourceHealthSnapshot> statuses,
        DateTime nowUtc,
        bool isTerminal = false)
    {
        lock (_sync)
        {
            foreach (var status in statuses)
            {
                _ = GetOrCreateSourceCountersLocked(status.Source);
            }

            var statusBySource = statuses.ToDictionary(status => status.Source, StringComparer.OrdinalIgnoreCase);
            return _sourceCounters
                .OrderBy(entry => entry.Key, StringComparer.OrdinalIgnoreCase)
                .Select(entry => BuildReport(entry.Key, entry.Value, statusBySource, nowUtc, isTerminal))
                .ToList();
        }
    }

    public static IReadOnlyList<EventSourceHealthSnapshot> ProjectTerminalStatuses(
        IReadOnlyList<EventSourceHealthSnapshot> statuses,
        IReadOnlySet<string> configuredSources,
        DateTime transitionUtc)
    {
        var projected = statuses
            .Select(status =>
            {
                var wasConfigured = configuredSources.Contains(status.Source);
                return status with
                {
                    Status = wasConfigured ? "Stopped" : "Disabled",
                    Detail = wasConfigured
                        ? $"{status.Source} capture stopped. Counters are totals for the completed live-capture run."
                        : $"{status.Source} was disabled for the completed live-capture run.",
                    IsEnabled = wasConfigured,
                    IsActive = false,
                    UpdatedUtc = transitionUtc
                };
            })
            .ToList();
        var reportedSources = projected
            .Select(status => status.Source)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        projected.AddRange(
            configuredSources
                .Where(source => !reportedSources.Contains(source))
                .Select(source => new EventSourceHealthSnapshot(
                    source,
                    "Stopped",
                    $"{source} capture stopped. Counters are totals for the completed live-capture run.",
                    IsEnabled: true,
                    IsActive: false,
                    transitionUtc,
                    string.Empty)));
        return projected;
    }

    public static CaptureHealthReport ProjectTerminalReport(
        CaptureHealthReport report,
        string detail,
        IReadOnlyList<CaptureSourceHealthReport> sources)
    {
        return report with
        {
            Health = CaptureHealth.Idle,
            Detail = detail,
            PendingEventWriteBatches = 0,
            PendingProcessWriteBatches = 0,
            LiveBufferMemoryBytes = 0,
            LiveBufferDiskBytes = 0,
            LiveBufferPendingBatches = 0,
            LiveBufferPendingRecords = 0,
            LiveBufferDrainingAfterStop = false,
            LiveBufferDrainActive = false,
            Sources = sources
        };
    }

    private CaptureSourceHealthReport BuildReport(
        string source,
        SourceCaptureCounters counters,
        IReadOnlyDictionary<string, EventSourceHealthSnapshot> statusBySource,
        DateTime nowUtc,
        bool isTerminal)
    {
        var recordsWritten = Interlocked.Read(ref counters.RecordsWritten);
        statusBySource.TryGetValue(source, out var status);
        var isRunning = !isTerminal && status?.IsActive == true;
        if (!isRunning)
        {
            counters.RecordsPerSecond = 0;
            counters.LastRateRecordsWritten = recordsWritten;
            counters.LastRateSampleUtc = nowUtc;
        }
        else
        {
            var elapsedSeconds = (nowUtc - counters.LastRateSampleUtc).TotalSeconds;
            if (elapsedSeconds >= 0.5)
            {
                counters.RecordsPerSecond = Math.Max(
                    0,
                    (recordsWritten - counters.LastRateRecordsWritten) / elapsedSeconds);
                counters.LastRateRecordsWritten = recordsWritten;
                counters.LastRateSampleUtc = nowUtc;
            }
        }

        return new CaptureSourceHealthReport
        {
            Source = source,
            Status = status?.Status ?? "Unknown",
            Detail = status?.Detail ?? string.Empty,
            IsEnabled = status?.IsEnabled ?? true,
            IsActive = status?.IsActive ?? false,
            UpdatedUtc = status?.UpdatedUtc ?? nowUtc,
            Error = status?.Error ?? string.Empty,
            DedupKeyCount = status?.DedupKeyCount ?? 0,
            DedupKeyCapacity = status?.DedupKeyCapacity ?? 0,
            DedupKeysEvicted = status?.DedupKeysEvicted ?? 0,
            RecordsSeen = status?.RecordsSeen ?? 0,
            RecordsMatched = status?.RecordsMatched ?? 0,
            DuplicateRecords = status?.DuplicateRecords ?? 0,
            UnmatchedRecords = status?.UnmatchedRecords ?? 0,
            MalformedRecords = status?.MalformedRecords ?? 0,
            RecordsWritten = recordsWritten,
            RecordsPerSecond = counters.RecordsPerSecond,
            RecordsQueued = isTerminal ? 0 : Math.Max(0, Interlocked.Read(ref counters.RecordsQueued)),
            RecordsDropped = Interlocked.Read(ref counters.RecordsDropped),
            WriteFailures = Interlocked.Read(ref counters.WriteFailures)
        };
    }

    private SourceCaptureCounters GetOrCreateSourceCounters(string source)
    {
        lock (_sync)
        {
            return GetOrCreateSourceCountersLocked(source);
        }
    }

    private SourceCaptureCounters GetOrCreateSourceCountersLocked(string source)
    {
        source = string.IsNullOrWhiteSpace(source) ? "Unknown" : source;
        if (!_sourceCounters.TryGetValue(source, out var counters))
        {
            counters = new SourceCaptureCounters
            {
                LastRateSampleUtc = _runStartedUtc
            };
            _sourceCounters[source] = counters;
        }

        return counters;
    }

    private sealed class SourceCaptureCounters
    {
        public long RecordsWritten;
        public long RecordsQueued;
        public long RecordsDropped;
        public long WriteFailures;
        public DateTime LastRateSampleUtc;
        public long LastRateRecordsWritten;
        public double RecordsPerSecond;
    }
}
