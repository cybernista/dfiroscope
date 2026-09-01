using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed class AgentRuntimeDiagnosticsSampler : IAsyncDisposable
{
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DatabaseDiagnosticsInterval = TimeSpan.FromSeconds(10);
    private const long MaxLogBytes = 20L * 1024 * 1024;

    private readonly InvestigationSessionPaths _sessionPaths;
    private readonly AgentJobQueue _jobQueue;
    private readonly AgentStagingWriter _stagingWriter;
    private readonly Func<CaptureHealthReport> _getCaptureHealth;
    private readonly TextWriter _log;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _samplingTask;
    private readonly Process _process = Process.GetCurrentProcess();
    private readonly object _stateLock = new();
    private readonly string _logPath;
    private DateTime _lastProcessSampleUtc = DateTime.UtcNow;
    private TimeSpan _lastProcessorTime;
    private long _lastIoReadBytes;
    private long _lastIoWriteBytes;
    private AgentSqliteDatabaseDiagnostics? _cachedDatabaseDiagnostics;
    private DateTime? _databaseDiagnosticsCapturedUtc;
    private string _databaseDiagnosticsCacheStatus = "SQLite diagnostics have not been sampled yet.";
    private DateTime? _lastSampleUtc;
    private string _lastSummary = "Capture diagnostics have not been sampled yet.";
    private bool _logLimitReached;

    public AgentRuntimeDiagnosticsSampler(
        InvestigationSessionPaths sessionPaths,
        AgentJobQueue jobQueue,
        AgentStagingWriter stagingWriter,
        Func<CaptureHealthReport> getCaptureHealth,
        TextWriter log)
    {
        _sessionPaths = sessionPaths;
        _jobQueue = jobQueue;
        _stagingWriter = stagingWriter;
        _getCaptureHealth = getCaptureHealth;
        _log = log;
        Directory.CreateDirectory(_sessionPaths.LogsDirectory);
        _logPath = Path.Combine(_sessionPaths.LogsDirectory, "agent-capture-diagnostics.jsonl");
        _lastProcessorTime = _process.TotalProcessorTime;
        (_lastIoReadBytes, _lastIoWriteBytes) = TryGetProcessIoBytes(_process);
        _samplingTask = Task.Run(RunAsync);
    }

    public string LogPath => _logPath;

    public AgentRuntimeDiagnosticsSnapshot GetSnapshot()
    {
        lock (_stateLock)
        {
            return new AgentRuntimeDiagnosticsSnapshot(
                _cachedDatabaseDiagnostics,
                _databaseDiagnosticsCapturedUtc,
                _databaseDiagnosticsCacheStatus,
                _logPath,
                _lastSampleUtc,
                _lastSummary);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        try
        {
            await _samplingTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
        }

        _shutdown.Dispose();
    }

    private async Task RunAsync()
    {
        using var timer = new PeriodicTimer(SampleInterval);
        while (await timer.WaitForNextTickAsync(_shutdown.Token).ConfigureAwait(false))
        {
            try
            {
                Sample();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                lock (_stateLock)
                {
                    _lastSummary = $"Capture diagnostics sample failed: {ex.Message}";
                }

                _log.WriteLine($"[{DateTimeOffset.Now:O}] Capture diagnostics sample failed: {ex.Message}");
            }
        }
    }

    private void Sample()
    {
        var capturedUtc = DateTime.UtcNow;
        var writer = _stagingWriter.GetSnapshot();
        var runtime = _jobQueue.GetRuntimeSnapshot();
        var capture = _getCaptureHealth();
        var process = CaptureProcessSample(capturedUtc);
        var databaseDiagnostics = RefreshDatabaseDiagnosticsIfDue(capturedUtc);
        var bottleneck = ClassifyBottleneck(capture, runtime, writer, databaseDiagnostics);
        var summary = BuildSummary(capture, runtime, writer, process, bottleneck);
        var sample = new AgentRuntimeDiagnosticsSample
        {
            CapturedAtUtc = capturedUtc,
            SessionId = _sessionPaths.SessionId,
            DatabasePath = _sessionPaths.LiveDatabasePath,
            CaptureHealth = capture.Health.ToString(),
            BottleneckHint = bottleneck,
            Summary = summary,
            Capture = CaptureDiagnostics.From(capture),
            Runtime = RuntimeDiagnostics.From(runtime),
            Writer = WriterDiagnostics.From(writer),
            Sqlite = SqliteDiagnostics.From(databaseDiagnostics, _databaseDiagnosticsCacheStatus),
            Process = process
        };

        AppendSample(sample);
        lock (_stateLock)
        {
            _lastSampleUtc = capturedUtc;
            _lastSummary = summary;
        }
    }

    private AgentSqliteDatabaseDiagnostics? RefreshDatabaseDiagnosticsIfDue(DateTime nowUtc)
    {
        var shouldRefresh = !_databaseDiagnosticsCapturedUtc.HasValue ||
                            nowUtc - _databaseDiagnosticsCapturedUtc.Value >= DatabaseDiagnosticsInterval;
        if (!shouldRefresh)
        {
            return _cachedDatabaseDiagnostics;
        }

        try
        {
            var diagnostics = _stagingWriter.GetDatabaseDiagnostics();
            lock (_stateLock)
            {
                _cachedDatabaseDiagnostics = diagnostics;
                _databaseDiagnosticsCapturedUtc = diagnostics.CapturedAtUtc;
                _databaseDiagnosticsCacheStatus = "Cached background SQLite diagnostics.";
            }

            return diagnostics;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            lock (_stateLock)
            {
                _databaseDiagnosticsCacheStatus = $"SQLite diagnostics refresh failed: {ex.Message}";
            }

            return _cachedDatabaseDiagnostics;
        }
    }

    private AgentProcessDiagnostics CaptureProcessSample(DateTime capturedUtc)
    {
        try
        {
            _process.Refresh();
        }
        catch (InvalidOperationException)
        {
        }

        var previousUtc = _lastProcessSampleUtc;
        var previousCpu = _lastProcessorTime;
        var previousReadBytes = _lastIoReadBytes;
        var previousWriteBytes = _lastIoWriteBytes;
        var currentCpu = _process.TotalProcessorTime;
        var (readBytes, writeBytes) = TryGetProcessIoBytes(_process);
        var elapsedSeconds = Math.Max(0.001, (capturedUtc - previousUtc).TotalSeconds);
        _lastProcessSampleUtc = capturedUtc;
        _lastProcessorTime = currentCpu;
        _lastIoReadBytes = readBytes;
        _lastIoWriteBytes = writeBytes;

        ThreadPool.GetAvailableThreads(out var availableWorkerThreads, out var availableCompletionPortThreads);
        ThreadPool.GetMaxThreads(out var maxWorkerThreads, out var maxCompletionPortThreads);

        return new AgentProcessDiagnostics
        {
            CpuPercent = Math.Max(0, (currentCpu - previousCpu).TotalMilliseconds / (elapsedSeconds * Environment.ProcessorCount * 10.0)),
            WorkingSetBytes = _process.WorkingSet64,
            PrivateMemoryBytes = _process.PrivateMemorySize64,
            GcHeapBytes = GC.GetTotalMemory(forceFullCollection: false),
            Gen0Collections = GC.CollectionCount(0),
            Gen1Collections = GC.CollectionCount(1),
            Gen2Collections = GC.CollectionCount(2),
            ThreadCount = _process.Threads.Count,
            HandleCount = _process.HandleCount,
            IoReadBytesPerSecond = Math.Max(0, (readBytes - previousReadBytes) / elapsedSeconds),
            IoWriteBytesPerSecond = Math.Max(0, (writeBytes - previousWriteBytes) / elapsedSeconds),
            ThreadPoolAvailableWorkerThreads = availableWorkerThreads,
            ThreadPoolMaxWorkerThreads = maxWorkerThreads,
            ThreadPoolAvailableCompletionPortThreads = availableCompletionPortThreads,
            ThreadPoolMaxCompletionPortThreads = maxCompletionPortThreads
        };
    }

    private void AppendSample(AgentRuntimeDiagnosticsSample sample)
    {
        if (_logLimitReached)
        {
            return;
        }

        try
        {
            if (File.Exists(_logPath) && new FileInfo(_logPath).Length >= MaxLogBytes)
            {
                _logLimitReached = true;
                _log.WriteLine($"[{DateTimeOffset.Now:O}] Capture diagnostics log reached {MaxLogBytes:N0} bytes; stopping samples for this agent run: {_logPath}");
                return;
            }

            var json = JsonSerializer.Serialize(sample, AgentJson.JsonOptions);
            File.AppendAllText(_logPath, json + Environment.NewLine);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to append capture diagnostics sample: {ex.Message}");
        }
    }

    private static string ClassifyBottleneck(
        CaptureHealthReport capture,
        AgentRuntimeSnapshot runtime,
        AgentStagingWriterSnapshot writer,
        AgentSqliteDatabaseDiagnostics? databaseDiagnostics)
    {
        if (writer.IsBackpressureActive ||
            writer.PendingWorkItemCount >= writer.BackpressureWarningWorkItemCount ||
            runtime.WriterBackpressureActive)
        {
            return "WriterBackpressure";
        }

        if (writer.BusyOrLockedFailureCount > 0 ||
            !string.IsNullOrWhiteSpace(writer.LastSqliteError) ||
            !string.IsNullOrWhiteSpace(databaseDiagnostics?.Error))
        {
            return "SqliteContentionOrError";
        }

        if (capture.PendingProcessWriteBatches >= capture.MaxPendingProcessWriteBatches)
        {
            return "ProcessWriteBacklog";
        }

        if (capture.LiveBufferDrainingAfterStop)
        {
            return "LiveBufferDraining";
        }

        if (capture.LiveBufferPendingRecords > 0 || capture.LiveBufferDiskBytes > 0)
        {
            return capture.LiveBufferDiskBytes > 0 ? "LiveBufferDiskSpill" : "LiveBufferBacklog";
        }

        if (capture.TotalProcessRecordsDropped > 0 || capture.ProcessBatchesDropped > 0)
        {
            return "ProcessDrops";
        }

        if (capture.Sources.Any(source =>
                string.Equals(source.Status, "Degraded", StringComparison.OrdinalIgnoreCase) ||
                source.WriteFailures > 0 ||
                source.MalformedRecords > 0))
        {
            return "SourceHealth";
        }

        if (runtime.QueuedJobCount > 0 || runtime.RunningJobCount >= Math.Max(1, runtime.WorkerCount))
        {
            return "JobQueue";
        }

        return capture.Health == CaptureHealth.Degraded ? "UnknownDegraded" : "None";
    }

    private static string BuildSummary(
        CaptureHealthReport capture,
        AgentRuntimeSnapshot runtime,
        AgentStagingWriterSnapshot writer,
        AgentProcessDiagnostics process,
        string bottleneck)
    {
        var totalWritten = capture.TotalEventsReceived + capture.TotalProcessRecordsWritten;
        var totalDropped = capture.TotalEventsDropped + capture.TotalProcessRecordsDropped;
        var recordsPerSecond = capture.Sources.Sum(source => Math.Max(0, source.RecordsPerSecond));
        return
            $"health={capture.Health}; hint={bottleneck}; rate={recordsPerSecond:F1}/s; written={totalWritten}; dropped={totalDropped}; " +
            $"live_buffer=pending {capture.LiveBufferPendingRecords}/{capture.LiveBufferPendingBatches} batches, ram_mb={capture.LiveBufferMemoryBytes / 1024.0 / 1024.0:F1}/{capture.LiveBufferMemoryLimitBytes / 1024.0 / 1024.0:F0}, disk_mb={capture.LiveBufferDiskBytes / 1024.0 / 1024.0:F1}, retries={capture.LiveBufferWriteRetries}; " +
            $"writer={writer.PendingWorkItemCount}/{writer.QueueCapacity}, tx={writer.LastTransactionMilliseconds:F1}ms, queue={writer.LastQueueDelayMilliseconds:F1}ms; " +
            $"jobs={runtime.RunningJobCount}/{runtime.WorkerCount}+{runtime.QueuedJobCount}; cpu={process.CpuPercent:F1}%; ws_mb={process.WorkingSetBytes / 1024.0 / 1024.0:F1}";
    }

    private static (long ReadBytes, long WriteBytes) TryGetProcessIoBytes(Process process)
    {
        try
        {
            return GetProcessIoCounters(process.Handle, out var counters)
                ? (ClampToLong(counters.ReadTransferCount), ClampToLong(counters.WriteTransferCount))
                : (0, 0);
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            return (0, 0);
        }
    }

    private static long ClampToLong(ulong value)
        => value > long.MaxValue ? long.MaxValue : (long)value;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessIoCounters(IntPtr processHandle, out IoCounters ioCounters);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct IoCounters
    {
        public readonly ulong ReadOperationCount;
        public readonly ulong WriteOperationCount;
        public readonly ulong OtherOperationCount;
        public readonly ulong ReadTransferCount;
        public readonly ulong WriteTransferCount;
        public readonly ulong OtherTransferCount;
    }

    private sealed class AgentRuntimeDiagnosticsSample
    {
        public DateTime CapturedAtUtc { get; init; }
        public string SessionId { get; init; } = string.Empty;
        public string DatabasePath { get; init; } = string.Empty;
        public string CaptureHealth { get; init; } = string.Empty;
        public string BottleneckHint { get; init; } = string.Empty;
        public string Summary { get; init; } = string.Empty;
        public CaptureDiagnostics Capture { get; init; } = new();
        public RuntimeDiagnostics Runtime { get; init; } = new();
        public WriterDiagnostics Writer { get; init; } = new();
        public SqliteDiagnostics Sqlite { get; init; } = new();
        public AgentProcessDiagnostics Process { get; init; } = new();
    }

    private sealed class CaptureDiagnostics
    {
        public long TotalEventsReceived { get; init; }
        public long TotalProcessRecordsWritten { get; init; }
        public long TotalEventsDropped { get; init; }
        public long TotalProcessRecordsDropped { get; init; }
        public long EventBatchesDropped { get; init; }
        public long ProcessBatchesDropped { get; init; }
        public int PendingEventWriteBatches { get; init; }
        public int PendingProcessWriteBatches { get; init; }
        public int MaxPendingEventWriteBatches { get; init; }
        public int MaxPendingProcessWriteBatches { get; init; }
        public long EventWriteFailures { get; init; }
        public long ProcessWriteFailures { get; init; }
        public long LiveBufferMemoryLimitBytes { get; init; }
        public long LiveBufferMemoryBytes { get; init; }
        public long LiveBufferPeakMemoryBytes { get; init; }
        public long LiveBufferDiskBytes { get; init; }
        public long LiveBufferPeakDiskBytes { get; init; }
        public int LiveBufferPendingBatches { get; init; }
        public long LiveBufferPendingRecords { get; init; }
        public long LiveBufferSpilledBatches { get; init; }
        public long LiveBufferSpilledRecords { get; init; }
        public long LiveBufferCompletedBatches { get; init; }
        public long LiveBufferCompletedRecords { get; init; }
        public long LiveBufferWriteRetries { get; init; }
        public bool LiveBufferDrainingAfterStop { get; init; }
        public bool LiveBufferDrainActive { get; init; }
        public string LiveBufferDirectory { get; init; } = string.Empty;
        public string LiveBufferLastError { get; init; } = string.Empty;
        public DateTime? LiveBufferLastErrorUtc { get; init; }
        public IReadOnlyList<SourceDiagnostics> Sources { get; init; } = [];

        public static CaptureDiagnostics From(CaptureHealthReport capture)
        {
            return new CaptureDiagnostics
            {
                TotalEventsReceived = capture.TotalEventsReceived,
                TotalProcessRecordsWritten = capture.TotalProcessRecordsWritten,
                TotalEventsDropped = capture.TotalEventsDropped,
                TotalProcessRecordsDropped = capture.TotalProcessRecordsDropped,
                EventBatchesDropped = capture.EventBatchesDropped,
                ProcessBatchesDropped = capture.ProcessBatchesDropped,
                PendingEventWriteBatches = capture.PendingEventWriteBatches,
                PendingProcessWriteBatches = capture.PendingProcessWriteBatches,
                MaxPendingEventWriteBatches = capture.MaxPendingEventWriteBatches,
                MaxPendingProcessWriteBatches = capture.MaxPendingProcessWriteBatches,
                EventWriteFailures = capture.EventWriteFailures,
                ProcessWriteFailures = capture.ProcessWriteFailures,
                LiveBufferMemoryLimitBytes = capture.LiveBufferMemoryLimitBytes,
                LiveBufferMemoryBytes = capture.LiveBufferMemoryBytes,
                LiveBufferPeakMemoryBytes = capture.LiveBufferPeakMemoryBytes,
                LiveBufferDiskBytes = capture.LiveBufferDiskBytes,
                LiveBufferPeakDiskBytes = capture.LiveBufferPeakDiskBytes,
                LiveBufferPendingBatches = capture.LiveBufferPendingBatches,
                LiveBufferPendingRecords = capture.LiveBufferPendingRecords,
                LiveBufferSpilledBatches = capture.LiveBufferSpilledBatches,
                LiveBufferSpilledRecords = capture.LiveBufferSpilledRecords,
                LiveBufferCompletedBatches = capture.LiveBufferCompletedBatches,
                LiveBufferCompletedRecords = capture.LiveBufferCompletedRecords,
                LiveBufferWriteRetries = capture.LiveBufferWriteRetries,
                LiveBufferDrainingAfterStop = capture.LiveBufferDrainingAfterStop,
                LiveBufferDrainActive = capture.LiveBufferDrainActive,
                LiveBufferDirectory = capture.LiveBufferDirectory,
                LiveBufferLastError = capture.LiveBufferLastError,
                LiveBufferLastErrorUtc = capture.LiveBufferLastErrorUtc,
                Sources = capture.Sources.Select(SourceDiagnostics.From).ToArray()
            };
        }
    }

    private sealed class SourceDiagnostics
    {
        public string Source { get; init; } = string.Empty;
        public string Status { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
        public bool IsEnabled { get; init; }
        public bool IsActive { get; init; }
        public string Error { get; init; } = string.Empty;
        public int DedupKeyCount { get; init; }
        public int DedupKeyCapacity { get; init; }
        public long DedupKeysEvicted { get; init; }
        public long RecordsSeen { get; init; }
        public long RecordsMatched { get; init; }
        public long DuplicateRecords { get; init; }
        public long UnmatchedRecords { get; init; }
        public long MalformedRecords { get; init; }
        public long RecordsWritten { get; init; }
        public double RecordsPerSecond { get; init; }
        public long RecordsQueued { get; init; }
        public long RecordsDropped { get; init; }
        public long WriteFailures { get; init; }

        public static SourceDiagnostics From(CaptureSourceHealthReport source)
        {
            return new SourceDiagnostics
            {
                Source = source.Source,
                Status = source.Status,
                Detail = source.Detail,
                IsEnabled = source.IsEnabled,
                IsActive = source.IsActive,
                Error = source.Error,
                DedupKeyCount = source.DedupKeyCount,
                DedupKeyCapacity = source.DedupKeyCapacity,
                DedupKeysEvicted = source.DedupKeysEvicted,
                RecordsSeen = source.RecordsSeen,
                RecordsMatched = source.RecordsMatched,
                DuplicateRecords = source.DuplicateRecords,
                UnmatchedRecords = source.UnmatchedRecords,
                MalformedRecords = source.MalformedRecords,
                RecordsWritten = source.RecordsWritten,
                RecordsPerSecond = source.RecordsPerSecond,
                RecordsQueued = source.RecordsQueued,
                RecordsDropped = source.RecordsDropped,
                WriteFailures = source.WriteFailures
            };
        }
    }

    private sealed class RuntimeDiagnostics
    {
        public int WorkerCount { get; init; }
        public int RunningJobCount { get; init; }
        public int QueueCapacity { get; init; }
        public int QueuedJobCount { get; init; }
        public int PeakQueuedJobCount { get; init; }
        public int CompletedJobCount { get; init; }
        public int RejectedJobCount { get; init; }
        public string LastError { get; init; } = string.Empty;

        public static RuntimeDiagnostics From(AgentRuntimeSnapshot runtime)
        {
            return new RuntimeDiagnostics
            {
                WorkerCount = runtime.WorkerCount,
                RunningJobCount = runtime.RunningJobCount,
                QueueCapacity = runtime.QueueCapacity,
                QueuedJobCount = runtime.QueuedJobCount,
                PeakQueuedJobCount = runtime.PeakQueuedJobCount,
                CompletedJobCount = runtime.CompletedJobCount,
                RejectedJobCount = runtime.RejectedJobCount,
                LastError = runtime.LastError
            };
        }
    }

    private sealed class WriterDiagnostics
    {
        public int QueueCapacity { get; init; }
        public int PendingWorkItemCount { get; init; }
        public int PeakPendingWorkItemCount { get; init; }
        public long CompletedWorkItemCount { get; init; }
        public long FailedWorkItemCount { get; init; }
        public long CompletedRowCount { get; init; }
        public long FailedRowCount { get; init; }
        public double LastQueueDelayMilliseconds { get; init; }
        public double MaxQueueDelayMilliseconds { get; init; }
        public double LastTransactionMilliseconds { get; init; }
        public double MaxTransactionMilliseconds { get; init; }
        public long LastBatchRowCount { get; init; }
        public long MaxBatchRowCount { get; init; }
        public string LastOperationName { get; init; } = string.Empty;
        public long BusyOrLockedFailureCount { get; init; }
        public string LastSqliteError { get; init; } = string.Empty;
        public DateTime? LastSqliteErrorUtc { get; init; }
        public bool BackpressureActive { get; init; }
        public int BackpressureWarningWorkItemCount { get; init; }
        public string LastCheckpointSummary { get; init; } = string.Empty;
        public DateTime? LastCheckpointUtc { get; init; }
        public long CheckpointAttemptCount { get; init; }

        public static WriterDiagnostics From(AgentStagingWriterSnapshot writer)
        {
            return new WriterDiagnostics
            {
                QueueCapacity = writer.QueueCapacity,
                PendingWorkItemCount = writer.PendingWorkItemCount,
                PeakPendingWorkItemCount = writer.PeakPendingWorkItemCount,
                CompletedWorkItemCount = writer.CompletedWorkItemCount,
                FailedWorkItemCount = writer.FailedWorkItemCount,
                CompletedRowCount = writer.CompletedRowCount,
                FailedRowCount = writer.FailedRowCount,
                LastQueueDelayMilliseconds = writer.LastQueueDelayMilliseconds,
                MaxQueueDelayMilliseconds = writer.MaxQueueDelayMilliseconds,
                LastTransactionMilliseconds = writer.LastTransactionMilliseconds,
                MaxTransactionMilliseconds = writer.MaxTransactionMilliseconds,
                LastBatchRowCount = writer.LastBatchRowCount,
                MaxBatchRowCount = writer.MaxBatchRowCount,
                LastOperationName = writer.LastOperationName,
                BusyOrLockedFailureCount = writer.BusyOrLockedFailureCount,
                LastSqliteError = writer.LastSqliteError,
                LastSqliteErrorUtc = writer.LastSqliteErrorUtc,
                BackpressureActive = writer.IsBackpressureActive,
                BackpressureWarningWorkItemCount = writer.BackpressureWarningWorkItemCount,
                LastCheckpointSummary = writer.LastCheckpointSummary,
                LastCheckpointUtc = writer.LastCheckpointUtc,
                CheckpointAttemptCount = writer.CheckpointAttemptCount
            };
        }
    }

    private sealed class SqliteDiagnostics
    {
        public DateTime? CapturedAtUtc { get; init; }
        public string CacheStatus { get; init; } = string.Empty;
        public string JournalMode { get; init; } = string.Empty;
        public string SynchronousMode { get; init; } = string.Empty;
        public int BusyTimeoutMilliseconds { get; init; }
        public int WalAutoCheckpointPages { get; init; }
        public long DatabaseSizeBytes { get; init; }
        public long WalSizeBytes { get; init; }
        public int LiveIndexCount { get; init; }
        public int LiveIndexExpectedCount { get; init; }
        public int AnalysisIndexCount { get; init; }
        public int AnalysisIndexExpectedCount { get; init; }
        public string Error { get; init; } = string.Empty;
        public string Summary { get; init; } = string.Empty;

        public static SqliteDiagnostics From(AgentSqliteDatabaseDiagnostics? diagnostics, string cacheStatus)
        {
            return new SqliteDiagnostics
            {
                CapturedAtUtc = diagnostics?.CapturedAtUtc,
                CacheStatus = cacheStatus,
                JournalMode = diagnostics?.JournalMode ?? string.Empty,
                SynchronousMode = diagnostics?.SynchronousMode ?? string.Empty,
                BusyTimeoutMilliseconds = diagnostics?.BusyTimeoutMilliseconds ?? 0,
                WalAutoCheckpointPages = diagnostics?.WalAutoCheckpointPages ?? 0,
                DatabaseSizeBytes = diagnostics?.DatabaseSizeBytes ?? 0,
                WalSizeBytes = diagnostics?.WalSizeBytes ?? 0,
                LiveIndexCount = diagnostics?.LiveIndexCount ?? 0,
                LiveIndexExpectedCount = diagnostics?.LiveIndexExpectedCount ?? 0,
                AnalysisIndexCount = diagnostics?.AnalysisIndexCount ?? 0,
                AnalysisIndexExpectedCount = diagnostics?.AnalysisIndexExpectedCount ?? 0,
                Error = diagnostics?.Error ?? string.Empty,
                Summary = diagnostics?.Summary ?? string.Empty
            };
        }
    }

    private sealed class AgentProcessDiagnostics
    {
        public double CpuPercent { get; init; }
        public long WorkingSetBytes { get; init; }
        public long PrivateMemoryBytes { get; init; }
        public long GcHeapBytes { get; init; }
        public int Gen0Collections { get; init; }
        public int Gen1Collections { get; init; }
        public int Gen2Collections { get; init; }
        public int ThreadCount { get; init; }
        public int HandleCount { get; init; }
        public double IoReadBytesPerSecond { get; init; }
        public double IoWriteBytesPerSecond { get; init; }
        public int ThreadPoolAvailableWorkerThreads { get; init; }
        public int ThreadPoolMaxWorkerThreads { get; init; }
        public int ThreadPoolAvailableCompletionPortThreads { get; init; }
        public int ThreadPoolMaxCompletionPortThreads { get; init; }
    }
}

internal sealed record AgentRuntimeDiagnosticsSnapshot(
    AgentSqliteDatabaseDiagnostics? DatabaseDiagnostics,
    DateTime? DatabaseDiagnosticsCapturedAtUtc,
    string DatabaseDiagnosticsCacheStatus,
    string LogPath,
    DateTime? LastSampleUtc,
    string Summary);
