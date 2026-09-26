using System.Text.Json;
using System.Threading.Channels;
using ProcInsider.Models;

namespace ProcInsider.Agent;

internal sealed class AgentLiveEventBuffer : IAsyncDisposable
{
    private static readonly TimeSpan InitialRetryDelay = TimeSpan.FromMilliseconds(100);
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(5);
    private const int MaxRecordsPerSqliteWrite = 1000;

    private readonly AgentStagingWriter _writer;
    private readonly TextWriter _log;
    private readonly AgentLiveEventBufferOptions _options;
    private readonly Action<string, long> _onQueuedRecordsChanged;
    private readonly Action<string, IReadOnlyList<TelemetryEventRecord>> _onBatchWritten;
    private readonly Channel<BufferedLiveEventBatch> _queue;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _drainTask;
    private readonly object _stateLock = new();
    private long _nextSpillSequence;
    private int _accepting = 1;
    private int _drainActive;
    private int _drainingAfterStop;
    private int _completed;
    private int _pendingBatchCount;
    private long _pendingRecordCount;
    private long _ramBufferedBytes;
    private long _peakRamBufferedBytes;
    private long _diskBufferedBytes;
    private long _peakDiskBufferedBytes;
    private long _spilledBatchCount;
    private long _spilledRecordCount;
    private long _completedBatchCount;
    private long _completedRecordCount;
    private long _writeRetryCount;
    private string _lastError = string.Empty;
    private DateTime? _lastErrorUtc;
    private string _lastSpillPath = string.Empty;
    private string _lastDrainSource = string.Empty;

    public AgentLiveEventBuffer(
        AgentStagingWriter writer,
        TextWriter log,
        AgentLiveEventBufferOptions options,
        Action<string, long> onQueuedRecordsChanged,
        Action<string, IReadOnlyList<TelemetryEventRecord>> onBatchWritten)
    {
        _writer = writer;
        _log = log;
        _options = options.Normalize();
        _onQueuedRecordsChanged = onQueuedRecordsChanged;
        _onBatchWritten = onBatchWritten;
        Directory.CreateDirectory(_options.SpillDirectory);
        _queue = Channel.CreateUnbounded<BufferedLiveEventBatch>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
        _drainTask = Task.Run(DrainAsync);
    }

    public AgentLiveEventBufferSnapshot GetSnapshot()
    {
        return new AgentLiveEventBufferSnapshot(
            _options.MemoryLimitBytes,
            _options.SpillDirectory,
            Math.Max(0, Interlocked.Read(ref _ramBufferedBytes)),
            Math.Max(0, Interlocked.Read(ref _peakRamBufferedBytes)),
            Math.Max(0, Interlocked.Read(ref _diskBufferedBytes)),
            Math.Max(0, Interlocked.Read(ref _peakDiskBufferedBytes)),
            Math.Max(0, Volatile.Read(ref _pendingBatchCount)),
            Math.Max(0, Interlocked.Read(ref _pendingRecordCount)),
            Interlocked.Read(ref _spilledBatchCount),
            Interlocked.Read(ref _spilledRecordCount),
            Interlocked.Read(ref _completedBatchCount),
            Interlocked.Read(ref _completedRecordCount),
            Interlocked.Read(ref _writeRetryCount),
            Volatile.Read(ref _drainActive) != 0,
            Volatile.Read(ref _drainingAfterStop) != 0,
            Volatile.Read(ref _completed) != 0,
            GetLastError(),
            GetLastErrorUtc(),
            GetLastSpillPath(),
            GetLastDrainSource());
    }

    public void Enqueue(string source, IReadOnlyList<TelemetryEventRecord> records)
    {
        if (records.Count == 0)
        {
            return;
        }

        if (Volatile.Read(ref _accepting) == 0)
        {
            throw new InvalidOperationException("Live event buffer is no longer accepting batches.");
        }

        var payload = JsonSerializer.SerializeToUtf8Bytes(records, AgentJson.JsonOptions);
        var item = TryCreateMemoryBatch(source, records.Count, payload) ??
                   CreateDiskBatch(source, records.Count, payload);

        Interlocked.Increment(ref _pendingBatchCount);
        Interlocked.Add(ref _pendingRecordCount, records.Count);
        _onQueuedRecordsChanged(source, records.Count);

        if (!_queue.Writer.TryWrite(item))
        {
            ReleaseBatchResources(item);
            Interlocked.Decrement(ref _pendingBatchCount);
            Interlocked.Add(ref _pendingRecordCount, -records.Count);
            _onQueuedRecordsChanged(source, -records.Count);
            throw new InvalidOperationException("Live event buffer stopped before the batch could be queued.");
        }
    }

    public void MarkDrainingAfterStop()
    {
        Volatile.Write(ref _drainingAfterStop, 1);
    }

    public async ValueTask CompleteAndDrainAsync(CancellationToken cancellationToken)
    {
        Interlocked.Exchange(ref _accepting, 0);
        _queue.Writer.TryComplete();
        await _drainTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        Volatile.Write(ref _completed, 1);
    }

    public async ValueTask DisposeAsync()
    {
        Interlocked.Exchange(ref _accepting, 0);
        _queue.Writer.TryComplete();
        _shutdown.Cancel();
        try
        {
            await _drainTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
        }

        _shutdown.Dispose();
    }

    private BufferedLiveEventBatch? TryCreateMemoryBatch(
        string source,
        int recordCount,
        byte[] payload)
    {
        while (true)
        {
            var currentBytes = Interlocked.Read(ref _ramBufferedBytes);
            if (currentBytes + payload.Length > _options.MemoryLimitBytes)
            {
                return null;
            }

            var updatedBytes = currentBytes + payload.Length;
            if (Interlocked.CompareExchange(ref _ramBufferedBytes, updatedBytes, currentBytes) == currentBytes)
            {
                UpdatePeak(ref _peakRamBufferedBytes, updatedBytes);
                return BufferedLiveEventBatch.InMemory(source, recordCount, payload);
            }
        }
    }

    private BufferedLiveEventBatch CreateDiskBatch(
        string source,
        int recordCount,
        byte[] payload)
    {
        var sequence = Interlocked.Increment(ref _nextSpillSequence);
        var fileName = $"live-events-{DateTime.UtcNow:yyyyMMddHHmmssfffffff}-{sequence:D8}.json";
        var path = Path.Combine(_options.SpillDirectory, fileName);
        try
        {
            File.WriteAllBytes(path, payload);
            var bytes = new FileInfo(path).Length;
            var diskBytes = Interlocked.Add(ref _diskBufferedBytes, bytes);
            UpdatePeak(ref _peakDiskBufferedBytes, diskBytes);
            Interlocked.Increment(ref _spilledBatchCount);
            Interlocked.Add(ref _spilledRecordCount, recordCount);
            SetLastSpillPath(path);
            return BufferedLiveEventBatch.OnDisk(source, recordCount, bytes, path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            RecordError($"Live event disk spill failed: {ex.Message}");
            throw;
        }
    }

    private async Task DrainAsync()
    {
        try
        {
            while (await _queue.Reader.WaitToReadAsync(_shutdown.Token).ConfigureAwait(false))
            {
                while (_queue.Reader.TryRead(out var firstItem))
                {
                    await DrainAvailableBatchAsync(firstItem).ConfigureAwait(false);
                }
            }

            Volatile.Write(ref _drainActive, 0);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
        }
    }

    private async Task DrainAvailableBatchAsync(BufferedLiveEventBatch firstItem)
    {
        Volatile.Write(ref _drainActive, 1);
        var items = new List<(BufferedLiveEventBatch Item, IReadOnlyList<TelemetryEventRecord> Records)>();
        var combinedRecords = new List<TelemetryEventRecord>(Math.Min(MaxRecordsPerSqliteWrite, firstItem.RecordCount));

        AddItem(firstItem);
        while (combinedRecords.Count < MaxRecordsPerSqliteWrite && _queue.Reader.TryRead(out var nextItem))
        {
            AddItem(nextItem);
        }

        try
        {
            await WriteWithRetryAsync(firstItem.Source, combinedRecords).ConfigureAwait(false);
            foreach (var item in items)
            {
                _onBatchWritten(item.Item.Source, item.Records);
                Interlocked.Increment(ref _completedBatchCount);
                Interlocked.Add(ref _completedRecordCount, item.Records.Count);
                SetLastDrainSource(item.Item.Source);
                DeleteSpillFile(item.Item);
            }
        }
        finally
        {
            foreach (var item in items)
            {
                ReleaseBatchResources(item.Item);
                Interlocked.Decrement(ref _pendingBatchCount);
                Interlocked.Add(ref _pendingRecordCount, -item.Item.RecordCount);
                _onQueuedRecordsChanged(item.Item.Source, -item.Item.RecordCount);
            }

            if (Math.Max(0, Volatile.Read(ref _pendingBatchCount)) == 0)
            {
                Volatile.Write(ref _drainActive, 0);
            }
        }

        void AddItem(BufferedLiveEventBatch item)
        {
            var records = ReadRecords(item);
            items.Add((item, records));
            combinedRecords.AddRange(records);
        }
    }

    private IReadOnlyList<TelemetryEventRecord> ReadRecords(BufferedLiveEventBatch item)
    {
        try
        {
            var payload = item.Payload ?? File.ReadAllBytes(item.FilePath);
            return JsonSerializer.Deserialize<List<TelemetryEventRecord>>(payload, AgentJson.JsonOptions) ??
                   new List<TelemetryEventRecord>();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            RecordError($"Live event buffer read failed for {item.Source}: {ex.Message}");
            throw;
        }
    }

    private async Task WriteWithRetryAsync(
        string source,
        IReadOnlyList<TelemetryEventRecord> records)
    {
        var delay = InitialRetryDelay;
        while (true)
        {
            _shutdown.Token.ThrowIfCancellationRequested();
            try
            {
                await _writer.AddEventsAsync(records, CancellationToken.None, AgentStagingWritePriority.High).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Interlocked.Increment(ref _writeRetryCount);
                RecordError($"Live event buffer write retry for {source}: {ex.Message}");
                _log.WriteLine($"[{DateTimeOffset.Now:O}] Live event buffer write retry for {source}: {ex.Message}");
                await Task.Delay(delay, _shutdown.Token).ConfigureAwait(false);
                delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, MaxRetryDelay.TotalMilliseconds));
            }
        }
    }

    private void ReleaseBatchResources(BufferedLiveEventBatch item)
    {
        if (item.Payload != null)
        {
            Interlocked.Add(ref _ramBufferedBytes, -item.PayloadByteCount);
        }
        else
        {
            Interlocked.Add(ref _diskBufferedBytes, -item.PayloadByteCount);
        }
    }

    private static void DeleteSpillFile(BufferedLiveEventBatch item)
    {
        if (item.Payload != null || string.IsNullOrWhiteSpace(item.FilePath))
        {
            return;
        }

        try
        {
            File.Delete(item.FilePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private void RecordError(string message)
    {
        lock (_stateLock)
        {
            _lastError = message;
            _lastErrorUtc = DateTime.UtcNow;
        }
    }

    private string GetLastError()
    {
        lock (_stateLock)
        {
            return _lastError;
        }
    }

    private DateTime? GetLastErrorUtc()
    {
        lock (_stateLock)
        {
            return _lastErrorUtc;
        }
    }

    private void SetLastSpillPath(string path)
    {
        lock (_stateLock)
        {
            _lastSpillPath = path;
        }
    }

    private string GetLastSpillPath()
    {
        lock (_stateLock)
        {
            return _lastSpillPath;
        }
    }

    private void SetLastDrainSource(string source)
    {
        lock (_stateLock)
        {
            _lastDrainSource = source;
        }
    }

    private string GetLastDrainSource()
    {
        lock (_stateLock)
        {
            return _lastDrainSource;
        }
    }

    private static void UpdatePeak(ref long target, long candidate)
    {
        var peak = Volatile.Read(ref target);
        while (candidate > peak)
        {
            var previous = Interlocked.CompareExchange(ref target, candidate, peak);
            if (previous == peak)
            {
                return;
            }

            peak = previous;
        }
    }

    private sealed record BufferedLiveEventBatch(
        string Source,
        int RecordCount,
        long PayloadByteCount,
        byte[]? Payload,
        string FilePath)
    {
        public static BufferedLiveEventBatch InMemory(string source, int recordCount, byte[] payload)
            => new(source, recordCount, payload.Length, payload, string.Empty);

        public static BufferedLiveEventBatch OnDisk(string source, int recordCount, long payloadByteCount, string filePath)
            => new(source, recordCount, payloadByteCount, null, filePath);
    }
}

internal sealed record AgentLiveEventBufferOptions
{
    public long MemoryLimitBytes { get; init; } =
        AgentWorkerOptions.DefaultLiveBufferMemoryMegabytes * 1024L * 1024L;

    public string SpillDirectory { get; init; } = Path.Combine(Path.GetTempPath(), "ProcInsider", "LiveEventBuffer");

    public static AgentLiveEventBufferOptions FromWorkerOptions(
        AgentWorkerOptions options,
        string sessionRoot)
    {
        var normalized = options.Normalize();
        var memoryLimitBytes = normalized.LiveBufferMemoryMegabytes * 1024L * 1024L;
        var spillDirectory = string.IsNullOrWhiteSpace(sessionRoot)
            ? Path.Combine(Path.GetTempPath(), "ProcInsider", "LiveEventBuffer")
            : Path.Combine(sessionRoot, "LiveEventBuffer");
        return new AgentLiveEventBufferOptions
        {
            MemoryLimitBytes = memoryLimitBytes,
            SpillDirectory = spillDirectory
        }.Normalize();
    }

    public AgentLiveEventBufferOptions Normalize()
    {
        return this with
        {
            MemoryLimitBytes = Math.Clamp(MemoryLimitBytes, 500L * 1024 * 1024, 2048L * 1024 * 1024),
            SpillDirectory = string.IsNullOrWhiteSpace(SpillDirectory)
                ? Path.Combine(Path.GetTempPath(), "ProcInsider", "LiveEventBuffer")
                : Path.GetFullPath(SpillDirectory)
        };
    }
}

internal sealed record AgentLiveEventBufferSnapshot(
    long MemoryLimitBytes,
    string SpillDirectory,
    long RamBufferedBytes,
    long PeakRamBufferedBytes,
    long DiskBufferedBytes,
    long PeakDiskBufferedBytes,
    int PendingBatchCount,
    long PendingRecordCount,
    long SpilledBatchCount,
    long SpilledRecordCount,
    long CompletedBatchCount,
    long CompletedRecordCount,
    long WriteRetryCount,
    bool IsDrainActive,
    bool IsDrainingAfterStop,
    bool IsCompleted,
    string LastError,
    DateTime? LastErrorUtc,
    string LastSpillPath,
    string LastDrainSource)
{
    public bool HasPendingData => PendingBatchCount > 0 || PendingRecordCount > 0 || RamBufferedBytes > 0 || DiskBufferedBytes > 0;

    public bool IsSpillingToDisk => DiskBufferedBytes > 0 || SpilledBatchCount > 0;
}
