using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services;
using ProcInsider.Services.EvidenceSources;

namespace ProcInsider.Agent;

internal sealed class AgentLiveCaptureJobHandler : IAgentJobHandler
{
    private const int DefaultProcessRefreshIntervalSeconds = 10;
    private const int MinimumProcessRefreshIntervalSeconds = 1;
    private const int MaximumProcessRefreshIntervalSeconds = 3600;
    private const int MaxPendingProcessWriteBatches = 8;
    private static readonly TimeSpan ProgressInterval = TimeSpan.FromSeconds(5);

    private readonly AgentStagingWriter _writer;
    private readonly TextWriter _log;
    private readonly AgentLiveEventBufferOptions _bufferOptions;
    private readonly RuntimeProcessSnapshotEvidenceSourceAdapter _runtimeProcessAdapter;
    private readonly ProcessLifecycleEvidenceSourceAdapter _lifecycleProcessAdapter;
    private readonly SysmonProcessEvidenceSourceAdapter _sysmonProcessAdapter;
    private readonly object _healthLock = new();
    private readonly object _activeCaptureLock = new();
    private readonly AgentLiveCaptureHealthTracker _sourceHealthTracker = new();
    private readonly HashSet<string> _stoppedSources = new(StringComparer.OrdinalIgnoreCase);
    private CaptureHealthReport _health = new()
    {
        Health = CaptureHealth.Idle,
        Detail = "Live capture is not running."
    };

    private long _eventsReceived;
    private long _eventsDropped;
    private long _processRecordsWritten;
    private long _processesObserved;
    private long _processRefreshes;
    private long _processDeltas;
    private long _newProcessDetections;
    private long _processRecordsDropped;
    private long _eventBatchesDropped;
    private long _processBatchesDropped;
    private long _eventWriteFailures;
    private long _processWriteFailures;
    private ProcessWriteThrottle? _activeProcessWriteThrottle;
    private AgentLiveEventBuffer? _activeEventBuffer;
    private ConfigurableEtwService? _activeConfigurableEtw;
    private EventCollectorService? _activeEventCollector;
    private ProcessTracker? _activeProcessTracker;
    private LiveCaptureOptions? _activeLiveOptions;
    private Guid? _activeJobId;
    private CancellationTokenSource? _activeCollectionStop;
    private int _etwStoppedByUser;
    private bool _isPaused;

    /// <summary>Raised after process rows have been committed to the live database.</summary>
    public event Action<IReadOnlyList<ProcessRecord>>? ProcessRecordsPersisted;

    public AgentLiveCaptureJobHandler(
        AgentStagingWriter writer,
        TextWriter log,
        AgentLiveEventBufferOptions bufferOptions,
        RuntimeProcessSnapshotEvidenceSourceAdapter? runtimeProcessAdapter = null,
        ProcessLifecycleEvidenceSourceAdapter? lifecycleProcessAdapter = null,
        SysmonProcessEvidenceSourceAdapter? sysmonProcessAdapter = null)
    {
        _writer = writer;
        _log = log;
        _bufferOptions = bufferOptions.Normalize();
        _runtimeProcessAdapter = runtimeProcessAdapter ?? new RuntimeProcessSnapshotEvidenceSourceAdapter();
        _lifecycleProcessAdapter = lifecycleProcessAdapter ?? new ProcessLifecycleEvidenceSourceAdapter();
        _sysmonProcessAdapter = sysmonProcessAdapter ?? new SysmonProcessEvidenceSourceAdapter();
    }

    public CaptureHealthReport GetHealthSnapshot()
    {
        lock (_healthLock)
        {
            var buffer = _activeEventBuffer?.GetSnapshot();
            return _health with
            {
                TotalEventsReceived = Interlocked.Read(ref _eventsReceived),
                TotalProcessRecordsWritten = Interlocked.Read(ref _processRecordsWritten),
                TotalEventsDropped = Interlocked.Read(ref _eventsDropped),
                TotalProcessRecordsDropped = Interlocked.Read(ref _processRecordsDropped),
                EventBatchesDropped = Interlocked.Read(ref _eventBatchesDropped),
                ProcessBatchesDropped = Interlocked.Read(ref _processBatchesDropped),
                PendingEventWriteBatches = buffer?.PendingBatchCount ?? _health.PendingEventWriteBatches,
                PendingProcessWriteBatches = _activeProcessWriteThrottle?.PendingProcessWrites ?? 0,
                MaxPendingEventWriteBatches = int.MaxValue,
                MaxPendingProcessWriteBatches = _activeProcessWriteThrottle?.MaxProcessWrites ?? MaxPendingProcessWriteBatches,
                EventWriteFailures = Interlocked.Read(ref _eventWriteFailures),
                ProcessWriteFailures = Interlocked.Read(ref _processWriteFailures),
                LiveBufferMemoryLimitBytes = buffer?.MemoryLimitBytes ?? _health.LiveBufferMemoryLimitBytes,
                LiveBufferMemoryBytes = buffer?.RamBufferedBytes ?? _health.LiveBufferMemoryBytes,
                LiveBufferPeakMemoryBytes = buffer?.PeakRamBufferedBytes ?? _health.LiveBufferPeakMemoryBytes,
                LiveBufferDiskBytes = buffer?.DiskBufferedBytes ?? _health.LiveBufferDiskBytes,
                LiveBufferPeakDiskBytes = buffer?.PeakDiskBufferedBytes ?? _health.LiveBufferPeakDiskBytes,
                LiveBufferPendingBatches = buffer?.PendingBatchCount ?? _health.LiveBufferPendingBatches,
                LiveBufferPendingRecords = buffer?.PendingRecordCount ?? _health.LiveBufferPendingRecords,
                LiveBufferSpilledBatches = buffer?.SpilledBatchCount ?? _health.LiveBufferSpilledBatches,
                LiveBufferSpilledRecords = buffer?.SpilledRecordCount ?? _health.LiveBufferSpilledRecords,
                LiveBufferCompletedBatches = buffer?.CompletedBatchCount ?? _health.LiveBufferCompletedBatches,
                LiveBufferCompletedRecords = buffer?.CompletedRecordCount ?? _health.LiveBufferCompletedRecords,
                LiveBufferWriteRetries = buffer?.WriteRetryCount ?? _health.LiveBufferWriteRetries,
                LiveBufferDrainingAfterStop = buffer?.IsDrainingAfterStop == true && buffer.HasPendingData,
                LiveBufferDrainActive = buffer?.IsDrainActive ?? _health.LiveBufferDrainActive,
                LiveBufferDirectory = buffer?.SpillDirectory ?? _health.LiveBufferDirectory,
                LiveBufferLastError = buffer?.LastError ?? _health.LiveBufferLastError,
                LiveBufferLastErrorUtc = buffer?.LastErrorUtc ?? _health.LiveBufferLastErrorUtc,
                Sources = _health.Sources.ToList()
            };
        }
    }

    public bool RequestStop(Guid jobId)
    {
        lock (_activeCaptureLock)
        {
            if (_activeCollectionStop == null ||
                !_activeJobId.HasValue ||
                _activeJobId.Value != jobId)
            {
                return false;
            }

            _activeEventBuffer?.MarkDrainingAfterStop();
            _activeCollectionStop.Cancel();
            return true;
        }
    }

    public async Task<bool> RequestPauseAsync(Guid jobId, CancellationToken cancellationToken)
    {
        ProcessTracker? processTracker;
        EventCollectorService? eventCollector;
        ConfigurableEtwService? configurableEtw;
        lock (_activeCaptureLock)
        {
            if (_activeJobId != jobId || _activeCollectionStop == null)
            {
                return false;
            }

            if (_isPaused)
            {
                return true;
            }

            _isPaused = true;
            processTracker = _activeProcessTracker;
            eventCollector = _activeEventCollector;
            configurableEtw = _activeConfigurableEtw;
        }

        processTracker?.StopRealtimeTracking();
        eventCollector?.Stop();
        configurableEtw?.Stop();

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var buffer = _activeEventBuffer?.GetSnapshot();
            var pendingEvents = buffer?.HasPendingData == true || buffer?.IsDrainActive == true;
            var pendingProcesses = (_activeProcessWriteThrottle?.PendingProcessWrites ?? 0) > 0;
            if (!pendingEvents && !pendingProcesses)
            {
                break;
            }

            await Task.Delay(25, cancellationToken).ConfigureAwait(false);
        }

        var pausedUtc = DateTime.UtcNow;
        var pausedSources = GetHealthSnapshot().Sources
            .Select(source => source with
            {
                Status = "Paused",
                Detail = "Configured capture is paused; activity during this acquisition gap is not collected or backfilled.",
                IsActive = false,
                RecordsPerSecond = 0,
                UpdatedUtc = pausedUtc
            })
            .ToArray();
        SetHealth(
            CaptureHealth.Healthy,
            "Live capture paused; accepted writes are drained and an acquisition gap is active.",
            pausedSources);
        return true;
    }

    public Task<bool> RequestResumeAsync(Guid jobId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ProcessTracker? processTracker;
        EventCollectorService? eventCollector;
        ConfigurableEtwService? configurableEtw;
        LiveCaptureOptions? options;
        lock (_activeCaptureLock)
        {
            if (_activeJobId != jobId || !_isPaused)
            {
                return Task.FromResult(false);
            }

            processTracker = _activeProcessTracker;
            eventCollector = _activeEventCollector;
            configurableEtw = _activeConfigurableEtw;
            options = _activeLiveOptions;
            _isPaused = false;
        }

        if (options == null || processTracker == null || eventCollector == null)
        {
            return Task.FromResult(false);
        }

        processTracker.StartRealtimeTracking();
        eventCollector.SetSecurityCollectionEnabled(IsSourceEnabled("Security", options.CollectSecurityEvents));
        eventCollector.SetPowerShellCollectionEnabled(IsSourceEnabled("PowerShell", options.CollectPowerShellEvents));
        eventCollector.SetOtherWindowsCollectionEnabled(IsSourceEnabled("WindowsOther", options.CollectOtherWindowsEvents));
        eventCollector.SetSysmonCollectionEnabled(IsSourceEnabled("Sysmon", options.CollectSysmonEvents));
        eventCollector.Start();
        if (configurableEtw != null && IsSourceEnabled("ETW", options.CollectEtwEvents))
        {
            configurableEtw.Start();
        }

        SetHealth(
            CaptureHealth.Healthy,
            "Live capture resumed after an explicit acquisition gap; new observations append under the same capture and source run.");
        return Task.FromResult(true);
    }

    public bool RequestSourceStop(string source)
    {
        var normalizedSource = NormalizeLiveSource(source);
        if (normalizedSource == null)
        {
            return false;
        }

        lock (_activeCaptureLock)
        {
            if (!_activeJobId.HasValue)
            {
                return false;
            }

            if (!_stoppedSources.Add(normalizedSource))
            {
                return true;
            }

            switch (normalizedSource)
            {
                case "ETW":
                    _activeConfigurableEtw?.Stop();
                    Volatile.Write(ref _etwStoppedByUser, 1);
                    break;
                case "Security":
                    _activeEventCollector?.SetSecurityCollectionEnabled(false);
                    break;
                case "PowerShell":
                    _activeEventCollector?.SetPowerShellCollectionEnabled(false);
                    break;
                case "WindowsOther":
                    _activeEventCollector?.SetOtherWindowsCollectionEnabled(false);
                    break;
                case "Sysmon":
                    _activeEventCollector?.SetSysmonCollectionEnabled(false);
                    break;
            }

            return true;
        }
    }

    public bool RequestSourceStart(string source)
    {
        var normalizedSource = NormalizeLiveSource(source);
        if (normalizedSource == null)
        {
            return false;
        }

        lock (_activeCaptureLock)
        {
            if (!_activeJobId.HasValue || !_stoppedSources.Remove(normalizedSource))
            {
                return false;
            }

            switch (normalizedSource)
            {
                case "ETW":
                    Volatile.Write(ref _etwStoppedByUser, 0);
                    _activeConfigurableEtw?.Start();
                    break;
                case "Security":
                    _activeEventCollector?.SetSecurityCollectionEnabled(true);
                    break;
                case "PowerShell":
                    _activeEventCollector?.SetPowerShellCollectionEnabled(true);
                    break;
                case "WindowsOther":
                    _activeEventCollector?.SetOtherWindowsCollectionEnabled(true);
                    break;
                case "Sysmon":
                    _activeEventCollector?.SetSysmonCollectionEnabled(true);
                    break;
            }

            return true;
        }
    }

    private void ClearActiveCapture(Guid jobId)
    {
        lock (_activeCaptureLock)
        {
            if (_activeJobId != jobId)
            {
                return;
            }

            _activeEventBuffer = null;
            _activeConfigurableEtw = null;
            _activeEventCollector = null;
            _activeProcessTracker = null;
            _activeLiveOptions = null;
            _activeCollectionStop = null;
            _activeJobId = null;
            _activeProcessWriteThrottle = null;
            _isPaused = false;
            _stoppedSources.Clear();
        }
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var liveOptions = ReadLiveCaptureOptions(context.Request);
        ResetCaptureCounters();
        Volatile.Write(ref _etwStoppedByUser, 0);
        var writeThrottle = new ProcessWriteThrottle(MaxPendingProcessWriteBatches);
        await using var eventBuffer = new AgentLiveEventBuffer(
            _writer,
            _log,
            _bufferOptions,
            AddSourceRecordsQueued,
            OnEventBufferBatchWritten);
        using var collectionStop = new CancellationTokenSource();
        using var collectionCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            context.CancellationToken,
            collectionStop.Token);
        _activeProcessWriteThrottle = writeThrottle;
        lock (_activeCaptureLock)
        {
            _activeEventBuffer = eventBuffer;
            _activeCollectionStop = collectionStop;
            _activeJobId = context.Request.JobId;
            _activeLiveOptions = liveOptions;
            _isPaused = false;
            _stoppedSources.Clear();
        }

        var processState = new ProcessSnapshotState();
        var processWrites = new LiveProcessWriteCoordinator(
            _writer,
            writeThrottle,
            count => AddSourceRecordsQueued("Runtime", count),
            OnProcessWriteCompleted,
            OnProcessWriteFailed);
        var options = EventCollectionOptions.CreateDefault();
        var runtimeEnabled = IsSourceEnabled("Runtime", liveOptions.CollectRuntimeEvents);
        options.CollectProcessEvents = runtimeEnabled;
        options.CollectNetworkEvents = runtimeEnabled && options.CollectNetworkEvents;
        options.CollectDnsEvents = runtimeEnabled && options.CollectDnsEvents;
        options.HonorSysmonIntegrationToggle = false;
        var processTracker = new ProcessTracker(new ProcessDataCollector());
        using var processEventContext = new AgentProcessEventContext(processTracker);
        var runtimeStore = CreateEventStore(options);
        var securityStore = CreateEventStore(options);
        var powerShellStore = CreateEventStore(options);
        var otherWindowsStore = CreateEventStore(options);
        var sysmonStore = CreateEventStore(options);
        var etwStore = CreateEventStore(options);
        using var configurableEtw = new ConfigurableEtwService(
            processEventContext,
            etwStore,
            liveOptions.EtwProfilePath,
            liveOptions.EtwProfileId,
            liveOptions.EtwProfileDisplayName);
        var eventCollector = new EventCollectorService(
            processEventContext,
            runtimeStore,
            securityStore,
            powerShellStore,
            otherWindowsStore,
            sysmonStore,
            options,
            new PowerShellAuditingService(),
            new SysmonService());
        eventCollector.SetSecurityCollectionEnabled(IsSourceEnabled("Security", liveOptions.CollectSecurityEvents));
        eventCollector.SetPowerShellCollectionEnabled(IsSourceEnabled("PowerShell", liveOptions.CollectPowerShellEvents));
        eventCollector.SetOtherWindowsCollectionEnabled(IsSourceEnabled("WindowsOther", liveOptions.CollectOtherWindowsEvents));
        eventCollector.SetSysmonCollectionEnabled(IsSourceEnabled("Sysmon", liveOptions.CollectSysmonEvents));
        lock (_activeCaptureLock)
        {
            _activeConfigurableEtw = configurableEtw;
            _activeEventCollector = eventCollector;
            _activeProcessTracker = processTracker;
        }

        processTracker.ProcessesUpdated += OnProcessesUpdated;
        processTracker.ProcessChangesDetected += OnProcessChangesDetected;
        processTracker.ExternalProcessObserved += OnExternalProcessObserved;
        runtimeStore.EventsAdded += (_, e) =>
        {
            if (IsSourceEnabled("Runtime", liveOptions.CollectRuntimeEvents))
            {
                PersistEvents("Runtime", e.Events, liveOptions, eventBuffer, collectionCancellation.Token);
            }
        };
        securityStore.EventsAdded += (_, e) => PersistEventsWhenEnabled("Security", e.Events);
        powerShellStore.EventsAdded += (_, e) => PersistEventsWhenEnabled("PowerShell", e.Events);
        otherWindowsStore.EventsAdded += (_, e) => PersistEventsWhenEnabled("WindowsOther", e.Events);
        sysmonStore.EventsAdded += (_, e) => PersistEventsWhenEnabled("Sysmon", e.Events);
        etwStore.EventsAdded += (_, e) => PersistEventsWhenEnabled("ETW", e.Events);

        try
        {
            SetHealth(CaptureHealth.Healthy, "Live capture is starting.");
            processTracker.StartRealtimeTracking();
            await processTracker.RefreshAsync(context.CancellationToken).ConfigureAwait(false);
            eventCollector.Start();
            if (IsSourceEnabled("ETW", liveOptions.CollectEtwEvents))
            {
                configurableEtw.Start();
            }

            PublishSourceHealth(context, liveOptions, configurableEtw, eventCollector, writeThrottle, eventBuffer);
            await context.ReportProgressAsync(0, -1, BuildProgressMessage(liveOptions, writeThrottle, eventBuffer.GetSnapshot(), 0, 0, 0, 0, 0)).ConfigureAwait(false);

            await Task.WhenAll(
                    RunPeriodicProcessRefreshAsync(processTracker, liveOptions, context, collectionCancellation.Token),
                    RunProgressLoopAsync(liveOptions, configurableEtw, eventCollector, writeThrottle, context, eventBuffer, collectionCancellation.Token))
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (collectionStop.IsCancellationRequested && !context.CancellationToken.IsCancellationRequested)
        {
        }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
        {
            SetHealth(CaptureHealth.Idle, "Live capture stopped.");
            ClearActiveCapture(context.Request.JobId);
            throw;
        }
        catch (Exception ex)
        {
            SetHealth(CaptureHealth.Error, $"Live capture failed: {ex.Message}");
            ClearActiveCapture(context.Request.JobId);
            throw;
        }
        finally
        {
            processTracker.ProcessesUpdated -= OnProcessesUpdated;
            processTracker.ProcessChangesDetected -= OnProcessChangesDetected;
            processTracker.ExternalProcessObserved -= OnExternalProcessObserved;
            eventCollector.Stop();
            configurableEtw.Stop();
            processTracker.StopRealtimeTracking();
        }

        try
        {
            eventBuffer.MarkDrainingAfterStop();
            PublishSourceHealth(context, liveOptions, configurableEtw, eventCollector, writeThrottle, eventBuffer);
            await context.ReportProgressAsync(
                Interlocked.Read(ref _eventsReceived),
                -1,
                BuildDrainProgressMessage(eventBuffer.GetSnapshot()),
                CancellationToken.None).ConfigureAwait(false);
            await Task.WhenAll(
                    eventBuffer.CompleteAndDrainAsync(context.CancellationToken).AsTask(),
                    processWrites.CompleteAndDrainAsync(context.CancellationToken))
                .ConfigureAwait(false);
            var transitionUtc = DateTime.UtcNow;
            var terminalStatuses = AgentLiveCaptureHealthTracker.ProjectTerminalStatuses(
                BuildSourceHealth(liveOptions, configurableEtw, eventCollector, Volatile.Read(ref _etwStoppedByUser) != 0),
                GetEnabledSources(liveOptions).ToHashSet(StringComparer.OrdinalIgnoreCase),
                transitionUtc);
            var drainedSourceReports = BuildSourceReports(terminalStatuses, transitionUtc, isTerminal: true);
            SetHealth(
                CaptureHealth.Idle,
                "Live capture stopped; accepted live event buffer has been loaded to SQLite.",
                drainedSourceReports,
                isTerminal: true);
            await context.ReportProgressAsync(
                Interlocked.Read(ref _eventsReceived),
                -1,
                "Live capture stopped; SQLite load complete.",
                CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            ClearActiveCapture(context.Request.JobId);
        }

        void OnProcessesUpdated(object? sender, ProcessUpdateEventArgs e)
        {
            if (!IsSourceEnabled("Runtime", liveOptions.CollectRuntimeEvents))
            {
                return;
            }

            if (e.IsFullSnapshot)
            {
                PersistProcesses(
                    e.AllProcesses,
                    "AgentLiveCaptureProcessRefresh",
                    liveOptions,
                    context,
                    processState,
                    isFullSnapshot: true,
                    processWrites,
                    context.CancellationToken);
            }
        }

        void OnProcessChangesDetected(object? sender, ProcessChangesEventArgs e)
        {
            if (!IsSourceEnabled("Runtime", liveOptions.CollectRuntimeEvents))
            {
                return;
            }

            if (e.NewProcesses.Count == 0 && e.ExitedProcesses.Count == 0)
            {
                return;
            }

            var changed = e.NewProcesses
                .Concat(e.ExitedProcesses)
                .ToList();
            PersistProcesses(
                changed,
                e.Source,
                liveOptions,
                context,
                processState,
                isFullSnapshot: false,
                processWrites,
                context.CancellationToken,
                e.ObservationKind == ProcessObservationKind.WmiLifecycle
                    ? ProcessLifecycleProducer.Wmi
                    : ProcessLifecycleProducer.Runtime);
        }

        void OnExternalProcessObserved(object? sender, ExternalProcessObservationEventArgs e)
        {
            if (!IsSourceEnabled("Sysmon", liveOptions.CollectSysmonEvents) ||
                e.ObservationKind is not (ProcessObservationKind.SysmonProcessCreate or ProcessObservationKind.SysmonProcessTerminate))
            {
                return;
            }

            PersistProcesses(
                [e.Process],
                e.Source,
                liveOptions,
                context,
                processState,
                isFullSnapshot: false,
                processWrites,
                context.CancellationToken,
                ProcessLifecycleProducer.Runtime,
                e.ObservationKind);
        }

        void OnProcessWriteFailed(IReadOnlyList<ProcessRecord> records, Exception ex)
        {
            Interlocked.Add(ref _processRecordsDropped, records.Count);
            Interlocked.Increment(ref _processBatchesDropped);
            Interlocked.Increment(ref _processWriteFailures);
            AddSourceRecordsDropped("Runtime", records.Count);
            AddSourceWriteFailure("Runtime");
            SetHealth(CaptureHealth.Degraded, $"Live process staging is degraded: {ex.Message}");
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Live process staging failed: {ex.Message}");
        }

        void OnProcessWriteCompleted(IReadOnlyList<ProcessRecord> records)
        {
            Interlocked.Add(ref _processRecordsWritten, records.Count);
            AddSourceRecordsWritten("Runtime", records.Count);
            ProcessRecordsPersisted?.Invoke(records);
        }

        void OnEventBufferBatchWritten(string source, IReadOnlyList<TelemetryEventRecord> records)
        {
            Interlocked.Add(ref _eventsReceived, records.Count);
            AddSourceRecordsWritten(source, records.Count);
        }

        void PersistEventsWhenEnabled(string source, IReadOnlyList<ProcessEventInfo> events)
        {
            if (IsSourceEnabled(source, GetConfiguredSourceState(source, liveOptions)))
            {
                PersistEvents(source, events, liveOptions, eventBuffer, collectionCancellation.Token);
                if (string.Equals(source, "ETW", StringComparison.OrdinalIgnoreCase))
                {
                    var lifecycleProcesses = events
                        .Where(processEvent =>
                            processEvent.ProcessId > 0 &&
                            processEvent.Action is ProcessEventAction.ProcessStart or ProcessEventAction.ProcessExit)
                        .Select(processEvent => new ProcessInfo
                        {
                            ProcessKey = processEvent.ProcessKey,
                            ProcessId = processEvent.ProcessId,
                            ProcessGuid = processEvent.ProcessGuid,
                            ProcessName = processEvent.ProcessName,
                            ParentProcessId = processEvent.ParentProcessId,
                            StartTime = processEvent.ProcessStartTimeUtc?.ToLocalTime(),
                            EndTime = processEvent.Action == ProcessEventAction.ProcessExit
                                ? processEvent.TimestampUtc.ToLocalTime()
                                : null,
                            Status = processEvent.Action == ProcessEventAction.ProcessExit
                                ? ProcessStatus.Exited
                                : ProcessStatus.Running
                        })
                        .ToList();
                    PersistProcesses(
                        lifecycleProcesses,
                        "EtwProcessLifecycle",
                        liveOptions,
                        context,
                        processState,
                        isFullSnapshot: false,
                        processWrites,
                        collectionCancellation.Token,
                        ProcessLifecycleProducer.Etw);
                }
            }
        }
    }

    private static ProcessEventStore CreateEventStore(EventCollectionOptions options)
    {
        return new ProcessEventStore(options, retainEvents: false);
    }

    private static LiveCaptureOptions ReadLiveCaptureOptions(AgentJobRequest request)
    {
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<LiveCaptureOptions>(
                request.ToParametersJson(),
                AgentJson.JsonOptions) ?? new LiveCaptureOptions();
        }
        catch
        {
            return new LiveCaptureOptions();
        }
    }

    private async Task RunPeriodicProcessRefreshAsync(
        ProcessTracker processTracker,
        LiveCaptureOptions options,
        AgentJobContext context,
        CancellationToken collectionToken)
    {
        using var timer = new PeriodicTimer(GetProcessRefreshInterval(options));
        while (await timer.WaitForNextTickAsync(collectionToken).ConfigureAwait(false))
        {
            try
            {
                if (IsSourceEnabled("Runtime", options.CollectRuntimeEvents))
                {
                    await processTracker.RefreshAsync(collectionToken).ConfigureAwait(false);
                    Interlocked.Increment(ref _processRefreshes);
                }
            }
            catch (OperationCanceledException) when (collectionToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _processRecordsDropped);
                AddSourceRecordsDropped("Runtime", 1);
                SetHealth(CaptureHealth.Degraded, $"Live process refresh is degraded: {ex.Message}");
                _log.WriteLine($"[{DateTimeOffset.Now:O}] Live process refresh failed: {ex.Message}");
            }
        }
    }

    private async Task RunProgressLoopAsync(
        LiveCaptureOptions options,
        ConfigurableEtwService configurableEtw,
        EventCollectorService eventCollector,
        ProcessWriteThrottle writeThrottle,
        AgentJobContext context,
        AgentLiveEventBuffer eventBuffer,
        CancellationToken collectionToken)
    {
        using var timer = new PeriodicTimer(ProgressInterval);
        while (await timer.WaitForNextTickAsync(collectionToken).ConfigureAwait(false))
        {
            var events = Interlocked.Read(ref _eventsReceived);
            var processes = Interlocked.Read(ref _processesObserved);
            var refreshes = Interlocked.Read(ref _processRefreshes);
            var deltas = Interlocked.Read(ref _processDeltas);
            var newProcesses = Interlocked.Read(ref _newProcessDetections);
            var buffer = eventBuffer.GetSnapshot();
            PublishSourceHealth(context, options, configurableEtw, eventCollector, writeThrottle, eventBuffer);

            await context.ReportProgressAsync(events, -1, BuildProgressMessage(options, writeThrottle, buffer, processes, events, refreshes, deltas, newProcesses)).ConfigureAwait(false);
        }
    }

    private static string BuildProgressMessage(
        LiveCaptureOptions options,
        ProcessWriteThrottle writeThrottle,
        AgentLiveEventBufferSnapshot buffer,
        long processes,
        long events,
        long refreshes,
        long deltas,
        long newProcesses)
    {
        var profile = string.IsNullOrWhiteSpace(options.EtwProfileDisplayName)
            ? options.EtwProfileId
            : options.EtwProfileDisplayName;
        var profileSuffix = string.IsNullOrWhiteSpace(profile)
            ? string.Empty
            : $" ETW profile: {profile}.";

        var intervalSeconds = (int)GetProcessRefreshInterval(options).TotalSeconds;
        var sources = string.Join(", ", GetEnabledSources(options));
        var countersSuffix = buffer.HasPendingData || writeThrottle.HasPendingPressure
            ? $" Pending SQLite load: events {buffer.PendingRecordCount:N0} in {buffer.PendingBatchCount:N0} batch(es), RAM {FormatBytes(buffer.RamBufferedBytes)}/{FormatBytes(buffer.MemoryLimitBytes)}, disk {FormatBytes(buffer.DiskBufferedBytes)}, processes {writeThrottle.PendingProcessWrites}/{writeThrottle.MaxProcessWrites} batch(es)."
            : string.Empty;
        return $"Live capture running. Sources: {sources}; processes observed: {processes}; new detections: {newProcesses}; events staged: {events}; process refresh every {intervalSeconds} seconds; snapshots: {refreshes}; delta rows: {deltas}.{countersSuffix}{profileSuffix}";
    }

    private static string BuildDrainProgressMessage(AgentLiveEventBufferSnapshot buffer)
    {
        return buffer.HasPendingData
            ? $"Live capture stopped; SQLite is loading accepted buffer data: {buffer.PendingRecordCount:N0} event(s) in {buffer.PendingBatchCount:N0} batch(es), RAM {FormatBytes(buffer.RamBufferedBytes)}, disk {FormatBytes(buffer.DiskBufferedBytes)}."
            : "Live capture stopped; SQLite buffer drain is finishing.";
    }

    private void PersistProcesses(
        IReadOnlyCollection<ProcessInfo> processes,
        string source,
        LiveCaptureOptions options,
        AgentJobContext context,
        ProcessSnapshotState processState,
        bool isFullSnapshot,
        LiveProcessWriteCoordinator processWrites,
        CancellationToken cancellationToken,
        ProcessLifecycleProducer lifecycleProducer = ProcessLifecycleProducer.Runtime,
        ProcessObservationKind? sourceObservationKind = null)
    {
        if (processes.Count == 0 || cancellationToken.IsCancellationRequested)
        {
            return;
        }

        var isSysmon = sourceObservationKind is
            ProcessObservationKind.SysmonProcessCreate or ProcessObservationKind.SysmonProcessTerminate;
        var adapter = isSysmon
            ? (IEvidenceSourceAdapter)_sysmonProcessAdapter
            : isFullSnapshot
                ? _runtimeProcessAdapter
                : _lifecycleProcessAdapter;
        var publisher = new LiveProcessEvidenceSourcePublisher(
            adapter.Descriptor.MaxBatchRowCount,
            (observations, aliases, statistics) =>
            {
                var records = observations.Select(observation => observation.Fields).ToList();
                var summary = processState.Apply(records);
                Interlocked.Exchange(ref _processesObserved, summary.TotalKnownProcesses);
                Interlocked.Add(ref _newProcessDetections, summary.NewProcesses);
                if (!isFullSnapshot)
                {
                    Interlocked.Add(ref _processDeltas, records.Count);
                }

                processWrites.Enqueue(observations, aliases, statistics, isFullSnapshot, cancellationToken);
            });
        object payload = isSysmon
            ? new SysmonProcessEvidenceSourceInput
            {
                CaptureId = options.CaptureId,
                ObservedUtc = DateTime.UtcNow,
                IsTermination = sourceObservationKind == ProcessObservationKind.SysmonProcessTerminate,
                Processes = processes.ToArray()
            }
            : isFullSnapshot
            ? new RuntimeProcessSnapshotInput
            {
                CaptureId = options.CaptureId,
                Source = source,
                ObservedUtc = DateTime.UtcNow,
                IsFullSnapshot = true,
                Processes = processes.ToArray()
            }
            : new ProcessLifecycleEvidenceSourceInput
            {
                CaptureId = options.CaptureId,
                Source = source,
                ObservedUtc = DateTime.UtcNow,
                Producer = lifecycleProducer,
                Processes = processes.ToArray()
            };
        var prerequisite = isSysmon
            ? SysmonProcessEvidenceSourceAdapter.SysmonPrerequisite
            : isFullSnapshot
            ? RuntimeProcessSnapshotEvidenceSourceAdapter.ProcessApiPrerequisite
            : ProcessLifecycleEvidenceSourceAdapter.LifecyclePrerequisite;
        var result = adapter.ExecuteAsync(
                new EvidenceSourceAdapterRequest
                {
                    SourceRunId = context.SourceRunId,
                    IngestionJobId = context.Request.JobId,
                    EvidenceIdentity = context.Request.EvidenceIdentity,
                    Payload = payload,
                    AvailablePrerequisiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    {
                        prerequisite
                    }
                },
                publisher,
                progress: null,
                cancellationToken)
            .AsTask()
            .GetAwaiter()
            .GetResult();
        if (result.State != EvidenceSourceCompletionState.Completed)
        {
            var diagnostic = result.Diagnostics.FirstOrDefault()?.Message;
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(diagnostic)
                    ? $"Process adapter {adapter.Descriptor.AdapterId} ended in {result.State}."
                    : diagnostic);
        }
    }

    private void PersistEvents(
        string source,
        IReadOnlyList<ProcessEventInfo> events,
        LiveCaptureOptions options,
        AgentLiveEventBuffer eventBuffer,
        CancellationToken cancellationToken)
    {
        if (events.Count == 0 || cancellationToken.IsCancellationRequested)
        {
            return;
        }

        try
        {
            var records = events
                .Select(processEvent => CreateTelemetryEvent(source, processEvent, options))
                .ToList();
            eventBuffer.Enqueue(source, records);
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _eventWriteFailures);
            AddSourceWriteFailure(source);
            SetHealth(CaptureHealth.Degraded, $"Live event buffer enqueue is degraded: {ex.Message}");
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Live event buffer enqueue failed: {ex.Message}");
        }
    }

    private static TimeSpan GetProcessRefreshInterval(LiveCaptureOptions options)
    {
        var seconds = Math.Clamp(
            options.ProcessRefreshIntervalSeconds <= 0
                ? DefaultProcessRefreshIntervalSeconds
                : options.ProcessRefreshIntervalSeconds,
            MinimumProcessRefreshIntervalSeconds,
            MaximumProcessRefreshIntervalSeconds);
        return TimeSpan.FromSeconds(seconds);
    }

    private static TelemetryEventRecord CreateTelemetryEvent(
        string source,
        ProcessEventInfo processEvent,
        LiveCaptureOptions options)
    {
        var eventMetadata = SystemActivityNormalizer.ExtractEventMetadata(processEvent.Details);
        return new TelemetryEventRecord
        {
            CaptureId = options.CaptureId,
            TimestampUtc = processEvent.TimestampUtc,
            Source = source,
            ProcessKey = processEvent.ProcessKey,
            ProcessId = processEvent.ProcessId,
            ProcessGuid = processEvent.ProcessGuid,
            ProcessStartTimeUtc = processEvent.ProcessStartTimeUtc,
            ProcessName = processEvent.ProcessName,
            ParentProcessId = processEvent.ParentProcessId,
            EventCode = processEvent.EventCode,
            Category = processEvent.Category,
            Action = processEvent.Action,
            Target = processEvent.Target,
            Summary = processEvent.Summary,
            Details = processEvent.Details,
            RiskFlags = processEvent.RiskFlags,
            IsInteresting = processEvent.IsInteresting,
            RepeatCount = processEvent.RepeatCount,
            RawProvider = eventMetadata.Provider,
            RawLogName = eventMetadata.LogName,
            RawRecordId = eventMetadata.RecordId,
            CorrelationMethod = string.IsNullOrWhiteSpace(processEvent.ProcessGuid) ? "PidAndTime" : "ProcessGuid"
        };
    }

    private void SetHealth(
        CaptureHealth health,
        string detail,
        IReadOnlyList<CaptureSourceHealthReport>? sources = null,
        bool isTerminal = false)
    {
        lock (_healthLock)
        {
            var buffer = _activeEventBuffer?.GetSnapshot();
            var report = new CaptureHealthReport
            {
                Health = health,
                Detail = detail,
                TotalEventsReceived = Interlocked.Read(ref _eventsReceived),
                TotalProcessRecordsWritten = Interlocked.Read(ref _processRecordsWritten),
                TotalEventsDropped = Interlocked.Read(ref _eventsDropped),
                TotalProcessRecordsDropped = Interlocked.Read(ref _processRecordsDropped),
                EventBatchesDropped = Interlocked.Read(ref _eventBatchesDropped),
                ProcessBatchesDropped = Interlocked.Read(ref _processBatchesDropped),
                PendingEventWriteBatches = buffer?.PendingBatchCount ?? 0,
                PendingProcessWriteBatches = _activeProcessWriteThrottle?.PendingProcessWrites ?? 0,
                MaxPendingEventWriteBatches = int.MaxValue,
                MaxPendingProcessWriteBatches = _activeProcessWriteThrottle?.MaxProcessWrites ?? MaxPendingProcessWriteBatches,
                EventWriteFailures = Interlocked.Read(ref _eventWriteFailures),
                ProcessWriteFailures = Interlocked.Read(ref _processWriteFailures),
                LiveBufferMemoryLimitBytes = buffer?.MemoryLimitBytes ?? _bufferOptions.MemoryLimitBytes,
                LiveBufferMemoryBytes = buffer?.RamBufferedBytes ?? 0,
                LiveBufferPeakMemoryBytes = buffer?.PeakRamBufferedBytes ?? 0,
                LiveBufferDiskBytes = buffer?.DiskBufferedBytes ?? 0,
                LiveBufferPeakDiskBytes = buffer?.PeakDiskBufferedBytes ?? 0,
                LiveBufferPendingBatches = buffer?.PendingBatchCount ?? 0,
                LiveBufferPendingRecords = buffer?.PendingRecordCount ?? 0,
                LiveBufferSpilledBatches = buffer?.SpilledBatchCount ?? 0,
                LiveBufferSpilledRecords = buffer?.SpilledRecordCount ?? 0,
                LiveBufferCompletedBatches = buffer?.CompletedBatchCount ?? 0,
                LiveBufferCompletedRecords = buffer?.CompletedRecordCount ?? 0,
                LiveBufferWriteRetries = buffer?.WriteRetryCount ?? 0,
                LiveBufferDrainingAfterStop = buffer?.IsDrainingAfterStop == true && buffer.HasPendingData,
                LiveBufferDrainActive = buffer?.IsDrainActive ?? false,
                LiveBufferDirectory = buffer?.SpillDirectory ?? _bufferOptions.SpillDirectory,
                LiveBufferLastError = buffer?.LastError ?? string.Empty,
                LiveBufferLastErrorUtc = buffer?.LastErrorUtc,
                Sources = sources ?? _health.Sources
            };
            _health = isTerminal
                ? AgentLiveCaptureHealthTracker.ProjectTerminalReport(report, detail, report.Sources)
                : report;
        }
    }

    private void PublishSourceHealth(
        AgentJobContext context,
        LiveCaptureOptions options,
        ConfigurableEtwService configurableEtw,
        EventCollectorService eventCollector,
        ProcessWriteThrottle writeThrottle,
        AgentLiveEventBuffer eventBuffer)
    {
        var statuses = BuildSourceHealth(
            options,
            configurableEtw,
            eventCollector,
            Volatile.Read(ref _etwStoppedByUser) != 0);
        var diagnostics = BuildDiagnostics(writeThrottle, eventBuffer.GetSnapshot());
        var health = statuses.Any(IsEnabledSourceDegraded) || diagnostics.IsDegraded
            ? CaptureHealth.Degraded
            : CaptureHealth.Healthy;
        var sourceReports = BuildSourceReports(statuses, DateTime.UtcNow);
        var detail = BuildHealthDetail(sourceReports, diagnostics);
        SetHealth(health, detail, sourceReports);
        _ = PersistSourceHealthAsync(context.SourceRunId, health, statuses, diagnostics, context.CancellationToken);
    }

    private async Task PersistSourceHealthAsync(
        string sourceRunId,
        CaptureHealth health,
        IReadOnlyList<EventSourceHealthSnapshot> statuses,
        LiveCaptureDiagnostics diagnostics,
        CancellationToken cancellationToken)
    {
        try
        {
            var metadata = System.Text.Json.JsonSerializer.Serialize(
                new LiveCaptureSourceMetadata
                {
                    UpdatedUtc = DateTime.UtcNow,
                    Sources = statuses,
                    Diagnostics = diagnostics
                },
                AgentJson.JsonOptions);
            await _writer.UpdateSourceRunStatusAsync(sourceRunId, health == CaptureHealth.Degraded ? "Degraded" : "Active", null, metadata, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Live source health metadata update failed: {ex.Message}");
        }
    }

    private IReadOnlyList<EventSourceHealthSnapshot> BuildSourceHealth(
        LiveCaptureOptions options,
        ConfigurableEtwService configurableEtw,
        EventCollectorService eventCollector,
        bool etwStoppedByUser)
    {
        var statuses = new List<EventSourceHealthSnapshot>
        {
            CreateEtwHealth(options, configurableEtw, etwStoppedByUser)
        };
        statuses.AddRange(eventCollector.GetSourceHealthSnapshots());
        var stoppedSources = GetStoppedSources();
        return statuses
            .Select(status => stoppedSources.Contains(status.Source)
                ? status with
                {
                    Status = "Disabled",
                    Detail = $"{status.Source} collection was stopped from the Agents tab; other live collectors remain active.",
                    IsEnabled = false,
                    IsActive = false,
                    Error = string.Empty
                }
                : status)
            .GroupBy(status => status.Source, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderByDescending(status => status.UpdatedUtc).First())
            .OrderBy(status => status.Source, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private IReadOnlyList<CaptureSourceHealthReport> BuildSourceReports(
        IReadOnlyList<EventSourceHealthSnapshot> statuses,
        DateTime nowUtc,
        bool isTerminal = false)
    {
        return _sourceHealthTracker.BuildReports(statuses, nowUtc, isTerminal);
    }

    private static EventSourceHealthSnapshot CreateEtwHealth(
        LiveCaptureOptions options,
        ConfigurableEtwService configurableEtw,
        bool etwStoppedByUser)
    {
        if (!options.CollectEtwEvents || etwStoppedByUser)
        {
            return new EventSourceHealthSnapshot(
                "ETW",
                "Disabled",
                etwStoppedByUser
                    ? "ETW collection was stopped from the Agents tab; other live collectors remain active."
                    : "ETW collection is disabled for this live-capture job.",
                IsEnabled: false,
                IsActive: false,
                DateTime.UtcNow,
                string.Empty);
        }

        var status = configurableEtw.StatusMessage ?? string.Empty;
        var degraded = status.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
                       status.Contains("error", StringComparison.OrdinalIgnoreCase);
        return new EventSourceHealthSnapshot(
            "ETW",
            degraded ? "Degraded" : "Active",
            string.IsNullOrWhiteSpace(status) ? "ETW collection is active." : status,
            IsEnabled: true,
            IsActive: !degraded,
            DateTime.UtcNow,
            degraded ? status : string.Empty);
    }

    private static bool IsEnabledSourceDegraded(EventSourceHealthSnapshot status)
    {
        return status.IsEnabled &&
               !string.Equals(status.Status, "Active", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsSourceEnabled(string source, bool configuredEnabled)
    {
        if (!configuredEnabled)
        {
            return false;
        }

        lock (_activeCaptureLock)
        {
            return !_isPaused && !_stoppedSources.Contains(source);
        }
    }

    private HashSet<string> GetStoppedSources()
    {
        lock (_activeCaptureLock)
        {
            return new HashSet<string>(_stoppedSources, StringComparer.OrdinalIgnoreCase);
        }
    }

    private static string? NormalizeLiveSource(string source)
    {
        return source.Trim() switch
        {
            "Runtime" => "Runtime",
            "ETW" => "ETW",
            "Security" => "Security",
            "PowerShell" => "PowerShell",
            "WindowsOther" => "WindowsOther",
            "Sysmon" => "Sysmon",
            _ => null
        };
    }

    private static bool GetConfiguredSourceState(string source, LiveCaptureOptions options)
    {
        return source switch
        {
            "Runtime" => options.CollectRuntimeEvents,
            "ETW" => options.CollectEtwEvents,
            "Security" => options.CollectSecurityEvents,
            "PowerShell" => options.CollectPowerShellEvents,
            "WindowsOther" => options.CollectOtherWindowsEvents,
            "Sysmon" => options.CollectSysmonEvents,
            _ => false
        };
    }

    private LiveCaptureDiagnostics BuildDiagnostics(
        ProcessWriteThrottle writeThrottle,
        AgentLiveEventBufferSnapshot buffer)
    {
        return new LiveCaptureDiagnostics
        {
            TotalEventsReceived = Interlocked.Read(ref _eventsReceived),
            TotalProcessRecordsWritten = Interlocked.Read(ref _processRecordsWritten),
            TotalEventsDropped = Interlocked.Read(ref _eventsDropped),
            TotalProcessRecordsDropped = Interlocked.Read(ref _processRecordsDropped),
            EventBatchesDropped = Interlocked.Read(ref _eventBatchesDropped),
            ProcessBatchesDropped = Interlocked.Read(ref _processBatchesDropped),
            PendingEventWriteBatches = buffer.PendingBatchCount,
            PendingProcessWriteBatches = writeThrottle.PendingProcessWrites,
            MaxPendingEventWriteBatches = int.MaxValue,
            MaxPendingProcessWriteBatches = writeThrottle.MaxProcessWrites,
            EventWriteFailures = Interlocked.Read(ref _eventWriteFailures),
            ProcessWriteFailures = Interlocked.Read(ref _processWriteFailures),
            LiveBufferMemoryLimitBytes = buffer.MemoryLimitBytes,
            LiveBufferMemoryBytes = buffer.RamBufferedBytes,
            LiveBufferPeakMemoryBytes = buffer.PeakRamBufferedBytes,
            LiveBufferDiskBytes = buffer.DiskBufferedBytes,
            LiveBufferPeakDiskBytes = buffer.PeakDiskBufferedBytes,
            LiveBufferPendingBatches = buffer.PendingBatchCount,
            LiveBufferPendingRecords = buffer.PendingRecordCount,
            LiveBufferSpilledBatches = buffer.SpilledBatchCount,
            LiveBufferSpilledRecords = buffer.SpilledRecordCount,
            LiveBufferCompletedBatches = buffer.CompletedBatchCount,
            LiveBufferCompletedRecords = buffer.CompletedRecordCount,
            LiveBufferWriteRetries = buffer.WriteRetryCount,
            LiveBufferDrainingAfterStop = buffer.IsDrainingAfterStop && buffer.HasPendingData,
            LiveBufferDrainActive = buffer.IsDrainActive,
            LiveBufferDirectory = buffer.SpillDirectory,
            LiveBufferLastError = buffer.LastError,
            LiveBufferLastErrorUtc = buffer.LastErrorUtc
        };
    }

    private static string BuildHealthDetail(IReadOnlyList<CaptureSourceHealthReport> statuses, LiveCaptureDiagnostics diagnostics)
    {
        var details = new List<string>();
        if (statuses.Count == 0)
        {
            details.Add("Live capture is running.");
        }
        else
        {
            var summary = string.Join(
                "; ",
                statuses.Select(FormatSourceHealthSummary));
            details.Add($"Live capture is running. Source health: {summary}.");
        }

        if (diagnostics.TotalEventsDropped > 0 || diagnostics.TotalProcessRecordsDropped > 0)
        {
            details.Add($"Dropped rows: events {diagnostics.TotalEventsDropped} in {diagnostics.EventBatchesDropped} batch(es), process rows {diagnostics.TotalProcessRecordsDropped} in {diagnostics.ProcessBatchesDropped} batch(es).");
        }

        if (diagnostics.EventWriteFailures > 0 || diagnostics.ProcessWriteFailures > 0)
        {
            details.Add($"Write failures: events {diagnostics.EventWriteFailures}, processes {diagnostics.ProcessWriteFailures}.");
        }

        if (diagnostics.HasPendingWrites)
        {
            details.Add($"Pending SQLite load: events {diagnostics.LiveBufferPendingRecords:N0} in {diagnostics.LiveBufferPendingBatches:N0} batch(es), RAM {FormatBytes(diagnostics.LiveBufferMemoryBytes)}/{FormatBytes(diagnostics.LiveBufferMemoryLimitBytes)}, disk {FormatBytes(diagnostics.LiveBufferDiskBytes)}, processes {diagnostics.PendingProcessWriteBatches}/{diagnostics.MaxPendingProcessWriteBatches} batch(es).");
        }

        if (diagnostics.LiveBufferSpilledBatches > 0)
        {
            details.Add($"Live event buffer spilled {diagnostics.LiveBufferSpilledRecords:N0} event(s) in {diagnostics.LiveBufferSpilledBatches:N0} batch(es) to disk under {diagnostics.LiveBufferDirectory}.");
        }

        if (diagnostics.LiveBufferDrainingAfterStop)
        {
            details.Add("Capture is stopped; SQLite is still loading accepted live event data.");
        }

        if (diagnostics.LiveBufferWriteRetries > 0)
        {
            details.Add($"Live buffer write retries: {diagnostics.LiveBufferWriteRetries:N0}.");
        }

        if (!string.IsNullOrWhiteSpace(diagnostics.LiveBufferLastError))
        {
            details.Add($"Last live buffer detail: {diagnostics.LiveBufferLastError}");
        }

        return string.Join(" ", details);
    }

    private static string FormatSourceHealthSummary(EventSourceHealthSnapshot status)
    {
        var ingress = FormatSourceIngressSummary(
            status.RecordsSeen,
            status.RecordsMatched,
            status.UnmatchedRecords,
            status.DuplicateRecords,
            status.MalformedRecords);
        if (status.DedupKeyCapacity <= 0)
        {
            return $"{status.Source}={status.Status}{ingress}";
        }

        return $"{status.Source}={status.Status} (dedup keys {status.DedupKeyCount}/{status.DedupKeyCapacity}, evicted {status.DedupKeysEvicted}{ingress})";
    }

    private static string FormatSourceHealthSummary(CaptureSourceHealthReport status)
    {
        var ingress = FormatSourceIngressSummary(
            status.RecordsSeen,
            status.RecordsMatched,
            status.UnmatchedRecords,
            status.DuplicateRecords,
            status.MalformedRecords);
        if (status.DedupKeyCapacity <= 0)
        {
            return $"{status.Source}={status.Status}{ingress}";
        }

        return $"{status.Source}={status.Status} (dedup keys {status.DedupKeyCount}/{status.DedupKeyCapacity}, evicted {status.DedupKeysEvicted}{ingress})";
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        var value = (double)Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:N1} {units[unit]}";
    }

    private static string FormatSourceIngressSummary(
        long recordsSeen,
        long recordsMatched,
        long unmatchedRecords,
        long duplicateRecords,
        long malformedRecords)
    {
        if (recordsSeen <= 0 &&
            recordsMatched <= 0 &&
            unmatchedRecords <= 0 &&
            duplicateRecords <= 0 &&
            malformedRecords <= 0)
        {
            return string.Empty;
        }

        return $"; input seen {recordsSeen}, matched {recordsMatched}, unmatched {unmatchedRecords}, duplicate {duplicateRecords}, malformed {malformedRecords}";
    }

    private static IEnumerable<string> GetEnabledSources(LiveCaptureOptions options)
    {
        if (options.CollectRuntimeEvents)
        {
            yield return "Runtime";
        }

        if (options.CollectEtwEvents)
        {
            yield return "ETW";
        }

        if (options.CollectSecurityEvents)
        {
            yield return "Security";
        }

        if (options.CollectPowerShellEvents)
        {
            yield return "PowerShell";
        }

        if (options.CollectOtherWindowsEvents)
        {
            yield return "WindowsOther";
        }

        if (options.CollectSysmonEvents)
        {
            yield return "Sysmon";
        }
    }

    private static string PreferKnownValue(string? incoming, string fallback)
    {
        return string.IsNullOrWhiteSpace(incoming) ? fallback : incoming;
    }

    private void ResetCaptureCounters()
    {
        Interlocked.Exchange(ref _eventsReceived, 0);
        Interlocked.Exchange(ref _eventsDropped, 0);
        Interlocked.Exchange(ref _processRecordsWritten, 0);
        Interlocked.Exchange(ref _processesObserved, 0);
        Interlocked.Exchange(ref _processRefreshes, 0);
        Interlocked.Exchange(ref _processDeltas, 0);
        Interlocked.Exchange(ref _newProcessDetections, 0);
        Interlocked.Exchange(ref _processRecordsDropped, 0);
        Interlocked.Exchange(ref _eventBatchesDropped, 0);
        Interlocked.Exchange(ref _processBatchesDropped, 0);
        Interlocked.Exchange(ref _eventWriteFailures, 0);
        Interlocked.Exchange(ref _processWriteFailures, 0);

        _sourceHealthTracker.BeginRun(DateTime.UtcNow);

        lock (_healthLock)
        {
            _health = _health with { Sources = Array.Empty<CaptureSourceHealthReport>() };
        }
    }

    private void AddSourceRecordsWritten(string source, long count)
    {
        if (count <= 0)
        {
            return;
        }

        _sourceHealthTracker.AddRecordsWritten(source, count);
    }

    private void AddSourceRecordsQueued(string source, long count)
    {
        if (count == 0)
        {
            return;
        }

        _sourceHealthTracker.AddRecordsQueued(source, count);
    }

    private void AddSourceRecordsDropped(string source, long count)
    {
        if (count <= 0)
        {
            return;
        }

        _sourceHealthTracker.AddRecordsDropped(source, count);
    }

    private void AddSourceWriteFailure(string source)
    {
        _sourceHealthTracker.AddWriteFailure(source);
    }

    private sealed record LiveCaptureOptions
    {
        public string CaptureId { get; init; } = string.Empty;

        public int ProcessRefreshIntervalSeconds { get; init; } = DefaultProcessRefreshIntervalSeconds;

        public string EtwProfileId { get; init; } = string.Empty;

        public string EtwProfileDisplayName { get; init; } = string.Empty;

        public string EtwProfilePath { get; init; } = string.Empty;

        public bool CollectRuntimeEvents { get; init; } = true;

        public bool CollectEtwEvents { get; init; } = true;

        public bool CollectSecurityEvents { get; init; } = true;

        public bool CollectPowerShellEvents { get; init; } = true;

        public bool CollectOtherWindowsEvents { get; init; } = true;

        public bool CollectSysmonEvents { get; init; } = true;
    }

    private sealed class LiveCaptureSourceMetadata
    {
        public DateTime UpdatedUtc { get; init; }

        public IReadOnlyList<EventSourceHealthSnapshot> Sources { get; init; } = Array.Empty<EventSourceHealthSnapshot>();

        public LiveCaptureDiagnostics Diagnostics { get; init; } = new();
    }

    private sealed class LiveCaptureDiagnostics
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

        public bool HasPendingWrites => PendingEventWriteBatches > 0 || PendingProcessWriteBatches > 0;

        public bool IsDegraded =>
            TotalEventsDropped > 0 ||
            TotalProcessRecordsDropped > 0 ||
            EventWriteFailures > 0 ||
            ProcessWriteFailures > 0 ||
            PendingProcessWriteBatches >= MaxPendingProcessWriteBatches ||
            !string.IsNullOrWhiteSpace(LiveBufferLastError);
    }

    private sealed class ProcessSnapshotState
    {
        private readonly object _lock = new();
        private readonly Dictionary<string, ProcessRecord> _processesByKey = new(StringComparer.Ordinal);

        public ProcessBatchSummary Apply(IReadOnlyCollection<ProcessRecord> records)
        {
            lock (_lock)
            {
                var newCount = 0;
                foreach (var record in records)
                {
                    if (!_processesByKey.ContainsKey(record.ProcessKey))
                    {
                        newCount++;
                    }

                    _processesByKey[record.ProcessKey] = record;
                }

                return new ProcessBatchSummary(_processesByKey.Count, newCount);
            }
        }
    }

    private sealed class LiveProcessWriteCoordinator
    {
        private static readonly TimeSpan ProcessWriteSlotRetryDelay = TimeSpan.FromMilliseconds(100);

        private readonly AgentStagingWriter _writer;
        private readonly ProcessWriteThrottle _writeThrottle;
        private readonly Action<long> _onQueuedRecordsChanged;
        private readonly Action<IReadOnlyList<ProcessRecord>> _onWriteCompleted;
        private readonly Action<IReadOnlyList<ProcessRecord>, Exception> _onWriteFailed;
        private readonly object _lock = new();
        private readonly Dictionary<string, ProcessObservation> _pendingDeltas = new(StringComparer.Ordinal);
        private readonly Dictionary<string, ProcessAlias> _pendingDeltaAliases = new(StringComparer.Ordinal);
        private readonly Dictionary<string, ProcessStatisticsRecord> _pendingDeltaStatistics = new(StringComparer.Ordinal);
        private readonly HashSet<string> _exitedProcessKeys = new(StringComparer.Ordinal);
        private List<ProcessObservation>? _pendingFullSnapshot;
        private List<ProcessAlias>? _pendingFullSnapshotAliases;
        private List<ProcessStatisticsRecord>? _pendingFullSnapshotStatistics;
        private bool _drainScheduled;
        private bool _acceptingWrites = true;
        private Task _drainTask = Task.CompletedTask;

        public LiveProcessWriteCoordinator(
            AgentStagingWriter writer,
            ProcessWriteThrottle writeThrottle,
            Action<long> onQueuedRecordsChanged,
            Action<IReadOnlyList<ProcessRecord>> onWriteCompleted,
            Action<IReadOnlyList<ProcessRecord>, Exception> onWriteFailed)
        {
            _writer = writer;
            _writeThrottle = writeThrottle;
            _onQueuedRecordsChanged = onQueuedRecordsChanged;
            _onWriteCompleted = onWriteCompleted;
            _onWriteFailed = onWriteFailed;
        }

        public void Enqueue(
            IReadOnlyList<ProcessObservation> observations,
            IReadOnlyList<ProcessAlias> aliases,
            IReadOnlyList<ProcessStatisticsRecord> statistics,
            bool isFullSnapshot,
            CancellationToken cancellationToken)
        {
            if (observations.Count == 0 || cancellationToken.IsCancellationRequested)
            {
                return;
            }

            lock (_lock)
            {
                if (!_acceptingWrites)
                {
                    return;
                }

                RememberExitedProcesses(observations);

                if (isFullSnapshot)
                {
                    _pendingFullSnapshot = FilterSnapshotForKnownExits(observations);
                    _pendingFullSnapshotAliases = aliases.ToList();
                    _pendingFullSnapshotStatistics = FilterStatisticsForRecords(statistics, _pendingFullSnapshot);
                }
                else
                {
                    var statisticsByProcessKey = new Dictionary<string, ProcessStatisticsRecord>(StringComparer.Ordinal);
                    foreach (var sample in statistics.Where(sample => !string.IsNullOrWhiteSpace(sample.ProcessKey)))
                    {
                        statisticsByProcessKey[sample.ProcessKey] =
                            statisticsByProcessKey.TryGetValue(sample.ProcessKey, out var existingSample) &&
                            existingSample.ObservedUtc > sample.ObservedUtc
                                ? existingSample
                                : sample;
                    }

                    foreach (var observation in observations)
                    {
                        if (string.IsNullOrWhiteSpace(observation.ObservationId))
                        {
                            continue;
                        }

                        _pendingDeltas[observation.ObservationId] = observation;
                        if (statisticsByProcessKey.TryGetValue(observation.Fields.ProcessKey, out var sample))
                        {
                            _pendingDeltaStatistics[observation.Fields.ProcessKey] =
                                _pendingDeltaStatistics.TryGetValue(observation.Fields.ProcessKey, out var existingSample) &&
                                existingSample.ObservedUtc > sample.ObservedUtc
                                    ? existingSample
                                    : sample;
                        }
                    }
                    foreach (var alias in aliases)
                    {
                        var key = $"{alias.ProcessEntityId}\u001f{alias.Kind}\u001f{alias.Value}\u001f{alias.SourceIdentityId}";
                        _pendingDeltaAliases[key] = alias;
                    }
                }

                if (_drainScheduled)
                {
                    return;
                }

                _drainScheduled = true;
                _drainTask = DrainAsync(cancellationToken);
            }
        }

        public async Task CompleteAndDrainAsync(CancellationToken cancellationToken)
        {
            Task drainTask;
            lock (_lock)
            {
                _acceptingWrites = false;
                drainTask = _drainTask;
            }

            await drainTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        private async Task DrainAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (!TryTakeNextBatch(out var records))
                    {
                        return;
                    }

                    if (records.Observations.Count == 0)
                    {
                        continue;
                    }

                    await WaitForProcessWriteSlotAsync(cancellationToken).ConfigureAwait(false);
                    _onQueuedRecordsChanged(records.Observations.Count);
                    try
                    {
                        await _writer.AppendProcessObservationBatchAsync(
                                records.Observations,
                                records.Aliases,
                                records.Statistics,
                                cancellationToken,
                                AgentStagingWritePriority.High)
                            .ConfigureAwait(false);
                        _onWriteCompleted(records.Observations.Select(observation => observation.Fields).ToList());
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        return;
                    }
                    catch (Exception ex)
                    {
                        _onWriteFailed(records.Observations.Select(observation => observation.Fields).ToList(), ex);
                    }
                    finally
                    {
                        _onQueuedRecordsChanged(-records.Observations.Count);
                        _writeThrottle.ReleaseProcessWrite();
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            finally
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    lock (_lock)
                    {
                        _drainScheduled = false;
                    }
                }
            }
        }

        private async Task WaitForProcessWriteSlotAsync(CancellationToken cancellationToken)
        {
            while (!_writeThrottle.TryAcquireProcessWrite())
            {
                await Task.Delay(ProcessWriteSlotRetryDelay, cancellationToken).ConfigureAwait(false);
            }
        }

        private bool TryTakeNextBatch(out ProcessObservationWriteBatch records)
        {
            lock (_lock)
            {
                if (_pendingDeltas.Count > 0)
                {
                    var observations = _pendingDeltas.Values.ToList();
                    var statistics = FilterStatisticsForRecords(_pendingDeltaStatistics.Values, observations);
                    var aliases = _pendingDeltaAliases.Values.ToList();
                    _pendingDeltas.Clear();
                    _pendingDeltaAliases.Clear();
                    _pendingDeltaStatistics.Clear();
                    records = new ProcessObservationWriteBatch(observations, aliases, statistics);
                    return true;
                }

                if (_pendingFullSnapshot != null)
                {
                    var observations = FilterSnapshotForKnownExits(_pendingFullSnapshot);
                    IEnumerable<ProcessStatisticsRecord> fullSnapshotStatistics = _pendingFullSnapshotStatistics is null
                        ? Array.Empty<ProcessStatisticsRecord>()
                        : _pendingFullSnapshotStatistics;
                    var statistics = FilterStatisticsForRecords(fullSnapshotStatistics, observations);
                    var aliases = _pendingFullSnapshotAliases ?? [];
                    _pendingFullSnapshot = null;
                    _pendingFullSnapshotAliases = null;
                    _pendingFullSnapshotStatistics = null;
                    records = new ProcessObservationWriteBatch(observations, aliases, statistics);
                    return true;
                }

                records = new ProcessObservationWriteBatch(
                    Array.Empty<ProcessObservation>(),
                    Array.Empty<ProcessAlias>(),
                    Array.Empty<ProcessStatisticsRecord>());
                _drainScheduled = false;
                return false;
            }
        }

        private void RememberExitedProcesses(IReadOnlyCollection<ProcessObservation> observations)
        {
            foreach (var observation in observations)
            {
                var record = observation.Fields;
                if (!string.IsNullOrWhiteSpace(record.ProcessKey) && IsExited(record))
                {
                    _exitedProcessKeys.Add(record.ProcessKey);
                }
            }
        }

        private List<ProcessObservation> FilterSnapshotForKnownExits(IReadOnlyCollection<ProcessObservation> observations)
        {
            return observations
                .Where(observation =>
                    !_exitedProcessKeys.Contains(observation.Fields.ProcessKey) || IsExited(observation.Fields))
                .ToList();
        }

        private static List<ProcessStatisticsRecord> FilterStatisticsForRecords(
            IEnumerable<ProcessStatisticsRecord> statistics,
            IReadOnlyCollection<ProcessObservation> observations)
        {
            if (observations.Count == 0)
            {
                return new List<ProcessStatisticsRecord>();
            }

            var processKeys = observations
                .Select(observation => observation.Fields)
                .Where(record => !string.IsNullOrWhiteSpace(record.ProcessKey))
                .Select(record => record.ProcessKey)
                .ToHashSet(StringComparer.Ordinal);
            return statistics
                .Where(sample => processKeys.Contains(sample.ProcessKey))
                .ToList();
        }

        private static bool IsExited(ProcessRecord record)
        {
            return record.Status == ProcessStatus.Exited || record.EndTimeUtc.HasValue;
        }

    }

    private sealed record ProcessObservationWriteBatch(
        IReadOnlyList<ProcessObservation> Observations,
        IReadOnlyList<ProcessAlias> Aliases,
        IReadOnlyList<ProcessStatisticsRecord> Statistics);

    /// <summary>
    /// Reassembles adapter-sized normalization batches before handing one whole
    /// full snapshot to the existing last-snapshot/delta coalescer.
    /// </summary>
    private sealed class LiveProcessEvidenceSourcePublisher : IEvidenceSourcePublisher
    {
        private readonly Action<IReadOnlyList<ProcessObservation>, IReadOnlyList<ProcessAlias>, IReadOnlyList<ProcessStatisticsRecord>> _publish;
        private readonly List<ProcessObservation> _observations = [];
        private readonly List<ProcessAlias> _aliases = [];
        private readonly List<ProcessStatisticsRecord> _statistics = [];

        public LiveProcessEvidenceSourcePublisher(
            int maxBatchRowCount,
            Action<IReadOnlyList<ProcessObservation>, IReadOnlyList<ProcessAlias>, IReadOnlyList<ProcessStatisticsRecord>> publish)
        {
            MaxBatchRowCount = Math.Max(1, maxBatchRowCount);
            _publish = publish;
        }

        public int MaxBatchRowCount { get; }

        public ValueTask<EvidenceSourcePublishResult> PublishAsync(
            EvidenceSourceEmissionBatch batch,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AgentEvidenceSourcePublisher.ValidateBatch(batch, MaxBatchRowCount);
            if (batch.Processes.Count > 0 || batch.Events.Count > 0 || batch.FilesystemArtifacts.Count > 0 ||
                batch.VolatilityPluginRuns.Count > 0 || batch.MemoryProcesses.Count > 0 || batch.Relations.Count > 0)
            {
                throw new InvalidOperationException(
                    "The runtime process publisher accepts only process observations and statistics.");
            }

            _observations.AddRange(batch.ProcessObservations);
            _aliases.AddRange(batch.ProcessAliases);
            _statistics.AddRange(batch.ProcessStatistics);
            if (!batch.IsFinalBatch)
            {
                return ValueTask.FromResult(new EvidenceSourcePublishResult());
            }

            _publish(_observations, _aliases, _statistics);
            return ValueTask.FromResult(new EvidenceSourcePublishResult
            {
                PersistedRowCount = _observations.Count + _aliases.Count + _statistics.Count
            });
        }
    }

    private sealed class ProcessWriteThrottle
    {
        private readonly SemaphoreSlim _processWriteSlots;
        private int _pendingProcessWrites;

        public ProcessWriteThrottle(int maxProcessWriteBatches)
        {
            MaxProcessWrites = Math.Max(1, maxProcessWriteBatches);
            _processWriteSlots = new SemaphoreSlim(MaxProcessWrites);
        }

        public int MaxProcessWrites { get; }

        public int PendingProcessWrites => Math.Max(0, Volatile.Read(ref _pendingProcessWrites));

        public bool HasPendingPressure => PendingProcessWrites > 0;

        public bool TryAcquireProcessWrite()
        {
            if (!_processWriteSlots.Wait(0))
            {
                return false;
            }

            Interlocked.Increment(ref _pendingProcessWrites);
            return true;
        }

        public void ReleaseProcessWrite()
        {
            Interlocked.Decrement(ref _pendingProcessWrites);
            _processWriteSlots.Release();
        }
    }

    private sealed record ProcessBatchSummary(int TotalKnownProcesses, int NewProcesses);
}
