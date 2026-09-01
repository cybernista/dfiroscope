using System.Diagnostics;
using System.Text.Json;
using System.Threading.Channels;
using ProcInsider.Models.Agent;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services;

namespace ProcInsider.Agent;

/// <summary>
/// The live SQLite evidence writer boundary. Agent jobs enqueue source, job, and
/// evidence rows here instead of opening their own write transactions.
/// </summary>
internal sealed class AgentStagingWriter : IAsyncDisposable
{
    private readonly SqliteStagingStore _store;
    private readonly TextWriter _log;
    private readonly AgentStagingWriterOptions _options;
    private readonly Channel<WriterWorkItem> _priorityQueue;
    private readonly Channel<WriterWorkItem> _backgroundQueue;
    private readonly Channel<DatabaseChangedNotification> _databaseCommitNotifications;
    private readonly Task _worker;
    private readonly Task _databaseCommitNotificationWorker;
    private readonly AsyncLocal<EvidenceWriteProvenance?> _currentProvenance = new();
    private readonly Guid _writerInstanceId = Guid.NewGuid();
    private long _nextEventSequenceId;
    private long _nextModuleSequenceId;
    private long _nextHandleSequenceId;
    private readonly object _metricsLock = new();
    private int _pendingWorkItemCount;
    private int _peakPendingWorkItemCount;
    private long _completedWorkItemCount;
    private long _failedWorkItemCount;
    private long _completedRowCount;
    private long _failedRowCount;
    private double _lastQueueDelayMilliseconds;
    private double _maxQueueDelayMilliseconds;
    private double _lastTransactionMilliseconds;
    private double _maxTransactionMilliseconds;
    private long _lastBatchRowCount;
    private long _maxBatchRowCount;
    private string _lastOperationName = string.Empty;
    private long _busyOrLockedFailureCount;
    private string _lastSqliteError = string.Empty;
    private DateTime? _lastSqliteErrorUtc;
    private string _lastCheckpointSummary = string.Empty;
    private DateTime? _lastCheckpointUtc;
    private AgentSqliteCheckpointDiagnostics? _lastCheckpoint;
    private long _checkpointAttemptCount;
    private long _databaseCommitGeneration;
    private long _databaseCommittedRowCount;
    private DatabaseChangedNotification? _latestDatabaseChanged;
    private long _databaseCommitObserverFailureCount;
    private string _lastDatabaseCommitObserverError = string.Empty;
    private DateTime? _lastDatabaseCommitObserverErrorUtc;
    private Guid _infrastructureOutboxOwnerId;

    public event Action<DatabaseChangedNotification>? DatabaseCommitted;

    internal AgentInfrastructureEvidenceOutbox EnableInfrastructureEvidenceOutbox(Guid ownerId)
    {
        if (ownerId == Guid.Empty)
        {
            throw new ArgumentException("The transactional evidence outbox owner is required.", nameof(ownerId));
        }

        lock (_metricsLock)
        {
            if (_infrastructureOutboxOwnerId != Guid.Empty && _infrastructureOutboxOwnerId != ownerId)
            {
                throw new InvalidOperationException("A different transactional evidence outbox owner is already active.");
            }
            if (_infrastructureOutboxOwnerId == Guid.Empty &&
                (Interlocked.Read(ref _completedWorkItemCount) != 0 ||
                 Interlocked.Read(ref _failedWorkItemCount) != 0 ||
                 Interlocked.Read(ref _databaseCommitGeneration) != 0 ||
                 Volatile.Read(ref _pendingWorkItemCount) != 0))
            {
                throw new InvalidOperationException(
                    "The transactional evidence outbox must be enabled before the first queued or committed writer item.");
            }

            _store.EnableInfrastructureEvidenceOutbox(ownerId, _writerInstanceId);
            _infrastructureOutboxOwnerId = ownerId;
            return new AgentInfrastructureEvidenceOutbox(this, ownerId);
        }
    }

    internal IReadOnlyList<InfrastructureEvidenceOutboxEntry> ListInfrastructureEvidenceOutbox(
        Guid ownerId,
        InfrastructureEvidenceOutboxState state,
        int maxCount = InfrastructureEvidenceOutboxPolicy.MaxPageSize)
    {
        EnsureInfrastructureOutboxOwner(ownerId);
        return _store.ListInfrastructureEvidenceOutbox(state, maxCount);
    }

    internal InfrastructureEvidenceOutboxEntry? GetInfrastructureEvidenceOutboxByBatchId(
        Guid ownerId,
        string batchId)
    {
        EnsureInfrastructureOutboxOwner(ownerId);
        return _store.GetInfrastructureEvidenceOutboxByBatchId(batchId);
    }

    internal ValueTask<InfrastructureEvidenceOutboxEntry> BindInfrastructureEvidenceOutboxPackageAsync(
        Guid ownerId,
        InfrastructureEvidenceOutboxPackageBinding binding,
        CancellationToken cancellationToken)
    {
        EnsureInfrastructureOutboxOwner(ownerId);
        return EnqueueAsync(
            store => store.BindInfrastructureEvidenceOutboxPackage(binding),
            cancellationToken,
            "BindInfrastructureEvidenceOutboxPackage",
            advancesDatabaseChangeCursor: false);
    }

    internal ValueTask<InfrastructureEvidenceOutboxEntry> RecordInfrastructureEvidenceOutboxAcknowledgementAsync(
        Guid ownerId,
        InfrastructureEvidenceOutboxAcknowledgement acknowledgement,
        CancellationToken cancellationToken)
    {
        EnsureInfrastructureOutboxOwner(ownerId);
        return EnqueueAsync(
            store => store.RecordInfrastructureEvidenceOutboxAcknowledgement(acknowledgement),
            cancellationToken,
            "RecordInfrastructureEvidenceOutboxAcknowledgement",
            advancesDatabaseChangeCursor: false);
    }

    internal ValueTask<InfrastructureEvidenceOutboxEntry> CompleteInfrastructureEvidenceOutboxCleanupAsync(
        Guid ownerId,
        Guid outboxId,
        DateTime completedAtUtc,
        CancellationToken cancellationToken)
    {
        EnsureInfrastructureOutboxOwner(ownerId);
        return EnqueueAsync(
            store => store.CompleteInfrastructureEvidenceOutboxCleanup(outboxId, completedAtUtc),
            cancellationToken,
            "CompleteInfrastructureEvidenceOutboxCleanup",
            advancesDatabaseChangeCursor: false);
    }

    internal ValueTask<InfrastructureEvidenceOutboxEntry> QuarantineInfrastructureEvidenceOutboxAsync(
        Guid ownerId,
        Guid outboxId,
        string errorCode,
        DateTime quarantinedAtUtc,
        CancellationToken cancellationToken)
    {
        EnsureInfrastructureOutboxOwner(ownerId);
        return EnqueueAsync(
            store => store.QuarantineInfrastructureEvidenceOutbox(outboxId, errorCode, quarantinedAtUtc),
            cancellationToken,
            "QuarantineInfrastructureEvidenceOutbox",
            advancesDatabaseChangeCursor: false);
    }

    private void EnsureInfrastructureOutboxOwner(Guid ownerId)
    {
        lock (_metricsLock)
        {
            if (ownerId == Guid.Empty || ownerId != _infrastructureOutboxOwnerId)
            {
                throw new InvalidOperationException("The transactional evidence outbox owner is unavailable or stale.");
            }
        }
    }

    public AgentStagingWriter(
        SqliteStagingStore store,
        TextWriter log,
        AgentStagingWriterOptions? options = null,
        CaptureCompatibilityAssessment? compatibility = null)
    {
        if (compatibility != null)
        {
            CaptureCompatibilityPolicy.EnsureAllowed(
                compatibility,
                compatibility.Context == CaptureOpenContext.ArchivedAnalysisMaintenance
                    ? CaptureOpenCapability.MaintainAnalysisState
                    : CaptureOpenCapability.WritePrimaryEvidence);
        }
        _store = store;
        _log = log;
        _options = (options ?? new AgentStagingWriterOptions()).Normalize();
        _nextEventSequenceId = store.GetNextEventSequenceId();
        _nextModuleSequenceId = store.GetNextModuleSequenceId();
        _nextHandleSequenceId = store.GetNextHandleSequenceId();
        _priorityQueue = CreateQueue();
        _backgroundQueue = CreateQueue();
        _databaseCommitNotifications = Channel.CreateBounded<DatabaseChangedNotification>(
            new BoundedChannelOptions(1)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.DropOldest
            });
        _worker = Task.Run(ProcessQueueAsync);
        _databaseCommitNotificationWorker = Task.Run(ProcessDatabaseCommitNotificationsAsync);
    }

    private Channel<WriterWorkItem> CreateQueue()
        => Channel.CreateBounded<WriterWorkItem>(new BoundedChannelOptions(_options.QueueCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });

    public AgentStagingWriterSnapshot GetSnapshot()
    {
        lock (_metricsLock)
        {
            return new AgentStagingWriterSnapshot(
                _options.QueueCapacity,
                _options.MaxRowsPerTransaction,
                (int)_options.MaxBatchLatency.TotalMilliseconds,
                _options.BackpressureWarningWorkItemCount,
                Math.Max(0, Volatile.Read(ref _pendingWorkItemCount)) >= _options.BackpressureWarningWorkItemCount,
                _options.CheckpointWalThresholdBytes,
                (int)_options.CheckpointMinInterval.TotalSeconds,
                Math.Max(0, Volatile.Read(ref _pendingWorkItemCount)),
                Math.Max(0, Volatile.Read(ref _peakPendingWorkItemCount)),
                Interlocked.Read(ref _completedWorkItemCount),
                Interlocked.Read(ref _failedWorkItemCount),
                Interlocked.Read(ref _completedRowCount),
                Interlocked.Read(ref _failedRowCount),
                _lastQueueDelayMilliseconds,
                _maxQueueDelayMilliseconds,
                _lastTransactionMilliseconds,
                _maxTransactionMilliseconds,
                _lastBatchRowCount,
                _maxBatchRowCount,
                _lastOperationName,
                Interlocked.Read(ref _busyOrLockedFailureCount),
                _lastSqliteError,
                _lastSqliteErrorUtc,
                _lastCheckpointSummary,
                _lastCheckpointUtc,
                Interlocked.Read(ref _checkpointAttemptCount),
                Interlocked.Read(ref _databaseCommitObserverFailureCount),
                _lastDatabaseCommitObserverError,
                _lastDatabaseCommitObserverErrorUtc);
        }
    }

    public DatabaseChangedNotification? GetLatestDatabaseChangedNotification() =>
        Volatile.Read(ref _latestDatabaseChanged);

    public AgentSqliteDatabaseDiagnostics GetDatabaseDiagnostics()
    {
        var diagnostics = _store.GetDatabaseDiagnostics(
            SqlitePerformanceProfileName.Conservative,
            "LiveDb");
        AgentSqliteCheckpointDiagnostics? lastCheckpoint;
        lock (_metricsLock)
        {
            lastCheckpoint = _lastCheckpoint;
        }

        return diagnostics with
        {
            LastCheckpoint = lastCheckpoint,
            Summary = lastCheckpoint == null
                ? diagnostics.Summary
                : $"{diagnostics.Summary} Last writer-owned {lastCheckpoint.Summary}"
        };
    }

    public ValueTask<SourceRunRegistration> CreateSourceRunAsync(AgentJobRequest request, CancellationToken cancellationToken)
    {
        return EnqueueAsync(
            store => store.CreateSourceRun(new SourceRunDescriptor
            {
                SourceRunId = request.SourceRunId,
                IngestionJobId = request.JobId,
                CaseId = request.EvidenceIdentity.CaseId,
                EvidenceSessionId = request.EvidenceIdentity.EvidenceSessionId,
                CaptureId = request.CaptureId,
                SourceIdentityId = request.EvidenceIdentity.SourceIdentityId,
                HostId = request.EvidenceIdentity.HostId,
                ExecutionRootId = request.EvidenceIdentity.ExecutionRootId,
                SourceType = request.SourceType,
                DisplayName = request.SourceDisplayName,
                SourcePath = FirstNonEmpty(
                    request.SourcePath,
                    request.ReadParameterString("SourcePath", "ImportPath", "FilePath", "FolderPath", "ImagePath", "PcapPath", "CapturePath")),
                Provider = FirstNonEmpty(request.SourceProvider, request.ReadParameterString("Provider")),
                Channel = FirstNonEmpty(request.SourceChannel, request.ReadParameterString("Channel", "LogName")),
                ConfigurationHash = SqliteStagingStore.CalculateConfigurationHash(request.ToParametersJson()),
                IsLive = request.IsLiveSource,
                ToolVersion = FirstNonEmpty(request.ToolVersion, request.ReadParameterString("ToolVersion", "VolatilityVersion", "ZeekVersion")),
                ParserVersion = FirstNonEmpty(request.ParserVersion, request.ReadParameterString("ParserVersion")),
                MetadataJson = BuildSourceRunMetadata(request),
                ParentSourceRunId = request.ParentSourceRunId,
                InputArtifactId = FirstNonEmpty(request.InputArtifactId, request.ReadParameterString("InputArtifactId", "ImageId", "NetworkCaptureId", "DumpId")),
                InputPath = FirstNonEmpty(request.InputPath, request.ReadParameterString("InputPath", "ImagePath", "PcapPath", "FilePath")),
                InputHash = FirstNonEmpty(request.InputHash, request.ReadParameterString("InputHash", "Sha256Hash", "FileHash")),
                StartedUtc = request.AcceptedAtUtc
            }),
            cancellationToken,
            "CreateSourceRun",
            1,
            advancesDatabaseChangeCursor: request.JobKind != JobKind.SqliteBenchmark);
    }

    private static string FirstNonEmpty(string first, string second)
        => string.IsNullOrWhiteSpace(first) ? second : first;

    public ValueTask UpdateSourceStatusAsync(
        int sourceId,
        string status,
        DateTime? endTimeUtc,
        string? metadataJson,
        CancellationToken cancellationToken)
    {
        return EnqueueAsync(
            store => store.UpdateSourceStatus(sourceId, status, endTimeUtc, metadataJson),
            cancellationToken,
            "UpdateSourceStatus",
            1);
    }

    private static string BuildSourceRunMetadata(AgentJobRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.EvidenceSourceAdapterId))
        {
            return request.SourceMetadataJson;
        }

        object? requestMetadata = null;
        try
        {
            requestMetadata = JsonSerializer.Deserialize<JsonElement>(request.SourceMetadataJson);
        }
        catch (JsonException)
        {
            requestMetadata = request.SourceMetadataJson;
        }

        return JsonSerializer.Serialize(new
        {
            adapterId = request.EvidenceSourceAdapterId,
            adapterVersion = request.EvidenceSourceAdapterVersion,
            requestMetadata
        });
    }

    public ValueTask UpdateSourceRunStatusAsync(
        string sourceRunId,
        string status,
        DateTime? endTimeUtc,
        string? metadataJson,
        CancellationToken cancellationToken,
        bool advancesDatabaseChangeCursor = true)
    {
        return EnqueueAsync(
            store => store.UpdateSourceRunStatus(sourceRunId, status, endTimeUtc, metadataJson),
            cancellationToken,
            "UpdateSourceRunStatus",
            1,
            advancesDatabaseChangeCursor: advancesDatabaseChangeCursor);
    }

    public ValueTask CreateJobAsync(AgentJobRequest request, SourceRunRegistration sourceRun, CancellationToken cancellationToken)
    {
        return EnqueueAsync(
            store => store.CreateIngestionJob(
                request.JobId,
                sourceRun.SourceId,
                sourceRun.SourceRunId,
                request.JobKind,
                request.ToParametersJson()),
            cancellationToken,
            "CreateIngestionJob",
            1,
            advancesDatabaseChangeCursor: request.JobKind != JobKind.SqliteBenchmark);
    }

    public IDisposable BeginSourceRunScope(string sourceRunId, Guid ingestionJobId)
    {
        var previous = _currentProvenance.Value;
        _currentProvenance.Value = new EvidenceWriteProvenance(sourceRunId, ingestionJobId);
        return new ProvenanceScope(_currentProvenance, previous);
    }

    public ValueTask UpsertProcessesAsync(
        IEnumerable<ProcessRecord> processes,
        CancellationToken cancellationToken,
        AgentStagingWritePriority priority = AgentStagingWritePriority.Normal)
    {
        var snapshot = processes.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertProcesses(batch),
            cancellationToken,
            "UpsertProcesses",
            priority);
    }

    public ValueTask UpsertProcessStatisticsAsync(
        IEnumerable<ProcessStatisticsRecord> samples,
        CancellationToken cancellationToken,
        AgentStagingWritePriority priority = AgentStagingWritePriority.Normal)
    {
        var snapshot = samples.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertProcessStatistics(batch),
            cancellationToken,
            "UpsertProcessStatistics",
            priority);
    }

    public async ValueTask<ProcessObservationWriteResult> AppendProcessObservationBatchAsync(
        IEnumerable<ProcessObservation> observations,
        IEnumerable<ProcessAlias> aliases,
        IEnumerable<ProcessStatisticsRecord> samples,
        CancellationToken cancellationToken,
        AgentStagingWritePriority priority = AgentStagingWritePriority.Normal)
    {
        var observationSnapshot = observations.ToList();
        var aliasSnapshot = aliases.ToList();
        var sampleSnapshot = samples.ToList();
        var rowCount = observationSnapshot.Count + aliasSnapshot.Count + sampleSnapshot.Count;
        if (rowCount == 0)
        {
            return new ProcessObservationWriteResult(0, 0, 0, 0, 0);
        }

        var aliasesByEntity = aliasSnapshot
            .GroupBy(alias => alias.ProcessEntityId, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToList(), StringComparer.Ordinal);
        var statisticsByProcessKey = sampleSnapshot
            .GroupBy(sample => sample.ProcessKey, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToList(), StringComparer.Ordinal);
        var assignedAliasEntities = new HashSet<string>(StringComparer.Ordinal);
        var assignedStatisticKeys = new HashSet<string>(StringComparer.Ordinal);
        var currentObservations = new List<ProcessObservation>();
        var currentAliases = new List<ProcessAlias>();
        var currentStatistics = new List<ProcessStatisticsRecord>();
        var persistedObservations = 0;
        var duplicateObservations = 0;
        var persistedAliases = 0;
        var duplicateAliases = 0;
        var persistedStatistics = 0;

        foreach (var observation in observationSnapshot)
        {
            var observationAliases = assignedAliasEntities.Add(observation.ProcessEntityId) &&
                                     aliasesByEntity.TryGetValue(observation.ProcessEntityId, out var matchingAliases)
                ? matchingAliases
                : [];
            var observationStatistics = assignedStatisticKeys.Add(observation.Fields.ProcessKey) &&
                                        statisticsByProcessKey.TryGetValue(observation.Fields.ProcessKey, out var matchingStatistics)
                ? matchingStatistics
                : [];
            var groupRowCount = 1 + observationAliases.Count + observationStatistics.Count;
            if (groupRowCount > _options.MaxRowsPerTransaction)
            {
                throw new InvalidOperationException(
                    $"One normalized process observation group has {groupRowCount:N0} rows; the writer limit is {_options.MaxRowsPerTransaction:N0}.");
            }

            if (currentObservations.Count > 0 &&
                currentObservations.Count + currentAliases.Count + currentStatistics.Count + groupRowCount >
                _options.MaxRowsPerTransaction)
            {
                await FlushAsync().ConfigureAwait(false);
            }

            currentObservations.Add(observation);
            currentAliases.AddRange(observationAliases);
            currentStatistics.AddRange(observationStatistics);
        }

        if (aliasSnapshot.Any(alias => !assignedAliasEntities.Contains(alias.ProcessEntityId)))
        {
            throw new InvalidOperationException("Normalized process aliases must belong to an observation in the same publication.");
        }

        var remainingStatistics = sampleSnapshot
            .Where(sample => !assignedStatisticKeys.Contains(sample.ProcessKey))
            .ToList();
        if (remainingStatistics.Count > 0)
        {
            if (currentObservations.Count > 0 &&
                currentObservations.Count + currentAliases.Count + currentStatistics.Count + remainingStatistics.Count >
                _options.MaxRowsPerTransaction)
            {
                await FlushAsync().ConfigureAwait(false);
            }
            currentStatistics.AddRange(remainingStatistics);
        }

        await FlushAsync().ConfigureAwait(false);
        return new ProcessObservationWriteResult(
            persistedObservations,
            duplicateObservations,
            persistedAliases,
            duplicateAliases,
            persistedStatistics);

        async ValueTask FlushAsync()
        {
            if (currentObservations.Count == 0 && currentStatistics.Count == 0)
            {
                return;
            }

            var observations = currentObservations.ToArray();
            var aliases = currentAliases.ToArray();
            var statistics = currentStatistics.ToArray();
            currentObservations.Clear();
            currentAliases.Clear();
            currentStatistics.Clear();
            var result = await EnqueueAsync(
                    store => store.AppendProcessObservationBatch(observations, aliases, statistics),
                    cancellationToken,
                    "AppendProcessObservationBatch",
                    observations.Length + aliases.Length + statistics.Length,
                    priority)
                .ConfigureAwait(false);
            persistedObservations += result.PersistedObservationCount;
            duplicateObservations += result.DuplicateObservationCount;
            persistedAliases += result.PersistedAliasCount;
            duplicateAliases += result.DuplicateAliasCount;
            persistedStatistics += result.PersistedStatisticsCount;
        }
    }

    public async ValueTask UpsertProcessBatchAsync(
        IEnumerable<ProcessRecord> processes,
        IEnumerable<ProcessStatisticsRecord> samples,
        CancellationToken cancellationToken,
        AgentStagingWritePriority priority = AgentStagingWritePriority.Normal)
    {
        var processSnapshot = processes.ToList();
        var sampleSnapshot = samples.ToList();
        if (processSnapshot.Count == 0 && sampleSnapshot.Count == 0)
        {
            return;
        }

        if (processSnapshot.Count == 0)
        {
            await EnqueueBatchesAsync(
                sampleSnapshot,
                (store, batch) => store.UpsertProcessStatistics(batch),
                cancellationToken,
                "UpsertProcessStatistics",
                priority).ConfigureAwait(false);
            return;
        }

        foreach (var processBatch in ChunkRows(processSnapshot))
        {
            var processKeys = processBatch
                .Where(process => !string.IsNullOrWhiteSpace(process.ProcessKey))
                .Select(process => process.ProcessKey)
                .ToHashSet(StringComparer.Ordinal);
            var sampleBatch = sampleSnapshot
                .Where(sample => processKeys.Contains(sample.ProcessKey))
                .ToList();
            var batchSnapshot = processBatch;
            await EnqueueAsync(
                store => store.UpsertProcessBatch(batchSnapshot, sampleBatch),
                cancellationToken,
                "UpsertProcessBatch",
                batchSnapshot.Count + sampleBatch.Count,
                priority).ConfigureAwait(false);
        }
    }

    public ValueTask AddEventsAsync(
        IEnumerable<TelemetryEventRecord> events,
        CancellationToken cancellationToken,
        AgentStagingWritePriority priority = AgentStagingWritePriority.Normal)
    {
        var snapshot = events.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        foreach (var processEvent in snapshot.Where(processEvent => processEvent.SequenceId <= 0))
        {
            processEvent.SequenceId = Interlocked.Increment(ref _nextEventSequenceId) - 1;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.AddEvents(batch),
            cancellationToken,
            "AddEvents",
            priority);
    }

    public ValueTask UpsertModulesAsync(
        IEnumerable<ModuleObservationRecord> modules,
        CancellationToken cancellationToken,
        AgentStagingWritePriority priority = AgentStagingWritePriority.Normal)
    {
        var snapshot = modules.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        foreach (var module in snapshot.Where(module => module.SequenceId <= 0))
        {
            module.SequenceId = Interlocked.Increment(ref _nextModuleSequenceId) - 1;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertModules(batch),
            cancellationToken,
            "UpsertModules",
            priority);
    }

    public ValueTask UpsertModuleSnapshotAsync(
        string processKey,
        IEnumerable<ModuleObservationRecord> modules,
        DateTime observedUtc,
        string source,
        CancellationToken cancellationToken)
    {
        var snapshot = modules.ToList();
        foreach (var module in snapshot.Where(module => module.SequenceId <= 0))
        {
            module.SequenceId = Interlocked.Increment(ref _nextModuleSequenceId) - 1;
        }

        processKey = string.IsNullOrWhiteSpace(processKey)
            ? snapshot.FirstOrDefault()?.ProcessKey ?? string.Empty
            : processKey;
        if (string.IsNullOrWhiteSpace(processKey))
        {
            return ValueTask.CompletedTask;
        }

        return UpsertModuleSnapshotInBatchesAsync(processKey, snapshot, observedUtc, source, cancellationToken);
    }

    public ValueTask UpsertHandlesAsync(
        IEnumerable<HandleObservationRecord> handles,
        CancellationToken cancellationToken,
        AgentStagingWritePriority priority = AgentStagingWritePriority.Normal)
    {
        var snapshot = handles.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        foreach (var handle in snapshot.Where(handle => handle.SequenceId <= 0))
        {
            handle.SequenceId = Interlocked.Increment(ref _nextHandleSequenceId) - 1;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertHandles(batch),
            cancellationToken,
            "UpsertHandles",
            priority);
    }

    public ValueTask UpsertHandleSnapshotAsync(
        string processKey,
        IEnumerable<HandleObservationRecord> handles,
        DateTime observedUtc,
        string source,
        CancellationToken cancellationToken)
    {
        var snapshot = handles.ToList();
        foreach (var handle in snapshot.Where(handle => handle.SequenceId <= 0))
        {
            handle.SequenceId = Interlocked.Increment(ref _nextHandleSequenceId) - 1;
        }

        processKey = string.IsNullOrWhiteSpace(processKey)
            ? snapshot.FirstOrDefault()?.ProcessKey ?? string.Empty
            : processKey;
        if (string.IsNullOrWhiteSpace(processKey))
        {
            return ValueTask.CompletedTask;
        }

        return UpsertHandleSnapshotInBatchesAsync(processKey, snapshot, observedUtc, source, cancellationToken);
    }

    public ValueTask UpsertMemoryDumpsAsync(
        IEnumerable<MemoryDumpRecord> memoryDumps,
        CancellationToken cancellationToken)
    {
        var snapshot = memoryDumps.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertMemoryDumps(batch),
            cancellationToken,
            "UpsertMemoryDumps");
    }

    public ValueTask UpsertPeAnalysesAsync(
        IEnumerable<PeAnalysisRecord> analyses,
        CancellationToken cancellationToken)
    {
        var snapshot = analyses.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertPeAnalyses(batch),
            cancellationToken,
            "UpsertPeAnalyses");
    }

    public ValueTask InsertAuthenticodeVerificationsAsync(
        IEnumerable<AuthenticodeVerificationRecord> verifications,
        CancellationToken cancellationToken)
    {
        var snapshot = verifications.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.InsertAuthenticodeVerifications(batch),
            cancellationToken,
            "InsertAuthenticodeVerifications");
    }

    public ValueTask UpsertNetworkCapturesAsync(
        IEnumerable<NetworkCaptureRecord> networkCaptures,
        CancellationToken cancellationToken)
    {
        var snapshot = networkCaptures.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertNetworkCaptures(batch),
            cancellationToken,
            "UpsertNetworkCaptures");
    }

    public ValueTask UpsertZeekNetworkArtifactsAsync(
        IEnumerable<ZeekNetworkRecord> artifacts,
        CancellationToken cancellationToken)
    {
        var snapshot = artifacts.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertZeekNetworkArtifacts(batch),
            cancellationToken,
            "UpsertZeekNetworkArtifacts");
    }

    public ValueTask UpsertFilesystemArtifactsAsync(
        IEnumerable<FilesystemArtifactRecord> artifacts,
        CancellationToken cancellationToken)
    {
        var snapshot = artifacts.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertFilesystemArtifacts(batch),
            cancellationToken,
            "UpsertFilesystemArtifacts");
    }

    public ValueTask UpsertEvidenceRelationsAsync(
        IEnumerable<EvidenceRelation> relations,
        CancellationToken cancellationToken)
    {
        var snapshot = relations.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertEvidenceRelations(batch),
            cancellationToken,
            "UpsertEvidenceRelations");
    }

    public ValueTask UpsertMemoryImagesAsync(
        IEnumerable<MemoryImageRecord> memoryImages,
        CancellationToken cancellationToken)
    {
        var snapshot = memoryImages.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertMemoryImages(batch),
            cancellationToken,
            "UpsertMemoryImages");
    }

    public ValueTask UpsertVolatilityPluginRunsAsync(
        IEnumerable<VolatilityPluginRunRecord> pluginRuns,
        CancellationToken cancellationToken)
    {
        var snapshot = pluginRuns.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertVolatilityPluginRuns(batch),
            cancellationToken,
            "UpsertVolatilityPluginRuns");
    }

    public ValueTask UpsertMemoryProcessesAsync(
        IEnumerable<MemoryProcessRecord> processes,
        CancellationToken cancellationToken)
    {
        var snapshot = processes.ToList();
        if (snapshot.Count == 0)
        {
            return ValueTask.CompletedTask;
        }

        return EnqueueBatchesAsync(
            snapshot,
            (store, batch) => store.UpsertMemoryProcesses(batch),
            cancellationToken,
            "UpsertMemoryProcesses");
    }

    public ValueTask ReplaceWithSnapshotAsync(
        TelemetryStoreSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        return EnqueueAsync(
            store =>
            {
                store.ReplaceWithSnapshot(snapshot);
                _nextEventSequenceId = store.GetNextEventSequenceId();
                _nextModuleSequenceId = store.GetNextModuleSequenceId();
                _nextHandleSequenceId = store.GetNextHandleSequenceId();
            },
            cancellationToken,
            "ReplaceWithSnapshot",
            CountSnapshotRows(snapshot));
    }

    public ValueTask UpdateJobAsync(
        Guid jobId,
        JobState state,
        long current,
        long total,
        string message,
        string? errorText,
        CancellationToken cancellationToken,
        bool advancesDatabaseChangeCursor = true)
    {
        return EnqueueAsync(
            store => store.UpdateIngestionJob(jobId, state, current, total, message, errorText),
            cancellationToken,
            "UpdateIngestionJob",
            1,
            advancesDatabaseChangeCursor: advancesDatabaseChangeCursor);
    }

    public ValueTask<YaraAnalysisPersistenceResult> PersistYaraAnalysisAsync(
        YaraAnalysisPersistenceRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var rowCount = 1L + request.Result.Matches.Count +
            request.Result.Matches.Sum(match => match.Tags.Count + match.Metadata.Count);
        return EnqueueAsync(
            store => store.PersistYaraAnalysis(request, cancellationToken),
            cancellationToken,
            "PersistYaraAnalysis",
            rowCount);
    }

    public ValueTask<ReputationAttributionPersistenceResult> PersistReputationAttributionAsync(
        ReputationProcessAttributionResult attribution,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attribution);
        return EnqueueAsync(
            store => store.PersistReputationAttribution(attribution, cancellationToken),
            cancellationToken,
            "PersistReputationAttribution",
            1);
    }

    public async ValueTask DisposeAsync()
    {
        _priorityQueue.Writer.TryComplete();
        _backgroundQueue.Writer.TryComplete();
        await _worker.ConfigureAwait(false);
        _databaseCommitNotifications.Writer.TryComplete();
        await _databaseCommitNotificationWorker.ConfigureAwait(false);
    }

    private async ValueTask<T> EnqueueAsync<T>(
        Func<SqliteStagingStore, T> action,
        CancellationToken cancellationToken,
        string operationName = "Unknown",
        long rowCount = 0,
        AgentStagingWritePriority priority = AgentStagingWritePriority.Normal,
        bool advancesDatabaseChangeCursor = true)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var provenance = _currentProvenance.Value;
        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        T? result = default;
        var workItem = new WriterWorkItem(
                store => result = provenance is null
                    ? action(store)
                    : store.ExecuteWithSourceRunProvenance(provenance, () => action(store)),
                () => completion.SetResult(result!),
                completion.SetException,
                operationName,
                rowCount,
                advancesDatabaseChangeCursor);

        IncrementPendingWorkItems();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_options.MaxBatchLatency);
            await GetQueue(priority).Writer.WriteAsync(workItem, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            DecrementPendingWorkItems();
            Interlocked.Increment(ref _failedWorkItemCount);
            Interlocked.Add(ref _failedRowCount, Math.Max(0, rowCount));
            var message =
                $"SQLite writer queue remained full for {_options.MaxBatchLatency.TotalMilliseconds:N0} ms while enqueueing {operationName}.";
            lock (_metricsLock)
            {
                _lastOperationName = operationName;
                _lastBatchRowCount = Math.Max(0, rowCount);
                _lastSqliteError = message;
                _lastSqliteErrorUtc = DateTime.UtcNow;
            }

            _log.WriteLine($"[{DateTimeOffset.Now:O}] {message}");
            throw new TimeoutException(message, ex);
        }
        catch
        {
            DecrementPendingWorkItems();
            throw;
        }

        return await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask EnqueueAsync(
        Action<SqliteStagingStore> action,
        CancellationToken cancellationToken,
        string operationName = "Unknown",
        long rowCount = 0,
        AgentStagingWritePriority priority = AgentStagingWritePriority.Normal,
        bool advancesDatabaseChangeCursor = true)
    {
        await EnqueueAsync(
            store =>
            {
                action(store);
                return true;
            },
            cancellationToken,
            operationName,
            rowCount,
            priority,
            advancesDatabaseChangeCursor).ConfigureAwait(false);
    }

    private async ValueTask EnqueueBatchesAsync<T>(
        IReadOnlyList<T> rows,
        Action<SqliteStagingStore, IReadOnlyList<T>> action,
        CancellationToken cancellationToken,
        string operationName,
        AgentStagingWritePriority priority = AgentStagingWritePriority.Normal)
    {
        foreach (var batch in ChunkRows(rows))
        {
            var batchSnapshot = batch;
            await EnqueueAsync(
                store => action(store, batchSnapshot),
                cancellationToken,
                operationName,
                batchSnapshot.Count,
                priority).ConfigureAwait(false);
        }
    }

    private async ValueTask UpsertModuleSnapshotInBatchesAsync(
        string processKey,
        IReadOnlyList<ModuleObservationRecord> snapshot,
        DateTime observedUtc,
        string source,
        CancellationToken cancellationToken)
    {
        var validSnapshot = snapshot
            .Where(module => !string.IsNullOrWhiteSpace(module.ModuleKey))
            .ToList();
        var seenKeys = validSnapshot
            .Select(module => module.ModuleKey)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var batch in ChunkRows(validSnapshot))
        {
            var batchSnapshot = batch;
            await EnqueueAsync(
                store => store.UpsertModuleSnapshotBatch(processKey, batchSnapshot, observedUtc, source),
                cancellationToken,
                "UpsertModuleSnapshot",
                batchSnapshot.Count).ConfigureAwait(false);
        }

        await CloseStaleModulesInBatchesAsync(processKey, seenKeys, observedUtc, source, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask UpsertHandleSnapshotInBatchesAsync(
        string processKey,
        IReadOnlyList<HandleObservationRecord> snapshot,
        DateTime observedUtc,
        string source,
        CancellationToken cancellationToken)
    {
        var validSnapshot = snapshot
            .Where(handle => !string.IsNullOrWhiteSpace(handle.HandleKey))
            .ToList();
        var seenKeys = validSnapshot
            .Select(handle => handle.HandleKey)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var batch in ChunkRows(validSnapshot))
        {
            var batchSnapshot = batch;
            await EnqueueAsync(
                store => store.UpsertHandleSnapshotBatch(processKey, batchSnapshot, observedUtc, source),
                cancellationToken,
                "UpsertHandleSnapshot",
                batchSnapshot.Count).ConfigureAwait(false);
        }

        await CloseStaleHandlesInBatchesAsync(processKey, seenKeys, observedUtc, source, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask CloseStaleModulesInBatchesAsync(
        string processKey,
        IReadOnlySet<string> seenKeys,
        DateTime observedUtc,
        string source,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var closed = await EnqueueAsync(
                store => store.CloseStaleModulesForSnapshot(processKey, seenKeys, observedUtc, source, _options.MaxRowsPerTransaction),
                cancellationToken,
                "CloseStaleModuleSnapshot").ConfigureAwait(false);
            if (closed <= 0)
            {
                return;
            }
        }
    }

    private async ValueTask CloseStaleHandlesInBatchesAsync(
        string processKey,
        IReadOnlySet<string> seenKeys,
        DateTime observedUtc,
        string source,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var closed = await EnqueueAsync(
                store => store.CloseStaleHandlesForSnapshot(processKey, seenKeys, observedUtc, source, _options.MaxRowsPerTransaction),
                cancellationToken,
                "CloseStaleHandleSnapshot").ConfigureAwait(false);
            if (closed <= 0)
            {
                return;
            }
        }
    }

    private async Task ProcessQueueAsync()
    {
        while (await WaitForQueuedWorkAsync().ConfigureAwait(false))
        {
            while (TryReadNextWorkItem(out var item))
            {
                ExecuteWorkItem(item);
            }
        }
    }

    private async ValueTask<bool> WaitForQueuedWorkAsync()
    {
        var priorityReady = _priorityQueue.Reader.WaitToReadAsync().AsTask();
        var backgroundReady = _backgroundQueue.Reader.WaitToReadAsync().AsTask();
        await Task.WhenAny(priorityReady, backgroundReady).ConfigureAwait(false);
        if (priorityReady.IsCompleted && await priorityReady.ConfigureAwait(false))
        {
            return true;
        }

        if (backgroundReady.IsCompleted && await backgroundReady.ConfigureAwait(false))
        {
            return true;
        }

        if (!priorityReady.IsCompleted && await priorityReady.ConfigureAwait(false))
        {
            return true;
        }

        if (!backgroundReady.IsCompleted && await backgroundReady.ConfigureAwait(false))
        {
            return true;
        }

        return false;
    }

    private bool TryReadNextWorkItem(out WriterWorkItem item)
    {
        if (_priorityQueue.Reader.TryRead(out var priorityItem))
        {
            item = priorityItem;
            return true;
        }

        if (_backgroundQueue.Reader.TryRead(out var backgroundItem))
        {
            item = backgroundItem;
            return true;
        }

        item = null!;
        return false;
    }

    private void ExecuteWorkItem(WriterWorkItem item)
    {
        var queueDelay = DateTime.UtcNow - item.EnqueuedAtUtc;
        var stopwatch = Stopwatch.StartNew();
        try
        {
            InfrastructureEvidenceOutboxEntry? outboxEntry = null;
            Guid outboxOwnerId;
            lock (_metricsLock)
            {
                outboxOwnerId = _infrastructureOutboxOwnerId;
            }
            if (outboxOwnerId == Guid.Empty)
            {
                item.Execute(_store);
            }
            else
            {
                var commit = item.AdvancesDatabaseChangeCursor
                    ? new InfrastructureEvidenceOutboxCommit
                    {
                        OutboxId = Guid.NewGuid(),
                        WriterInstanceId = _writerInstanceId,
                        WriterCommitGeneration = Interlocked.Read(ref _databaseCommitGeneration) + 1,
                        OperationName = InfrastructureEvidenceOutboxPolicy.NormalizeOperationName(item.OperationName),
                        ApproximateRowCount = Math.Max(0, item.RowCount),
                        CommittedAtUtc = DateTime.UtcNow
                    }
                    : null;
                outboxEntry = _store.ExecuteAgentWriterTransaction(
                    outboxOwnerId,
                    commit,
                    item.Execute);
            }
            stopwatch.Stop();
            RecordSuccess(item, queueDelay, stopwatch.Elapsed);
            Interlocked.Increment(ref _completedWorkItemCount);
            if (item.AdvancesDatabaseChangeCursor)
            {
                PublishDatabaseCommit(item, outboxEntry);
            }
            item.SetResult();
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            item.SetException(ex);
            RecordFailure(item, queueDelay, stopwatch.Elapsed, ex);
            Interlocked.Increment(ref _failedWorkItemCount);
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Staging writer failed: {ex.Message}");
        }
        finally
        {
            DecrementPendingWorkItems();
            TryRunIdleCheckpoint();
        }
    }

    private void PublishDatabaseCommit(
        WriterWorkItem item,
        InfrastructureEvidenceOutboxEntry? outboxEntry)
    {
        var committedAtUtc = outboxEntry?.CommittedAtUtc ?? DateTime.UtcNow;
        var generation = outboxEntry?.WriterCommitGeneration ??
                         Interlocked.Increment(ref _databaseCommitGeneration);
        if (outboxEntry != null)
        {
            Interlocked.Exchange(ref _databaseCommitGeneration, generation);
        }
        var rowCount = Math.Max(0, item.RowCount);
        var committedRowCount = Interlocked.Add(ref _databaseCommittedRowCount, rowCount);
        var notification = new DatabaseChangedNotification
        {
            EmittedAtUtc = committedAtUtc,
            WriterInstanceId = _writerInstanceId,
            CommitGeneration = generation,
            LastCommittedAtUtc = committedAtUtc,
            CommittedWorkItemCount = generation,
            CommittedRowCount = committedRowCount,
            ApproximateNewRowCount = (int)Math.Min(int.MaxValue, rowCount)
        };
        Volatile.Write(ref _latestDatabaseChanged, notification);
        _databaseCommitNotifications.Writer.TryWrite(notification);
    }

    private async Task ProcessDatabaseCommitNotificationsAsync()
    {
        await foreach (var notification in _databaseCommitNotifications.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            var handlers = DatabaseCommitted;
            if (handlers == null)
            {
                continue;
            }

            foreach (Action<DatabaseChangedNotification> handler in handlers.GetInvocationList())
            {
                try
                {
                    handler(notification);
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref _databaseCommitObserverFailureCount);
                    lock (_metricsLock)
                    {
                        _lastDatabaseCommitObserverError = ex.Message;
                        _lastDatabaseCommitObserverErrorUtc = DateTime.UtcNow;
                    }

                    try
                    {
                        _log.WriteLine(
                            $"[{DateTimeOffset.Now:O}] Database commit observer failed without affecting the committed writer item: {ex.Message}");
                    }
                    catch
                    {
                        // Diagnostics must never fault the serialized evidence writer or notification dispatcher.
                    }
                }
            }
        }
    }

    private Channel<WriterWorkItem> GetQueue(AgentStagingWritePriority priority)
        => priority == AgentStagingWritePriority.High
            ? _priorityQueue
            : _backgroundQueue;

    private void IncrementPendingWorkItems()
    {
        var pending = Interlocked.Increment(ref _pendingWorkItemCount);
        var peak = Volatile.Read(ref _peakPendingWorkItemCount);
        while (pending > peak)
        {
            var previous = Interlocked.CompareExchange(ref _peakPendingWorkItemCount, pending, peak);
            if (previous == peak)
            {
                break;
            }

            peak = previous;
        }
    }

    private void DecrementPendingWorkItems()
    {
        Interlocked.Decrement(ref _pendingWorkItemCount);
    }

    private IEnumerable<IReadOnlyList<T>> ChunkRows<T>(IReadOnlyList<T> rows)
    {
        if (rows.Count <= _options.MaxRowsPerTransaction)
        {
            yield return rows;
            yield break;
        }

        for (var offset = 0; offset < rows.Count; offset += _options.MaxRowsPerTransaction)
        {
            var count = Math.Min(_options.MaxRowsPerTransaction, rows.Count - offset);
            var batch = new List<T>(count);
            for (var index = 0; index < count; index++)
            {
                batch.Add(rows[offset + index]);
            }

            yield return batch;
        }
    }

    private void TryRunIdleCheckpoint()
    {
        if (!_store.CanCheckpointAuthoritativeLiveDatabase ||
            _options.CheckpointWalThresholdBytes <= 0 ||
            Math.Max(0, Volatile.Read(ref _pendingWorkItemCount)) > 0)
        {
            return;
        }

        var now = DateTime.UtcNow;
        DateTime? lastCheckpointUtc;
        lock (_metricsLock)
        {
            lastCheckpointUtc = _lastCheckpointUtc;
        }

        if (lastCheckpointUtc.HasValue &&
            now - lastCheckpointUtc.Value < _options.CheckpointMinInterval)
        {
            return;
        }

        var walPath = $"{_store.DatabasePath}-wal";
        long walSize;
        try
        {
            walSize = File.Exists(walPath) ? new FileInfo(walPath).Length : 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }

        if (walSize < _options.CheckpointWalThresholdBytes)
        {
            return;
        }

        var checkpoint = _store.CheckpointAuthoritativeLiveWalFromAgentWriter();
        Interlocked.Increment(ref _checkpointAttemptCount);
        lock (_metricsLock)
        {
            _lastCheckpoint = checkpoint;
            _lastCheckpointSummary = checkpoint.Summary;
            _lastCheckpointUtc = checkpoint.CheckedAtUtc;
        }

        SqliteDiagnosticsLogger.LogOperation(
            _store.DatabasePath,
            "LiveWriter",
            "IdleWalCheckpoint",
            TimeSpan.FromMilliseconds(checkpoint.DurationMilliseconds),
            checkpoint.Summary,
            force: true);
    }

    private void RecordSuccess(WriterWorkItem item, TimeSpan queueDelay, TimeSpan transactionDuration)
    {
        var rowCount = Math.Max(0, item.RowCount);
        Interlocked.Add(ref _completedRowCount, rowCount);
        lock (_metricsLock)
        {
            _lastOperationName = item.OperationName;
            _lastBatchRowCount = rowCount;
            _maxBatchRowCount = Math.Max(_maxBatchRowCount, rowCount);
            _lastQueueDelayMilliseconds = queueDelay.TotalMilliseconds;
            _maxQueueDelayMilliseconds = Math.Max(_maxQueueDelayMilliseconds, queueDelay.TotalMilliseconds);
            _lastTransactionMilliseconds = transactionDuration.TotalMilliseconds;
            _maxTransactionMilliseconds = Math.Max(_maxTransactionMilliseconds, transactionDuration.TotalMilliseconds);
        }

        SqliteDiagnosticsLogger.LogOperation(
            _store.DatabasePath,
            "LiveWriter",
            item.OperationName,
            transactionDuration,
            $"queue_delay_ms={queueDelay.TotalMilliseconds:F1}",
            rowCount);
    }

    private void RecordFailure(WriterWorkItem item, TimeSpan queueDelay, TimeSpan transactionDuration, Exception exception)
    {
        var rowCount = Math.Max(0, item.RowCount);
        Interlocked.Add(ref _failedRowCount, rowCount);
        if (IsBusyOrLocked(exception))
        {
            Interlocked.Increment(ref _busyOrLockedFailureCount);
        }

        lock (_metricsLock)
        {
            _lastOperationName = item.OperationName;
            _lastBatchRowCount = rowCount;
            _maxBatchRowCount = Math.Max(_maxBatchRowCount, rowCount);
            _lastQueueDelayMilliseconds = queueDelay.TotalMilliseconds;
            _maxQueueDelayMilliseconds = Math.Max(_maxQueueDelayMilliseconds, queueDelay.TotalMilliseconds);
            _lastTransactionMilliseconds = transactionDuration.TotalMilliseconds;
            _maxTransactionMilliseconds = Math.Max(_maxTransactionMilliseconds, transactionDuration.TotalMilliseconds);
            _lastSqliteError = exception.Message;
            _lastSqliteErrorUtc = DateTime.UtcNow;
        }

        SqliteDiagnosticsLogger.LogOperation(
            _store.DatabasePath,
            "LiveWriter",
            item.OperationName,
            transactionDuration,
            $"FAILED queue_delay_ms={queueDelay.TotalMilliseconds:F1}; error={exception.Message}",
            rowCount,
            force: true);
    }

    private static bool IsBusyOrLocked(Exception exception)
    {
        for (var current = exception; current != null; current = current.InnerException)
        {
            if (current.Message.Contains("busy", StringComparison.OrdinalIgnoreCase) ||
                current.Message.Contains("locked", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static long CountSnapshotRows(TelemetryStoreSnapshot snapshot)
    {
        return snapshot.Processes.Count +
               snapshot.Events.Count +
               snapshot.Modules.Count +
               snapshot.Handles.Count +
               snapshot.MemoryDumps.Count +
               snapshot.PeAnalyses.Count +
               snapshot.NetworkCaptures.Count +
               snapshot.ZeekNetworkArtifacts.Count;
    }

    private sealed class ProvenanceScope(
        AsyncLocal<EvidenceWriteProvenance?> current,
        EvidenceWriteProvenance? previous) : IDisposable
    {
        public void Dispose() => current.Value = previous;
    }

    private sealed class WriterWorkItem
    {
        private readonly Action<SqliteStagingStore> _execute;
        private readonly Action _setResult;
        private readonly Action<Exception> _setException;

        public WriterWorkItem(
            Action<SqliteStagingStore> execute,
            Action setResult,
            Action<Exception> setException,
            string operationName,
            long rowCount,
            bool advancesDatabaseChangeCursor)
        {
            _execute = execute;
            _setResult = setResult;
            _setException = setException;
            OperationName = string.IsNullOrWhiteSpace(operationName) ? "Unknown" : operationName;
            RowCount = rowCount;
            AdvancesDatabaseChangeCursor = advancesDatabaseChangeCursor;
            EnqueuedAtUtc = DateTime.UtcNow;
        }

        public string OperationName { get; }

        public long RowCount { get; }

        public bool AdvancesDatabaseChangeCursor { get; }

        public DateTime EnqueuedAtUtc { get; }

        public void Execute(SqliteStagingStore store)
        {
            _execute(store);
        }

        public void SetResult()
        {
            _setResult();
        }

        public void SetException(Exception exception)
        {
            _setException(exception);
        }
    }
}

internal sealed record AgentStagingWriterSnapshot(
    int QueueCapacity,
    int MaxRowsPerTransaction,
    int MaxBatchLatencyMilliseconds,
    int BackpressureWarningWorkItemCount,
    bool IsBackpressureActive,
    long CheckpointWalThresholdBytes,
    int CheckpointMinIntervalSeconds,
    int PendingWorkItemCount,
    int PeakPendingWorkItemCount,
    long CompletedWorkItemCount,
    long FailedWorkItemCount,
    long CompletedRowCount,
    long FailedRowCount,
    double LastQueueDelayMilliseconds,
    double MaxQueueDelayMilliseconds,
    double LastTransactionMilliseconds,
    double MaxTransactionMilliseconds,
    long LastBatchRowCount,
    long MaxBatchRowCount,
    string LastOperationName,
    long BusyOrLockedFailureCount,
    string LastSqliteError,
    DateTime? LastSqliteErrorUtc,
    string LastCheckpointSummary,
    DateTime? LastCheckpointUtc,
    long CheckpointAttemptCount,
    long DatabaseCommitObserverFailureCount,
    string LastDatabaseCommitObserverError,
    DateTime? LastDatabaseCommitObserverErrorUtc);

internal enum AgentStagingWritePriority
{
    Normal = 0,
    High = 1
}

internal sealed record AgentStagingWriterOptions
{
    public int QueueCapacity { get; init; } = AgentWorkerOptions.DefaultWriterQueueCapacity;

    public int MaxRowsPerTransaction { get; init; } = AgentWorkerOptions.DefaultWriterMaxBatchRows;

    public TimeSpan MaxBatchLatency { get; init; } =
        TimeSpan.FromMilliseconds(AgentWorkerOptions.DefaultWriterMaxBatchLatencyMilliseconds);

    public long CheckpointWalThresholdBytes { get; init; } =
        AgentWorkerOptions.DefaultWriterCheckpointWalMegabytes * 1024L * 1024L;

    public TimeSpan CheckpointMinInterval { get; init; } =
        TimeSpan.FromSeconds(AgentWorkerOptions.DefaultWriterCheckpointMinIntervalSeconds);

    public int BackpressureWarningWorkItemCount =>
        Math.Clamp((int)Math.Ceiling(QueueCapacity * 0.8), 1, QueueCapacity);

    public static AgentStagingWriterOptions FromWorkerOptions(AgentWorkerOptions options)
    {
        var normalized = options.Normalize();
        return new AgentStagingWriterOptions
        {
            QueueCapacity = normalized.WriterQueueCapacity,
            MaxRowsPerTransaction = normalized.WriterMaxBatchRows,
            MaxBatchLatency = TimeSpan.FromMilliseconds(normalized.WriterMaxBatchLatencyMilliseconds),
            CheckpointWalThresholdBytes = normalized.WriterCheckpointWalMegabytes * 1024L * 1024L,
            CheckpointMinInterval = TimeSpan.FromSeconds(normalized.WriterCheckpointMinIntervalSeconds)
        }.Normalize();
    }

    public AgentStagingWriterOptions Normalize()
    {
        return this with
        {
            QueueCapacity = Math.Clamp(QueueCapacity, 1, 100000),
            MaxRowsPerTransaction = Math.Clamp(MaxRowsPerTransaction, 1, 100000),
            MaxBatchLatency = Clamp(MaxBatchLatency, TimeSpan.FromMilliseconds(50), TimeSpan.FromMinutes(1)),
            CheckpointWalThresholdBytes = Math.Clamp(CheckpointWalThresholdBytes, 1L * 1024 * 1024, 4096L * 1024 * 1024),
            CheckpointMinInterval = Clamp(CheckpointMinInterval, TimeSpan.FromSeconds(1), TimeSpan.FromHours(1))
        };
    }

    private static TimeSpan Clamp(TimeSpan value, TimeSpan min, TimeSpan max)
    {
        if (value < min)
        {
            return min;
        }

        return value > max ? max : value;
    }
}
