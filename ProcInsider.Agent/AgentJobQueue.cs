using System.Collections.Concurrent;
using System.Threading.Channels;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal sealed record AgentConfiguredCaptureTransitionPlan(
    bool CanExecute,
    bool IsIdempotent,
    string ErrorCode,
    string Message,
    IReadOnlyList<AgentActiveWorkItem> Work)
{
    public static AgentConfiguredCaptureTransitionPlan Accepted(IReadOnlyList<AgentActiveWorkItem> work) =>
        new(true, false, string.Empty, string.Empty, work);

    public static AgentConfiguredCaptureTransitionPlan Idempotent(IReadOnlyList<AgentActiveWorkItem> work) =>
        new(false, true, string.Empty, string.Empty, work);

    public static AgentConfiguredCaptureTransitionPlan Rejected(string errorCode, string message) =>
        new(false, false, errorCode, message, Array.Empty<AgentActiveWorkItem>());
}

internal sealed class AgentJobQueue : IAsyncDisposable
{
    private readonly AgentStagingWriter _writer;
    private readonly IAgentJobHandler _handler;
    private readonly AgentWorkerOptions _options;
    private readonly TextWriter _log;
    private readonly AgentArtifactEnrichmentStatistics _artifactEnrichmentStatistics;
    private readonly Channel<QueuedJob> _queue;
    private readonly AgentJobConcurrencyCoordinator _concurrency;
    private readonly ConcurrentDictionary<Guid, QueuedJob> _queuedJobs = new();
    private readonly ConcurrentDictionary<Guid, CancellationTokenSource> _runningJobs = new();
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource> _jobCompletions = new();
    private readonly ConcurrentDictionary<Guid, JobProgress> _jobStatuses = new();
    private readonly ConcurrentDictionary<Guid, byte> _cancelRequested = new();
    private readonly object _controlLock = new();
    private readonly object _enqueueLifecycleLock = new();
    private readonly TaskCompletionSource _enqueuesDrained =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Dictionary<Guid, ActiveWorkEntry> _activeWork = new();
    private readonly HashSet<string> _stoppingConfiguredCaptureIds = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task[] _workers;
    private int _queuedJobCount;
    private int _peakQueuedJobCount;
    private int _runningJobCount;
    private int _completedJobCount;
    private int _rejectedJobCount;
    private string _lastError = string.Empty;
    private long _controlSnapshotGeneration;
    private AgentCaptureRunState _captureRunState = AgentCaptureRunState.Off;
    private string _activeCaptureId = string.Empty;
    private DateTime _captureStateChangedAtUtc = DateTime.UtcNow;
    private bool _lastCaptureFailed;
    private AgentCaptureRunState _configuredCaptureTransition = AgentCaptureRunState.Unknown;
    private string _configuredCaptureTransitionId = string.Empty;
    private DateTime? _pauseStartedAtUtc;
    private DateTime? _lastResumedAtUtc;
    private TimeSpan? _lastPauseDuration;
    private string _acquisitionGapDetail = string.Empty;
    private bool _acceptingJobs = true;
    private int _activeEnqueues;

    public AgentJobQueue(AgentStagingWriter writer, IAgentJobHandler handler, AgentWorkerOptions options, TextWriter log, AgentArtifactEnrichmentStatistics artifactEnrichmentStatistics)
    {
        _writer = writer;
        _handler = handler;
        _options = options.Normalize();
        _log = log;
        _artifactEnrichmentStatistics = artifactEnrichmentStatistics;
        _concurrency = new AgentJobConcurrencyCoordinator(_options);
        _queue = Channel.CreateBounded<QueuedJob>(new BoundedChannelOptions(_options.QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = false
        });
        _workers = Enumerable
            .Range(1, _options.WorkerCount)
            .Select(workerId => Task.Run(() => ProcessJobsAsync(workerId)))
            .ToArray();
    }

    public event Action<JobProgress>? JobProgressChanged;

    public int KnownJobCount => _jobStatuses.Count;

    public AgentRuntimeSnapshot GetRuntimeSnapshot()
    {
        return new AgentRuntimeSnapshot
        {
            WorkerCount = _options.WorkerCount,
            QueueCapacity = _options.QueueCapacity,
            QueuedJobCount = Math.Max(0, Volatile.Read(ref _queuedJobCount)),
            PeakQueuedJobCount = Math.Max(0, Volatile.Read(ref _peakQueuedJobCount)),
            RunningJobCount = Math.Max(0, Volatile.Read(ref _runningJobCount)),
            CompletedJobCount = Math.Max(0, Volatile.Read(ref _completedJobCount)),
            RejectedJobCount = Math.Max(0, Volatile.Read(ref _rejectedJobCount)),
            KnownJobCount = KnownJobCount,
            MaxParallelEnrichmentJobs = _options.MaxParallelEnrichmentJobs,
            MaxParallelImportJobs = _options.MaxParallelImportJobs,
            MaxParallelProcessDumpJobs = _options.MaxParallelProcessDumpJobs,
            MaxParallelZeekJobs = _options.MaxParallelZeekJobs,
            MaxParallelArtifactImportJobs = _options.MaxParallelArtifactImportJobs,
            MaxParallelVolatilityJobs = _options.MaxParallelVolatilityJobs,
            ArtifactEnrichment = _artifactEnrichmentStatistics.GetSnapshot(),
            LastError = Volatile.Read(ref _lastError)
        };
    }

    public AgentControlSnapshot GetControlSnapshot(CaptureHealthReport captureHealth)
    {
        lock (_controlLock)
        {
            var now = DateTime.UtcNow;
            var activeWork = _activeWork.Values
                .Select(entry => entry.ToSnapshot())
                .OrderBy(entry => entry.AcceptedAtUtc)
                .ThenBy(entry => entry.JobId)
                .ToArray();
            var capture = AgentControlSnapshotProjection.ProjectCapture(
                activeWork,
                captureHealth,
                _lastCaptureFailed);
            if (_configuredCaptureTransition is AgentCaptureRunState.Pausing or AgentCaptureRunState.Resuming)
            {
                capture = new AgentCaptureControlProjection
                {
                    State = _configuredCaptureTransition,
                    ActiveCaptureId = _configuredCaptureTransitionId
                };
            }
            if (capture.State != _captureRunState ||
                !string.Equals(capture.ActiveCaptureId, _activeCaptureId, StringComparison.Ordinal))
            {
                _captureRunState = capture.State;
                _activeCaptureId = capture.ActiveCaptureId;
                _captureStateChangedAtUtc = now;
            }

            return new AgentControlSnapshot
            {
                IsAuthoritative = true,
                Generation = ++_controlSnapshotGeneration,
                EmittedAtUtc = now,
                CaptureState = _captureRunState,
                ActiveCaptureId = _activeCaptureId,
                CaptureStateChangedAtUtc = _captureStateChangedAtUtc,
                PauseStartedAtUtc = _pauseStartedAtUtc,
                LastResumedAtUtc = _lastResumedAtUtc,
                LastPauseDuration = _lastPauseDuration,
                AcquisitionGapDetail = _acquisitionGapDetail,
                ActiveWork = activeWork,
                ModuleEnrichment = AgentControlSnapshotProjection.ProjectWorkload(
                    activeWork,
                    workloads => workloads.CaptureModules),
                HandleEnrichment = AgentControlSnapshotProjection.ProjectWorkload(
                    activeWork,
                    workloads => workloads.CaptureHandles),
                PeAnalysis = AgentControlSnapshotProjection.ProjectWorkload(
                    activeWork,
                    workloads => workloads.CapturePeMetadata)
            };
        }
    }

    public async ValueTask<Guid> EnqueueAsync(AgentJobRequest request, CancellationToken cancellationToken)
    {
        EnterEnqueue();
        try
        {
            ThrowIfAutomaticConfiguredCaptureIsStopping(request);
            var sourceRun = await _writer.CreateSourceRunAsync(request, cancellationToken).ConfigureAwait(false);
            await _writer.CreateJobAsync(request, sourceRun, cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfAutomaticConfiguredCaptureIsStopping(request);
            }
            catch (AgentConfiguredCaptureStoppingException)
            {
                await _writer.UpdateJobAsync(
                    request.JobId,
                    JobState.Cancelled,
                    0,
                    -1,
                    "Configured capture stopped before automatic enrichment was queued.",
                    null,
                    CancellationToken.None,
                    advancesDatabaseChangeCursor: AdvancesDatabaseChangeCursor(request)).ConfigureAwait(false);
                await _writer.UpdateSourceRunStatusAsync(
                    sourceRun.SourceRunId,
                    "Stopped",
                    DateTime.UtcNow,
                    null,
                    CancellationToken.None,
                    advancesDatabaseChangeCursor: AdvancesDatabaseChangeCursor(request)).ConfigureAwait(false);
                throw;
            }
            _jobCompletions[request.JobId] = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            RegisterActiveWork(request);
            PublishProgress(request, JobState.Queued, 0, -1, "Queued.");
            var queuedJob = new QueuedJob(request, sourceRun.SourceId, sourceRun.SourceRunId);
            _queuedJobs[request.JobId] = queuedJob;
            UpdateQueuedJobCount(Interlocked.Increment(ref _queuedJobCount));
            try
            {
                if (!_queue.Writer.TryWrite(queuedJob))
                {
                    await RejectSaturatedJobAsync(request, sourceRun.SourceRunId, cancellationToken).ConfigureAwait(false);
                    throw new AgentQueueSaturatedException(
                        $"Agent job queue is full ({Math.Max(0, Volatile.Read(ref _queuedJobCount))}/{_options.QueueCapacity}); rejected {request.JobKind} job {request.JobId}.");
                }
            }
            catch
            {
                if (_queuedJobs.TryRemove(request.JobId, out _))
                {
                    Interlocked.Decrement(ref _queuedJobCount);
                }

                throw;
            }

            _log.WriteLine($"[{DateTimeOffset.Now:O}] Queued {request.JobKind} job {request.JobId}. Queue depth: {Math.Max(0, Volatile.Read(ref _queuedJobCount))}.");
            return request.JobId;
        }
        finally
        {
            ExitEnqueue();
        }
    }

    public async Task DrainAcceptedWorkAsync(CancellationToken cancellationToken)
    {
        Task enqueuesDrained;
        lock (_enqueueLifecycleLock)
        {
            _acceptingJobs = false;
            if (_activeEnqueues == 0)
            {
                _enqueuesDrained.TrySetResult();
            }
            enqueuesDrained = _enqueuesDrained.Task;
        }
        await enqueuesDrained.WaitAsync(cancellationToken).ConfigureAwait(false);
        var accepted = _jobCompletions.Values.Select(completion => completion.Task).ToArray();
        if (accepted.Length != 0)
        {
            await Task.WhenAll(accepted).WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private void EnterEnqueue()
    {
        lock (_enqueueLifecycleLock)
        {
            if (!_acceptingJobs)
            {
                throw new InvalidOperationException("The Agent job queue is draining and rejects new work.");
            }
            _activeEnqueues++;
        }
    }

    private void ExitEnqueue()
    {
        lock (_enqueueLifecycleLock)
        {
            _activeEnqueues--;
            if (!_acceptingJobs && _activeEnqueues == 0)
            {
                _enqueuesDrained.TrySetResult();
            }
        }
    }

    private void ThrowIfAutomaticConfiguredCaptureIsStopping(AgentJobRequest request)
    {
        if (request.Ownership != AgentJobOwnership.ConfiguredCapture || request.OriginatingCommandId.HasValue)
        {
            return;
        }

        lock (_controlLock)
        {
            if (_stoppingConfiguredCaptureIds.Contains(request.CaptureId))
            {
                throw new AgentConfiguredCaptureStoppingException(request.CaptureId);
            }
        }
    }

    public bool TryGetJobStatus(Guid jobId, out JobProgress progress)
    {
        return _jobStatuses.TryGetValue(jobId, out progress!);
    }

    public bool TryGetActiveJob(JobKind jobKind, out JobProgress progress)
    {
        progress = _jobStatuses.Values
            .Where(candidate => candidate.JobKind == jobKind)
            .Where(candidate => candidate.State is JobState.Queued or JobState.Running or JobState.Paused)
            .OrderByDescending(candidate => candidate.StartedAtUtc ?? DateTime.MinValue)
            .FirstOrDefault()!;
        return progress is not null;
    }

    public bool TryGetInFlightJob(JobKind jobKind, out JobProgress progress)
    {
        var runningJobIds = _runningJobs.Keys.ToHashSet();
        progress = _jobStatuses.Values
            .Where(candidate => candidate.JobKind == jobKind)
            .Where(candidate =>
                candidate.State is JobState.Queued or JobState.Running or JobState.Paused ||
                runningJobIds.Contains(candidate.JobId))
            .OrderByDescending(candidate => candidate.StartedAtUtc ?? DateTime.MinValue)
            .FirstOrDefault()!;
        return progress is not null;
    }

    public IReadOnlyList<AgentActiveWorkItem> GetConfiguredCaptureWork(string captureId = "", Guid? originatingCommandId = null)
    {
        lock (_controlLock)
        {
            var work = _activeWork.Values
                .Where(entry => !originatingCommandId.HasValue ||
                                entry.Request.OriginatingCommandId == originatingCommandId)
                .Select(entry => entry.ToSnapshot())
                .ToArray();
            return AgentConfiguredCaptureWorkProjection.Select(work, captureId);
        }
    }

    public bool TryGetAcceptingConfiguredCapture(out string captureId)
    {
        lock (_controlLock)
        {
            var accepting = AgentConfiguredCaptureWorkProjection.TryGetAcceptingCaptureId(
                _activeWork.Values.Select(entry => entry.ToSnapshot()).ToArray(),
                out captureId);
            return accepting && !_stoppingConfiguredCaptureIds.Contains(captureId);
        }
    }

    public void AllowConfiguredCapture(string captureId)
    {
        if (string.IsNullOrWhiteSpace(captureId))
        {
            return;
        }

        lock (_controlLock)
        {
            _stoppingConfiguredCaptureIds.Remove(captureId);
            if (!string.Equals(_activeCaptureId, captureId, StringComparison.Ordinal))
            {
                _pauseStartedAtUtc = null;
                _lastResumedAtUtc = null;
                _lastPauseDuration = null;
                _acquisitionGapDetail = string.Empty;
            }
        }
    }

    public AgentConfiguredCaptureTransitionPlan BeginConfiguredCaptureTransition(
        string captureId,
        Guid jobId,
        AgentCaptureRunState transition)
    {
        if (string.IsNullOrWhiteSpace(captureId) || jobId == Guid.Empty ||
            transition is not (AgentCaptureRunState.Pausing or AgentCaptureRunState.Resuming))
        {
            return AgentConfiguredCaptureTransitionPlan.Rejected(
                "InvalidCaptureTransitionTarget",
                "Pause/Resume requires an exact configured capture ID, anchor job ID, and transition.");
        }

        lock (_controlLock)
        {
            if (_configuredCaptureTransition is AgentCaptureRunState.Pausing or AgentCaptureRunState.Resuming)
            {
                return AgentConfiguredCaptureTransitionPlan.Rejected(
                    "CaptureTransitionInProgress",
                    $"Configured capture '{_configuredCaptureTransitionId}' is already {_configuredCaptureTransition}.");
            }

            var work = _activeWork.Values
                .Select(entry => entry.ToSnapshot())
                .Where(item => item.Ownership == AgentJobOwnership.ConfiguredCapture && item.IsLiveSource)
                .Where(item => string.Equals(item.CaptureId, captureId, StringComparison.Ordinal))
                .OrderBy(item => item.AcceptedAtUtc)
                .ThenBy(item => item.JobId)
                .ToArray();
            if (work.Length == 0 || work.All(item => item.JobId != jobId))
            {
                return AgentConfiguredCaptureTransitionPlan.Rejected(
                    "ConfiguredCaptureTargetMismatch",
                    $"Configured capture '{captureId}' does not contain exact anchor job '{jobId}'.");
            }

            if (work.Any(item => item.StopRequested))
            {
                return AgentConfiguredCaptureTransitionPlan.Rejected(
                    "ConfiguredCaptureEnding",
                    $"Configured capture '{captureId}' is ending and cannot be paused or resumed.");
            }

            var targetState = transition == AgentCaptureRunState.Pausing
                ? JobState.Paused
                : JobState.Running;
            if (work.All(item => item.State == targetState))
            {
                return AgentConfiguredCaptureTransitionPlan.Idempotent(work);
            }

            var requiredState = transition == AgentCaptureRunState.Pausing
                ? JobState.Running
                : JobState.Paused;
            if (work.Any(item => item.State != requiredState))
            {
                return AgentConfiguredCaptureTransitionPlan.Rejected(
                    "InvalidCaptureTransition",
                    $"Configured capture '{captureId}' cannot enter {transition} while source jobs are not all {requiredState}.");
            }

            _configuredCaptureTransition = transition;
            _configuredCaptureTransitionId = captureId;
            return AgentConfiguredCaptureTransitionPlan.Accepted(work);
        }
    }

    public async Task<IReadOnlyList<AgentActiveWorkItem>> CompleteConfiguredCaptureTransitionAsync(
        string captureId,
        JobState state,
        string message,
        CancellationToken cancellationToken)
    {
        ActiveWorkEntry[] entries;
        lock (_controlLock)
        {
            var expectedTransition = state == JobState.Paused
                ? AgentCaptureRunState.Pausing
                : AgentCaptureRunState.Resuming;
            if (_configuredCaptureTransition != expectedTransition ||
                !string.Equals(_configuredCaptureTransitionId, captureId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Configured capture '{captureId}' no longer owns the {expectedTransition} transition; terminal control may have superseded it.");
            }

            entries = _activeWork.Values
                .Where(entry => entry.Request.Ownership == AgentJobOwnership.ConfiguredCapture &&
                                entry.Request.IsLiveSource &&
                                string.Equals(entry.Request.CaptureId, captureId, StringComparison.Ordinal))
                .ToArray();
        }

        foreach (var entry in entries)
        {
            await entry.ProgressUpdateGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                _jobStatuses.TryGetValue(entry.Request.JobId, out var progress);
                var current = progress?.ProcessedCount ?? 0;
                var total = progress?.TotalCount ?? -1;
                await _writer.UpdateJobAsync(
                    entry.Request.JobId,
                    state,
                    current,
                    total,
                    message,
                    null,
                    cancellationToken).ConfigureAwait(false);
                PublishProgress(entry.Request, state, current, total, message);
            }
            finally
            {
                entry.ProgressUpdateGate.Release();
            }
        }

        lock (_controlLock)
        {
            var now = DateTime.UtcNow;
            if (state == JobState.Paused)
            {
                _pauseStartedAtUtc = now;
                _acquisitionGapDetail =
                    $"Acquisition paused at {now:O}; activity during this gap is not collected or backfilled.";
            }
            else if (state == JobState.Running && _pauseStartedAtUtc.HasValue)
            {
                _lastResumedAtUtc = now;
                _lastPauseDuration = now - _pauseStartedAtUtc.Value;
                _acquisitionGapDetail =
                    $"Last acquisition gap: {_pauseStartedAtUtc.Value:O} to {now:O} ({_lastPauseDuration.Value}). Activity during the gap was not collected or backfilled.";
                _pauseStartedAtUtc = null;
            }

            _configuredCaptureTransition = AgentCaptureRunState.Unknown;
            _configuredCaptureTransitionId = string.Empty;
            return _activeWork.Values
                .Select(entry => entry.ToSnapshot())
                .Where(item => item.Ownership == AgentJobOwnership.ConfiguredCapture &&
                               item.IsLiveSource &&
                               string.Equals(item.CaptureId, captureId, StringComparison.Ordinal))
                .OrderBy(item => item.AcceptedAtUtc)
                .ThenBy(item => item.JobId)
                .ToArray();
        }
    }

    public void AbortConfiguredCaptureTransition(string captureId)
    {
        lock (_controlLock)
        {
            if (string.Equals(_configuredCaptureTransitionId, captureId, StringComparison.Ordinal))
            {
                _configuredCaptureTransition = AgentCaptureRunState.Unknown;
                _configuredCaptureTransitionId = string.Empty;
            }
        }
    }

    public IReadOnlyList<AgentActiveWorkItem> MarkConfiguredCaptureStopRequested(string captureId)
    {
        lock (_controlLock)
        {
            var matches = _activeWork.Values
                .Where(entry => entry.Request.Ownership == AgentJobOwnership.ConfiguredCapture)
                .Where(entry => string.IsNullOrWhiteSpace(captureId) ||
                                string.Equals(entry.Request.CaptureId, captureId, StringComparison.Ordinal))
                .ToArray();
            foreach (var entry in matches)
            {
                entry.StopRequested = true;
                if (!string.IsNullOrWhiteSpace(entry.Request.CaptureId))
                {
                    _stoppingConfiguredCaptureIds.Add(entry.Request.CaptureId);
                }
            }

            if (matches.Any(entry => string.Equals(
                    entry.Request.CaptureId,
                    _configuredCaptureTransitionId,
                    StringComparison.Ordinal)))
            {
                _configuredCaptureTransition = AgentCaptureRunState.Unknown;
                _configuredCaptureTransitionId = string.Empty;
            }

            return matches
                .Select(entry => entry.ToSnapshot())
                .OrderBy(entry => entry.AcceptedAtUtc)
                .ThenBy(entry => entry.JobId)
                .ToArray();
        }
    }

    public async ValueTask WaitForJobAsync(Guid jobId, CancellationToken cancellationToken)
    {
        if (_jobCompletions.TryGetValue(jobId, out var completion))
        {
            await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask CancelJobAsync(Guid jobId, CancellationToken cancellationToken)
    {
        MarkJobStopRequested(jobId);
        _cancelRequested.TryAdd(jobId, 0);
        var wasQueued = _queuedJobs.TryRemove(jobId, out _);
        if (wasQueued)
        {
            Interlocked.Decrement(ref _queuedJobCount);
        }

        if (_runningJobs.TryGetValue(jobId, out var runningJob))
        {
            runningJob.Cancel();
        }

        _jobStatuses.TryGetValue(jobId, out var previous);
        await _writer.UpdateJobAsync(
            jobId,
            JobState.Cancelled,
            0,
            -1,
            "Cancellation requested.",
            null,
            cancellationToken,
            advancesDatabaseChangeCursor: previous?.JobKind != JobKind.SqliteBenchmark).ConfigureAwait(false);
        if (previous != null)
        {
            PublishProgress(
                previous with
                {
                    State = JobState.Cancelled,
                    ProgressMessage = "Cancellation requested.",
                    FinishedAtUtc = DateTime.UtcNow
                });
        }

        if (wasQueued && !_runningJobs.ContainsKey(jobId))
        {
            MarkCompleted(jobId);
        }
    }

    public bool MarkJobStopRequested(Guid jobId)
    {
        lock (_controlLock)
        {
            if (!_activeWork.TryGetValue(jobId, out var entry))
            {
                return false;
            }

            entry.StopRequested = true;
            return true;
        }
    }

    public async ValueTask DisposeAsync()
    {
        Task enqueuesDrained;
        lock (_enqueueLifecycleLock)
        {
            _acceptingJobs = false;
            if (_activeEnqueues == 0)
            {
                _enqueuesDrained.TrySetResult();
            }
            enqueuesDrained = _enqueuesDrained.Task;
        }
        await enqueuesDrained.ConfigureAwait(false);
        _queue.Writer.TryComplete();
        foreach (var queuedJob in _queuedJobs.Values)
        {
            _cancelRequested.TryAdd(queuedJob.Request.JobId, 0);
            await _writer.UpdateJobAsync(
                queuedJob.Request.JobId,
                JobState.Cancelled,
                0,
                -1,
                "Canceled during agent shutdown.",
                null,
                CancellationToken.None,
                advancesDatabaseChangeCursor: AdvancesDatabaseChangeCursor(queuedJob.Request)).ConfigureAwait(false);
            PublishProgress(queuedJob.Request, JobState.Cancelled, 0, -1, "Canceled during agent shutdown.");
            MarkCompleted(queuedJob.Request.JobId);
        }

        _queuedJobs.Clear();
        Interlocked.Exchange(ref _queuedJobCount, 0);

        foreach (var cancellation in _runningJobs.Values)
        {
            cancellation.Cancel();
        }

        try
        {
            await Task.WhenAll(_workers).ConfigureAwait(false);
        }
        finally
        {
            _shutdown.Cancel();
            _shutdown.Dispose();
        }
    }

    private async Task ProcessJobsAsync(int workerId)
    {
        _log.WriteLine($"[{DateTimeOffset.Now:O}] Agent worker {workerId} started.");
        try
        {
            await foreach (var queuedJob in _queue.Reader.ReadAllAsync(_shutdown.Token).ConfigureAwait(false))
            {
                await RunJobAsync(queuedJob, workerId).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
        }
        finally
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Agent worker {workerId} stopped.");
        }
    }

    private async Task RunJobAsync(QueuedJob queuedJob, int workerId)
    {
        var request = queuedJob.Request;
        var advancesDatabaseChangeCursor = AdvancesDatabaseChangeCursor(request);
        using var jobCancellation = new CancellationTokenSource();
        _runningJobs[request.JobId] = jobCancellation;
        if (_queuedJobs.TryRemove(request.JobId, out _))
        {
            Interlocked.Decrement(ref _queuedJobCount);
        }

        if (_cancelRequested.TryRemove(request.JobId, out _))
        {
            await _writer.UpdateJobAsync(
                request.JobId, JobState.Cancelled, 0, -1, "Canceled before start.", null, CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            await _writer.UpdateSourceRunStatusAsync(
                queuedJob.SourceRunId, "Stopped", DateTime.UtcNow, null, CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            PublishProgress(request, JobState.Cancelled, 0, -1, "Canceled before start.");
            _runningJobs.TryRemove(request.JobId, out _);
            MarkCompleted(request.JobId);
            return;
        }

        JobConcurrencyLease? lease = null;
        long current = 0;
        long total = -1;
        AgentSqliteBenchmarkResult? sqliteBenchmark = null;
        AgentMemoryActionResult? memoryAction = null;
        var lastPeProgressMessage = string.Empty;

        try
        {
            await _writer.UpdateJobAsync(
                request.JobId, JobState.Queued, 0, -1, "Waiting for an available worker/policy slot.", null, CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            PublishProgress(request, JobState.Queued, 0, -1, "Waiting for an available worker/policy slot.");
            lease = await _concurrency.AcquireAsync(request, jobCancellation.Token).ConfigureAwait(false);
            Interlocked.Increment(ref _runningJobCount);
            await _writer.UpdateJobAsync(
                request.JobId, JobState.Running, 0, -1, "Running.", null, CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            await _writer.UpdateSourceRunStatusAsync(
                queuedJob.SourceRunId, "Running", null, null, CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            PublishProgress(request, JobState.Running, 0, -1, "Running.");
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Worker {workerId} running {request.JobKind} job {request.JobId}.");
            var context = new AgentJobContext(
                request,
                queuedJob.SourceId,
                queuedJob.SourceRunId,
                async (progressCurrent, progressTotal, message, benchmark, memory, cancellationToken) =>
                {
                    current = progressCurrent;
                    total = progressTotal;
                    sqliteBenchmark = benchmark;
                    memoryAction = memory;
                    if (message.Contains("PE analysis", StringComparison.OrdinalIgnoreCase))
                    {
                        lastPeProgressMessage = message;
                    }
                    ActiveWorkEntry? entry;
                    lock (_controlLock)
                    {
                        _activeWork.TryGetValue(request.JobId, out entry);
                    }

                    if (entry is null)
                    {
                        return;
                    }

                    await entry.ProgressUpdateGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                    try
                    {
                        JobState progressState;
                        lock (_controlLock)
                        {
                            progressState = entry.Progress?.State == JobState.Paused
                                ? JobState.Paused
                                : JobState.Running;
                        }

                        await _writer.UpdateJobAsync(
                            request.JobId, progressState, progressCurrent, progressTotal, message, null, cancellationToken,
                            advancesDatabaseChangeCursor).ConfigureAwait(false);
                        PublishProgress(
                            request,
                            progressState,
                            progressCurrent,
                            progressTotal,
                            message,
                            benchmark: benchmark,
                            memory: memory);
                    }
                    finally
                    {
                        entry.ProgressUpdateGate.Release();
                    }
                },
                jobCancellation.Token);

            using (_writer.BeginSourceRunScope(queuedJob.SourceRunId, request.JobId))
            {
                await _handler.ExecuteAsync(context).ConfigureAwait(false);
            }
            var completedMessage = BuildPeTerminalMessage("Completed.", lastPeProgressMessage);
            await _writer.UpdateJobAsync(
                request.JobId, JobState.Completed, current, total, completedMessage, null, CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            await _writer.UpdateSourceRunStatusAsync(
                queuedJob.SourceRunId,
                context.SourceRunCompletionStatus,
                DateTime.UtcNow,
                context.SourceRunCompletionMetadataJson,
                CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            PublishProgress(
                request,
                JobState.Completed,
                current,
                total,
                completedMessage,
                benchmark: sqliteBenchmark,
                memory: memoryAction);
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Completed {request.JobKind} job {request.JobId}.");
        }
        catch (OperationCanceledException) when (jobCancellation.IsCancellationRequested)
        {
            var cancelledMessage = BuildPeTerminalMessage("Canceled.", lastPeProgressMessage);
            await _writer.UpdateJobAsync(
                request.JobId, JobState.Cancelled, current, total, cancelledMessage, null, CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            await _writer.UpdateSourceRunStatusAsync(
                queuedJob.SourceRunId, "Stopped", DateTime.UtcNow, null, CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            PublishProgress(
                request,
                JobState.Cancelled,
                current,
                total,
                cancelledMessage,
                benchmark: sqliteBenchmark,
                memory: memoryAction);
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Canceled {request.JobKind} job {request.JobId}.");
        }
        catch (Exception ex)
        {
            var failedMessage = BuildPeTerminalMessage("Failed.", lastPeProgressMessage);
            await _writer.UpdateJobAsync(
                request.JobId, JobState.Failed, current, total, failedMessage, ex.Message, CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            await _writer.UpdateSourceRunStatusAsync(
                queuedJob.SourceRunId, "Error", DateTime.UtcNow, ex.Message, CancellationToken.None,
                advancesDatabaseChangeCursor).ConfigureAwait(false);
            PublishProgress(
                request,
                JobState.Failed,
                current,
                total,
                failedMessage,
                ex.Message,
                sqliteBenchmark,
                memoryAction);
            Volatile.Write(ref _lastError, ex.Message);
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed {request.JobKind} job {request.JobId}: {ex.Message}");
        }
        finally
        {
            lease?.Dispose();
            _runningJobs.TryRemove(request.JobId, out _);
            if (lease is not null)
            {
                Interlocked.Decrement(ref _runningJobCount);
            }

            MarkCompleted(request.JobId);
        }
    }

    private static string BuildPeTerminalMessage(string state, string peProgressMessage)
        => string.IsNullOrWhiteSpace(peProgressMessage)
            ? state
            : $"{state} {peProgressMessage}";

    private void PublishProgress(
        AgentJobRequest request,
        JobState state,
        long current,
        long total,
        string message,
        string errorText = "",
        AgentSqliteBenchmarkResult? benchmark = null,
        AgentMemoryActionResult? memory = null)
    {
        PublishProgress(new JobProgress
        {
            JobId = request.JobId,
            SourceRunId = request.SourceRunId,
            OriginatingCommandId = request.OriginatingCommandId,
            JobKind = request.JobKind,
            State = state,
            ProgressMessage = message,
            ProcessedCount = current,
            TotalCount = total,
            StartedAtUtc = state is JobState.Queued ? null : DateTime.UtcNow,
            FinishedAtUtc = state is JobState.Completed or JobState.Cancelled or JobState.Failed ? DateTime.UtcNow : null,
            ErrorText = errorText,
            SqliteBenchmark = benchmark,
            MemoryAction = memory
        });
    }

    private void PublishProgress(JobProgress progress)
    {
        _jobStatuses[progress.JobId] = progress;
        lock (_controlLock)
        {
            if (_activeWork.TryGetValue(progress.JobId, out var entry))
            {
                entry.Update(progress);
            }
        }

        JobProgressChanged?.Invoke(progress);
    }

    private void MarkCompleted(Guid jobId)
    {
        lock (_controlLock)
        {
            if (_activeWork.Remove(jobId, out var entry) &&
                IsCaptureWork(entry.Request) &&
                entry.Progress?.State == JobState.Failed)
            {
                _lastCaptureFailed = true;
            }
        }

        if (_jobCompletions.TryRemove(jobId, out var completion))
        {
            Interlocked.Increment(ref _completedJobCount);
            completion.TrySetResult();
        }
    }

    private async ValueTask RejectSaturatedJobAsync(AgentJobRequest request, string sourceRunId, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _rejectedJobCount);
        var message = $"Agent job queue is full; rejected {request.JobKind} job.";
        Volatile.Write(ref _lastError, message);
        var advancesDatabaseChangeCursor = AdvancesDatabaseChangeCursor(request);
        await _writer.UpdateJobAsync(
            request.JobId, JobState.Failed, 0, -1, message, message, cancellationToken,
            advancesDatabaseChangeCursor).ConfigureAwait(false);
        await _writer.UpdateSourceRunStatusAsync(
            sourceRunId, "Error", DateTime.UtcNow, message, cancellationToken,
            advancesDatabaseChangeCursor).ConfigureAwait(false);
        PublishProgress(request, JobState.Failed, 0, -1, message, message);
        MarkCompleted(request.JobId);
        _log.WriteLine($"[{DateTimeOffset.Now:O}] {message} Queue capacity: {_options.QueueCapacity}.");
    }

    private void UpdateQueuedJobCount(int queuedCount)
    {
        var peak = Volatile.Read(ref _peakQueuedJobCount);
        while (queuedCount > peak)
        {
            var previous = Interlocked.CompareExchange(ref _peakQueuedJobCount, queuedCount, peak);
            if (previous == peak)
            {
                return;
            }

            peak = previous;
        }
    }

    private void RegisterActiveWork(AgentJobRequest request)
    {
        lock (_controlLock)
        {
            if (IsCaptureWork(request) && !_activeWork.Values.Any(entry => IsCaptureWork(entry.Request)))
            {
                _lastCaptureFailed = false;
            }

            _activeWork[request.JobId] = new ActiveWorkEntry(request);
        }
    }

    private static bool IsCaptureWork(AgentJobRequest request)
        => request.IsCaptureScoped || request.IsLiveSource;

    private static bool AdvancesDatabaseChangeCursor(AgentJobRequest request) =>
        request.JobKind != JobKind.SqliteBenchmark;

    private sealed class ActiveWorkEntry
    {
        private DateTime? _startedAtUtc;

        public ActiveWorkEntry(AgentJobRequest request)
        {
            Request = request;
        }

        public AgentJobRequest Request { get; }

        public JobProgress? Progress { get; private set; }

        public SemaphoreSlim ProgressUpdateGate { get; } = new(1, 1);

        public bool StopRequested { get; set; }

        public void Update(JobProgress progress)
        {
            Progress = progress;
            if (!_startedAtUtc.HasValue && progress.State is JobState.Running or JobState.Paused)
            {
                _startedAtUtc = progress.EmittedAtUtc;
            }
        }

        public AgentActiveWorkItem ToSnapshot()
        {
            var progress = Progress;
            var ownership = Request.Ownership != AgentJobOwnership.Unknown
                ? Request.Ownership
                : Request.OriginatingCommandId.HasValue
                    ? AgentJobOwnership.AnalystInitiated
                    : AgentJobOwnership.Background;
            return new AgentActiveWorkItem
            {
                JobId = Request.JobId,
                SourceRunId = Request.SourceRunId,
                JobKind = Request.JobKind,
                State = progress?.State ?? JobState.Unknown,
                CaptureId = Request.CaptureId,
                SourceType = Request.SourceType,
                SourceDisplayName = Request.SourceDisplayName,
                OriginatingCommandId = Request.OriginatingCommandId,
                Ownership = ownership,
                IsCaptureScoped = Request.IsCaptureScoped,
                IsLiveSource = Request.IsLiveSource,
                StopRequested = StopRequested,
                AcceptedAtUtc = Request.AcceptedAtUtc,
                StartedAtUtc = _startedAtUtc,
                UpdatedAtUtc = progress?.EmittedAtUtc ?? Request.AcceptedAtUtc,
                RequestedWorkloads = Request.RequestedWorkloads
            };
        }
    }

    private sealed record QueuedJob(AgentJobRequest Request, int SourceId, string SourceRunId);
}

internal sealed class AgentQueueSaturatedException : InvalidOperationException
{
    public AgentQueueSaturatedException(string message)
        : base(message)
    {
    }
}

internal sealed class AgentConfiguredCaptureStoppingException : InvalidOperationException
{
    public AgentConfiguredCaptureStoppingException(string captureId)
        : base($"Configured capture '{captureId}' is stopping; automatic enrichment was not queued.")
    {
    }
}
