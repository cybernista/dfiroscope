using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Models.Persistence;
using ProcInsider.Services.Features;

namespace ProcInsider.Agent;

internal sealed record AgentPersistenceCaptureParameters(int IntervalMinutes);
internal sealed record AgentPersistenceCollectionParameters(Guid CaptureGeneration, PersistenceCollectionReason Reason, string ResetReason);

/// <summary>One registered scheduling lifecycle, finite single-flight jobs, and exact commit admission.</summary>
internal sealed class AgentPersistenceCaptureWorkflow : IAgentJobHandler
{
    internal const string SourceIdentityId = PersistenceCollection.LocalSourceIdentityId;
    private readonly object _gate = new();
    private readonly IFeatureCatalog _catalog;
    private readonly bool _sealed;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly Func<Task>? _beforeScheduledAdmission;
    private readonly TimeProvider _clock;
    internal static readonly TimeSpan BaselinePeriod = TimeSpan.FromHours(24);
    private AgentJobQueue? _queue;
    private CaptureState? _state;
    private bool _starting;
    private IReadOnlyList<AgentPersistenceSourceHealth> _health = [];

    public AgentPersistenceCaptureWorkflow(IFeatureCatalog catalog, bool captureSealed,
        Func<TimeSpan, CancellationToken, Task>? delay = null, Func<Task>? beforeScheduledAdmission = null,
        TimeProvider? clock = null)
    { _catalog = catalog; _sealed = captureSealed; _delay = delay ?? Task.Delay; _beforeScheduledAdmission = beforeScheduledAdmission; _clock = clock ?? TimeProvider.System; }

    internal DateTime UtcNow => _clock.GetUtcNow().UtcDateTime;

    public void AttachQueue(AgentJobQueue queue) => _queue = queue;
    public IReadOnlyList<AgentPersistenceSourceHealth> GetHealth() { lock (_gate) return _health.ToArray(); }

    public async Task<Guid> StartAsync(EvidenceIdentity identity, AgentPersistenceCapturePolicy policy, Guid commandId, CancellationToken token)
    {
        EnsurePublished();
        if (!policy.Enabled || policy.IntervalMinutes is < 1 or > 1440 || string.IsNullOrWhiteSpace(identity.CaptureId))
            throw new InvalidOperationException("Persistence requires an enabled valid configured capture.");
        lock (_gate)
        {
            if (_starting || _state != null) throw new InvalidOperationException("Persistence capture is already active.");
            _starting = true;
        }
        try
        {
            return await Queue.EnqueueAsync(new AgentJobRequest
            {
                JobKind = JobKind.PersistenceCapture, OriginatingCommandId = commandId,
                SourceType = "PersistenceCapture", SourceDisplayName = "Persistence capture scheduler",
                EvidenceIdentity = identity, CaptureId = identity.CaptureId, IsCaptureScoped = true, IsLiveSource = true,
                Ownership = AgentJobOwnership.ConfiguredCapture, Parameters = new AgentPersistenceCaptureParameters(policy.IntervalMinutes)
            }, token).ConfigureAwait(false);
        }
        finally { lock (_gate) _starting = false; }
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        EnsurePublished();
        var parameters = JsonSerializer.Deserialize<AgentPersistenceCaptureParameters>(context.Request.ToParametersJson(), AgentJson.JsonOptions)
            ?? throw new InvalidDataException("Persistence schedule parameters missing.");
        if (parameters.IntervalMinutes is < 1 or > 1440) throw new InvalidDataException("Persistence interval invalid.");
        var state = new CaptureState(context.Request.JobId, context.Request.EvidenceIdentity, context.CancellationToken, parameters.IntervalMinutes);
        lock (_gate)
        {
            if (_state != null) throw new InvalidOperationException("Persistence lifecycle overlap.");
            _state = state; _health = [];
        }
        try
        {
            await CollectAndWaitAsync(state, PersistenceCollectionReason.Startup).ConfigureAwait(false);
            while (true)
            {
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
                Task resume;
                lock (_gate) resume = state.ResumeWake.Task;
                var delay = _delay(TimeSpan.FromMinutes(parameters.IntervalMinutes), wait.Token);
                if (await Task.WhenAny(delay, resume).ConfigureAwait(false) == resume)
                {
                    wait.Cancel();
                    try { await delay.ConfigureAwait(false); } catch (OperationCanceledException) when (!context.CancellationToken.IsCancellationRequested) { }
                    lock (_gate) state.ResumeWake = new(TaskCreationOptions.RunContinuationsAsynchronously);
                }
                else await delay.ConfigureAwait(false);
                await CollectAndWaitAsync(state, PersistenceCollectionReason.Scheduled).ConfigureAwait(false);
            }
        }
        finally
        {
            lock (_gate) state.Paused = true;
            await CancelAndDrainChildAsync(state).ConfigureAwait(false);
            lock (_gate) if (ReferenceEquals(_state, state)) _state = null;
        }
    }

    private async Task CollectAndWaitAsync(CaptureState state, PersistenceCollectionReason reason)
    {
        Guid? id;
        lock (_gate) { if (state.Paused || state.ChildId != null) return; }
        if (_beforeScheduledAdmission != null) await _beforeScheduledAdmission().ConfigureAwait(false);
        id = await RequestCollectionAsync(state.Identity.CaptureId, reason, "", null, state.Token).ConfigureAwait(false);
        if (id != null) await Queue.WaitForJobAsync(id.Value, state.Token).ConfigureAwait(false);
    }

    public async Task<Guid?> RequestCollectionAsync(string captureId, PersistenceCollectionReason reason, string resetReason,
        Guid? commandId, CancellationToken token)
    {
        EnsurePublished();
        if (reason == PersistenceCollectionReason.Rebaseline && (string.IsNullOrWhiteSpace(resetReason) || resetReason.Length > 2048))
            throw new InvalidDataException("Rebaseline requires a bounded explicit reset reason.");
        CaptureState state; AgentJobRequest request; TaskCompletionSource admission;
        lock (_gate)
        {
            state = _state ?? throw new InvalidOperationException("Persistence configured capture is not running.");
            if (state.Paused && reason is PersistenceCollectionReason.Startup or PersistenceCollectionReason.Scheduled) return null;
            if (state.Identity.CaptureId != captureId || state.Paused || state.Token.IsCancellationRequested)
                throw new InvalidOperationException("Persistence target capture is inactive, paused or superseded.");
            if (state.ChildId != null)
            {
                if (Queue.HasJobCompleted(state.ChildId.Value)) state.ChildId = null;
            }
            if (state.ChildId != null)
            {
                if (reason == PersistenceCollectionReason.Scheduled) return null;
                throw new InvalidOperationException("Persistence collection is already in flight; no overlapping request was accepted.");
            }
            request = new AgentJobRequest
            {
                JobKind = JobKind.PersistenceCollection, OriginatingCommandId = commandId,
                SourceType = "PersistenceCollection", SourceDisplayName = "Persistence collection",
                EvidenceIdentity = state.Identity, CaptureId = captureId, IsCaptureScoped = true,
                Ownership = AgentJobOwnership.ConfiguredCapture,
                Parameters = new AgentPersistenceCollectionParameters(state.Generation, reason, resetReason)
            };
            state.ChildId = request.JobId; // Reserve before any asynchronous queue admission.
            // A delay-winning admission may also satisfy an overdue resume. Consume
            // that wake here, after the scheduling seam and under the reservation lock.
            // A later wake during pause/cancellation of this child remains pending.
            if (state.ResumeWake.Task.IsCompleted) state.ResumeWake = new(TaskCreationOptions.RunContinuationsAsynchronously);
            state.ChildAdmission = admission = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        try
        {
            await Queue.EnqueueAsync(request, token).ConfigureAwait(false);
            lock (_gate) state.ChildCompletion = MonitorChildAsync(state, request.JobId);
            return request.JobId;
        }
        catch { lock (_gate) state.ChildId = null; throw; }
        finally { admission.TrySetResult(); }
    }

    private async Task MonitorChildAsync(CaptureState state, Guid jobId)
    {
        await Queue.WaitForJobAsync(jobId, CancellationToken.None).ConfigureAwait(false);
        lock (_gate) if (state.ChildId == jobId) state.ChildId = null;
    }

    public void EnsureCurrent(AgentJobContext context, Guid generation)
    {
        lock (_gate) EnsureCurrentLocked(context, generation);
    }
    public PersistenceAcceptedState? GetAcceptedState(AgentJobContext context, Guid generation)
    {
        lock (_gate) { EnsureCurrentLocked(context, generation); return _state!.AcceptedState; }
    }
    public void CacheAcceptedState(AgentJobContext context, Guid generation, PersistenceAcceptedState? accepted, bool recovered = false)
    {
        lock (_gate)
        {
            // A commit-winning cancellation must still publish its accepted cache/health.
            if (_state == null || _state.Generation != generation || _state.Identity != context.Request.EvidenceIdentity || _state.ChildId != context.Request.JobId)
                throw new InvalidOperationException("Persistence cache belongs to a superseded lifecycle.");
            if (accepted != null && accepted.Scope != _state!.Identity) throw new InvalidDataException("Persistence cache scope differs.");
            _state!.AcceptedState = accepted;
            if (accepted != null)
            {
                // Nulling an uncertain cache must not restart elapsed age. Only a verified
                // different accepted period establishes a new monotonic anchor.
                if (_state.PeriodId != accepted.Checkpoint.StateGenerationId && accepted.PeriodStartedUtc is DateTime started)
                {
                    _state.PeriodId = accepted.Checkpoint.StateGenerationId;
                    _state.PeriodAgeAtAnchor = recovered ? TimeSpan.FromTicks(Math.Clamp((UtcNow - started).Ticks, 0, BaselinePeriod.Ticks)) : TimeSpan.Zero;
                    _state.PeriodAnchor = _clock.GetTimestamp();
                }
                if (!recovered) _state.LastAcceptedTimestamp = _clock.GetTimestamp();
            }
        }
    }
    public bool IsBoundaryDue(AgentJobContext context, Guid generation)
    {
        lock (_gate)
        {
            EnsureCurrentLocked(context, generation);
            return IsBoundaryDueLocked(_state!);
        }
    }
    private bool IsBoundaryDueLocked(CaptureState state) => state.AcceptedState?.PeriodStartedUtc != null &&
        state.PeriodAgeAtAnchor + _clock.GetElapsedTime(state.PeriodAnchor) >= BaselinePeriod;
    public PersistenceAcceptance CommitIfCurrent(AgentJobContext context, Guid generation, Func<PersistenceAcceptance> commit)
    {
        // Serialize revocation with the actual store acceptance, not with in-memory enqueue.
        lock (_gate) { EnsureCurrentLocked(context, generation); return commit(); }
    }
    private void EnsureCurrentLocked(AgentJobContext context, Guid generation)
    {
        EnsurePublished(); context.CancellationToken.ThrowIfCancellationRequested();
        if (_state == null || _state.Generation != generation || _state.Identity != context.Request.EvidenceIdentity ||
            _state.ChildId != context.Request.JobId || _state.Paused || _state.Token.IsCancellationRequested)
            throw new InvalidOperationException("Persistence collection capture generation is no longer authorized.");
    }

    public async Task<bool> RequestPauseAsync(Guid jobId, CancellationToken token)
    {
        CaptureState state;
        lock (_gate) { if (_state?.JobId != jobId) return false; state = _state; state.Paused = true; }
        await CancelAndDrainChildAsync(state).WaitAsync(token).ConfigureAwait(false);
        return true;
    }
    public Task<bool> RequestResumeAsync(Guid jobId, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); EnsurePublished();
        lock (_gate)
        {
            if (_state?.JobId != jobId || _state.Token.IsCancellationRequested) return Task.FromResult(false);
            _state.Paused = false;
            if (IsBoundaryDueLocked(_state) || _state.LastAcceptedTimestamp is long timestamp &&
                _clock.GetElapsedTime(timestamp) >= TimeSpan.FromMinutes(_state.IntervalMinutes))
                _state.ResumeWake.TrySetResult();
        }
        return Task.FromResult(true);
    }
    private async Task CancelAndDrainChildAsync(CaptureState state)
    {
        Task admission;
        lock (_gate) admission = state.ChildAdmission.Task;
        await admission.ConfigureAwait(false);
        Guid? child; Task completion;
        lock (_gate) { child = state.ChildId; completion = state.ChildCompletion; }
        if (child != null) { await Queue.CancelJobAsync(child.Value, CancellationToken.None).ConfigureAwait(false); await Queue.WaitForJobAsync(child.Value, CancellationToken.None).ConfigureAwait(false); }
        await completion.ConfigureAwait(false);
    }

    public void RecordAccepted(IReadOnlyList<PersistenceCollectorResult> results, DateTime completedUtc)
    {
        lock (_gate)
        {
            _health = results.GroupBy(result => result.CollectorId).Select(group =>
            {
                var success = group.All(result => result.Status == PersistenceCollectionStatus.Complete);
                var previous = _health.FirstOrDefault(health => health.CollectorId == group.Key);
                return new AgentPersistenceSourceHealth
                {
                    CollectorId = group.Key, Status = success ? PersistenceCollectionStatus.Complete : group.Any(result => result.Status is PersistenceCollectionStatus.Complete or PersistenceCollectionStatus.Partial) ? PersistenceCollectionStatus.Partial : group.All(result => result.Status == PersistenceCollectionStatus.Cancelled) ? PersistenceCollectionStatus.Cancelled : PersistenceCollectionStatus.Failed,
                    ArtifactCount = group.Sum(result => result.Artifacts.Count), Coverage = group.Select(result => result.Coverage).ToArray(),
                    LastSuccessfulCollectionUtc = success ? completedUtc : previous?.LastSuccessfulCollectionUtc,
                    Diagnostic = success ? "Complete declared coverage committed." : "Incomplete source coverage committed; prior unsupported partitions remain stale."
                };
            }).ToArray();
        }
    }
    public void RecordAcceptanceFailure(AgentJobContext context, Guid generation, IReadOnlyList<PersistenceCollectorResult> results)
    {
        lock (_gate)
        {
            if (_state?.Generation != generation || _state.ChildId != context.Request.JobId || _state.Paused) return;
            _health = results.GroupBy(result => result.CollectorId).Select(group => new AgentPersistenceSourceHealth
            {
                CollectorId = group.Key, Status = PersistenceCollectionStatus.Failed, ArtifactCount = group.Sum(result => result.Artifacts.Count),
                Coverage = group.Select(result => result.Coverage).ToArray(),
                LastSuccessfulCollectionUtc = _health.FirstOrDefault(previous => previous.CollectorId == group.Key)?.LastSuccessfulCollectionUtc,
                Diagnostic = "Collection observation was not durably accepted; checkpoint and prior confirmation remain unchanged."
            }).ToArray();
        }
    }
    private AgentJobQueue Queue => _queue ?? throw new InvalidOperationException("Persistence queue has not been composed.");
    private void EnsurePublished()
    {
        if (_sealed || !_catalog.IsPublished(FeatureIds.Persistence) || !_catalog.IsPublished(FeatureIds.AgentsAndCapture))
            throw new InvalidOperationException("Persistence acquisition is hidden or the capture is sealed.");
    }
    private sealed class CaptureState(Guid jobId, EvidenceIdentity identity, CancellationToken token, int intervalMinutes)
    {
        public Guid JobId { get; } = jobId;
        public Guid Generation { get; } = Guid.NewGuid();
        public EvidenceIdentity Identity { get; } = identity;
        public CancellationToken Token { get; } = token;
        public bool Paused { get; set; }
        public int IntervalMinutes { get; } = intervalMinutes;
        public string? PeriodId { get; set; }
        public long PeriodAnchor { get; set; }
        public TimeSpan PeriodAgeAtAnchor { get; set; }
        public long? LastAcceptedTimestamp { get; set; }
        public TaskCompletionSource ResumeWake { get; set; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public PersistenceAcceptedState? AcceptedState { get; set; }
        public Guid? ChildId { get; set; }
        public Task ChildCompletion { get; set; } = Task.CompletedTask;
        public TaskCompletionSource ChildAdmission { get; set; } = CompletedAdmission();
        private static TaskCompletionSource CompletedAdmission() { var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); completion.SetResult(); return completion; }
    }
}
