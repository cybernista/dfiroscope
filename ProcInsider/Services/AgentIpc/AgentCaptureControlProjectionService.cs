using System;
using System.Collections.Generic;
using System.Linq;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public enum AgentControlSnapshotStatus
{
    Unknown = 0,
    Current = 1,
    Stale = 2,
    WrongSession = 3,
    Unsupported = 4,
}

public enum AgentCapturePendingAction
{
    None = 0,
    Start = 1,
    Stop = 2,
    Pause = 3,
    Resume = 4,
}

public sealed record AgentCaptureSourceControlState
{
    public AgentCaptureRunState State { get; init; } = AgentCaptureRunState.Unknown;

    public bool CanStart { get; init; }

    public bool CanStop { get; init; }

    public string StatusText { get; init; } = "Runtime state is unavailable.";

    public IReadOnlyList<Guid> JobIds { get; init; } = Array.Empty<Guid>();
}

/// <summary>
/// Viewer-safe operational capture state. Every capture label and command
/// consumes this projection instead of viewer-memory job ids or health counters.
/// </summary>
public sealed record AgentCaptureControlViewState
{
    private static readonly AgentCaptureSourceControlState UnknownSource = new();

    public AgentControlSnapshotStatus SnapshotStatus { get; init; }

    public AgentCaptureRunState State { get; init; } = AgentCaptureRunState.Unknown;

    public string ActiveCaptureId { get; init; } = string.Empty;

    public bool CanStart { get; init; }

    public bool CanStop { get; init; }

    public bool CanPause { get; init; }

    public bool CanResume { get; init; }

    public bool CanEnd { get; init; }

    public long SnapshotGeneration { get; init; }

    public DateTime? SnapshotEmittedAtUtc { get; init; }

    public DateTime? CaptureStateChangedAtUtc { get; init; }

    public DateTime? PauseStartedAtUtc { get; init; }

    public DateTime? LastResumedAtUtc { get; init; }

    public TimeSpan? LastPauseDuration { get; init; }

    public string AcquisitionGapDetail { get; init; } = string.Empty;

    public bool SnapshotAccepted { get; init; }

    public AgentCapturePendingAction PendingAction { get; init; }

    public string StatusText { get; init; } = "Capture runtime: Unknown.";

    public string StatusDetail { get; init; } = "Waiting for an authoritative agent control snapshot.";

    public IReadOnlyDictionary<JobKind, AgentCaptureSourceControlState> JobSources { get; init; } =
        new Dictionary<JobKind, AgentCaptureSourceControlState>();

    public IReadOnlyDictionary<string, AgentCaptureSourceControlState> LiveSources { get; init; } =
        new Dictionary<string, AgentCaptureSourceControlState>(StringComparer.OrdinalIgnoreCase);

    public AgentCaptureSourceControlState GetJobSource(JobKind jobKind)
        => JobSources.TryGetValue(jobKind, out var source) ? source : UnknownSource;

    public AgentCaptureSourceControlState GetLiveSource(string source)
        => LiveSources.TryGetValue(source, out var value) ? value : UnknownSource;

    public static AgentCaptureControlViewState Unknown(string detail = "Waiting for an authoritative agent control snapshot.")
        => new() { StatusDetail = detail };
}

public sealed record AgentEnrichmentCancellationPlan
{
    public IReadOnlyList<Guid> JobIds { get; init; } = Array.Empty<Guid>();

    public IReadOnlyList<JobKind> AffectedWorkloads { get; init; } = Array.Empty<JobKind>();
}

public static class AgentEnrichmentControlPlanning
{
    private static readonly JobKind[] WorkloadKinds =
    [
        JobKind.ModuleEnrichment,
        JobKind.HandleEnrichment,
        JobKind.PeAnalysis
    ];

    public static AgentEnrichmentCancellationPlan PlanCancellation(
        AgentCaptureControlViewState projection,
        params JobKind[] requestedWorkloads)
    {
        ArgumentNullException.ThrowIfNull(projection);
        var jobIds = requestedWorkloads
            .SelectMany(kind => projection.GetJobSource(kind).JobIds)
            .Where(jobId => jobId != Guid.Empty)
            .Distinct()
            .ToArray();
        var affectedWorkloads = WorkloadKinds
            .Where(kind => projection.GetJobSource(kind).JobIds.Any(jobIds.Contains))
            .ToArray();
        return new AgentEnrichmentCancellationPlan
        {
            JobIds = jobIds,
            AffectedWorkloads = affectedWorkloads
        };
    }
}

/// <summary>
/// Accepts ordered agent health snapshots and projects the single capture truth
/// used by the viewer. The service has no IO and accepts the clock explicitly so
/// its ordering, freshness, and pending-command behavior is deterministic.
/// </summary>
public sealed class AgentCaptureControlProjectionService
{
    public static readonly TimeSpan DefaultFreshnessWindow = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan DefaultPendingCommandTimeout = TimeSpan.FromSeconds(30);

    private static readonly JobKind[] ProjectedJobKinds =
    [
        JobKind.LiveCapture,
        JobKind.NetworkCapture,
        JobKind.ProcessMonitorCapture,
        JobKind.ModuleEnrichment,
        JobKind.HandleEnrichment,
        JobKind.PeAnalysis
    ];

    private static readonly string[] ProjectedLiveSources =
    [
        "Runtime",
        "ETW",
        "Security",
        "PowerShell",
        "WindowsOther",
        "Sysmon"
    ];

    private readonly TimeSpan _freshnessWindow;
    private readonly TimeSpan _pendingCommandTimeout;
    private readonly Dictionary<JobKind, PendingCommand> _pendingJobs = new();
    private AgentControlSnapshot? _lastSnapshot;
    private CaptureHealthReport? _lastCaptureHealth;
    private PendingCommand? _pendingCapture;
    private string _agentInstanceKey = string.Empty;
    private long _lastGeneration;
    private DateTime _lastEmittedAtUtc;

    public AgentCaptureControlProjectionService(
        TimeSpan? freshnessWindow = null,
        TimeSpan? pendingCommandTimeout = null)
    {
        _freshnessWindow = freshnessWindow ?? DefaultFreshnessWindow;
        _pendingCommandTimeout = pendingCommandTimeout ?? DefaultPendingCommandTimeout;
        Current = AgentCaptureControlViewState.Unknown();
    }

    public AgentCaptureControlViewState Current { get; private set; }

    public AgentCaptureControlViewState ApplyHealth(
        AgentHealthSnapshot health,
        bool isExpectedSession,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(health);

        if (!isExpectedSession)
        {
            Current = Unavailable(
                AgentControlSnapshotStatus.WrongSession,
                "Capture runtime: Unknown (wrong session).",
                "The agent snapshot does not match the active capture session.");
            return Current;
        }

        var snapshot = health.Control;
        if (!snapshot.IsAuthoritative || snapshot.CaptureState == AgentCaptureRunState.Unknown)
        {
            Current = Unavailable(
                AgentControlSnapshotStatus.Unsupported,
                "Capture runtime: Unknown (agent control snapshot unavailable).",
                "This agent does not publish an authoritative capture control snapshot.");
            return Current;
        }

        if (!IsFresh(snapshot.EmittedAtUtc, nowUtc))
        {
            Current = Unavailable(
                AgentControlSnapshotStatus.Stale,
                "Capture runtime: Unknown (stale snapshot).",
                FormatLastSnapshotDetail(snapshot.EmittedAtUtc, "The received control snapshot is stale."),
                snapshot);
            return Current;
        }

        var instanceKey = $"{health.ProcessId}:{health.StartedAtUtc.ToUniversalTime().Ticks}";
        if (!string.Equals(instanceKey, _agentInstanceKey, StringComparison.Ordinal))
        {
            ResetOrdering(instanceKey);
        }

        var outOfOrder = snapshot.Generation < _lastGeneration ||
                         snapshot.Generation == _lastGeneration &&
                         snapshot.EmittedAtUtc < _lastEmittedAtUtc;
        if (outOfOrder)
        {
            Current = BuildCurrent(
                nowUtc,
                snapshotAccepted: false,
                $"Ignored out-of-order control snapshot generation {snapshot.Generation}; " +
                $"retained generation {_lastGeneration}.");
            return Current;
        }

        _lastSnapshot = snapshot;
        _lastCaptureHealth = health.CaptureHealth;
        _lastGeneration = snapshot.Generation;
        _lastEmittedAtUtc = snapshot.EmittedAtUtc;
        ReconcilePending(snapshot, nowUtc);
        Current = BuildCurrent(nowUtc, snapshotAccepted: true);
        return Current;
    }

    public AgentCaptureControlViewState BeginPendingCapture(
        AgentCapturePendingAction action,
        DateTime nowUtc,
        string captureId = "")
    {
        if (action == AgentCapturePendingAction.None)
        {
            return Current;
        }

        _pendingCapture = new PendingCommand(action, nowUtc, _lastGeneration, captureId);
        Current = BuildCurrent(nowUtc, snapshotAccepted: Current.SnapshotAccepted);
        return Current;
    }

    public AgentCaptureControlViewState BeginPendingJob(
        JobKind jobKind,
        AgentCapturePendingAction action,
        DateTime nowUtc)
    {
        if (action == AgentCapturePendingAction.None)
        {
            return Current;
        }

        _pendingJobs[jobKind] = new PendingCommand(action, nowUtc, _lastGeneration, string.Empty);
        Current = BuildCurrent(nowUtc, snapshotAccepted: Current.SnapshotAccepted);
        return Current;
    }

    public AgentCaptureControlViewState MarkUnavailable(string detail, DateTime nowUtc)
    {
        var status = _lastSnapshot == null
            ? AgentControlSnapshotStatus.Unknown
            : AgentControlSnapshotStatus.Stale;
        var statusText = status == AgentControlSnapshotStatus.Stale
            ? "Capture runtime: Unknown (agent status stale)."
            : "Capture runtime: Unknown.";
        Current = Unavailable(
            status,
            statusText,
            FormatLastSnapshotDetail(_lastSnapshot?.EmittedAtUtc, detail));
        return Current;
    }

    public AgentCaptureControlViewState Reset(string detail)
    {
        _lastSnapshot = null;
        _lastCaptureHealth = null;
        _pendingCapture = null;
        _pendingJobs.Clear();
        _agentInstanceKey = string.Empty;
        _lastGeneration = 0;
        _lastEmittedAtUtc = default;
        Current = AgentCaptureControlViewState.Unknown(detail);
        return Current;
    }

    private AgentCaptureControlViewState BuildCurrent(
        DateTime nowUtc,
        bool snapshotAccepted,
        string additionalDetail = "")
    {
        if (_lastSnapshot == null || _lastCaptureHealth == null)
        {
            return AgentCaptureControlViewState.Unknown(additionalDetail);
        }

        if (!IsFresh(_lastSnapshot.EmittedAtUtc, nowUtc))
        {
            return Unavailable(
                AgentControlSnapshotStatus.Stale,
                "Capture runtime: Unknown (agent status stale).",
                FormatLastSnapshotDetail(_lastSnapshot.EmittedAtUtc, additionalDetail));
        }

        ExpirePending(nowUtc);
        IReadOnlyDictionary<JobKind, AgentCaptureSourceControlState> jobSources = ProjectedJobKinds.ToDictionary(
            jobKind => jobKind,
            jobKind => BuildJobSource(jobKind, _lastSnapshot, _lastCaptureHealth));
        IReadOnlyDictionary<string, AgentCaptureSourceControlState> liveSources = ProjectedLiveSources.ToDictionary(
            source => source,
            source => BuildLiveSource(source, jobSources[JobKind.LiveCapture], _lastCaptureHealth),
            StringComparer.OrdinalIgnoreCase);

        var state = _lastSnapshot.CaptureState;
        var activeCaptureId = _lastSnapshot.ActiveCaptureId;
        var pendingAction = AgentCapturePendingAction.None;
        if (_pendingCapture != null)
        {
            pendingAction = _pendingCapture.Action;
            state = pendingAction switch
            {
                AgentCapturePendingAction.Start => AgentCaptureRunState.Starting,
                AgentCapturePendingAction.Pause => AgentCaptureRunState.Pausing,
                AgentCapturePendingAction.Resume => AgentCaptureRunState.Resuming,
                _ => state == AgentCaptureRunState.Draining
                    ? AgentCaptureRunState.Draining
                    : AgentCaptureRunState.Stopping
            };
            activeCaptureId = FirstNonEmpty(_pendingCapture.CaptureId, activeCaptureId);
            jobSources = DisableSourcesForCapturePending(jobSources, state);
            liveSources = DisableLiveSourcesForCapturePending(liveSources, state);
        }
        else if (_pendingJobs.Count > 0 &&
                 state is AgentCaptureRunState.Off or AgentCaptureRunState.Failed)
        {
            state = _pendingJobs.Values.Any(pending => pending.Action == AgentCapturePendingAction.Start)
                ? AgentCaptureRunState.Starting
                : AgentCaptureRunState.Stopping;
        }

        if (_pendingCapture == null && state is AgentCaptureRunState.Off or AgentCaptureRunState.Failed)
        {
            activeCaptureId = string.Empty;
        }

        var canStart = _pendingCapture == null &&
                       state is AgentCaptureRunState.Off or AgentCaptureRunState.Failed;
        var canPause = _pendingCapture == null && state == AgentCaptureRunState.Running;
        var canResume = _pendingCapture == null && state == AgentCaptureRunState.Paused;
        var canEnd = _pendingCapture == null &&
                     state is AgentCaptureRunState.Running or AgentCaptureRunState.Paused;
        var detail = BuildStatusDetail(_lastSnapshot, pendingAction, additionalDetail);
        return new AgentCaptureControlViewState
        {
            SnapshotStatus = AgentControlSnapshotStatus.Current,
            State = state,
            ActiveCaptureId = activeCaptureId,
            CanStart = canStart,
            CanStop = canEnd,
            CanPause = canPause,
            CanResume = canResume,
            CanEnd = canEnd,
            SnapshotGeneration = _lastSnapshot.Generation,
            SnapshotEmittedAtUtc = _lastSnapshot.EmittedAtUtc,
            CaptureStateChangedAtUtc = _lastSnapshot.CaptureStateChangedAtUtc,
            PauseStartedAtUtc = _lastSnapshot.PauseStartedAtUtc,
            LastResumedAtUtc = _lastSnapshot.LastResumedAtUtc,
            LastPauseDuration = _lastSnapshot.LastPauseDuration,
            AcquisitionGapDetail = _lastSnapshot.AcquisitionGapDetail,
            SnapshotAccepted = snapshotAccepted,
            PendingAction = pendingAction,
            StatusText = FormatCaptureStatus(state),
            StatusDetail = detail,
            JobSources = jobSources,
            LiveSources = liveSources
        };
    }

    private AgentCaptureSourceControlState BuildJobSource(
        JobKind jobKind,
        AgentControlSnapshot snapshot,
        CaptureHealthReport health)
    {
        var workload = GetWorkloadActivity(jobKind, snapshot);
        var jobs = workload == null
            ? snapshot.ActiveWork.Where(item => item.JobKind == jobKind).ToArray()
            : snapshot.ActiveWork.Where(item => workload.JobIds.Contains(item.JobId)).ToArray();
        jobs = jobs
            .OrderBy(item => item.AcceptedAtUtc)
            .ToArray();
        var state = workload == null
            ? ProjectJobState(jobKind, jobs, health)
            : ProjectWorkloadState(workload, jobs);
        if (_pendingJobs.TryGetValue(jobKind, out var pending))
        {
            state = pending.Action == AgentCapturePendingAction.Start
                ? AgentCaptureRunState.Starting
                : state == AgentCaptureRunState.Draining
                    ? AgentCaptureRunState.Draining
                    : AgentCaptureRunState.Stopping;
        }

        var globalTransition = _pendingCapture != null ||
                               snapshot.CaptureState is AgentCaptureRunState.Starting or
                                   AgentCaptureRunState.Pausing or AgentCaptureRunState.Resuming or
                                   AgentCaptureRunState.Stopping or AgentCaptureRunState.Draining or
                                   AgentCaptureRunState.Paused;
        return new AgentCaptureSourceControlState
        {
            State = state,
            CanStart = !globalTransition &&
                       state is AgentCaptureRunState.Off or AgentCaptureRunState.Failed,
            CanStop = !globalTransition && jobs.Length > 0 &&
                      state is AgentCaptureRunState.Starting or AgentCaptureRunState.Running,
            StatusText = FormatSourceStatus(jobKind, state, jobs),
            JobIds = workload?.JobIds ?? jobs.Select(job => job.JobId).ToArray()
        };
    }

    private static AgentCaptureSourceControlState BuildLiveSource(
        string sourceName,
        AgentCaptureSourceControlState liveCapture,
        CaptureHealthReport health)
    {
        if (liveCapture.State != AgentCaptureRunState.Running)
        {
            return liveCapture with
            {
                StatusText = liveCapture.State == AgentCaptureRunState.Off
                    ? $"{FormatLiveSourceName(sourceName)}: off."
                    : $"{FormatLiveSourceName(sourceName)}: live capture is {FormatState(liveCapture.State)}."
            };
        }

        var source = health.Sources.FirstOrDefault(candidate =>
            string.Equals(candidate.Source, sourceName, StringComparison.OrdinalIgnoreCase));
        if (source == null)
        {
            return new AgentCaptureSourceControlState
            {
                State = AgentCaptureRunState.Unknown,
                StatusText = "Live capture source state is not available yet.",
                JobIds = liveCapture.JobIds
            };
        }

        var active = source.IsActive && source.IsEnabled;
        var status = string.IsNullOrWhiteSpace(source.Detail)
            ? source.Status
            : $"{source.Status}: {source.Detail}";
        return new AgentCaptureSourceControlState
        {
            State = active ? AgentCaptureRunState.Running : AgentCaptureRunState.Off,
            CanStart = !active,
            CanStop = active,
            StatusText = status,
            JobIds = liveCapture.JobIds
        };
    }

    private static AgentCaptureRunState ProjectJobState(
        JobKind jobKind,
        IReadOnlyList<AgentActiveWorkItem> jobs,
        CaptureHealthReport health)
    {
        if (jobs.Any(job => job.StopRequested))
        {
            var draining = jobKind == JobKind.LiveCapture &&
                           (health.LiveBufferDrainingAfterStop ||
                            health.LiveBufferDrainActive ||
                            health.LiveBufferPendingRecords > 0 ||
                            health.LiveBufferPendingBatches > 0 ||
                            health.PendingEventWriteBatches > 0 ||
                            health.PendingProcessWriteBatches > 0);
            return draining ? AgentCaptureRunState.Draining : AgentCaptureRunState.Stopping;
        }

        if (jobs.Count > 0 && jobs.All(job => job.State == JobState.Paused))
        {
            return AgentCaptureRunState.Paused;
        }

        if (jobs.Any(job => job.State == JobState.Running))
        {
            return AgentCaptureRunState.Running;
        }

        return jobs.Any(job => job.State is JobState.Queued or JobState.Unknown)
            ? AgentCaptureRunState.Starting
            : AgentCaptureRunState.Off;
    }

    private static AgentCaptureRunState ProjectWorkloadState(
        AgentWorkloadActivitySnapshot workload,
        IReadOnlyList<AgentActiveWorkItem> jobs)
    {
        if (workload.IsStopping || jobs.Any(job => job.StopRequested))
        {
            return AgentCaptureRunState.Stopping;
        }

        if (jobs.Any(job => job.State is JobState.Running or JobState.Paused))
        {
            return AgentCaptureRunState.Running;
        }

        if (workload.IsActive || jobs.Any(job => job.State is JobState.Queued or JobState.Unknown))
        {
            return jobs.Count > 0 ? AgentCaptureRunState.Starting : AgentCaptureRunState.Running;
        }

        return AgentCaptureRunState.Off;
    }

    private static AgentWorkloadActivitySnapshot? GetWorkloadActivity(
        JobKind jobKind,
        AgentControlSnapshot snapshot)
        => jobKind switch
        {
            JobKind.ModuleEnrichment => snapshot.ModuleEnrichment,
            JobKind.HandleEnrichment => snapshot.HandleEnrichment,
            JobKind.PeAnalysis => snapshot.PeAnalysis,
            _ => null
        };

    private void ReconcilePending(AgentControlSnapshot snapshot, DateTime nowUtc)
    {
        ExpirePending(nowUtc);
        if (_pendingCapture != null)
        {
            var newer = IsNewerThan(snapshot, _pendingCapture);
            var reflected = _pendingCapture.Action switch
            {
                AgentCapturePendingAction.Start => snapshot.CaptureState is
                    AgentCaptureRunState.Starting or AgentCaptureRunState.Running or AgentCaptureRunState.Failed,
                AgentCapturePendingAction.Stop => snapshot.CaptureState is
                    AgentCaptureRunState.Stopping or AgentCaptureRunState.Draining,
                AgentCapturePendingAction.Pause => snapshot.CaptureState is
                    AgentCaptureRunState.Pausing or AgentCaptureRunState.Paused or AgentCaptureRunState.Failed,
                AgentCapturePendingAction.Resume => snapshot.CaptureState is
                    AgentCaptureRunState.Resuming or AgentCaptureRunState.Running or AgentCaptureRunState.Failed,
                _ => true
            };
            var terminal = newer && snapshot.CaptureState is AgentCaptureRunState.Off or AgentCaptureRunState.Failed;
            if (reflected || terminal)
            {
                _pendingCapture = null;
            }
        }

        foreach (var pair in _pendingJobs.ToArray())
        {
            var workload = GetWorkloadActivity(pair.Key, snapshot);
            var jobs = workload == null
                ? snapshot.ActiveWork.Where(item => item.JobKind == pair.Key).ToArray()
                : snapshot.ActiveWork.Where(item => workload.JobIds.Contains(item.JobId)).ToArray();
            var reflected = pair.Value.Action == AgentCapturePendingAction.Start
                ? workload?.IsActive == true || jobs.Length > 0
                : workload?.IsStopping == true ||
                  workload?.IsActive == false ||
                  jobs.Length == 0 ||
                  jobs.Any(job => job.StopRequested);
            if (reflected || IsNewerThan(snapshot, pair.Value) &&
                snapshot.CaptureState is AgentCaptureRunState.Off or AgentCaptureRunState.Failed)
            {
                _pendingJobs.Remove(pair.Key);
            }
        }
    }

    private void ExpirePending(DateTime nowUtc)
    {
        if (_pendingCapture != null && nowUtc - _pendingCapture.AcceptedAtUtc > _pendingCommandTimeout)
        {
            _pendingCapture = null;
        }

        foreach (var pair in _pendingJobs
                     .Where(pair => nowUtc - pair.Value.AcceptedAtUtc > _pendingCommandTimeout)
                     .ToArray())
        {
            _pendingJobs.Remove(pair.Key);
        }
    }

    private AgentCaptureControlViewState Unavailable(
        AgentControlSnapshotStatus status,
        string statusText,
        string detail,
        AgentControlSnapshot? receivedSnapshot = null)
    {
        var snapshot = receivedSnapshot ?? _lastSnapshot;
        return new AgentCaptureControlViewState
        {
            SnapshotStatus = status,
            State = AgentCaptureRunState.Unknown,
            ActiveCaptureId = Current.ActiveCaptureId,
            SnapshotGeneration = snapshot?.Generation ?? Current.SnapshotGeneration,
            SnapshotEmittedAtUtc = snapshot?.EmittedAtUtc ?? Current.SnapshotEmittedAtUtc,
            CaptureStateChangedAtUtc = snapshot?.CaptureStateChangedAtUtc ?? Current.CaptureStateChangedAtUtc,
            PauseStartedAtUtc = snapshot?.PauseStartedAtUtc ?? Current.PauseStartedAtUtc,
            LastResumedAtUtc = snapshot?.LastResumedAtUtc ?? Current.LastResumedAtUtc,
            LastPauseDuration = snapshot?.LastPauseDuration ?? Current.LastPauseDuration,
            AcquisitionGapDetail = snapshot?.AcquisitionGapDetail ?? Current.AcquisitionGapDetail,
            StatusText = statusText,
            StatusDetail = detail,
            JobSources = UnknownJobSources(detail),
            LiveSources = UnknownLiveSources(detail)
        };
    }

    private void ResetOrdering(string instanceKey)
    {
        _agentInstanceKey = instanceKey;
        _lastSnapshot = null;
        _lastCaptureHealth = null;
        _lastGeneration = 0;
        _lastEmittedAtUtc = default;
        _pendingCapture = null;
        _pendingJobs.Clear();
    }

    private bool IsFresh(DateTime emittedAtUtc, DateTime nowUtc)
    {
        if (emittedAtUtc == default)
        {
            return false;
        }

        var age = nowUtc - emittedAtUtc;
        return age <= _freshnessWindow && age >= -TimeSpan.FromMinutes(1);
    }

    private static bool IsNewerThan(AgentControlSnapshot snapshot, PendingCommand pending)
        => snapshot.Generation > pending.BaselineGeneration && snapshot.EmittedAtUtc >= pending.AcceptedAtUtc;

    private static IReadOnlyDictionary<JobKind, AgentCaptureSourceControlState> DisableSourcesForCapturePending(
        IReadOnlyDictionary<JobKind, AgentCaptureSourceControlState> sources,
        AgentCaptureRunState state)
        => sources.ToDictionary(
            pair => pair.Key,
            pair =>
            {
                var projectedState = state == AgentCaptureRunState.Starting ||
                                     pair.Value.State is not AgentCaptureRunState.Off and not AgentCaptureRunState.Failed
                    ? state
                    : pair.Value.State;
                return pair.Value with
                {
                    State = projectedState,
                    CanStart = false,
                    CanStop = false,
                    StatusText = FormatSourceStatus(pair.Key, projectedState)
                };
            });

    private static IReadOnlyDictionary<string, AgentCaptureSourceControlState> DisableLiveSourcesForCapturePending(
        IReadOnlyDictionary<string, AgentCaptureSourceControlState> sources,
        AgentCaptureRunState state)
        => sources.ToDictionary(
            pair => pair.Key,
            pair =>
            {
                var projectedState = state == AgentCaptureRunState.Starting ||
                                     pair.Value.State is not AgentCaptureRunState.Off and not AgentCaptureRunState.Failed
                    ? state
                    : pair.Value.State;
                return pair.Value with
                {
                    State = projectedState,
                    CanStart = false,
                    CanStop = false,
                    StatusText = $"{FormatLiveSourceName(pair.Key)}: {FormatState(projectedState)}."
                };
            },
            StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyDictionary<JobKind, AgentCaptureSourceControlState> UnknownJobSources(string detail)
        => ProjectedJobKinds.ToDictionary(
            jobKind => jobKind,
            _ => new AgentCaptureSourceControlState { StatusText = detail });

    private static IReadOnlyDictionary<string, AgentCaptureSourceControlState> UnknownLiveSources(string detail)
        => ProjectedLiveSources.ToDictionary(
            source => source,
            _ => new AgentCaptureSourceControlState { StatusText = detail },
            StringComparer.OrdinalIgnoreCase);

    private static string BuildStatusDetail(
        AgentControlSnapshot snapshot,
        AgentCapturePendingAction pendingAction,
        string additionalDetail)
    {
        var timestamp = snapshot.EmittedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        var pending = pendingAction == AgentCapturePendingAction.None
            ? string.Empty
            : $" Pending {pendingAction.ToString().ToLowerInvariant()} command is awaiting agent reconciliation.";
        var extra = string.IsNullOrWhiteSpace(additionalDetail) ? string.Empty : $" {additionalDetail}";
        var gap = string.IsNullOrWhiteSpace(snapshot.AcquisitionGapDetail)
            ? string.Empty
            : $" {snapshot.AcquisitionGapDetail}";
        return $"Authoritative agent snapshot {snapshot.Generation:N0} at {timestamp}.{pending}{gap}{extra}";
    }

    private static string FormatLastSnapshotDetail(DateTime? emittedAtUtc, string detail)
    {
        var snapshot = emittedAtUtc.HasValue && emittedAtUtc.Value != default
            ? $" Last authoritative snapshot: {emittedAtUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}."
            : string.Empty;
        return $"{detail}{snapshot}".Trim();
    }

    private static string FormatCaptureStatus(AgentCaptureRunState state)
        => state switch
        {
            AgentCaptureRunState.Off => "Capture runtime: Off.",
            AgentCaptureRunState.Starting => "Capture runtime: Starting.",
            AgentCaptureRunState.Running => "Capture runtime: Running.",
            AgentCaptureRunState.Pausing => "Capture runtime: Pausing and draining accepted evidence.",
            AgentCaptureRunState.Paused => "Capture runtime: Paused; acquisition gap is open.",
            AgentCaptureRunState.Resuming => "Capture runtime: Resuming under the existing capture identity.",
            AgentCaptureRunState.Stopping => "Capture runtime: Stopping.",
            AgentCaptureRunState.Draining => "Capture runtime: Draining accepted evidence.",
            AgentCaptureRunState.Failed => "Capture runtime: Failed; Start is available for recovery.",
            _ => "Capture runtime: Unknown."
        };

    private static string FormatSourceStatus(
        JobKind jobKind,
        AgentCaptureRunState state,
        IReadOnlyList<AgentActiveWorkItem>? jobs = null)
    {
        var name = jobKind switch
        {
            JobKind.LiveCapture => "Live capture",
            JobKind.NetworkCapture => "Network capture",
            JobKind.ProcessMonitorCapture => "Process Monitor",
            JobKind.ModuleEnrichment => "Module enrichment",
            JobKind.HandleEnrichment => "Handle enrichment",
            JobKind.PeAnalysis => "PE analysis",
            _ => "Capture"
        };
        var coupling = FormatSharedWorkloadCoupling(jobKind, jobs);
        return $"{name}: {FormatState(state)}.{coupling}";
    }

    private static string FormatSharedWorkloadCoupling(
        JobKind jobKind,
        IReadOnlyList<AgentActiveWorkItem>? jobs)
    {
        if (jobs == null || jobs.Count == 0 ||
            jobKind is not (JobKind.ModuleEnrichment or JobKind.HandleEnrichment or JobKind.PeAnalysis))
        {
            return string.Empty;
        }

        var related = new List<string>();
        if (jobKind != JobKind.ModuleEnrichment && jobs.Any(job => job.RequestedWorkloads.CaptureModules))
        {
            related.Add("modules");
        }

        if (jobKind != JobKind.HandleEnrichment && jobs.Any(job => job.RequestedWorkloads.CaptureHandles))
        {
            related.Add("handles");
        }

        if (jobKind != JobKind.PeAnalysis && jobs.Any(job => job.RequestedWorkloads.CapturePeMetadata))
        {
            related.Add("PE analysis");
        }

        return related.Count == 0
            ? string.Empty
            : $" Shares {jobs.Count:N0} active job(s) with {string.Join(" and ", related)}; stopping this row cancels the shared job.";
    }

    private static string FormatLiveSourceName(string sourceName)
        => sourceName switch
        {
            "Runtime" => "Runtime events",
            "ETW" => "ETW events",
            "Security" => "Security events",
            "PowerShell" => "PowerShell events",
            "WindowsOther" => "Windows logs (other)",
            "Sysmon" => "Sysmon events",
            _ => sourceName
        };

    private static string FormatState(AgentCaptureRunState state)
        => state switch
        {
            AgentCaptureRunState.Off => "off",
            AgentCaptureRunState.Starting => "starting",
            AgentCaptureRunState.Running => "running",
            AgentCaptureRunState.Pausing => "pausing",
            AgentCaptureRunState.Paused => "paused",
            AgentCaptureRunState.Resuming => "resuming",
            AgentCaptureRunState.Stopping => "stopping",
            AgentCaptureRunState.Draining => "draining",
            AgentCaptureRunState.Failed => "failed",
            _ => "unknown"
        };

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private sealed record PendingCommand(
        AgentCapturePendingAction Action,
        DateTime AcceptedAtUtc,
        long BaselineGeneration,
        string CaptureId);
}
