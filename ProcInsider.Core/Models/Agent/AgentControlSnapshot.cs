using System;
using System.Collections.Generic;
using System.Linq;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Portable authoritative operational capture state reported by the agent.
/// Unknown = 0 is intentional so a viewer can distinguish an older agent that
/// does not publish the control snapshot from an authoritative Off state.
/// </summary>
public enum AgentCaptureRunState
{
    Unknown = 0,
    Off = 1,
    Starting = 2,
    Running = 3,
    Stopping = 4,
    Draining = 5,
    Failed = 6,
    Pausing = 7,
    Paused = 8,
    Resuming = 9,
}

/// <summary>Who initiated an in-flight job.</summary>
public enum AgentJobOwnership
{
    Unknown = 0,
    AnalystInitiated = 1,
    Background = 2,
    ConfiguredCapture = 3,
}

/// <summary>
/// Explicit enrichment workload selection carried independently from
/// <see cref="JobKind"/> so combined and future job kinds project safely.
/// </summary>
public sealed record AgentRequestedWorkloads
{
    public bool CaptureModules { get; init; }

    public bool CaptureHandles { get; init; }

    public bool CapturePeMetadata { get; init; }

    public static AgentRequestedWorkloads ForEnrichment(
        bool captureModules,
        bool captureHandles,
        bool capturePeMetadata)
        => new()
        {
            CaptureModules = captureModules,
            CaptureHandles = captureHandles,
            CapturePeMetadata = capturePeMetadata
        };
}

/// <summary>
/// One queued or executing unit of work. Completed history remains available
/// through job-status queries and is deliberately excluded from health.
/// </summary>
public sealed record AgentActiveWorkItem
{
    public Guid JobId { get; init; }

    public string SourceRunId { get; init; } = string.Empty;

    public JobKind JobKind { get; init; }

    public JobState State { get; init; }

    public string CaptureId { get; init; } = string.Empty;

    public string SourceType { get; init; } = string.Empty;

    public string SourceDisplayName { get; init; } = string.Empty;

    public Guid? OriginatingCommandId { get; init; }

    public AgentJobOwnership Ownership { get; init; }

    /// <summary>
    /// True when the job belongs to the operational capture lifecycle and may
    /// be stopped as part of that capture. This is independent of ownership.
    /// </summary>
    public bool IsCaptureScoped { get; init; }

    public bool IsLiveSource { get; init; }

    public bool StopRequested { get; init; }

    public DateTime AcceptedAtUtc { get; init; }

    public DateTime? StartedAtUtc { get; init; }

    public DateTime UpdatedAtUtc { get; init; }

    public AgentRequestedWorkloads RequestedWorkloads { get; init; } = new();
}

/// <summary>Job-level activity for one independently controlled workload.</summary>
public sealed record AgentWorkloadActivitySnapshot
{
    public bool IsActive { get; init; }

    public bool IsStopping { get; init; }

    public int JobCount { get; init; }

    public IReadOnlyList<Guid> JobIds { get; init; } = Array.Empty<Guid>();
}

/// <summary>
/// Additive, bounded control-plane snapshot included in agent health. It is
/// assembled only from in-memory queue state and never contains evidence rows.
/// </summary>
public sealed record AgentControlSnapshot
{
    /// <summary>False when this object is only the compatibility default from an older agent.</summary>
    public bool IsAuthoritative { get; init; }

    /// <summary>Monotonically increasing per-agent snapshot generation.</summary>
    public long Generation { get; init; }

    public DateTime EmittedAtUtc { get; init; }

    public AgentCaptureRunState CaptureState { get; init; }

    public string ActiveCaptureId { get; init; } = string.Empty;

    public DateTime? CaptureStateChangedAtUtc { get; init; }

    public DateTime? PauseStartedAtUtc { get; init; }

    public DateTime? LastResumedAtUtc { get; init; }

    public TimeSpan? LastPauseDuration { get; init; }

    public string AcquisitionGapDetail { get; init; } = string.Empty;

    public IReadOnlyList<AgentActiveWorkItem> ActiveWork { get; init; } = Array.Empty<AgentActiveWorkItem>();

    public AgentWorkloadActivitySnapshot ModuleEnrichment { get; init; } = new();

    public AgentWorkloadActivitySnapshot HandleEnrichment { get; init; } = new();

    public AgentWorkloadActivitySnapshot PeAnalysis { get; init; } = new();
}

public sealed record AgentCaptureControlProjection
{
    public AgentCaptureRunState State { get; init; }

    public string ActiveCaptureId { get; init; } = string.Empty;
}

/// <summary>Pure projection rules shared by the agent and deterministic contract tests.</summary>
public static class AgentControlSnapshotProjection
{
    public static AgentCaptureControlProjection ProjectCapture(
        IReadOnlyList<AgentActiveWorkItem> activeWork,
        CaptureHealthReport captureHealth,
        bool lastCaptureFailed = false)
    {
        ArgumentNullException.ThrowIfNull(activeWork);
        ArgumentNullException.ThrowIfNull(captureHealth);

        var captureWork = activeWork
            .Where(item => item.IsCaptureScoped || item.IsLiveSource)
            .OrderByDescending(item => item.JobKind == JobKind.LiveCapture)
            .ThenBy(item => item.AcceptedAtUtc)
            .ToArray();

        if (captureWork.Length == 0)
        {
            return new AgentCaptureControlProjection
            {
                State = lastCaptureFailed || captureHealth.Health == CaptureHealth.Error
                    ? AgentCaptureRunState.Failed
                    : AgentCaptureRunState.Off
            };
        }

        var activeCaptureId = captureWork
            .Select(item => item.CaptureId)
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

        if (captureWork.Any(item => item.StopRequested))
        {
            var draining = captureHealth.LiveBufferDrainingAfterStop ||
                           captureHealth.LiveBufferDrainActive ||
                           captureHealth.LiveBufferPendingBatches > 0 ||
                           captureHealth.LiveBufferPendingRecords > 0 ||
                           captureHealth.PendingEventWriteBatches > 0 ||
                           captureHealth.PendingProcessWriteBatches > 0;
            return new AgentCaptureControlProjection
            {
                State = draining ? AgentCaptureRunState.Draining : AgentCaptureRunState.Stopping,
                ActiveCaptureId = activeCaptureId
            };
        }

        var liveCaptureWork = captureWork.Where(item => item.IsLiveSource).ToArray();
        if (liveCaptureWork.Length > 0 && liveCaptureWork.All(item => item.State == JobState.Paused))
        {
            return new AgentCaptureControlProjection
            {
                State = AgentCaptureRunState.Paused,
                ActiveCaptureId = activeCaptureId
            };
        }

        if (captureWork.Any(item => item.State is JobState.Running or JobState.Paused))
        {
            return new AgentCaptureControlProjection
            {
                State = AgentCaptureRunState.Running,
                ActiveCaptureId = activeCaptureId
            };
        }

        if (captureWork.Any(item => item.State is JobState.Queued or JobState.Unknown))
        {
            return new AgentCaptureControlProjection
            {
                State = AgentCaptureRunState.Starting,
                ActiveCaptureId = activeCaptureId
            };
        }

        return new AgentCaptureControlProjection
        {
            State = captureWork.Any(item => item.State == JobState.Failed) || captureHealth.Health == CaptureHealth.Error
                ? AgentCaptureRunState.Failed
                : AgentCaptureRunState.Off
        };
    }

    public static AgentWorkloadActivitySnapshot ProjectWorkload(
        IReadOnlyList<AgentActiveWorkItem> activeWork,
        Func<AgentRequestedWorkloads, bool> includesWorkload)
    {
        ArgumentNullException.ThrowIfNull(activeWork);
        ArgumentNullException.ThrowIfNull(includesWorkload);

        var jobs = activeWork
            .Where(item => includesWorkload(item.RequestedWorkloads))
            .OrderBy(item => item.AcceptedAtUtc)
            .ToArray();
        return new AgentWorkloadActivitySnapshot
        {
            IsActive = jobs.Length > 0,
            IsStopping = jobs.Any(item => item.StopRequested),
            JobCount = jobs.Length,
            JobIds = jobs.Select(item => item.JobId).ToArray()
        };
    }
}

/// <summary>Pure configured-capture selection rules shared by queue code and contract tests.</summary>
public static class AgentConfiguredCaptureWorkProjection
{
    public static IReadOnlyList<AgentActiveWorkItem> Select(
        IReadOnlyList<AgentActiveWorkItem> activeWork,
        string captureId = "")
    {
        ArgumentNullException.ThrowIfNull(activeWork);
        return activeWork
            .Where(item => item.Ownership == AgentJobOwnership.ConfiguredCapture)
            .Where(item => string.IsNullOrWhiteSpace(captureId) ||
                           string.Equals(item.CaptureId, captureId, StringComparison.Ordinal))
            .OrderBy(item => item.AcceptedAtUtc)
            .ThenBy(item => item.JobId)
            .ToArray();
    }

    public static bool TryGetAcceptingCaptureId(
        IReadOnlyList<AgentActiveWorkItem> activeWork,
        out string captureId)
    {
        captureId = Select(activeWork)
            .Where(item => !item.StopRequested)
            .Select(item => item.CaptureId)
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
        return !string.IsNullOrWhiteSpace(captureId);
    }
}
