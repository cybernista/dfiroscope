using System;
using System.Collections.Generic;
using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;

namespace ProcInsider.Models.Agent;

/// <summary>Core-owned response envelope shared by the viewer and agent.</summary>
public sealed record AgentIpcResponse
{
    public int ContractVersion { get; init; } = AgentContracts.ContractVersion;

    public Guid RequestId { get; init; }

    public bool Success { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public string ErrorMessage { get; init; } = string.Empty;

    /// <summary>
    /// Whether repeating the same request without changing prerequisites may
    /// succeed. Release-publication rejections are always false.
    /// </summary>
    public bool IsRetryable { get; init; }

    public AgentHealthSnapshot? Health { get; init; }

    public Guid? AcceptedJobId { get; init; }

    public JobProgress? Job { get; init; }

    /// <summary>
    /// Every queued or reused job accepted by a configured-capture start.
    /// Older agents omit this additive collection and continue to populate
    /// <see cref="AcceptedJobId"/> and <see cref="Job"/>.
    /// </summary>
    public IReadOnlyList<AgentActiveWorkItem> AcceptedJobs { get; init; } = Array.Empty<AgentActiveWorkItem>();

    /// <summary>
    /// Every capture-owned in-flight job targeted by a configured-capture stop.
    /// It is empty for older agents and commands that do not affect a job set.
    /// </summary>
    public IReadOnlyList<AgentActiveWorkItem> AffectedJobs { get; init; } = Array.Empty<AgentActiveWorkItem>();

    public DatabaseChangedNotification? DatabaseChanged { get; init; }

    public AgentHostMonitoringConfiguration? HostMonitoringConfiguration { get; init; }

    public AgentCaptureConfiguration? CaptureConfiguration { get; init; }

    public AgentConfigurationCheckResult? ConfigurationCheck { get; init; }

    public AgentMonitoringDeploymentResult? MonitoringDeployment { get; init; }

    public AgentCaptureLifecycleResult? CaptureLifecycle { get; init; }

    /// <summary>Nonce returned without health disclosure for a pairing challenge.</summary>
    public AgentPairingChallenge? PairingChallenge { get; init; }

    /// <summary>Non-secret pairing state returned after an authenticated pairing operation.</summary>
    public AgentPairingStatusSnapshot? PairingStatus { get; init; }

    public static AgentIpcResponse Ok(Guid requestId)
        => new() { RequestId = requestId, Success = true };

    public static AgentIpcResponse Failure(
        Guid requestId,
        string errorCode,
        string errorMessage,
        bool isRetryable = false)
        => new()
        {
            RequestId = requestId,
            Success = false,
            ErrorCode = errorCode,
            ErrorMessage = errorMessage,
            IsRetryable = isRetryable
        };
}

/// <summary>Compatibility projection for new multi-job and legacy single-job responses.</summary>
public static class AgentIpcResponseJobProjection
{
    public static IReadOnlyList<AgentActiveWorkItem> GetAcceptedJobs(AgentIpcResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.AcceptedJobs is { Count: > 0 })
        {
            return response.AcceptedJobs;
        }

        return FromLegacy(response);
    }

    public static IReadOnlyList<AgentActiveWorkItem> GetAffectedJobs(AgentIpcResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.AffectedJobs is { Count: > 0 })
        {
            return response.AffectedJobs;
        }

        return FromLegacy(response);
    }

    private static IReadOnlyList<AgentActiveWorkItem> FromLegacy(AgentIpcResponse response)
    {
        if (response.Job == null && !response.AcceptedJobId.HasValue)
        {
            return Array.Empty<AgentActiveWorkItem>();
        }

        var job = response.Job;
        return
        [
            new AgentActiveWorkItem
            {
                JobId = response.AcceptedJobId ?? job!.JobId,
                SourceRunId = job?.SourceRunId ?? string.Empty,
                JobKind = job?.JobKind ?? JobKind.Unknown,
                State = job?.State ?? JobState.Unknown,
                CaptureId = response.CaptureLifecycle?.CaptureId ?? string.Empty,
                Ownership = AgentJobOwnership.Unknown,
                IsCaptureScoped = response.CaptureLifecycle != null,
                UpdatedAtUtc = job?.EmittedAtUtc ?? DateTime.UtcNow
            }
        ];
    }
}

public enum AgentHostMode
{
    Unknown = 0,
    Interactive = 1,
    WindowsService = 2
}

public enum AgentHostPathScope
{
    Unknown = 0,
    SessionScopedLocalAppData = 1,
    MachineScopedProgramData = 2
}

/// <summary>
/// Bounded host-lifetime identity. This is operational metadata, not authentication
/// or authorization, and older agents omit it through the default Unknown values.
/// </summary>
public sealed record AgentHostRuntimeSnapshot
{
    public AgentHostMode Mode { get; init; } = AgentHostMode.Unknown;

    public AgentHostPathScope PathScope { get; init; } = AgentHostPathScope.Unknown;

    public string EffectiveAccountName { get; init; } = string.Empty;

    public string EffectiveAccountSid { get; init; } = string.Empty;

    public bool IsLocalSystem { get; init; }

    public string ProcessVersion { get; init; } = string.Empty;

    public string SessionRoot { get; init; } = string.Empty;

    public string DatabasePath { get; init; } = string.Empty;
}

public sealed record AgentHealthSnapshot
{
    public int ContractVersion { get; init; } = AgentContracts.ContractVersion;

    public string AgentVersion { get; init; } = string.Empty;

    public int ProcessId { get; init; }

    public string MachineName { get; init; } = string.Empty;

    public string DatabasePath { get; init; } = string.Empty;

    public string SessionId { get; init; } = string.Empty;

    public AgentHostRuntimeSnapshot Host { get; init; } = new();

    public CaptureWorkspaceMode WorkspaceMode { get; init; } = CaptureWorkspaceMode.None;

    public bool CaptureSealed { get; init; }

    public CaptureCompatibilityAssessment? CaptureCompatibility { get; init; }

    public AgentReleaseProfileSnapshot ReleaseProfile { get; init; } = new();

    /// <summary>
    /// Published built-in acquisition/analyzer metadata. Older agents omit this
    /// additive collection; archived readers never depend on adapter availability.
    /// </summary>
    public IReadOnlyList<EvidenceSourceAdapterDescriptor> EvidenceSourceAdapters { get; init; } =
        Array.Empty<EvidenceSourceAdapterDescriptor>();

    public DateTime StartedAtUtc { get; init; }

    public CaptureHealthReport CaptureHealth { get; init; } = new()
    {
        Health = ProcInsider.Models.Agent.CaptureHealth.Idle,
        Detail = "Live capture is not running."
    };

    /// <summary>
    /// Authoritative, in-memory operational state. Older agents omit this
    /// additive field, leaving <see cref="AgentControlSnapshot.IsAuthoritative"/> false.
    /// </summary>
    public AgentControlSnapshot Control { get; init; } = new();

    public int KnownJobCount { get; init; }

    public AgentRuntimeSnapshot Runtime { get; init; } = new();
}

public sealed record AgentRuntimeSnapshot
{
    public int WorkerCount { get; init; }

    public int QueueCapacity { get; init; }

    public int QueuedJobCount { get; init; }

    public int PeakQueuedJobCount { get; init; }

    public int RunningJobCount { get; init; }

    public int CompletedJobCount { get; init; }

    public int RejectedJobCount { get; init; }

    public int KnownJobCount { get; init; }

    public int MaxParallelEnrichmentJobs { get; init; }

    public int MaxParallelImportJobs { get; init; }

    public int MaxParallelProcessDumpJobs { get; init; }

    public int MaxParallelZeekJobs { get; init; }

    public int MaxParallelArtifactImportJobs { get; init; }

    public int MaxParallelVolatilityJobs { get; init; }

    public int WriterQueueCapacity { get; init; }

    public int WriterPendingWorkItemCount { get; init; }

    public int WriterPeakPendingWorkItemCount { get; init; }

    public long WriterCompletedWorkItemCount { get; init; }

    public long WriterFailedWorkItemCount { get; init; }

    public long WriterCompletedRowCount { get; init; }

    public long WriterFailedRowCount { get; init; }

    public double WriterLastQueueDelayMilliseconds { get; init; }

    public double WriterMaxQueueDelayMilliseconds { get; init; }

    public double WriterLastTransactionMilliseconds { get; init; }

    public double WriterMaxTransactionMilliseconds { get; init; }

    public long WriterLastBatchRowCount { get; init; }

    public long WriterMaxBatchRowCount { get; init; }

    public string WriterLastOperation { get; init; } = string.Empty;

    public long WriterBusyOrLockedFailureCount { get; init; }

    public string WriterLastSqliteError { get; init; } = string.Empty;

    public DateTime? WriterLastSqliteErrorUtc { get; init; }

    public int WriterMaxRowsPerTransaction { get; init; }

    public int WriterMaxBatchLatencyMilliseconds { get; init; }

    public int WriterBackpressureWarningWorkItemCount { get; init; }

    public bool WriterBackpressureActive { get; init; }

    public long WriterCheckpointWalThresholdBytes { get; init; }

    public int WriterCheckpointMinIntervalSeconds { get; init; }

    public string WriterLastCheckpointSummary { get; init; } = string.Empty;

    public DateTime? WriterLastCheckpointUtc { get; init; }

    public AgentSqliteDatabaseDiagnostics? LiveDatabaseDiagnostics { get; init; }

    public DateTime? LiveDatabaseDiagnosticsCapturedAtUtc { get; init; }

    public bool LiveDatabaseDiagnosticsCached { get; init; }

    public string LiveDatabaseDiagnosticsCacheStatus { get; init; } = string.Empty;

    public string CaptureDiagnosticsLogPath { get; init; } = string.Empty;

    public DateTime? CaptureDiagnosticsLastSampleUtc { get; init; }

    public string CaptureDiagnosticsSummary { get; init; } = string.Empty;

    public AgentArtifactEnrichmentSnapshot ArtifactEnrichment { get; init; } = new();

    public string LastError { get; init; } = string.Empty;
}

/// <summary>Per-artifact outcomes collected by the agent enrichment handlers.</summary>
public sealed record AgentArtifactEnrichmentSnapshot
{
    public long ModuleActiveCount { get; init; }
    public long ModuleAttemptCount { get; init; }
    public long ModuleCompletedCount { get; init; }
    public long ModuleRecordCount { get; init; }
    public long ModuleFailureCount { get; init; }
    public string ModuleLastError { get; init; } = string.Empty;
    public DateTime? ModuleLastCompletedUtc { get; init; }
    public long HandleActiveCount { get; init; }
    public long HandleAttemptCount { get; init; }
    public long HandleCompletedCount { get; init; }
    public long HandleRecordCount { get; init; }
    public long HandleFailureCount { get; init; }
    public string HandleLastError { get; init; } = string.Empty;
    public DateTime? HandleLastCompletedUtc { get; init; }

    /// <summary>PE process-image targets currently inside an analysis attempt.</summary>
    public long PeActiveCount { get; init; }

    /// <summary>PE targets whose analysis actually started; freshness skips are excluded.</summary>
    public long PeAttemptCount { get; init; }

    /// <summary>PE targets that produced a successful completed analysis result.</summary>
    public long PeCompletedCount { get; init; }

    /// <summary>Durable PE rows written, including rows whose analysis status is Failed.</summary>
    public long PeRecordCount { get; init; }

    /// <summary>Targets skipped before analysis because an unchanged completed row was fresh.</summary>
    public long PeFreshnessSkipCount { get; init; }

    /// <summary>Targets served from completed-cache or in-flight same-file reuse within a batch.</summary>
    public long PeReuseCount { get; init; }

    /// <summary>Targets that produced a failed PE analysis result, whether or not that row was later persisted.</summary>
    public long PeFailureCount { get; init; }

    /// <summary>Started PE targets interrupted by cancellation before producing a result.</summary>
    public long PeCancellationCount { get; init; }

    public string PeLastError { get; init; } = string.Empty;

    /// <summary>UTC time of the latest successful, failed, or cancelled PE target completion.</summary>
    public DateTime? PeLastCompletedUtc { get; init; }
}

public sealed record AgentSqliteDatabaseDiagnostics
{
    public DateTime CapturedAtUtc { get; init; } = DateTime.UtcNow;

    public string Role { get; init; } = string.Empty;

    public string DatabasePath { get; init; } = string.Empty;

    public string DiagnosticsLogPath { get; init; } = string.Empty;

    public string Profile { get; init; } = string.Empty;

    public string JournalMode { get; init; } = string.Empty;

    public string SynchronousMode { get; init; } = string.Empty;

    public int BusyTimeoutMilliseconds { get; init; }

    public int WalAutoCheckpointPages { get; init; }

    public int CacheSizePages { get; init; }

    public int TempStore { get; init; }

    public long MmapSizeBytes { get; init; }

    public long DatabaseSizeBytes { get; init; }

    public long WalSizeBytes { get; init; }

    public int PageSizeBytes { get; init; }

    public long PageCount { get; init; }

    public long FreelistCount { get; init; }

    public int LiveIndexCount { get; init; }

    public int LiveIndexExpectedCount { get; init; }

    public int AnalysisIndexCount { get; init; }

    public int AnalysisIndexExpectedCount { get; init; }

    public AgentSqliteCheckpointDiagnostics? LastCheckpoint { get; init; }

    public string Error { get; init; } = string.Empty;

    public string Summary { get; init; } = string.Empty;
}

public sealed record AgentSqliteCheckpointDiagnostics
{
    public DateTime CheckedAtUtc { get; init; } = DateTime.UtcNow;

    public string Mode { get; init; } = string.Empty;

    public bool Succeeded { get; init; }

    public int BusyFrameCount { get; init; }

    public int LogFrameCount { get; init; }

    public int CheckpointedFrameCount { get; init; }

    public double DurationMilliseconds { get; init; }

    public string Error { get; init; } = string.Empty;

    public string Summary { get; init; } = string.Empty;
}
