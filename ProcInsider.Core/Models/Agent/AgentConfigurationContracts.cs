using System;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Portable configuration document family owned by an agent and shared across the IPC boundary.
/// Unknown = 0 keeps older viewers tolerant of future target kinds.
/// </summary>
public enum AgentConfigurationTargetKind
{
    Unknown = 0,
    HostMonitoring = 1,
    Capture = 2,
}

/// <summary>
/// Lifecycle state for saved or draft agent configuration.
/// </summary>
public enum AgentConfigurationStatus
{
    Unknown = 0,
    Draft = 1,
    Saved = 2,
    Checking = 3,
    Ready = 4,
    Warning = 5,
    Blocked = 6,
    Deploying = 7,
    Deployed = 8,
    Reversing = 9,
    Reversed = 10,
    Starting = 11,
    Running = 12,
    Stopping = 13,
    Stopped = 14,
    Failed = 15,
}

public enum AgentConfigurationCheckState
{
    Unknown = 0,
    Ready = 1,
    Warning = 2,
    Blocked = 3,
}

public enum AgentConfigurationFindingSeverity
{
    Unknown = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Blocked = 4,
}

public enum AgentConfigurationAreaKind
{
    Unknown = 0,
    Sysmon = 1,
    WindowsSecurityAuditPolicy = 2,
    WindowsEventLogs = 3,
    PowerShellAuditing = 4,
    Etw = 5,
    ScheduledDumps = 6,
    RuntimeProcessSnapshots = 7,
    RuntimeEvents = 8,
    SecurityEvents = 9,
    PowerShellEvents = 10,
    WindowsOtherEvents = 11,
    SysmonEvents = 12,
    NetworkCapture = 13,
    ZeekAnalysis = 14,
    ModuleCapture = 15,
    HandleCapture = 16,
    PeMetadataCapture = 17,
    DumpMetadataCapture = 18,
    SourceHealth = 19,
    VolumeRetentionGuardrails = 20,
    HostPrivileges = 21,
    LiveDatabase = 22,
    ReverseDeployment = 23,
    ProcessCommandLineAuditing = 24,
}

public enum AgentConfigurationOperationStatus
{
    Unknown = 0,
    NotStarted = 1,
    Skipped = 2,
    Success = 3,
    Warning = 4,
    Unsupported = 5,
    Failed = 6,
}

public enum AgentMonitoringDeploymentAction
{
    Unknown = 0,
    Check = 1,
    Deploy = 2,
    Reverse = 3,
}

public enum AgentCaptureLifecycleAction
{
    Unknown = 0,
    Check = 1,
    Start = 2,
    Stop = 3,
    Pause = 4,
    Resume = 5,
}

/// <summary>
/// Shared identity and version fields for agent-owned configuration documents.
/// </summary>
public abstract record AgentConfigurationDocument
{
    public string AgentId { get; init; } = string.Empty;

    /// <summary>Optional host identity. Empty means the local/default host for the agent.</summary>
    public string HostId { get; init; } = string.Empty;

    public string ConfigurationVersion { get; init; } = string.Empty;

    public string ConfigurationHash { get; init; } = string.Empty;

    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;

    public DateTime UpdatedAtUtc { get; init; } = DateTime.UtcNow;

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Draft;

    public string LastError { get; init; } = string.Empty;
}

/// <summary>
/// Settings that prepare or alter host monitoring prerequisites. Saving or deploying this
/// configuration must not start capture.
/// </summary>
public sealed record AgentHostMonitoringConfiguration : AgentConfigurationDocument
{
    public AgentSysmonMonitoringIntent Sysmon { get; init; } = new();

    public AgentSecurityAuditMonitoringIntent SecurityAuditPolicy { get; init; } = new();

    public AgentEventLogMonitoringIntent EventLogs { get; init; } = new();

    public AgentPowerShellMonitoringIntent PowerShellAuditing { get; init; } = new();

    public AgentEtwMonitoringIntent Etw { get; init; } = new();

    public AgentScheduledDumpPolicy ScheduledDumps { get; init; } = new();

    public AgentMonitoringDeploymentMetadata Deployment { get; init; } = new();

    public AgentReverseDeploymentMetadata ReverseDeployment { get; init; } = new();

    public AgentMonitoringOriginalStateSnapshot OriginalState { get; init; } = new();
}

public sealed record AgentSysmonMonitoringIntent
{
    public bool InstallOrUpdate { get; init; }

    public bool VerifyService { get; init; } = true;

    public string ProfileId { get; init; } = string.Empty;

    public string ProfileDisplayName { get; init; } = string.Empty;

    public string ConfigurationPath { get; init; } = string.Empty;

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentSecurityAuditMonitoringIntent
{
    public bool ConfigureAuditPolicy { get; init; }

    public bool EnableProcessCommandLineLogging { get; init; }

    public string PolicyProfileId { get; init; } = string.Empty;

    public string PolicyProfileDisplayName { get; init; } = string.Empty;

    public string AuditPolicyPath { get; init; } = string.Empty;

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentEventLogMonitoringIntent
{
    public bool ConfigureChannels { get; init; }

    public bool ConfigureRetention { get; init; }

    public string ProfileId { get; init; } = string.Empty;

    public string ProfileDisplayName { get; init; } = string.Empty;

    public string[] ChannelNames { get; init; } = Array.Empty<string>();

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentPowerShellMonitoringIntent
{
    public bool EnableScriptBlockLogging { get; init; }

    public bool EnableModuleLogging { get; init; }

    public bool EnableTranscription { get; init; }

    public string ProfileId { get; init; } = string.Empty;

    public string TranscriptDirectory { get; init; } = string.Empty;

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentEtwMonitoringIntent
{
    public bool ConfigureSession { get; init; }

    public string ProfileId { get; init; } = string.Empty;

    public string ProfileDisplayName { get; init; } = string.Empty;

    public string ProfilePath { get; init; } = string.Empty;

    public string SessionName { get; init; } = string.Empty;

    public string[] ProviderNames { get; init; } = Array.Empty<string>();

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentScheduledDumpPolicy
{
    public bool Enabled { get; init; }

    public int IntervalSeconds { get; init; }

    /// <summary>Comma-delimited offsets from capture start, such as "30s,2m,10m".</summary>
    public string OffsetsFromCaptureStart { get; init; } = string.Empty;

    public string TargetPolicy { get; init; } = string.Empty;

    public string OutputDirectory { get; init; } = string.Empty;

    public int MaxDumpsPerCapture { get; init; }

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentMonitoringDeploymentMetadata
{
    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;

    public DateTime? LastCheckedUtc { get; init; }

    public DateTime? LastDeployedUtc { get; init; }

    public DateTime? LastDriftCheckedUtc { get; init; }

    public string DriftSummary { get; init; } = string.Empty;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentReverseDeploymentMetadata
{
    public bool SupportsReverseDeployment { get; init; }

    public bool CanRemoveSysmon { get; init; }

    public bool CanRestoreAuditPolicy { get; init; }

    public bool CanRestorePowerShellAuditing { get; init; }

    public bool CanRestoreEventLogs { get; init; }

    public bool CanStopEtwSessions { get; init; }

    public DateTime? LastReversedUtc { get; init; }

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;

    public string[] Warnings { get; init; } = Array.Empty<string>();

    public string ManualCleanupGuidance { get; init; } = string.Empty;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentMonitoringOriginalStateSnapshot
{
    public bool BaselineExists { get; init; }

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string ConfigurationHash { get; init; } = string.Empty;

    public DateTime? CapturedAtUtc { get; init; }

    public DateTime? LastRevertedUtc { get; init; }

    public AgentConfigurationOperationStatus LastRevertStatus { get; init; } = AgentConfigurationOperationStatus.Unknown;

    public string Summary { get; init; } = "No original host monitoring state has been captured.";

    public AgentMonitoringOriginalStateArea[] Areas { get; init; } = Array.Empty<AgentMonitoringOriginalStateArea>();
}

public sealed record AgentMonitoringOriginalStateArea
{
    public AgentConfigurationAreaKind Area { get; init; }

    public AgentConfigurationOperationStatus Status { get; init; } = AgentConfigurationOperationStatus.Unknown;

    public bool RestoreSupported { get; init; }

    public string Summary { get; init; } = string.Empty;

    public string Detail { get; init; } = string.Empty;

    public string RestoreGuidance { get; init; } = string.Empty;
}

/// <summary>
/// Settings that decide what the agent writes into the live evidence database.
/// Saving or starting this configuration must not deploy host monitoring settings.
/// </summary>
public sealed record AgentCaptureConfiguration : AgentConfigurationDocument
{
    public AgentRuntimeSnapshotCapturePolicy RuntimeProcessSnapshots { get; init; } = new();

    public AgentCaptureSourceToggles SourceToggles { get; init; } = new();

    public AgentEtwMonitoringIntent Etw { get; init; } = new();

    public AgentNetworkCaptureMetadataPolicy NetworkCapture { get; init; } = new();

    public AgentZeekAnalysisImportPolicy Zeek { get; init; } = new();

    public AgentArtifactCapturePolicy ArtifactCapture { get; init; } = new();

    public AgentSourceHealthPolicy SourceHealth { get; init; } = new();

    public AgentVolumeRetentionGuardrailPolicy Guardrails { get; init; } = new();
}

public sealed record AgentRuntimeSnapshotCapturePolicy
{
    public bool Enabled { get; init; } = true;

    public int RefreshIntervalSeconds { get; init; } = 10;

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentCaptureSourceToggles
{
    public bool Runtime { get; init; } = true;

    public bool Etw { get; init; } = true;

    public bool Security { get; init; } = true;

    public bool PowerShell { get; init; } = true;

    public bool WindowsOther { get; init; } = true;

    public bool Sysmon { get; init; } = true;
}

public sealed record AgentNetworkCaptureMetadataPolicy
{
    public bool Enabled { get; init; }

    public bool RecordMetadataOnly { get; init; } = true;

    public string ToolPreference { get; init; } = string.Empty;

    public string FilterDescription { get; init; } = string.Empty;

    public int SegmentSeconds { get; init; }

    public long MaxSegmentBytes { get; init; }

    public string OutputDirectory { get; init; } = string.Empty;

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;
}

public sealed record AgentZeekAnalysisImportPolicy
{
    public bool Enabled { get; init; }

    public bool RunAfterNetworkCapture { get; init; }

    public bool ImportLogs { get; init; } = true;

    public string ZeekPath { get; init; } = string.Empty;

    public string WslDistributionName { get; init; } = string.Empty;

    public string WslZeekCommand { get; init; } = string.Empty;

    public string OutputDirectory { get; init; } = string.Empty;

    public string[] LogTypes { get; init; } = Array.Empty<string>();

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;
}

public sealed record AgentArtifactCapturePolicy
{
    public bool CaptureModules { get; init; } = true;

    public bool CaptureHandles { get; init; } = true;

    /// <summary>
    /// Enables safe deferred PE metadata analysis for staged process images. The false initializer is
    /// the compatibility default for saved configurations created before this field existed; new UI
    /// and agent-created drafts set it to true explicitly.
    /// </summary>
    public bool CapturePeMetadata { get; init; }

    public bool CaptureDumpMetadata { get; init; }

    public int RefreshIntervalSeconds { get; init; }

    public string ScopePolicy { get; init; } = string.Empty;

    public AgentConfigurationStatus Status { get; init; } = AgentConfigurationStatus.Unknown;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentSourceHealthPolicy
{
    public bool TrackSourceHealth { get; init; } = true;

    public bool PersistHealthSnapshots { get; init; } = true;

    public int WarningAfterDroppedEvents { get; init; }

    public int WarningAfterSourceSilenceSeconds { get; init; }

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentVolumeRetentionGuardrailPolicy
{
    public bool Enabled { get; init; } = true;

    public int MaxEventsPerSecondWarning { get; init; }

    public long MaxLiveDatabaseBytesWarning { get; init; }

    public int RetentionDaysPlaceholder { get; init; }

    public string RetentionPolicyPlaceholder { get; init; } = string.Empty;

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentConfigurationFinding
{
    public AgentConfigurationAreaKind Area { get; init; }

    public AgentConfigurationFindingSeverity Severity { get; init; }

    public string Message { get; init; } = string.Empty;

    public string TechnicalDetail { get; init; } = string.Empty;

    public string SuggestedRemediation { get; init; } = string.Empty;
}

public sealed record AgentConfigurationCheckResult
{
    public AgentConfigurationTargetKind TargetKind { get; init; }

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string ConfigurationVersion { get; init; } = string.Empty;

    public string ConfigurationHash { get; init; } = string.Empty;

    public DateTime CheckedAtUtc { get; init; } = DateTime.UtcNow;

    public AgentConfigurationCheckState OverallState { get; init; } = AgentConfigurationCheckState.Unknown;

    public AgentConfigurationFinding[] Findings { get; init; } = Array.Empty<AgentConfigurationFinding>();

    public string LastError { get; init; } = string.Empty;
}

public sealed record AgentMonitoringDeploymentAreaResult
{
    public AgentConfigurationAreaKind Area { get; init; }

    public AgentConfigurationOperationStatus Status { get; init; }

    public bool ReverseSupported { get; init; }

    public string Message { get; init; } = string.Empty;

    public string TechnicalDetail { get; init; } = string.Empty;
}

public sealed record AgentMonitoringDeploymentResult
{
    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string ConfigurationVersion { get; init; } = string.Empty;

    public string ConfigurationHash { get; init; } = string.Empty;

    public AgentMonitoringDeploymentAction Action { get; init; }

    public DateTime StartedAtUtc { get; init; } = DateTime.UtcNow;

    public DateTime? CompletedAtUtc { get; init; }

    public AgentConfigurationOperationStatus Status { get; init; } = AgentConfigurationOperationStatus.Unknown;

    public AgentMonitoringDeploymentAreaResult[] AreaResults { get; init; } = Array.Empty<AgentMonitoringDeploymentAreaResult>();

    public string[] Warnings { get; init; } = Array.Empty<string>();

    public string LastError { get; init; } = string.Empty;

    public AgentMonitoringOriginalStateSnapshot OriginalState { get; init; } = new();
}

public sealed record AgentCaptureLifecycleResult
{
    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string CaptureId { get; init; } = string.Empty;

    public string ConfigurationVersion { get; init; } = string.Empty;

    public string ConfigurationHash { get; init; } = string.Empty;

    public AgentCaptureLifecycleAction Action { get; init; }

    public DateTime StartedAtUtc { get; init; } = DateTime.UtcNow;

    public DateTime? CompletedAtUtc { get; init; }

    public AgentConfigurationOperationStatus Status { get; init; } = AgentConfigurationOperationStatus.Unknown;

    public string Message { get; init; } = string.Empty;

    public string LastError { get; init; } = string.Empty;
}
