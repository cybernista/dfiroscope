using System;
using ProcInsider.Models;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Base type for all viewer-to-agent command messages.
/// Subclasses carry per-command parameters.
/// The <see cref="Kind"/> property is the JSON discriminator.
/// </summary>
public abstract record AgentCommand
{
    /// <summary>
    /// Discriminator for JSON deserialization.
    /// Must match the concrete command type.
    /// </summary>
    public abstract AgentCommandKind Kind { get; }

    /// <summary>
    /// Unique identifier assigned by the viewer for correlating status updates
    /// back to a specific command invocation.
    /// </summary>
    public Guid CommandId { get; init; } = Guid.NewGuid();

    /// <summary>UTC timestamp when the viewer issued the command.</summary>
    public DateTime IssuedAtUtc { get; init; } = DateTime.UtcNow;

    /// <summary>Session identity the viewer had active when it issued this command.</summary>
    public string TargetSessionId { get; init; } = string.Empty;

    /// <summary>Normalized evidence database the command is permitted to affect.</summary>
    public string TargetDatabasePath { get; init; } = string.Empty;

    /// <summary>Workspace mode used for the viewer-side policy decision.</summary>
    public CaptureWorkspaceMode TargetWorkspaceMode { get; init; } = CaptureWorkspaceMode.None;

    /// <summary>
    /// Explicit requested write category. The agent recomputes this from
    /// <see cref="Kind"/> and rejects a mismatch before queueing work.
    /// </summary>
    public CaptureWriteCategory RequestedWriteCategory { get; init; } = CaptureWriteCategory.Unspecified;
}

/// <summary>
/// Instructs the agent to begin live process and event capture.
/// </summary>
public sealed record StartLiveCaptureCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StartLiveCapture;

    /// <summary>Stable capture identity stamped onto evidence rows produced by this job.</summary>
    public string CaptureId { get; init; } = string.Empty;

    /// <summary>Interval, in seconds, for agent-owned full process snapshots.</summary>
    public int ProcessRefreshIntervalSeconds { get; init; } = 10;

    /// <summary>Selected ETW profile identifier from the bundled profile manifest.</summary>
    public string EtwProfileId { get; init; } = string.Empty;

    /// <summary>Display name for status and diagnostics.</summary>
    public string EtwProfileDisplayName { get; init; } = string.Empty;

    /// <summary>Resolved ETW profile JSON path. Empty means the agent should use its default bundled profile.</summary>
    public string EtwProfilePath { get; init; } = string.Empty;

    /// <summary>Whether the agent should stage runtime process snapshots and deltas.</summary>
    public bool CollectRuntimeEvents { get; init; } = true;

    /// <summary>Whether the agent should start the configured ETW profile source.</summary>
    public bool CollectEtwEvents { get; init; } = true;

    /// <summary>Whether the agent should watch the Windows Security event log.</summary>
    public bool CollectSecurityEvents { get; init; } = true;

    /// <summary>Whether the agent should watch PowerShell event logs and transcript files.</summary>
    public bool CollectPowerShellEvents { get; init; } = true;

    /// <summary>Whether the agent should watch supported non-Security Windows operational logs.</summary>
    public bool CollectOtherWindowsEvents { get; init; } = true;

    /// <summary>Whether the agent should watch the Sysmon operational log when available.</summary>
    public bool CollectSysmonEvents { get; init; } = true;
}

/// <summary>
/// Instructs the agent to stop live capture without discarding staged data.
/// </summary>
public sealed record StopLiveCaptureCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StopLiveCapture;
}

/// <summary>Pauses the exact active configured capture without ending its jobs or provenance.</summary>
public sealed record PauseJobCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.PauseJob;

    public Guid JobId { get; init; }

    public string CaptureId { get; init; } = string.Empty;

    public string Reason { get; init; } = string.Empty;
}

/// <summary>Resumes the exact paused configured capture under the same jobs and provenance.</summary>
public sealed record ResumeJobCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.ResumeJob;

    public Guid JobId { get; init; }

    public string CaptureId { get; init; } = string.Empty;
}

/// <summary>Stops only the configurable ETW collector within an active live-capture job.</summary>
public sealed record StopEtwCaptureCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StopEtwCapture;
}

/// <summary>
/// Stops one source in an active live-capture job without stopping the other collectors.
/// Supported sources are Runtime, ETW, Security, PowerShell, WindowsOther, and Sysmon.
/// </summary>
public sealed record StopLiveCaptureSourceCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StopLiveCaptureSource;

    public string Source { get; init; } = string.Empty;
}

/// <summary>
/// Restarts one source that was explicitly stopped within an active live-capture job.
/// Supported sources are Runtime, ETW, Security, PowerShell, WindowsOther, and Sysmon.
/// </summary>
public sealed record StartLiveCaptureSourceCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StartLiveCaptureSource;

    public string Source { get; init; } = string.Empty;
}

/// <summary>
/// Queues an enrichment job that captures modules, handles, or both
/// for the nominated processes.
/// </summary>
public sealed record QueueEnrichmentCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.QueueEnrichment;

    /// <summary>
    /// Explicit opt-in to enrich all known live processes. This must be false when
    /// either exact target array is populated.
    /// </summary>
    public bool AllProcesses { get; init; }

    /// <summary>
    /// One or more <c>ProcessKey</c> values to enrich.
    /// Empty or null is valid only when <see cref="AllProcesses"/> is true or durable
    /// process entity identities are supplied.
    /// </summary>
    public string[]? ProcessKeys { get; init; }

    /// <summary>
    /// Durable process entity identities to enrich. New schedulers prefer these;
    /// ProcessKeys remains an additive compatibility selector.
    /// </summary>
    public string[]? ProcessEntityIds { get; init; }

    /// <summary>Whether to capture loaded modules.</summary>
    public bool CaptureModules { get; init; } = true;

    /// <summary>Whether to capture open handles.</summary>
    public bool CaptureHandles { get; init; } = true;

    /// <summary>Whether to parse bounded PE metadata for the process image.</summary>
    public bool CapturePe { get; init; }

    /// <summary>Whether bounded printable-string extraction runs immediately or remains deferred.</summary>
    public PeStringExtractionMode PeStringExtractionMode { get; init; } = PeStringExtractionMode.Deferred;
}

/// <summary>
/// Queues metadata and future execution work for a process memory dump.
/// The process target is identified by ProcessKey, never PID alone.
/// </summary>
public sealed record QueueProcessDumpCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.QueueProcessDump;

    /// <summary><c>ProcessKey</c> value (<c>"{PID}_{StartTimeTicks}"</c>) for the target process.</summary>
    public string ProcessKey { get; init; } = string.Empty;

    /// <summary>Requested dump shape. Execution is implemented by a later phase.</summary>
    public MemoryDumpKind DumpKind { get; init; } = MemoryDumpKind.Full;

    /// <summary>Optional directory where a future dump file should be written.</summary>
    public string OutputDirectory { get; init; } = string.Empty;

    /// <summary>Whether a future executor may replace an existing dump file.</summary>
    public bool OverwriteExisting { get; init; }
}

/// <summary>
/// Starts a long-running local network capture job. Packet bytes are written
/// to external ETL/PCAPNG segment files; staging stores metadata and file paths only.
/// </summary>
public sealed record StartNetworkCaptureCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StartNetworkCapture;

    /// <summary>Optional directory for ETL and PCAPNG capture segment files.</summary>
    public string OutputDirectory { get; init; } = string.Empty;
}

/// <summary>
/// Stops the active local network capture job and finalizes its current segment.
/// </summary>
public sealed record StopNetworkCaptureCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StopNetworkCapture;
}

/// <summary>
/// Queues Zeek processing for a staged PCAP/PCAPNG capture segment.
/// Zeek output is imported as metadata and raw identity; packet bytes remain on disk.
/// </summary>
public sealed record QueueZeekAnalysisCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.QueueZeekAnalysis;

    /// <summary>Capture segment id from <see cref="NetworkCaptureRecord.CaptureId"/>.</summary>
    public string CaptureId { get; init; } = string.Empty;

    /// <summary>Optional PCAP/PCAPNG path. When empty, the agent resolves it from staging.</summary>
    public string PcapPath { get; init; } = string.Empty;

    /// <summary>Optional native Windows Zeek executable path.</summary>
    public string ZeekPath { get; init; } = string.Empty;

    /// <summary>Optional WSL distribution name, such as Ubuntu or Ubuntu-22.04.</summary>
    public string WslDistributionName { get; init; } = string.Empty;

    /// <summary>Optional Zeek command or absolute path inside WSL. Defaults to zeek.</summary>
    public string WslZeekCommand { get; init; } = string.Empty;

    /// <summary>Optional directory where Zeek logs should be written.</summary>
    public string OutputDirectory { get; init; } = string.Empty;
}

/// <summary>
/// Queues filesystem artifact loading for NTFS metadata files and Prefetch files.
/// Source evidence files are read-only; staging stores metadata, raw identity, and bounded samples.
/// </summary>
public sealed record QueueArtifactImportCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.QueueArtifactImport;

    /// <summary>File or folder path containing NTFS or Prefetch artifacts.</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Whether folder imports should traverse child directories.</summary>
    public bool Recurse { get; init; } = true;

    /// <summary>Whether to include NTFS artifacts such as $MFT, $UsnJrnl, and $LogFile.</summary>
    public bool IncludeNtfs { get; init; } = true;

    /// <summary>Whether to include Windows Prefetch .pf artifacts.</summary>
    public bool IncludePrefetch { get; init; } = true;

    /// <summary>Upper bound for files loaded by one queued job.</summary>
    public int MaxFiles { get; init; } = 10000;
}

/// <summary>
/// Starts a local Sysinternals Process Monitor capture using Procmon.exe.
/// The native PML and exported CSV stay as session files; imported rows are
/// normalized into process/event evidence when the capture is stopped.
/// </summary>
public sealed record StartProcessMonitorCaptureCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StartProcessMonitorCapture;

    /// <summary>Optional explicit path to Procmon.exe or Procmon64.exe.</summary>
    public string ProcmonPath { get; init; } = string.Empty;

    /// <summary>Stable capture identity stamped onto imported Procmon evidence rows.</summary>
    public string CaptureId { get; init; } = string.Empty;

    /// <summary>Optional directory for PML, CSV, and diagnostic transcript files.</summary>
    public string OutputDirectory { get; init; } = string.Empty;

    /// <summary>Optional explicit native Process Monitor backing file path.</summary>
    public string BackingFilePath { get; init; } = string.Empty;

    /// <summary>Optional explicit CSV export path used during stop/finalize.</summary>
    public string CsvOutputPath { get; init; } = string.Empty;

    /// <summary>Whether to pass /AcceptEula to Procmon. Defaults to true for unattended analyst-initiated captures.</summary>
    public bool AcceptEula { get; init; } = true;

    /// <summary>Upper bound for rows imported after stop/finalize.</summary>
    public int MaxRows { get; init; } = 200000;
}

/// <summary>
/// Stops the active Procmon capture job and asks the handler to export/import
/// the generated Process Monitor output.
/// </summary>
public sealed record StopProcessMonitorCaptureCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StopProcessMonitorCapture;

    /// <summary>Optional explicit path to Procmon.exe or Procmon64.exe for the /Terminate call.</summary>
    public string ProcmonPath { get; init; } = string.Empty;
}

/// <summary>
/// Imports an existing Process Monitor CSV or PML file into process/event
/// staging. PML input requires a local Procmon executable for CSV export.
/// </summary>
public sealed record QueueProcessMonitorImportCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.QueueProcessMonitorImport;

    /// <summary>Path to a Procmon CSV export or native PML log.</summary>
    public string InputPath { get; init; } = string.Empty;

    /// <summary>Optional explicit path to Procmon.exe or Procmon64.exe for PML-to-CSV export.</summary>
    public string ProcmonPath { get; init; } = string.Empty;

    /// <summary>Stable capture identity stamped onto imported Procmon evidence rows.</summary>
    public string CaptureId { get; init; } = string.Empty;

    /// <summary>Optional directory for generated CSV and diagnostic transcript files.</summary>
    public string OutputDirectory { get; init; } = string.Empty;

    /// <summary>Upper bound for rows imported by one queued job.</summary>
    public int MaxRows { get; init; } = 200000;
}

/// <summary>
/// Queues an isolated agent-owned SQLite write-throughput benchmark.
/// Benchmark rows are written only to a benchmark database under the active
/// session and must never be mixed into the live evidence database.
/// </summary>
public sealed record QueueSqliteBenchmarkCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.QueueSqliteBenchmark;

    /// <summary>Seconds to spend in each synthetic workload phase.</summary>
    public int PhaseDurationSeconds { get; init; } = 5;

    /// <summary>Maximum number of workload phases to run.</summary>
    public int MaxPhaseCount { get; init; } = 4;

    /// <summary>Initial process records per batch. Later phases scale this upward.</summary>
    public int InitialProcessBatchSize { get; init; } = 50;

    /// <summary>Initial event records per process. Later phases scale this upward.</summary>
    public int InitialEventsPerProcess { get; init; } = 2;

    /// <summary>Maximum concurrent benchmark write batches awaiting the serialized writer.</summary>
    public int MaxInFlightBatches { get; init; } = 8;

    /// <summary>Writer pending-work-item threshold that marks the benchmark saturated/degraded.</summary>
    public int MaxPendingWriterWorkItems { get; init; } = 1024;

    /// <summary>Progress report interval in milliseconds.</summary>
    public int ProgressIntervalMilliseconds { get; init; } = 1000;
}

/// <summary>
/// Queues read-only import of an analyst-provided full system memory image.
/// Large image bytes stay on disk; SQLite stores metadata, hashes, and provenance only.
/// </summary>
public sealed record QueueMemoryImageImportCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.QueueMemoryImageImport;

    /// <summary>Absolute or environment-expanded path to a .raw, .mem, .dmp, .vmem, or similar memory image.</summary>
    public string ImagePath { get; init; } = string.Empty;

    /// <summary>Optional analyst display name for the imported image.</summary>
    public string DisplayName { get; init; } = string.Empty;

    /// <summary>Optional acquisition/import host identity supplied by the analyst.</summary>
    public string HostName { get; init; } = string.Empty;

    /// <summary>Optional source OS/build metadata supplied by the analyst.</summary>
    public string OsBuild { get; init; } = string.Empty;

    /// <summary>Tool used to acquire or provide the image. Import-only default is analyst provided.</summary>
    public string AcquisitionTool { get; init; } = "Analyst import";

    /// <summary>Optional tool version string.</summary>
    public string AcquisitionToolVersion { get; init; } = string.Empty;

    /// <summary>Optional acquisition command line/provenance note.</summary>
    public string AcquisitionCommandLine { get; init; } = string.Empty;

    /// <summary>Optional privilege/elevation note at acquisition/import time.</summary>
    public string PrivilegeState { get; init; } = string.Empty;
}

/// <summary>
/// Queues full-system-memory acquisition in the elevated agent. The agent resolves the explicitly
/// configured trusted tool and allocates the output beneath the active session memory directory.
/// </summary>
public sealed record QueueMemoryAcquisitionCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.QueueMemoryAcquisition;

    /// <summary>
    /// Optional leaf file name used for deterministic/manual validation. Empty selects a unique
    /// agent-generated name. Directory separators and rooted paths are rejected.
    /// </summary>
    public string RequestedOutputFileName { get; init; } = string.Empty;

    /// <summary>Bounded acquisition timeout in seconds.</summary>
    public int TimeoutSeconds { get; init; } = 1800;
}

/// <summary>
/// Queues Volatility 3 plugin execution for a staged full system memory image.
/// Raw output is preserved as sidecar files and normalized rows are written to SQLite.
/// </summary>
public sealed record QueueVolatilityAnalysisCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.QueueVolatilityAnalysis;

    /// <summary>Memory image id from <c>MemoryImageRecord.ImageId</c>.</summary>
    public string ImageId { get; init; } = string.Empty;

    /// <summary>Optional explicit image path. When empty, the agent resolves it from staging.</summary>
    public string ImagePath { get; init; } = string.Empty;

    /// <summary>Volatility plugin names to run. Empty means the initial process-oriented defaults.</summary>
    public string[]? PluginNames { get; init; }

    /// <summary>Optional output directory for raw stdout/stderr sidecars.</summary>
    public string OutputDirectory { get; init; } = string.Empty;

    /// <summary>Per-plugin timeout in seconds.</summary>
    public int TimeoutSeconds { get; init; } = 600;
}

/// <summary>
/// Requests graceful shutdown of the foreground local agent.
/// The viewer only sends this after matching the agent health database path
/// to the active session so unrelated agents are left alone.
/// </summary>
public sealed record ShutdownAgentCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.ShutdownAgent;

    /// <summary>Human-readable reason for diagnostics.</summary>
    public string Reason { get; init; } = string.Empty;

    /// <summary>
    /// Optional active-session database path the viewer verified before shutdown.
    /// The agent refuses shutdown when this does not match its own database path.
    /// </summary>
    public string ExpectedDatabasePath { get; init; } = string.Empty;
}

/// <summary>
/// Requests cancellation of a running or queued job.
/// </summary>
public sealed record CancelJobCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.CancelJob;

    /// <summary>Identifier of the job to cancel, from <see cref="JobProgress.JobId"/>.</summary>
    public Guid JobId { get; init; }
}
