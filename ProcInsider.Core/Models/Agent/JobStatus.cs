namespace ProcInsider.Models.Agent;

/// <summary>
/// Portable lifecycle state of a job managed by the agent.
/// Unknown = 0 is intentional so callers tolerate future values
/// received from a newer agent version.
/// </summary>
public enum JobState
{
    Unknown = 0,

    /// <summary>Job is queued and waiting to be started.</summary>
    Queued = 1,

    /// <summary>Job has been started and is actively running.</summary>
    Running = 2,

    /// <summary>Job has been suspended at a safe checkpoint and can be resumed.</summary>
    Paused = 3,

    /// <summary>Job completed successfully.</summary>
    Completed = 4,

    /// <summary>Job was cancelled before completion.</summary>
    Cancelled = 5,

    /// <summary>Job terminated with an unrecoverable error.</summary>
    Failed = 6,
}

/// <summary>
/// Coarse health of the agent's live capture pipeline.
/// Unknown = 0 is intentional for forward-compatibility.
/// </summary>
public enum CaptureHealth
{
    Unknown = 0,

    /// <summary>Live capture is not running.</summary>
    Idle = 1,

    /// <summary>Live capture is running and receiving data.</summary>
    Healthy = 2,

    /// <summary>
    /// Live capture is running but has encountered a non-fatal issue
    /// (e.g., a provider reported event loss or access was denied for one source).
    /// </summary>
    Degraded = 3,

    /// <summary>
    /// Live capture failed to start or has stopped unexpectedly.
    /// Viewer should surface an error and allow the user to restart capture.
    /// </summary>
    Error = 4,
}

/// <summary>
/// Durable readiness of the current live-capture run's first complete runtime
/// process inventory. Unknown = 0 lets a newer Viewer degrade safely when an
/// older Agent omits this additive health field.
/// </summary>
public enum InitialProcessInventoryState
{
    Unknown = 0,

    /// <summary>The configured capture does not collect runtime processes.</summary>
    NotExpected = 1,

    /// <summary>The Agent is collecting or committing the first full process snapshot.</summary>
    Pending = 2,

    /// <summary>The first full runtime process snapshot committed successfully.</summary>
    Ready = 3,
}

/// <summary>
/// Category of work a job performs.
/// Unknown = 0 is intentional for forward-compatibility.
/// </summary>
public enum JobKind
{
    Unknown = 0,
    LiveCapture = 1,
    /// <summary>
    /// Reserved historical failed-backfill job identity. Current agents never
    /// create this job kind; value 2 remains readable and is never reused.
    /// </summary>
    Backfill = 2,
    Import = 3,
    ModuleEnrichment = 4,
    HandleEnrichment = 5,
    ProcessDump = 6,
    NetworkCapture = 7,
    ZeekAnalysis = 8,
    ArtifactImport = 9,
    MemoryImageImport = 10,
    VolatilityAnalysis = 11,
    ProcessMonitorCapture = 12,
    ProcessMonitorImport = 13,
    SqliteBenchmark = 14,
    PeAnalysis = 15,
    MemoryAcquisition = 16,
}
