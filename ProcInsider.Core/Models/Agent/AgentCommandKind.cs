namespace ProcInsider.Models.Agent;

/// <summary>
/// Discriminator for viewer-to-agent command messages.
/// Used as a JSON discriminator field so the agent can deserialize
/// commands without requiring .NET-specific polymorphism support.
/// </summary>
public enum AgentCommandKind
{
    Unknown = 0,
    StartLiveCapture = 1,
    StopLiveCapture = 2,
    /// <summary>
    /// Reserved historical event-log backfill discriminator. Current agents
    /// reject it without queue or evidence side effects; value 3 is never reused.
    /// </summary>
    QueueBackfill = 3,
    QueueImport = 4,
    QueueEnrichment = 5,
    CancelJob = 6,
    /// <summary>
    /// Reserved historical pause discriminator. Current agents reject it
    /// without queue, job-state, resource, or evidence side effects; value 7
    /// is never reused.
    /// </summary>
    PauseJob = 7,
    /// <summary>
    /// Reserved historical resume discriminator. Current agents reject it
    /// without queue, job-state, resource, or evidence side effects; value 8
    /// is never reused.
    /// </summary>
    ResumeJob = 8,
    QueueProcessDump = 9,
    StartNetworkCapture = 10,
    StopNetworkCapture = 11,
    QueueZeekAnalysis = 12,
    QueueArtifactImport = 13,
    ShutdownAgent = 14,
    QueueMemoryImageImport = 15,
    QueueVolatilityAnalysis = 16,
    GetHostMonitoringConfiguration = 17,
    SaveHostMonitoringConfiguration = 18,
    CheckHostMonitoringConfiguration = 19,
    DeployHostMonitoringConfiguration = 20,
    ReverseHostMonitoringDeployment = 21,
    GetCaptureConfiguration = 22,
    SaveCaptureConfiguration = 23,
    CheckCaptureConfiguration = 24,
    StartConfiguredCapture = 25,
    StopConfiguredCapture = 26,
    StartProcessMonitorCapture = 27,
    StopProcessMonitorCapture = 28,
    QueueProcessMonitorImport = 29,
    QueueSqliteBenchmark = 30,
    StopEtwCapture = 31,
    StopLiveCaptureSource = 32,
    StartLiveCaptureSource = 33,
    QueueMemoryAcquisition = 34,
}
