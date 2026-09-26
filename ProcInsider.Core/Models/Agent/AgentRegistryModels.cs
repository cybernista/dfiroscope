using System;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Portable transport identity used to reach a configured DFIRoscope Live agent.
/// Unknown = 0 keeps older viewers tolerant of future transports.
/// </summary>
public enum AgentTransportKind
{
    Unknown = 0,
    LocalNamedPipe = 1,
    RemoteHttp = 2,
    RemoteNamedPipe = 3,
}

/// <summary>
/// Capability flags advertised or assumed for a configured agent.
/// </summary>
[Flags]
public enum AgentCapabilityFlags
{
    Unknown = 0,
    LocalIpc = 1 << 0,
    Health = 1 << 1,
    LiveCapture = 1 << 2,
    ArtifactEnrichment = 1 << 3,
    ProcessDump = 1 << 4,
    NetworkCapture = 1 << 5,
    ZeekAnalysis = 1 << 6,
    FilesystemArtifactImport = 1 << 7,
    MemoryImageImport = 1 << 8,
    VolatilityAnalysis = 1 << 9,
    MonitoringConfiguration = 1 << 10,
    CaptureConfiguration = 1 << 11,
    ProcessMonitor = 1 << 12,
    PeAnalysis = 1 << 13,
    MemoryAcquisition = 1 << 14,
}

/// <summary>
/// High-level deployment/configuration state for an agent.
/// </summary>
public enum AgentDeploymentState
{
    Unknown = 0,
    NotConfigured = 1,
    Available = 2,
    Unavailable = 3,
    Deployed = 4,
    Failed = 5,
}

/// <summary>
/// High-level capture state shown in the viewer's agent registry.
/// </summary>
public enum AgentCaptureState
{
    Unknown = 0,
    Idle = 1,
    Healthy = 2,
    Degraded = 3,
    Error = 4,
}

/// <summary>
/// Future-ready configured-agent registry entry. The first supported entry is
/// the local named-pipe agent; remote transports can reuse this shape later.
/// </summary>
public sealed record AgentRegistryEntry
{
    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public AgentTransportKind TransportKind { get; init; }

    public string Endpoint { get; init; } = string.Empty;

    public AgentCapabilityFlags Capabilities { get; init; } = AgentCapabilityFlags.Unknown;

    public string ConfigurationVersion { get; init; } = string.Empty;

    public string ConfigurationHash { get; init; } = string.Empty;

    public AgentDeploymentState DeploymentState { get; init; } = AgentDeploymentState.Unknown;

    public AgentCaptureState CaptureState { get; init; } = AgentCaptureState.Unknown;

    public DateTime? LastCheckUtc { get; init; }

    public string LastError { get; init; } = string.Empty;

    public static AgentRegistryEntry CreateLocal()
    {
        return new AgentRegistryEntry
        {
            AgentId = "local",
            HostId = Environment.MachineName,
            DisplayName = "Local Agent",
            TransportKind = AgentTransportKind.LocalNamedPipe,
            Endpoint = AgentContracts.PipeName,
            Capabilities =
                AgentCapabilityFlags.LocalIpc |
                AgentCapabilityFlags.Health |
                AgentCapabilityFlags.LiveCapture |
                AgentCapabilityFlags.ArtifactEnrichment |
                AgentCapabilityFlags.ProcessDump |
                AgentCapabilityFlags.NetworkCapture |
                AgentCapabilityFlags.ZeekAnalysis |
                AgentCapabilityFlags.FilesystemArtifactImport |
                AgentCapabilityFlags.MemoryImageImport |
                AgentCapabilityFlags.MemoryAcquisition |
                AgentCapabilityFlags.VolatilityAnalysis |
                AgentCapabilityFlags.MonitoringConfiguration |
                AgentCapabilityFlags.CaptureConfiguration |
                AgentCapabilityFlags.ProcessMonitor |
                AgentCapabilityFlags.PeAnalysis,
            ConfigurationVersion = "pending",
            ConfigurationHash = "pending",
            DeploymentState = AgentDeploymentState.NotConfigured,
            CaptureState = AgentCaptureState.Idle
        };
    }
}
