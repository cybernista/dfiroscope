using System;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Portable base type for agent-owned monitoring and capture configuration commands.
/// </summary>
public abstract record AgentConfigurationCommand : AgentCommand
{
    public string AgentId { get; init; } = string.Empty;

    /// <summary>Optional host identity. Empty means the local/default host for the agent.</summary>
    public string HostId { get; init; } = string.Empty;

    public string ConfigurationVersion { get; init; } = string.Empty;

    public string ConfigurationHash { get; init; } = string.Empty;
}

/// <summary>Requests the selected agent's saved host monitoring configuration.</summary>
public sealed record GetHostMonitoringConfigurationCommand : AgentConfigurationCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.GetHostMonitoringConfiguration;
}

/// <summary>Saves a host monitoring configuration draft to the selected agent.</summary>
public sealed record SaveHostMonitoringConfigurationCommand : AgentConfigurationCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.SaveHostMonitoringConfiguration;

    public AgentHostMonitoringConfiguration Configuration { get; init; } = new();
}

/// <summary>Checks host monitoring configuration prerequisites without applying settings.</summary>
public sealed record CheckHostMonitoringConfigurationCommand : AgentConfigurationCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.CheckHostMonitoringConfiguration;

    public AgentHostMonitoringConfiguration? DraftConfiguration { get; init; }
}

/// <summary>Deploys previously saved host monitoring configuration without starting capture.</summary>
public sealed record DeployHostMonitoringConfigurationCommand : AgentConfigurationCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.DeployHostMonitoringConfiguration;

    public bool RequireMatchingHash { get; init; } = true;
}

/// <summary>Attempts safe reverse deployment of host monitoring settings.</summary>
public sealed record ReverseHostMonitoringDeploymentCommand : AgentConfigurationCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.ReverseHostMonitoringDeployment;

    public string[] AcknowledgedWarnings { get; init; } = Array.Empty<string>();
}

/// <summary>Requests the selected agent's saved capture configuration.</summary>
public sealed record GetCaptureConfigurationCommand : AgentConfigurationCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.GetCaptureConfiguration;
}

/// <summary>Saves a capture configuration draft to the selected agent.</summary>
public sealed record SaveCaptureConfigurationCommand : AgentConfigurationCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.SaveCaptureConfiguration;

    public AgentCaptureConfiguration Configuration { get; init; } = new();
}

/// <summary>Checks capture configuration readiness without starting capture.</summary>
public sealed record CheckCaptureConfigurationCommand : AgentConfigurationCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.CheckCaptureConfiguration;

    public AgentCaptureConfiguration? DraftConfiguration { get; init; }
}

/// <summary>Starts capture from the selected agent's saved capture configuration.</summary>
public sealed record StartConfiguredCaptureCommand : AgentConfigurationCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StartConfiguredCapture;

    public string CaptureId { get; init; } = string.Empty;

    public bool RequireMatchingHash { get; init; } = true;
}

/// <summary>Stops configured capture without reversing host monitoring deployment.</summary>
public sealed record StopConfiguredCaptureCommand : AgentConfigurationCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.StopConfiguredCapture;

    public string CaptureId { get; init; } = string.Empty;

    public string Reason { get; init; } = string.Empty;
}
