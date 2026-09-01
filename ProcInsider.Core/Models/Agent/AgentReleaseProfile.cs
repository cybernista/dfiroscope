using System;
using System.Collections.Generic;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Portable relationship between the agent's compiled educational-release profile and
/// the release identity supplied by the viewer on the current IPC request.
/// </summary>
public enum AgentReleaseProfileMatch
{
    Unknown = 0,
    Match = 1,
    Mismatch = 2
}

/// <summary>
/// Diagnostic description of one command discriminator published by the
/// agent's compiled release profile. Operational availability remains separate;
/// payload-specific commands still require the shared policy check at submit.
/// </summary>
public sealed record AgentCommandCapability
{
    public const int MaxAvailabilityReasonLength = 160;

    public AgentCommandKind CommandKind { get; init; }

    public bool IsCoreControl { get; init; }

    public bool HasPayloadSpecificRequirements { get; init; }

    public IReadOnlyList<string> PublishedFeatureIds { get; init; } = Array.Empty<string>();

    public AgentCommandOperationalAvailability OperationalAvailability { get; init; } =
        AgentCommandOperationalAvailability.Unknown;

    public string AvailabilityReason { get; init; } = string.Empty;
}

/// <summary>
/// Additive health-contract payload for diagnosing viewer/agent release
/// compatibility and the agent's published command surface.
/// </summary>
public sealed record AgentReleaseProfileSnapshot
{
    public string ReleaseId { get; init; } = string.Empty;

    public string ViewerReleaseId { get; init; } = string.Empty;

    public AgentReleaseProfileMatch Match { get; init; } = AgentReleaseProfileMatch.Unknown;

    public string Status { get; init; } = string.Empty;

    public IReadOnlyList<AgentCommandCapability> PublishedCommandCapabilities { get; init; } =
        Array.Empty<AgentCommandCapability>();
}
