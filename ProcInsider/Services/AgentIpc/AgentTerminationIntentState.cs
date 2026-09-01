using System.IO;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public sealed record AgentTerminationIntentTarget(
    string AgentId,
    string HostId,
    AgentTransportKind TransportKind,
    string Endpoint,
    long WorkspaceGeneration,
    string SessionId,
    string LiveDatabasePath);

public enum AgentTerminationIntentConsumeOutcome
{
    Consumed,
    NotArmed,
    TargetChanged
}

/// <summary>
/// Owns the Viewer user's explicit, single-use intent to terminate one exact agent/workspace target.
/// WPF row state is only a visual projection and is never used as the authorization token.
/// </summary>
public sealed class AgentTerminationIntentState
{
    private readonly object _sync = new();
    private AgentTerminationIntentTarget? _target;

    public bool IsArmed
    {
        get
        {
            lock (_sync)
            {
                return _target != null;
            }
        }
    }

    public void Arm(AgentTerminationIntentTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        Validate(target);

        lock (_sync)
        {
            _target = target;
        }
    }

    public AgentTerminationIntentConsumeOutcome TryConsume(
        AgentTerminationIntentTarget? candidate)
    {
        AgentTerminationIntentTarget? armed;
        lock (_sync)
        {
            armed = _target;
            _target = null;
        }

        if (armed == null)
        {
            return AgentTerminationIntentConsumeOutcome.NotArmed;
        }

        return candidate != null && IdentifiesSameTarget(armed, candidate)
            ? AgentTerminationIntentConsumeOutcome.Consumed
            : AgentTerminationIntentConsumeOutcome.TargetChanged;
    }

    public bool Cancel()
    {
        lock (_sync)
        {
            var wasArmed = _target != null;
            _target = null;
            return wasArmed;
        }
    }

    private static bool IdentifiesSameTarget(
        AgentTerminationIntentTarget left,
        AgentTerminationIntentTarget right) =>
        string.Equals(left.AgentId, right.AgentId, StringComparison.Ordinal) &&
        string.Equals(left.HostId, right.HostId, StringComparison.OrdinalIgnoreCase) &&
        left.TransportKind == right.TransportKind &&
        string.Equals(left.Endpoint, right.Endpoint, StringComparison.Ordinal) &&
        left.WorkspaceGeneration == right.WorkspaceGeneration &&
        string.Equals(left.SessionId, right.SessionId, StringComparison.Ordinal) &&
        PathsEqual(left.LiveDatabasePath, right.LiveDatabasePath);

    private static bool PathsEqual(string left, string right)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(left),
                Path.GetFullPath(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static void Validate(AgentTerminationIntentTarget target)
    {
        if (string.IsNullOrWhiteSpace(target.AgentId) ||
            string.IsNullOrWhiteSpace(target.HostId) ||
            target.TransportKind == AgentTransportKind.Unknown ||
            string.IsNullOrWhiteSpace(target.Endpoint) ||
            target.WorkspaceGeneration < 0 ||
            string.IsNullOrWhiteSpace(target.SessionId) ||
            string.IsNullOrWhiteSpace(target.LiveDatabasePath) ||
            !Path.IsPathFullyQualified(target.LiveDatabasePath))
        {
            throw new ArgumentException(
                "Agent termination intent requires a complete agent and live-workspace identity.",
                nameof(target));
        }
    }
}
