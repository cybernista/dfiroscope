using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public enum LocalAgentRecoveryPromptReason
{
    None,
    VerifiedExit,
    SustainedUnresponsive
}

/// <summary>
/// Decides when the Viewer may offer, but never execute, an analyst-approved process action.
/// </summary>
public static class LocalAgentRecoveryPromptPolicy
{
    private static readonly TimeSpan StallThreshold = TimeSpan.FromMinutes(1);

    public static LocalAgentRecoveryPromptReason Evaluate(
        LocalAgentDiscoveryResult discovery,
        LocalAgentVerifiedShutdownTarget target,
        string activeSessionId,
        string activeDatabaseIdentity,
        bool authenticatedHealthReachable,
        DateTime? disconnectedSinceUtc,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(discovery);
        ArgumentNullException.ThrowIfNull(target);
        if (target.ProcessId <= 0 || target.StartedAtUtc == default ||
            !string.Equals(target.SessionId, activeSessionId, StringComparison.Ordinal) ||
            !string.Equals(target.DatabasePath, activeDatabaseIdentity, StringComparison.OrdinalIgnoreCase))
        {
            return LocalAgentRecoveryPromptReason.None;
        }

        bool MatchesLease(AgentPairingLeaseMetadata lease) =>
            lease.WorkspaceMode == CaptureWorkspaceMode.LiveCapture &&
            !lease.CaptureSealed &&
            lease.AgentProcessId == target.ProcessId &&
            lease.AgentStartedAtUtc == target.StartedAtUtc &&
            string.Equals(lease.SessionId, activeSessionId, StringComparison.Ordinal) &&
            string.Equals(lease.DatabaseIdentity, activeDatabaseIdentity, StringComparison.OrdinalIgnoreCase);

        if (discovery.Outcome == LocalAgentDiscoveryOutcome.Absent &&
            discovery.Conflicts.Any(conflict =>
                conflict.Kind == LocalAgentRecoveryConflictKind.ProcessExited &&
                conflict.ProcessVerification?.IsStopped == true &&
                conflict.Discovery is { } record &&
                MatchesLease(record.Lease)))
        {
            return LocalAgentRecoveryPromptReason.VerifiedExit;
        }

        if (!authenticatedHealthReachable &&
            disconnectedSinceUtc is { } lostAtUtc &&
            nowUtc - lostAtUtc >= StallThreshold &&
            discovery.Outcome == LocalAgentDiscoveryOutcome.SingleCandidate &&
            discovery.Candidates.Count == 1 &&
            discovery.Candidates[0].ProcessVerification.Outcome == LocalAgentProcessOutcome.VerifiedRunning &&
            MatchesLease(discovery.Candidates[0].Discovery.Lease) &&
            nowUtc - discovery.Candidates[0].Discovery.Lease.LastHeartbeatUtc >= StallThreshold)
        {
            return LocalAgentRecoveryPromptReason.SustainedUnresponsive;
        }

        return LocalAgentRecoveryPromptReason.None;
    }
}
