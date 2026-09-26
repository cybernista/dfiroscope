using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

/// <summary>
/// Owns the disconnected episode, discovery pacing, and selection of an exact
/// live-workspace candidate before the Viewer invokes authenticated recovery.
/// </summary>
public sealed class LocalAgentAutomaticRecoveryWorkflow
{
    private readonly LocalAgentAutomaticReconnectSchedule _schedule = new();
    private readonly Func<DateTime> _nowUtc;
    private LocalAgentVerifiedShutdownTarget? _lastPromptedTarget;
    private LocalAgentVerifiedShutdownTarget? _declinedTarget;
    private bool _promptOpen;

    public LocalAgentAutomaticRecoveryWorkflow(Func<DateTime>? nowUtc = null) =>
        _nowUtc = nowUtc ?? (() => DateTime.UtcNow);

    public DateTime? DisconnectedSinceUtc => _schedule.DisconnectedSinceUtc;
    public bool IsPromptOpen => _promptOpen;

    public void Reset(bool clearDeclinedTarget = false)
    {
        _schedule.Reset();
        _lastPromptedTarget = null;
        if (clearDeclinedTarget)
        {
            _declinedTarget = null;
        }
    }

    public bool TryBeginPrompt(
        LocalAgentDiscoveryResult discovery,
        LocalAgentVerifiedShutdownTarget target,
        string activeSessionId,
        string activeDatabaseIdentity,
        bool authenticatedHealthReachable,
        out LocalAgentRecoveryPromptReason reason)
    {
        reason = LocalAgentRecoveryPromptReason.None;
        if (_promptOpen || target == _lastPromptedTarget || target == _declinedTarget)
        {
            return false;
        }

        reason = LocalAgentRecoveryPromptPolicy.Evaluate(
            discovery, target, activeSessionId, activeDatabaseIdentity,
            authenticatedHealthReachable, DisconnectedSinceUtc, _nowUtc());
        if (reason == LocalAgentRecoveryPromptReason.None)
        {
            return false;
        }

        _promptOpen = true;
        _lastPromptedTarget = target;
        return true;
    }

    public bool IsConsentStillValid(
        LocalAgentDiscoveryResult discovery,
        LocalAgentVerifiedShutdownTarget target,
        string activeSessionId,
        string activeDatabaseIdentity,
        bool authenticatedHealthReachable,
        LocalAgentRecoveryPromptReason expectedReason)
    {
        var currentReason = LocalAgentRecoveryPromptPolicy.Evaluate(
            discovery, target, activeSessionId, activeDatabaseIdentity,
            authenticatedHealthReachable, DisconnectedSinceUtc, _nowUtc());
        if (currentReason == expectedReason)
        {
            return true;
        }

        if (authenticatedHealthReachable ||
            discovery.Outcome is LocalAgentDiscoveryOutcome.SingleCandidate or
                LocalAgentDiscoveryOutcome.Absent)
        {
            _lastPromptedTarget = null;
        }
        return false;
    }

    public void EndPrompt() => _promptOpen = false;

    public void InvalidatePrompt() => _lastPromptedTarget = null;

    public void RememberDecline(LocalAgentVerifiedShutdownTarget target) =>
        _declinedTarget = target;

    public async Task<bool> TryReconnectAsync(
        DateTime nowUtc,
        Func<Task<LocalAgentDiscoveryResult>> discover,
        Func<AgentPairingLeaseMetadata, bool> matchesActiveLease,
        Func<LocalAgentDiscoveryResult, Task<bool>> offerProcessRecovery,
        Func<Task<bool>> reconnect,
        Func<bool> isConnected,
        Func<bool> contextCurrent)
    {
        ArgumentNullException.ThrowIfNull(discover);
        ArgumentNullException.ThrowIfNull(matchesActiveLease);
        ArgumentNullException.ThrowIfNull(offerProcessRecovery);
        ArgumentNullException.ThrowIfNull(reconnect);
        ArgumentNullException.ThrowIfNull(isConnected);
        ArgumentNullException.ThrowIfNull(contextCurrent);

        if (isConnected())
        {
            Reset();
            return false;
        }

        // Start the episode before discovery: inspection failures must not extend
        // the fast retry window indefinitely.
        if (!_schedule.TryBegin(nowUtc, out var attemptId))
        {
            return false;
        }

        try
        {
            var discovery = await discover();
            if (!contextCurrent())
            {
                return false;
            }

            if (await offerProcessRecovery(discovery))
            {
                return false;
            }

            if (!contextCurrent())
            {
                return false;
            }

            if (discovery.Outcome != LocalAgentDiscoveryOutcome.SingleCandidate ||
                discovery.Candidates.Count != 1 ||
                !matchesActiveLease(discovery.Candidates[0].Discovery.Lease))
            {
                return false;
            }

            return await reconnect();
        }
        finally
        {
            _schedule.Complete(attemptId, _nowUtc(), isConnected());
        }
    }
}
