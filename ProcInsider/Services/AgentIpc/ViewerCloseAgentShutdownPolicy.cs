namespace ProcInsider.Services.AgentIpc;

public enum ViewerCloseAgentShutdownOutcome
{
    NoVerifiedTarget,
    ExactProcessStopped,
    ExactIdentityRejected,
    PromptForVerifiedProcess,
    PromptForUnresolvedProcess
}

public sealed record ViewerCloseAgentShutdownDecision(
    ViewerCloseAgentShutdownOutcome Outcome,
    string Detail)
{
    public bool ShouldPrompt => Outcome is
        ViewerCloseAgentShutdownOutcome.PromptForVerifiedProcess or
        ViewerCloseAgentShutdownOutcome.PromptForUnresolvedProcess;
}

/// <summary>
/// Classifies the close-time process observation for one previously authenticated,
/// exact local-agent target. Transient viewer-attachment presentation state is not
/// an input because it cannot invalidate that stronger PID/start/session binding.
/// </summary>
public static class ViewerCloseAgentShutdownPolicy
{
    public static ViewerCloseAgentShutdownDecision Evaluate(
        LocalAgentVerifiedShutdownTarget? target,
        LocalAgentProcessResult? process)
    {
        if (target == null ||
            target.ProcessId <= 0 ||
            target.StartedAtUtc == default ||
            string.IsNullOrWhiteSpace(target.SessionId) ||
            string.IsNullOrWhiteSpace(target.DatabasePath))
        {
            return new ViewerCloseAgentShutdownDecision(
                ViewerCloseAgentShutdownOutcome.NoVerifiedTarget,
                "No authenticated exact local-agent target is retained for the active workspace.");
        }

        if (process == null || process.ProcessId != target.ProcessId)
        {
            return new ViewerCloseAgentShutdownDecision(
                ViewerCloseAgentShutdownOutcome.PromptForUnresolvedProcess,
                "The previously authenticated local-agent process could not be re-inspected before Viewer close. Shutdown will revalidate the exact target before taking any action.");
        }

        if (process.IsConfirmedExactExit)
        {
            return new ViewerCloseAgentShutdownDecision(
                ViewerCloseAgentShutdownOutcome.ExactProcessStopped,
                process.Detail);
        }

        if (process.Outcome == LocalAgentProcessOutcome.VerificationRejected)
        {
            return new ViewerCloseAgentShutdownDecision(
                ViewerCloseAgentShutdownOutcome.ExactIdentityRejected,
                process.Detail);
        }

        if (process.Outcome == LocalAgentProcessOutcome.VerifiedRunning && process.IsRunning)
        {
            return new ViewerCloseAgentShutdownDecision(
                ViewerCloseAgentShutdownOutcome.PromptForVerifiedProcess,
                process.Detail);
        }

        var detail = string.IsNullOrWhiteSpace(process.Detail)
            ? "The previously authenticated local-agent process could not be conclusively re-inspected before Viewer close. Shutdown will revalidate the exact target before taking any action."
            : $"The previously authenticated local-agent process could not be conclusively re-inspected before Viewer close: {process.Detail} Shutdown will revalidate the exact target before taking any action.";
        return new ViewerCloseAgentShutdownDecision(
            ViewerCloseAgentShutdownOutcome.PromptForUnresolvedProcess,
            detail);
    }
}
