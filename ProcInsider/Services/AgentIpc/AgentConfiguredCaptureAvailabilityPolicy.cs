using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public sealed record AgentConfiguredCaptureAvailabilityContext
{
    public bool IsFeaturePublished { get; init; }

    public CaptureWorkspaceMode WorkspaceMode { get; init; }

    public bool IsShutdownInProgress { get; init; }

    public bool HasSelectedLocalAgent { get; init; }

    public bool IsVerifiedAgentReachable { get; init; }

    public AgentPairingState PairingState { get; init; }

    public bool HasActiveSqliteBenchmark { get; init; }

    public AgentCaptureControlViewState Control { get; init; } =
        AgentCaptureControlViewState.Unknown();
}

public sealed record AgentConfiguredCaptureAvailability(
    bool CanStart,
    bool CanStop,
    bool CanPause,
    bool CanResume,
    bool CanEnd,
    string StartUnavailableReason,
    string StopUnavailableReason,
    string PauseUnavailableReason,
    string ResumeUnavailableReason,
    string EndUnavailableReason);

/// <summary>
/// Pure viewer policy for configured capture command availability. Viewer attachment is
/// deliberately absent: authenticated reachability and a current authoritative agent
/// projection are the operational boundary for configured capture.
/// </summary>
public static class AgentConfiguredCaptureAvailabilityPolicy
{
    public static AgentConfiguredCaptureAvailability Evaluate(
        AgentConfiguredCaptureAvailabilityContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.Control);

        var commonFailure = EvaluateCommonFailure(context);
        if (!string.IsNullOrWhiteSpace(commonFailure))
        {
            return new(
                false, false, false, false, false,
                commonFailure, commonFailure, commonFailure, commonFailure, commonFailure);
        }

        var startFailure = context.HasActiveSqliteBenchmark
            ? "Wait for the active SQLite benchmark to finish before starting configured capture."
            : context.Control.SnapshotStatus != AgentControlSnapshotStatus.Current
                ? FirstNonEmpty(
                    context.Control.StatusDetail,
                    "Wait for a fresh matching-session agent control snapshot before starting capture.")
                : !context.Control.CanStart
                    ? FormatStartStateFailure(context.Control.State)
                    : string.Empty;
        var stopFailure = context.Control.SnapshotStatus != AgentControlSnapshotStatus.Current
            ? FirstNonEmpty(
                context.Control.StatusDetail,
                "Wait for a fresh matching-session agent control snapshot before stopping capture.")
            : !context.Control.CanStop
                ? FormatStopStateFailure(context.Control.State)
                : string.Empty;
        var pauseFailure = context.Control.SnapshotStatus != AgentControlSnapshotStatus.Current
            ? FirstNonEmpty(context.Control.StatusDetail, "Wait for a fresh matching-session snapshot before pausing capture.")
            : !context.Control.CanPause
                ? FormatPauseStateFailure(context.Control.State)
                : string.Empty;
        var resumeFailure = context.Control.SnapshotStatus != AgentControlSnapshotStatus.Current
            ? FirstNonEmpty(context.Control.StatusDetail, "Wait for a fresh matching-session snapshot before resuming capture.")
            : !context.Control.CanResume
                ? FormatResumeStateFailure(context.Control.State)
                : string.Empty;
        var endFailure = context.Control.SnapshotStatus != AgentControlSnapshotStatus.Current
            ? FirstNonEmpty(context.Control.StatusDetail, "Wait for a fresh matching-session snapshot before ending capture.")
            : !context.Control.CanEnd
                ? FormatStopStateFailure(context.Control.State)
                : string.Empty;

        return new(
            string.IsNullOrWhiteSpace(startFailure),
            string.IsNullOrWhiteSpace(stopFailure),
            string.IsNullOrWhiteSpace(pauseFailure),
            string.IsNullOrWhiteSpace(resumeFailure),
            string.IsNullOrWhiteSpace(endFailure),
            startFailure,
            stopFailure,
            pauseFailure,
            resumeFailure,
            endFailure);
    }

    private static string EvaluateCommonFailure(AgentConfiguredCaptureAvailabilityContext context)
    {
        if (!context.IsFeaturePublished)
        {
            return "Configured capture is unavailable in the current release profile.";
        }

        if (context.WorkspaceMode != CaptureWorkspaceMode.LiveCapture)
        {
            return context.WorkspaceMode == CaptureWorkspaceMode.ArchivedCapture
                ? "Archived captures are sealed; switch to a live capture workspace."
                : "A live capture workspace is required.";
        }

        if (context.IsShutdownInProgress)
        {
            return "Agent shutdown is in progress.";
        }

        if (!context.HasSelectedLocalAgent)
        {
            return "Select the deployed local agent first.";
        }

        if (!context.IsVerifiedAgentReachable)
        {
            return "The selected local agent is not freshly verified for this live session.";
        }

        if (context.PairingState != AgentPairingState.Connected)
        {
            return "The selected local agent does not have a current authenticated pairing.";
        }

        return string.Empty;
    }

    private static string FormatStartStateFailure(AgentCaptureRunState state) => state switch
    {
        AgentCaptureRunState.Starting => "Configured capture start is already pending.",
        AgentCaptureRunState.Running => "Configured capture is already running.",
        AgentCaptureRunState.Pausing => "Configured capture is pausing.",
        AgentCaptureRunState.Paused => "Configured capture is paused; use Resume Capture.",
        AgentCaptureRunState.Resuming => "Configured capture resume is already pending.",
        AgentCaptureRunState.Stopping => "Configured capture is stopping; wait for authoritative completion.",
        AgentCaptureRunState.Draining => "Accepted capture data is still draining to SQLite.",
        _ => "The authoritative agent state does not currently allow configured capture start."
    };

    private static string FormatStopStateFailure(AgentCaptureRunState state) => state switch
    {
        AgentCaptureRunState.Off => "No configured capture is active.",
        AgentCaptureRunState.Starting => "Configured capture start is still pending.",
        AgentCaptureRunState.Stopping => "Configured capture stop is already pending.",
        AgentCaptureRunState.Draining => "Capture is stopped and accepted data is still draining to SQLite.",
        _ => "The authoritative agent state does not currently allow configured capture stop."
    };

    private static string FormatPauseStateFailure(AgentCaptureRunState state) => state switch
    {
        AgentCaptureRunState.Off => "No configured capture is active.",
        AgentCaptureRunState.Pausing => "Configured capture pause is already pending.",
        AgentCaptureRunState.Paused => "Configured capture is already paused.",
        AgentCaptureRunState.Resuming => "Configured capture is resuming; wait for authoritative running state.",
        AgentCaptureRunState.Stopping or AgentCaptureRunState.Draining => "Configured capture is ending and cannot be paused.",
        _ => "The authoritative agent state does not currently allow configured capture pause."
    };

    private static string FormatResumeStateFailure(AgentCaptureRunState state) => state switch
    {
        AgentCaptureRunState.Off => "No paused configured capture is active.",
        AgentCaptureRunState.Running => "Configured capture is already running.",
        AgentCaptureRunState.Pausing => "Configured capture is pausing; wait for authoritative paused state.",
        AgentCaptureRunState.Resuming => "Configured capture resume is already pending.",
        AgentCaptureRunState.Stopping or AgentCaptureRunState.Draining => "Configured capture is ending and cannot be resumed.",
        _ => "The authoritative agent state does not currently allow configured capture resume."
    };

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
}
