using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal sealed record AgentConfiguredCapturePauseResult(
    bool Success,
    bool IsIdempotent,
    string ErrorCode,
    string Message,
    IReadOnlyList<AgentActiveWorkItem> AffectedWork);

/// <summary>
/// Agent-owned authoritative pause/resume state machine for configured live sources.
/// It preserves the queue jobs/source runs and delegates collector checkpoints to their
/// concrete handlers before publishing Paused or Running.
/// </summary>
internal sealed class AgentConfiguredCapturePauseCoordinator
{
    private readonly AgentJobQueue _jobQueue;
    private readonly AgentLiveCaptureJobHandler _liveCapture;
    private readonly AgentNetworkCaptureJobHandler _networkCapture;

    public AgentConfiguredCapturePauseCoordinator(
        AgentJobQueue jobQueue,
        AgentLiveCaptureJobHandler liveCapture,
        AgentNetworkCaptureJobHandler networkCapture)
    {
        _jobQueue = jobQueue;
        _liveCapture = liveCapture;
        _networkCapture = networkCapture;
    }

    public Task<AgentConfiguredCapturePauseResult> PauseAsync(
        PauseJobCommand command,
        CancellationToken cancellationToken) =>
        TransitionAsync(
            command.CaptureId,
            command.JobId,
            AgentCaptureRunState.Pausing,
            JobState.Paused,
            pause: true,
            cancellationToken);

    public Task<AgentConfiguredCapturePauseResult> ResumeAsync(
        ResumeJobCommand command,
        CancellationToken cancellationToken) =>
        TransitionAsync(
            command.CaptureId,
            command.JobId,
            AgentCaptureRunState.Resuming,
            JobState.Running,
            pause: false,
            cancellationToken);

    private async Task<AgentConfiguredCapturePauseResult> TransitionAsync(
        string captureId,
        Guid jobId,
        AgentCaptureRunState transition,
        JobState completedState,
        bool pause,
        CancellationToken cancellationToken)
    {
        var plan = _jobQueue.BeginConfiguredCaptureTransition(captureId, jobId, transition);
        if (plan.IsIdempotent)
        {
            return new AgentConfiguredCapturePauseResult(
                true,
                true,
                string.Empty,
                pause
                    ? "Configured capture is already paused."
                    : "Configured capture is already running.",
                plan.Work);
        }

        if (!plan.CanExecute)
        {
            return new AgentConfiguredCapturePauseResult(
                false,
                false,
                plan.ErrorCode,
                plan.Message,
                plan.Work);
        }

        var transitioned = new List<AgentActiveWorkItem>();
        try
        {
            foreach (var work in plan.Work)
            {
                // Include the in-progress source in compensation. A handler can reach its
                // checkpoint and then fault while publishing diagnostics.
                transitioned.Add(work);
                var succeeded = await RequestSourceTransitionAsync(work, pause, cancellationToken)
                    .ConfigureAwait(false);
                if (!succeeded)
                {
                    throw new InvalidOperationException(
                        $"{work.JobKind} job '{work.JobId}' did not reach its safe {(pause ? "pause" : "resume")} checkpoint.");
                }
            }

            var message = pause
                ? "Configured capture paused after collectors stopped accepting observations and accepted writes drained."
                : "Configured capture resumed under the same capture, jobs, and source-run provenance.";
            var affected = await _jobQueue.CompleteConfiguredCaptureTransitionAsync(
                    captureId,
                    completedState,
                    message,
                    CancellationToken.None)
                .ConfigureAwait(false);
            return new AgentConfiguredCapturePauseResult(
                true,
                false,
                string.Empty,
                message,
                affected);
        }
        catch (Exception ex)
        {
            foreach (var work in transitioned.AsEnumerable().Reverse())
            {
                try
                {
                    await RequestSourceTransitionAsync(work, !pause, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch
                {
                    // The authoritative transition remains rejected; health will expose any source failure.
                }
            }

            _jobQueue.AbortConfiguredCaptureTransition(captureId);
            return new AgentConfiguredCapturePauseResult(
                false,
                false,
                pause ? "ConfiguredCapturePauseFailed" : "ConfiguredCaptureResumeFailed",
                ex.Message,
                plan.Work);
        }
    }

    private Task<bool> RequestSourceTransitionAsync(
        AgentActiveWorkItem work,
        bool pause,
        CancellationToken cancellationToken) =>
        work.JobKind switch
        {
            JobKind.LiveCapture => pause
                ? _liveCapture.RequestPauseAsync(work.JobId, cancellationToken)
                : _liveCapture.RequestResumeAsync(work.JobId, cancellationToken),
            JobKind.NetworkCapture => pause
                ? _networkCapture.RequestPauseAsync(work.JobId, cancellationToken)
                : _networkCapture.RequestResumeAsync(work.JobId, cancellationToken),
            _ => Task.FromResult(false)
        };
}
