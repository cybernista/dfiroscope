using ProcInsider.Models.Features;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.Features;

namespace ProcInsider.Features.InvestigationWorkspaces;

/// <summary>Capture-owned Agent control dependency; the workspace never reads the Prefetch directory itself.</summary>
internal sealed class ArtifactsWorkspaceActionService(FeatureAccessService access, ViewerAgentEvidenceActionService evidenceActions,
    ViewerAgentCaptureActionService captureActions, Func<ViewerAgentCaptureActionTarget?> target, Func<bool> writable)
{
    internal bool Available => access.IsPublished(FeatureIds.FilesystemArtifacts) && writable() && target() != null;
    internal ViewerAgentCaptureActionTarget? CaptureTarget() => Available ? target() : null;
    internal Task<ViewerAgentEvidenceActionResult> CollectPrefetchAsync(ViewerAgentCaptureActionTarget captured, CancellationToken token)
        => Available && captured == target()
            ? evidenceActions.CollectPrefetchAsync(captured, wait: false, cancellationToken: token)
            : Task.FromResult(Unavailable());
    internal async Task<ViewerAgentEvidenceActionResult> WaitAsync(ViewerAgentCaptureActionTarget captured, Guid jobId, CancellationToken token)
    {
        if (!Available || captured != target()) return Unavailable();
        var result = await captureActions.WaitForJobAsync(captured, jobId, cancellationToken: token);
        return new() { Outcome = result.Succeeded ? ViewerAgentEvidenceActionOutcome.Succeeded : ViewerAgentEvidenceActionOutcome.JobFailed, ErrorCode = result.ErrorCode, Diagnostic = result.Diagnostic };
    }
    internal async Task<ViewerAgentEvidenceActionResult> CancelAsync(ViewerAgentCaptureActionTarget captured, Guid jobId, CancellationToken token)
    {
        if (!Available || captured != target()) return Unavailable();
        var result = await captureActions.CancelJobAsync(captured, jobId, token);
        return new() { Outcome = result.Succeeded ? ViewerAgentEvidenceActionOutcome.Succeeded : ViewerAgentEvidenceActionOutcome.Unavailable, ErrorCode = result.ErrorCode, Diagnostic = result.Diagnostic };
    }
    private static ViewerAgentEvidenceActionResult Unavailable() => new()
    {
        Outcome = ViewerAgentEvidenceActionOutcome.Unavailable,
        ErrorCode = "PrefetchControlUnavailable",
        Diagnostic = "Collect Prefetch requires a published, writable live capture and a connected exact Agent target."
    };
}
