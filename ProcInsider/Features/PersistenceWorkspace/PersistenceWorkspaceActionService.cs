using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.Features;

namespace ProcInsider.Features.InvestigationWorkspaces;

/// <summary>Capture-owned control dependency; workspaces retain only their own job/operation state.</summary>
internal sealed class PersistenceWorkspaceActionService(FeatureAccessService access, ViewerAgentCaptureActionService actions,
    Func<ViewerAgentCaptureActionTarget?> target, Func<bool> writable, Func<string> databasePath)
{
    internal bool Available => access.IsPublished(FeatureIds.Persistence) && writable() && target() != null;
    internal ViewerAgentCaptureActionTarget? CaptureTarget() => Available ? target() : null;
    internal bool CanCollect(EvidenceIdentity scope) => CaptureTarget() is { } captured &&
        scope.SourceIdentityId == ProcInsider.Models.Persistence.PersistenceCollection.LocalSourceIdentityId &&
        scope.EvidenceSessionId == captured.SessionId && scope.HostId == captured.HostId;
    internal async Task<ViewerAgentCaptureActionResult> SubmitAsync(ViewerAgentCaptureActionTarget captured, EvidenceIdentity scope, string? resetReason, CancellationToken token)
    {
        if (!CanCollect(scope) || captured != target()) return Unavailable();
        return await actions.CollectPersistenceAsync(captured, scope, databasePath(), resetReason, token);
    }
    internal Task<ViewerAgentCaptureActionResult> WaitAsync(ViewerAgentCaptureActionTarget captured, Guid jobId, EvidenceIdentity scope, CancellationToken token)
    {
        if (!Available || captured != target() || captured.SessionId != scope.EvidenceSessionId || captured.HostId != scope.HostId) return Task.FromResult(Unavailable());
        return actions.WaitForJobAsync(captured, jobId, cancellationToken: token);
    }
    internal Task<ViewerAgentCaptureActionResult> StatusAsync(ViewerAgentCaptureActionTarget captured, Guid jobId, EvidenceIdentity scope, CancellationToken token)
    {
        if (!Available || captured != target() || captured.SessionId != scope.EvidenceSessionId || captured.HostId != scope.HostId) return Task.FromResult(Unavailable());
        return actions.GetJobStatusAsync(captured, jobId, token);
    }
    internal Task<ViewerAgentCaptureActionResult> CancelAsync(ViewerAgentCaptureActionTarget captured, Guid jobId, EvidenceIdentity scope, CancellationToken token)
    {
        if (!Available || captured != target() || captured.SessionId != scope.EvidenceSessionId || captured.HostId != scope.HostId) return Task.FromResult(Unavailable());
        return actions.CancelJobAsync(captured, jobId, token);
    }
    private static ViewerAgentCaptureActionResult Unavailable() => new() { Outcome = ViewerAgentCaptureActionOutcome.Unavailable, ErrorCode = "PersistenceControlUnavailable", Diagnostic = "Persistence controls require a published, writable live capture and a connected exact Agent target." };
}
