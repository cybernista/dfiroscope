using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services;
using ProcInsider.Services.Ai;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed partial class WorkspaceNavigationService
{
    internal async Task<AiWorkspaceViewModel?> OpenAiWorkspaceAsync(WorkspaceNavigationMode mode = WorkspaceNavigationMode.Reuse)
    {
        if (_disposed || _manager.ReadsSuspended || !_manager.IsAvailable(WorkspaceTypeId.Ai)) return null;
        var workspace = mode == WorkspaceNavigationMode.OpenNew ? null : Resolve(new(WorkspaceTypeId.Ai, Capture)) as AiWorkspaceViewModel;
        _activating = true;
        try
        {
            if (workspace == null) workspace = await _manager.OpenAiAsync();
            else await _manager.ActivateAsync(workspace);
        }
        finally { _activating = false; }
        await workspace.RefreshCommand.ExecuteAsync(null);
        return workspace.IsDisposed || _manager.ReadsSuspended || !ReferenceEquals(workspace, _manager.ActiveInstance) ||
            workspace.Context != Capture ? null : workspace;
    }

    internal async Task<WorkspaceNavigationResult> NavigateAiConversationAsync(string id,
        CancellationToken cancellationToken = default, WorkspaceNavigationMode mode = WorkspaceNavigationMode.Reuse)
    {
        var binding = _manager.CaptureBinding;
        var revision = ContextRevision;
        Cancel();
        var action = ActionGeneration;
        if (_disposed || _manager.ReadsSuspended || binding == null || !_manager.IsAvailable(WorkspaceTypeId.Ai) ||
            !_access.IsPublished(FeatureIds.AiAssistance) || string.IsNullOrWhiteSpace(id))
            return new(ViewerNavigationOutcome.Unavailable);
        bool Current() => !cancellationToken.IsCancellationRequested && action == ActionGeneration &&
            revision == ContextRevision && ReferenceEquals(binding, _manager.CaptureBinding) && !_manager.ReadsSuspended;
        try
        {
            var saved = await binding.Annotations.LoadConversationAsync(id, cancellationToken);
            if (!Current()) return new(ViewerNavigationOutcome.Superseded);
            if (saved == null) return new(ViewerNavigationOutcome.NotFound);
            if (!ConversationExplorerViewModel.IsCompatible(saved, binding)) return new(ViewerNavigationOutcome.Unavailable);
            AiObjectContext? target = null;
            if (saved.Scope.ContextType == AiConversationContextType.Object)
            {
                var reference = saved.Scope.ObjectReference!;
                target = await Task.Run(async () =>
                {
                    if (reference.Evidence.Kind == ProcInsider.Models.EvidenceReferenceKind.ProcessEntity)
                    {
                        var original = new AiEvidenceReferenceResolver(binding.Query).ResolveProcess(reference, binding.Paths.SessionId);
                        return original.IsResolved ? ProcessEvidenceAgentTools.CreateObjectContext(original.Process!) : null;
                    }
                    return await EvidenceObjectAgentTools.ResolveAsync(binding.Query!, _access, reference, binding.Paths.SessionId, cancellationToken);
                }, cancellationToken);
                if (!Current()) return new(ViewerNavigationOutcome.Superseded);
                if (target == null) { Status = "The exact saved conversation original is unavailable."; return new(ViewerNavigationOutcome.Unavailable); }
            }
            var workspace = await OpenAiWorkspaceAsync(mode);
            // Activation may advance ContextRevision legitimately; cancellation cannot be rebased.
            if (workspace == null || _disposed || action != ActionGeneration || _manager.ReadsSuspended ||
                !ReferenceEquals(binding, _manager.CaptureBinding) || cancellationToken.IsCancellationRequested ||
                workspace.IsDisposed || !ReferenceEquals(workspace, _manager.ActiveInstance))
                return new(ViewerNavigationOutcome.Superseded);
            revision = ContextRevision;
            bool loaded;
            if (target != null)
            {
                workspace.ObjectConversation.SelectObject(target);
                loaded = await workspace.ObjectConversation.LoadConversationAsync(id, cancellationToken);
                if (!Current() || workspace.IsDisposed || !ReferenceEquals(workspace, _manager.ActiveInstance))
                    return new(ViewerNavigationOutcome.Superseded);
                if (loaded) workspace.ShowObject();
                Status = workspace.ObjectConversation.Status;
            }
            else
            {
                workspace.GeneralContextId = saved.Scope.ContextId;
                var assistant = workspace.General;
                if (assistant == null) return new(ViewerNavigationOutcome.Unavailable);
                // Opening an exact saved ID replaces the previous analyst scope choice.
                // Capture requalifies the saved identity against the current assessed roots.
                workspace.SelectedEvidenceScope = null;
                workspace.SelectedEvidenceScopeGeneration = binding.CaptureGeneration;
                // Saved identity qualifies the General context; it grants no selected-object identity.
                workspace.SubmissionContext = new(saved.Scope.Identity, DateTime.UtcNow, null, null, "AI",
                    "No selected entity", null);
                assistant.SetGeneralContextId(saved.Scope.ContextId);
                assistant.RefreshContext();
                loaded = saved.IsHistorical ? await assistant.LoadHistoricalConversationAsync(id, cancellationToken) :
                    await assistant.LoadConversationAsync(id, cancellationToken);
                if (!Current() || workspace.IsDisposed || !ReferenceEquals(workspace, _manager.ActiveInstance))
                    return new(ViewerNavigationOutcome.Superseded);
                if (loaded) workspace.ShowGeneral();
                Status = assistant.StatusMessage;
            }
            if (!Current() || workspace.IsDisposed || !ReferenceEquals(workspace, _manager.ActiveInstance))
                return new(ViewerNavigationOutcome.Superseded);
            return new(loaded ? ViewerNavigationOutcome.Succeeded : ViewerNavigationOutcome.Unavailable, workspace.Id);
        }
        catch (OperationCanceledException) { return new(ViewerNavigationOutcome.Superseded); }
        catch (Exception error)
        {
            if (Current()) Status = "Conversation navigation failed: " + error.Message;
            return new(ViewerNavigationOutcome.Failed);
        }
    }

    internal async Task<WorkspaceNavigationResult> NavigateAiInvestigationAsync(string id,
        CancellationToken cancellationToken = default, WorkspaceNavigationMode mode = WorkspaceNavigationMode.Reuse)
    {
        var binding = _manager.CaptureBinding;
        var revision = ContextRevision;
        Cancel();
        var action = ActionGeneration;
        if (_disposed || _manager.ReadsSuspended || binding == null || !_manager.IsAvailable(WorkspaceTypeId.Ai) ||
            !_access.IsPublished(FeatureIds.AiAssistance) || string.IsNullOrWhiteSpace(id))
            return new(ViewerNavigationOutcome.Unavailable);
        bool Current() => !cancellationToken.IsCancellationRequested && action == ActionGeneration &&
            revision == ContextRevision && ReferenceEquals(binding, _manager.CaptureBinding) && !_manager.ReadsSuspended;
        try
        {
            var saved = await binding.Annotations.LoadInvestigationAsync(id, cancellationToken);
            var conversation = saved == null ? null : await binding.Annotations.LoadConversationAsync(saved.ConversationId, cancellationToken);
            if (!Current()) return new(ViewerNavigationOutcome.Superseded);
            if (saved == null) return new(ViewerNavigationOutcome.NotFound);
            if (!InvestigationExplorerViewModel.IsCompatible(saved, conversation, binding)) return new(ViewerNavigationOutcome.Unavailable);
            var workspace = await OpenAiWorkspaceAsync(mode);
            // Recheck before even constructing/loading the formal presenter after an awaited refresh.
            if (workspace == null || _disposed || action != ActionGeneration || _manager.ReadsSuspended ||
                cancellationToken.IsCancellationRequested || !ReferenceEquals(binding, _manager.CaptureBinding) ||
                workspace.IsDisposed || !ReferenceEquals(workspace, _manager.ActiveInstance))
                return new(ViewerNavigationOutcome.Superseded);
            revision = ContextRevision;
            if (workspace.InvestigationConversation is not { } presenter)
                return new(ViewerNavigationOutcome.Unavailable);
            var loaded = await presenter.LoadAsync(id, cancellationToken);
            if (!Current() || workspace.IsDisposed || !ReferenceEquals(workspace, _manager.ActiveInstance))
                return new(ViewerNavigationOutcome.Superseded);
            if (loaded) workspace.ShowInvestigation();
            Status = presenter.Status;
            return new(loaded ? ViewerNavigationOutcome.Succeeded : ViewerNavigationOutcome.Unavailable, workspace.Id);
        }
        catch (OperationCanceledException) { return new(ViewerNavigationOutcome.Superseded); }
        catch (Exception error)
        {
            if (Current()) Status = "Investigation navigation failed: " + error.Message;
            return new(ViewerNavigationOutcome.Failed);
        }
    }
}