using ProcInsider.Features.InvestigationWorkspaces;
using ProcInsider.Services.Presentation;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;
using ProcInsider.Services.Ai;
using ProcInsider.Models.Ai;

namespace ProcInsider.ViewModels;

public partial class MainViewModel
{
    private ProcessConversationViewModel CreateWorkspaceObjectConversation(WorkspaceInstanceViewModel owner)
    {
        var service = _featureModules.GetOrActivate<AiInvestigationService>(FeatureIds.AiAssistance)
            ?? throw new InvalidOperationException("AI assistance is unavailable.");
        var policy = new AgentPolicy(_featureAccess, _telemetryProjectionService);
        var tools = new AgentToolRegistry(policy, _telemetryProjectionService);
        var skills = new AgentSkillRegistry(tools);
        return new(() => _annotationStore is { } store ? new AgentRuntime(service, store, policy, tools, skills, new ContextBroker()) : null,
            () => _annotationStore, service, () => _captureWorkspaceCoordinator.Generation,
            () => !owner.IsDisposed && _presentationHost is InvestigationWorkspaceFeatureModule host &&
                !host.Manager.ReadsSuspended && ReferenceEquals(host.Manager.ActiveInstance, owner),
            async reference => { if (_presentationHost is InvestigationWorkspaceFeatureModule host)
                await host.Manager.Navigation.NavigateCitationAsync(reference); }, ResolveWorkspaceAiObjectAsync)
        { SettingsViewModel = new(service, _featureAccess), OwnsSettingsViewModel = true };
    }

    private async Task<AiObjectContext?> ResolveWorkspaceAiObjectAsync(AiEvidenceReference reference, CancellationToken token)
    {
        var generation = _captureWorkspaceCoordinator.Generation;
        var binding = _telemetryProjectionService.CaptureReadBindingToken();
        if (binding is null) return null;
        using var scope = _telemetryProjectionService.BeginReadScope(binding);
        var sessionId = _sessionPaths.SessionId;
        var resolved = await Task.Run(() => AiEvidenceReferenceResolver.ResolveObjectAsync(
            _telemetryProjectionService, _featureAccess, reference, sessionId, token), token);
        return generation == _captureWorkspaceCoordinator.Generation && _telemetryProjectionService.IsCurrentReadBinding(binding)
            && !token.IsCancellationRequested ? resolved : null;
    }

    private InvestigationDataViewModel CreateWorkspaceInvestigation(WorkspaceInstanceViewModel owner)
    {
        var service = _featureModules.GetOrActivate<AiInvestigationService>(FeatureIds.AiAssistance)
            ?? throw new InvalidOperationException("AI assistance is unavailable.");
        var policy = new AgentPolicy(_featureAccess, _telemetryProjectionService);
        var tools = new AgentToolRegistry(policy, _telemetryProjectionService);
        var skills = new AgentSkillRegistry(tools);
        return new(() => _annotationStore is { } store ? new AgentRuntime(service, store, policy, tools, skills, new ContextBroker()) : null,
            () => _annotationStore, service, () => _captureWorkspaceCoordinator.Generation,
            () => !owner.IsDisposed && _presentationHost is InvestigationWorkspaceFeatureModule host &&
                !host.Manager.ReadsSuspended && ReferenceEquals(host.Manager.ActiveInstance, owner),
            ProcessEvidenceAgentTools.CreateObjectContext, ResolveWorkspaceAiObjectAsync,
            async reference => { if (_presentationHost is InvestigationWorkspaceFeatureModule host)
                await host.Manager.Navigation.NavigateCitationAsync(reference); }, () => _sessionPaths.SessionId);
    }
    private AiChatViewModel CreateWorkspaceAssistant(WorkspaceManager manager)
    {
        var service = _featureModules.GetOrActivate<AiInvestigationService>(FeatureIds.AiAssistance)
            ?? throw new InvalidOperationException("AI assistance is unavailable.");
        var policy = new AgentPolicy(_featureAccess, _telemetryProjectionService);
        var tools = new AgentToolRegistry(policy, _telemetryProjectionService);
        var skills = new AgentSkillRegistry(tools);
        return new(() => manager.CaptureBinding?.Annotations is { } store ? new AgentRuntime(service, store, policy, tools, skills, new ContextBroker()) : null,
            () => manager.CaptureBinding?.Annotations, service, _featureAccess, () => _captureWorkspaceCoordinator.Generation,
            () => manager.CaptureBinding is not null && !manager.ReadsSuspended,
            () => AssistantWorkspaceContext.Capture(manager), AssistantWorkspaceContext.Queries,
            async reference => { await manager.Navigation.NavigateCitationAsync(reference); },
            async (id, token) => { await manager.Navigation.NavigateInvestigationAsync(id, cancellationToken: token); },
            () => AssistantWorkspaceContext.ScopeOptions(manager), identity => AssistantWorkspaceContext.SelectScope(manager, identity),
            ResolveWorkspaceAiObjectAsync)
        { SettingsViewModel = new(service, _featureAccess) };
    }

    public ProcessingOperationsViewModel ProcessingOperations {get;}=new();
    partial void NotifyCompiledWorkspaceActionAvailability()
    {
        if (_presentationHost is InvestigationWorkspaceFeatureModule host) host.NotifyActionAvailability();
    }
    partial void ConfigureCompiledViewerPresentation(ViewerPresentationHostRegistration registration,
        Func<ProcessPresentationViewModel> createPresentation, Func<ProcessDescriptionViewModel> createProcessOverview)
    {
        if (InvestigationWorkspaceFeatureModule.IsAvailable(_featureAccess))
            registration.Register(() => new InvestigationWorkspaceFeatureModule(_featureAccess, createPresentation,
                LoadExplorerChildrenAsync, CreateWorkspaceSharedExplorerTabs(),
                () => (_featureModules.GetOrActivate<WindowsSecurityPresentationServices>(FeatureIds.WindowsSecurityEvents)
                    ?? throw new InvalidOperationException("Security definitions are unavailable.")).DetailsStore,
                CreateWorkspaceObjectConversation,
                getProfiles: () => _featureAccess.IsPublished(FeatureIds.WindowsSecurityEvents)
                    ? (_featureModules.GetOrActivate<WindowsSecurityPresentationServices>(FeatureIds.WindowsSecurityEvents)
                        ?? throw new InvalidOperationException("Security profiles are unavailable.")).Profiles
                    : (_featureModules.GetOrActivate<EventTelemetryPresentationServices>(FeatureIds.EventTelemetry)
                        ?? throw new InvalidOperationException("Event telemetry profiles are unavailable.")).Profiles,
                createProcessOverview: createProcessOverview, processingOperations: ProcessingOperations,
                createPersistenceActions: () => new PersistenceWorkspaceActionService(_featureAccess, _agentCaptureActionService,
                    () => IsAgentViewerConnected && AgentsViewModel.SelectedAgent is { IsViewerConnected: true } agent
                        ? CreateAgentCaptureActionTarget(agent, requireViewerConnection: true) : null,
                    () => _captureWorkspaceCoordinator.Mode == ProcInsider.Models.CaptureWorkspaceMode.LiveCapture,
                    () => _sessionPaths.LiveDatabasePath),
                createArtifactsActions: () => new ArtifactsWorkspaceActionService(_featureAccess, _agentEvidenceActionService, _agentCaptureActionService,
                    () => IsAgentViewerConnected && AgentsViewModel.SelectedAgent is { IsViewerConnected: true } agent
                        ? CreateAgentCaptureActionTarget(agent, requireViewerConnection: true) : null,
                    () => _captureWorkspaceCoordinator.Mode == ProcInsider.Models.CaptureWorkspaceMode.LiveCapture),
                createAssistant: CreateWorkspaceAssistant, createInvestigation: CreateWorkspaceInvestigation));
    }
    private IReadOnlyList<FeatureTabDescriptor> CreateWorkspaceSharedExplorerTabs()
    {
        List<FeatureTabDescriptor> tabs =
        [
            new(ExplorerTabKeys.Agents, "Endpoints", FeatureIds.AgentsAndCapture, 100, () => AgentsViewModel),
            new(ExplorerTabKeys.Sigma, "Sigma", FeatureIds.SearchAndSigma, 300, () => SigmaViewModel, showCount: true)
        ];
        tabs.AddRange(_viewerFeatures.CreateTabDescriptors(FeatureTabSurface.Explorer, _featureModules));
        return tabs.Where(t => _featureAccess.IsPublished(t.FeatureId)).ToArray();
    }
}
