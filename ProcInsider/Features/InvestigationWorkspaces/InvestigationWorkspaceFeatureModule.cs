using ProcInsider.Features.NativeEventProfiles;
using System.Runtime.CompilerServices;
using ProcInsider.Models.Features;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services.Features;
using ProcInsider.Services.Presentation;
using ProcInsider.ViewModels;

[assembly: InternalsVisibleTo("InvestigationWorkspacesSelfTest")]

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class InvestigationWorkspaceFeatureModule : IViewerPresentationHost
{
    private readonly WorkspaceSnapshotParticipant _snapshots;
    private WorkspaceShellView? _content;
    private readonly FeatureAccessService _access;
    private readonly System.Windows.Threading.Dispatcher _dispatcher = System.Windows.Threading.Dispatcher.CurrentDispatcher;
    private PreparedEventsWorkspace? _preparedEvents;
    private PreparedPersistenceWorkspace? _preparedPersistence;
    internal sealed record PreparedPersistenceWorkspace(PersistenceWorkspaceViewModel Instance, ProcInsider.Features.PersistenceWorkspace.PersistenceWorkspacePage Page, ProcInsider.Features.PersistenceWorkspace.PersistenceWorkspaceQuery Request, ProcInsider.Services.SqliteStagingQueryService Query, WorkspaceContext Context, long ReadRevision);
    internal sealed record PreparedEventsWorkspace(EventsWorkspaceViewModel Instance, EventsPage Page, ProcInsider.Services.SqliteStagingQueryService Query, EventsQuery Request);
    public WorkspaceManager Manager { get; }
    internal InvestigationWorkspaceFeatureModule(FeatureAccessService access, Func<ProcessPresentationViewModel> createPresentation,
        Func<ProcInsider.Models.ExplorerScope, Task<IReadOnlyList<ExplorerNodeViewModel>>>? loadChildren = null,
        IReadOnlyList<FeatureTabDescriptor>? sharedTabs = null,
        Func<ProcInsider.Features.WindowsSecurityDetails.SecurityDetailsStore>? getDefinitions = null,
        Func<WorkspaceInstanceViewModel, ProcessConversationViewModel>? createObjectConversation = null,
        Func<NativeEventProfileStore>? getProfiles = null, Func<NativeEventPresetStore>? getPresets = null, Func<ProcessDescriptionViewModel>? createProcessOverview = null, ProcessingOperationsViewModel? processingOperations = null,
        Func<PersistenceWorkspaceActionService>? createPersistenceActions = null,
        Func<ArtifactsWorkspaceActionService>? createArtifactsActions = null,
        Func<WorkspaceManager, AiChatViewModel>? createAssistant = null,
        Func<WorkspaceInstanceViewModel, InvestigationDataViewModel>? createInvestigation = null)
    {
        if (!IsAvailable(access)) throw new InvalidOperationException("Investigation workspaces are unavailable.");
        _access = access;
        if (!access.IsPublished(FeatureIds.AiAssistance)) { createObjectConversation = null; createAssistant = null; createInvestigation = null; }
        var registry = new WorkspaceRegistry(access);
        var processes = new WorkspaceTypeMetadata(WorkspaceTypeId.Processes, "Processes", "Process investigation");
        registry.Register(processes, FeatureIds.InvestigationWorkspaces,
            ordinal => new ProcessesWorkspaceViewModel(processes, ordinal, createPresentation()));
        Manager = new WorkspaceManager(registry);
        Manager.Navigation = new(Manager, access);
        if (access.IsPublished(FeatureIds.Persistence))
        {
            var session = Manager.PersistenceSession = new();
            var actions = createPersistenceActions?.Invoke();
            var persistence = new WorkspaceTypeMetadata(WorkspaceTypeId.Persistence, "Persistence", "Accepted latest-known state and immutable observation changes");
            registry.Register(persistence, FeatureIds.Persistence, ordinal => new PersistenceWorkspaceViewModel(persistence, ordinal, session, actions, createObjectConversation: createObjectConversation));
            Manager.PersistenceExplorer = new(Manager, session);
        }
        if (access.IsPublished(FeatureIds.FilesystemArtifacts))
        {
            var session = Manager.ArtifactsSession = new();
            var artifacts = new WorkspaceTypeMetadata(WorkspaceTypeId.Artifacts, "Artifacts", "Retained structured forensic analysis results");
            var actions = createArtifactsActions?.Invoke();
            registry.Register(artifacts, FeatureIds.FilesystemArtifacts, ordinal => new ArtifactsWorkspaceViewModel(artifacts, ordinal, session, actions));
            Manager.ArtifactsExplorer = new(Manager, session);
        }
        if(access.IsPublished(FeatureIds.NetworkWorkspace) && access.IsPublished(FeatureIds.EventTelemetry))
        {
            var session=Manager.NetworkSession=new(processingOperations);
            var network=new WorkspaceTypeMetadata(WorkspaceTypeId.Network,"Network","Recorded Sysmon 3 observations");
            registry.Register(network,FeatureIds.NetworkWorkspace,ordinal=>new NetworkWorkspaceViewModel(network,ordinal,session,createProcessOverview?.Invoke(),Manager.Navigation, createObjectConversation));
            Manager.NetworkExplorer=new(Manager,session);
        }
        if (access.IsPublished(EventsWorkspaceFeatureComposition.Id) &&
            (access.IsPublished(FeatureIds.WindowsSecurityEvents) || access.IsPublished(FeatureIds.EventTelemetry)))
        {
            var session = Manager.EventsSession = new(access);
            var events = new WorkspaceTypeMetadata(WorkspaceTypeId.Events, "Events", "Recorded event investigation");
            var profiles = new Lazy<NativeEventProfileStore>(() => getProfiles?.Invoke() ?? new(ProcInsider.Services.SessionPathService.GetNativeEventProfilesPath()));
            var presets = new Lazy<NativeEventPresetStore>(() => getPresets?.Invoke() ?? new(ProcInsider.Services.SessionPathService.GetNativeEventPresetsPath()));
            registry.Register(events, EventsWorkspaceFeatureComposition.Id, ordinal => new EventsWorkspaceViewModel(events, ordinal,
                session, access.IsPublished(FeatureIds.WindowsSecurityEvents)
                    ? getDefinitions?.Invoke() ?? throw new InvalidOperationException("Security definitions are unavailable.")
                    : null,
                access, profiles, presets, createObjectConversation: createObjectConversation));
            Manager.EventsExplorer = new(Manager, session, access.IsPublished(FeatureIds.WindowsSecurityEvents),
                access.IsPublished(EventSourceFamilyOwnershipCatalog.Definitions.Single(definition => definition.Family == EventSourceFamilyKind.Sysmon).PresentationFeatureId));
        }
        Manager.ExplorerSections = new(Manager, access, loadChildren, sharedTabs, createAssistant);
        if (access.IsPublished(FeatureIds.AiAssistance) && createObjectConversation != null && createAssistant != null)
        {
            var ai = new WorkspaceTypeMetadata(WorkspaceTypeId.Ai, "AI", "Saved chats and investigations");
            registry.Register(ai, FeatureIds.AiAssistance, ordinal => new AiWorkspaceViewModel(ai, ordinal,
                Manager, createObjectConversation, createInvestigation, createAssistant));
        }
        _snapshots = new(Manager);
        Manager.OpenProcessesAsync().GetAwaiter().GetResult();
        Manager.SharedActions = Manager.ActivePresentation!.SharedActions;
    }
    internal static bool IsAvailable(FeatureAccessService access) =>
        access.IsPublished(FeatureIds.InvestigationWorkspaces) && access.IsPublished(FeatureIds.ProcessListing) &&
        access.IsPublished(FeatureIds.SelectedProcessDetails);
    public object Content => _content ??= new WorkspaceShellView { DataContext = Manager };
    public ProcessPresentationViewModel? ActiveProcessPresentation => Manager.ActivePresentation;
    public InspectorPaneViewModel? ActiveDetailsPresentation => Manager.ActiveInstance is ArtifactsWorkspaceViewModel artifacts ? artifacts.InspectorPaneViewModel : Manager.ActiveInstance is PersistenceWorkspaceViewModel persistence ? persistence.InspectorPaneViewModel : Manager.ActiveInstance is EventsWorkspaceViewModel events
        ? events.InspectorPaneViewModel : Manager.ActiveInstance is NetworkWorkspaceViewModel network?network.InspectorPaneViewModel:ActiveProcessPresentation?.InspectorPaneViewModel;
    public IReadOnlyList<ProcessPresentationViewModel> ProcessPresentations =>
        Manager.Instances.OfType<ProcessesWorkspaceViewModel>().Select(x => x.Presentation).ToArray();
    public long ContextRevision => Manager.ContextRevision;
    public event Action? ActiveContextChanged { add => Manager.ActiveContextChanged += value; remove => Manager.ActiveContextChanged -= value; }
    public async Task<PreparedProcessListingSnapshot?> PrepareAsync(ViewerReadBinding candidate, ProcessListingSnapshotRequest? request, CancellationToken token)
    {
        _preparedEvents = null;
        _preparedPersistence = null;
        var persistenceContext = await _dispatcher.InvokeAsync(() => (Instance: Manager.ActiveInstance as PersistenceWorkspaceViewModel, Query: (Manager.ActiveInstance as PersistenceWorkspaceViewModel)?.CaptureQuery(), Context: Manager.ActiveInstance?.Context, Revision: Manager.PersistenceSession?.Revision));
        if (persistenceContext.Instance is { } persistence && persistenceContext.Query is { } persistenceQuery && persistenceContext.Context is { } context && persistenceContext.Revision is { } readRevision)
        {
            if (candidate.CaptureGeneration != context.CaptureGeneration) throw new OperationCanceledException("Persistence candidate capture generation was superseded.", token);
            var page = await Task.Run(() => candidate.QueryService.PersistenceQueries.Query(persistenceQuery, token), token);
            token.ThrowIfCancellationRequested();
            var current = await _dispatcher.InvokeAsync(() => !persistence.IsDisposed && ReferenceEquals(Manager.ActiveInstance, persistence) && persistence.Context == context && Manager.PersistenceSession?.Revision == readRevision && persistence.MatchesQuery(persistenceQuery));
            if (!current) throw new OperationCanceledException("Persistence preparation was superseded.", token);
            _preparedPersistence = new(persistence, page, persistenceQuery, candidate.QueryService, context, readRevision);
            return null;
        }
        var active = await _dispatcher.InvokeAsync(() => (Instance: Manager.ActiveInstance, Capture: Manager.CaptureBinding,
            Query: (Manager.ActiveInstance as EventsWorkspaceViewModel)?.CaptureQuery()));
        if (active.Instance is EventsWorkspaceViewModel events && active.Capture is { } capture && active.Query is { } eventQuery)
        {
            var binding = new EventsReadBinding(null, capture.Paths.SessionId, null, candidate.CaptureGeneration, candidate.SnapshotGeneration);
            await using var reader = new ProcInsider.Services.EventsWorkspaceQueryService(_access.Catalog, candidate.QueryService, binding, () => !token.IsCancellationRequested);
            var page = await reader.QueryAsync(eventQuery, token);
            token.ThrowIfCancellationRequested();
            _preparedEvents = new(events, page, candidate.QueryService, eventQuery);
            return null;
        }
        return request == null || active.Instance is not ProcessesWorkspaceViewModel process ? null :
            await process.Presentation._listingWorkflow.PrepareSnapshotAsync(candidate, request, token);
    }
    public Task QuiesceAsync(CancellationToken token) { Manager.ExplorerSections.Assistant?.Cancel(); Manager.Navigation.Cancel(); return _snapshots.QuiesceAsync(token); }
    public void Publish(ViewerReadBinding binding) => _snapshots.Publish(binding, _preparedEvents, _preparedPersistence);
    public void CommitPublication() { _snapshots.Commit(); Manager.ExplorerSections.Assistant?.RefreshContext(); (Manager.ActiveInstance as AiWorkspaceViewModel)?.RefreshGeneralContext(); }
    public void Abort() { _snapshots.Abort(); Manager.ExplorerSections.Assistant?.RefreshContext(); (Manager.ActiveInstance as AiWorkspaceViewModel)?.RefreshGeneralContext(); }
    public void BindCapture(ViewerCaptureBinding binding)
    {
        Manager.Navigation.ResetCapture();
        foreach (var ai in Manager.Instances.OfType<AiWorkspaceViewModel>()) ai.CaptureChanged();
        Manager.CaptureBinding = binding;
        foreach (var ai in Manager.Instances.OfType<AiWorkspaceViewModel>()) { ai.Context = new(binding.Paths.SessionId, binding.CaptureGeneration); ai.RefreshGeneralContext(); }
        Manager.ExplorerSections.Assistant?.RefreshContext();
        Manager.ExplorerSections.Conversations?.CaptureChanged();
        Manager.ExplorerSections.Investigations?.CaptureChanged();
        Manager.PersistenceSession?.Bind(binding);
        Manager.ArtifactsSession?.Bind(binding);
        Manager.ArtifactsExplorer?.Invalidate();
        Manager.PersistenceExplorer?.Invalidate();
        foreach (var persistence in Manager.Instances.OfType<PersistenceWorkspaceViewModel>()) { persistence.Context = new(binding.Paths.SessionId, binding.CaptureGeneration); persistence.Invalidate(true); }
        foreach (var artifacts in Manager.Instances.OfType<ArtifactsWorkspaceViewModel>()) { artifacts.Context = new(binding.Paths.SessionId, binding.CaptureGeneration); artifacts.Invalidate(true); }
        Manager.ArtifactsExplorer?.Resume();
        Manager.PersistenceExplorer?.Resume();
        Manager.EventsSession?.Bind(binding);
        Manager.NetworkSession?.Bind(binding);
        Manager.NetworkExplorer?.Invalidate();
        foreach(var network in Manager.Instances.OfType<NetworkWorkspaceViewModel>()){network.Context=new(binding.Paths.SessionId,binding.CaptureGeneration);network.Invalidate(true);}
        Manager.EventsExplorer?.Invalidate();
        foreach (var events in Manager.Instances.OfType<EventsWorkspaceViewModel>())
        {
            events.Context = new(binding.Paths.SessionId, binding.CaptureGeneration);
            events.Invalidate(captureChanged: true);
            events.BindAnnotations(binding.Annotations);
        }
        foreach (var instance in Manager.Instances.OfType<ProcessesWorkspaceViewModel>())
        {
            instance.Context = new(binding.Paths.SessionId, binding.CaptureGeneration);
            instance.Presentation.BindCapture(binding);
            instance.CaptureChanged();
        }
    }
    public void Detach(long generation)
    {
        Manager.Navigation.ResetCapture();
        foreach (var ai in Manager.Instances.OfType<AiWorkspaceViewModel>()) ai.CaptureChanged();
        Manager.CaptureBinding = null;
        foreach (var ai in Manager.Instances.OfType<AiWorkspaceViewModel>()) { ai.Context = null; ai.RefreshGeneralContext(); }
        Manager.ExplorerSections.Assistant?.RefreshContext();
        Manager.ExplorerSections.Conversations?.CaptureChanged();
        Manager.ExplorerSections.Investigations?.CaptureChanged();
        Manager.PersistenceSession?.Bind(null);
        Manager.ArtifactsSession?.Bind(null);
        Manager.ArtifactsExplorer?.Invalidate();
        Manager.PersistenceExplorer?.Invalidate();
        foreach (var persistence in Manager.Instances.OfType<PersistenceWorkspaceViewModel>()) { persistence.Context = null; persistence.Invalidate(true); }
        foreach (var artifacts in Manager.Instances.OfType<ArtifactsWorkspaceViewModel>()) { artifacts.Context = null; artifacts.Invalidate(true); }
        Manager.EventsSession?.Bind(null);
        Manager.NetworkSession?.Bind(null);
        Manager.NetworkExplorer?.Invalidate();
        foreach(var network in Manager.Instances.OfType<NetworkWorkspaceViewModel>()){network.Context=null;network.Invalidate(true);}
        Manager.EventsExplorer?.Invalidate();
        foreach (var events in Manager.Instances.OfType<EventsWorkspaceViewModel>()) { events.Context = null; events.Invalidate(captureChanged: true); }
        foreach (var instance in Manager.Instances.OfType<ProcessesWorkspaceViewModel>())
        {
            instance.Context = null;
            instance.CaptureChanged();
            instance.Presentation.DetachReadBinding(generation);
        }
    }
    public void ResetCapture()
    {
        Manager.ExplorerSections.Reset();
        Manager.ExplorerMetadata = null;
        foreach (var presentation in ProcessPresentations) presentation.ResetCapture();
    }
    public void ApplyExplorerMetadata(ProcInsider.Services.ExplorerCountRefreshPayload payload)
    {
        Manager.ExplorerMetadata = payload;
        Manager.ExplorerSections.ApplyMetadata(payload);
        foreach (var presentation in ProcessPresentations) presentation.ApplyExplorerMetadata(payload);
    }
    public bool NavigateToDataTab(FeatureTabKey key, string action) => ActiveProcessPresentation?.TryNavigateToDataTab(key, action) ?? false;
    public bool NavigateToExplorerTab(FeatureTabKey key, string action)
    {
        if (!Manager.ExplorerSections.Expand(key)) return false;
        return ActiveProcessPresentation?.TryNavigateToExplorerTab(key, action) ?? true;
    }
    public void NavigateToSearchResult(ProcInsider.Models.TelemetrySearchResult result)
        => _ = Manager.Navigation.NavigateSearchResultAsync(result);
    internal void NotifyActionAvailability()
    {
        foreach (var workspace in Manager.Instances.OfType<ArtifactsWorkspaceViewModel>()) workspace.NotifyActions();
        foreach (var workspace in Manager.Instances.OfType<PersistenceWorkspaceViewModel>()) workspace.NotifyActions();
    }
    public void Dispose() { Manager.ExplorerSections.Dispose(); Manager.Navigation.Dispose(); Manager.Dispose(); }
}
