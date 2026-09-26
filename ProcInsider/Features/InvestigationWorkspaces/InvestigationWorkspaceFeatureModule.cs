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
    internal sealed record PreparedEventsWorkspace(EventsWorkspaceViewModel Instance, EventsPage Page, ProcInsider.Services.SqliteStagingQueryService Query, EventsQuery Request);
    public WorkspaceManager Manager { get; }
    internal InvestigationWorkspaceFeatureModule(FeatureAccessService access, Func<ProcessPresentationViewModel> createPresentation,
        Func<ProcInsider.Models.ExplorerScope, Task<IReadOnlyList<ExplorerNodeViewModel>>>? loadChildren = null,
        IReadOnlyList<FeatureTabDescriptor>? sharedTabs = null,
        Func<ProcInsider.Features.WindowsSecurityDetails.SecurityDetailsStore>? getDefinitions = null,
        Func<InspectorPaneViewModel, AiDetailsInvestigationViewModel>? createAi = null,
        Func<NativeEventProfileStore>? getProfiles = null, Func<NativeEventPresetStore>? getPresets = null)
    {
        if (!IsAvailable(access)) throw new InvalidOperationException("Investigation workspaces are unavailable.");
        _access = access;
        var registry = new WorkspaceRegistry(access);
        var processes = new WorkspaceTypeMetadata(WorkspaceTypeId.Processes, "Processes", "Process investigation");
        registry.Register(processes, FeatureIds.InvestigationWorkspaces,
            ordinal => new ProcessesWorkspaceViewModel(processes, ordinal, createPresentation()));
        Manager = new WorkspaceManager(registry);
        Manager.Navigation = new(Manager, access);
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
                access, createAi, profiles, presets));
            Manager.EventsExplorer = new(Manager, session, access.IsPublished(FeatureIds.WindowsSecurityEvents),
                access.IsPublished(EventSourceFamilyOwnershipCatalog.Definitions.Single(definition => definition.Family == EventSourceFamilyKind.Sysmon).PresentationFeatureId));
        }
        Manager.ExplorerSections = new(Manager, access, loadChildren, sharedTabs);
        _snapshots = new(Manager);
        Manager.OpenProcessesAsync().GetAwaiter().GetResult();
        Manager.SharedActions = Manager.ActivePresentation!.SharedActions;
    }
    internal static bool IsAvailable(FeatureAccessService access) =>
        access.IsPublished(FeatureIds.InvestigationWorkspaces) && access.IsPublished(FeatureIds.ProcessListing) &&
        access.IsPublished(FeatureIds.SelectedProcessDetails);
    public object Content => _content ??= new WorkspaceShellView { DataContext = Manager };
    public ProcessPresentationViewModel? ActiveProcessPresentation => Manager.ActivePresentation;
    public InspectorPaneViewModel? ActiveDetailsPresentation => Manager.ActiveInstance is EventsWorkspaceViewModel events
        ? events.InspectorPaneViewModel : ActiveProcessPresentation?.InspectorPaneViewModel;
    public IReadOnlyList<ProcessPresentationViewModel> ProcessPresentations =>
        Manager.Instances.OfType<ProcessesWorkspaceViewModel>().Select(x => x.Presentation).ToArray();
    public long ContextRevision => Manager.ContextRevision;
    public event Action? ActiveContextChanged { add => Manager.ActiveContextChanged += value; remove => Manager.ActiveContextChanged -= value; }
    public async Task<PreparedProcessListingSnapshot?> PrepareAsync(ViewerReadBinding candidate, ProcessListingSnapshotRequest? request, CancellationToken token)
    {
        _preparedEvents = null;
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
    public Task QuiesceAsync(CancellationToken token) { Manager.Navigation.Cancel(); return _snapshots.QuiesceAsync(token); }
    public void Publish(ViewerReadBinding binding) => _snapshots.Publish(binding, _preparedEvents);
    public void CommitPublication() => _snapshots.Commit();
    public void Abort() => _snapshots.Abort();
    public void BindCapture(ViewerCaptureBinding binding)
    {
        Manager.Navigation.Cancel();
        Manager.CaptureBinding = binding;
        Manager.EventsSession?.Bind(binding);
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
        Manager.Navigation.Cancel();
        Manager.CaptureBinding = null;
        Manager.EventsSession?.Bind(null);
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
    public void Dispose() { Manager.ExplorerSections.Dispose(); Manager.Navigation.Dispose(); Manager.Dispose(); }
}
