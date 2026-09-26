using System.ComponentModel;
using ProcInsider.Models;
using ProcInsider.ViewModels;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.Presentation;

/// <summary>The App Info view activates only descriptors belonging to its presentation.</summary>
public interface IAppInfoPresentation
{
    IReadOnlyList<FeatureTabDescriptor> AppInfoExtensionTabs { get; }
}

/// <summary>WPF event translation for a process listing, independent of its containing window.</summary>
public interface IProcessListingPresentation
{
    event Action<ProcessRowViewModel>? ProcessRowNavigationRequested;
    event Func<ViewerProcessViewportAnchor?>? ProcessViewportAnchorCaptureRequested;
    event Action<ProcessRowViewModel, double>? ProcessViewportAnchorRestoreRequested;

    void SortVisibleProcessRows(string columnName);
    ListSortDirection? GetSortDirection(string columnName);
    void RequestProcessListingRange(int firstIndex, int itemCount = 1);
    void NotifyProcessViewportChanged();
}

/// <summary>Optional contributions register against this presentation without activating modules.</summary>
internal sealed class ViewerPresentationRegistrationContext
{
    private readonly List<Func<FeatureId?, IEnumerable<ISelectedProcessFanOutConsumer>>> _consumers = [];
    private readonly List<Action<InvestigationSessionPaths?>> _workspaceCallbacks = [];
    private readonly List<Func<CancellationToken, Task>> _quiesceCallbacks = [];
    public ProcessPresentationViewModel Presentation { get; }
    public ProcessDescriptionViewModel Description => Presentation.ProcessDescriptionViewModel;
    public FeatureActivationRegistry Registry => Presentation._featureModules;
    public FeatureAccessService Access { get; }
    public ApplicationCatalogService? ApplicationCatalog { get; }
    public Func<InvestigationSessionPaths> SessionPaths { get; }
    public List<IViewerFeatureDefinition> Definitions { get; } = [];
    public List<FeatureId> RequiredFeatureIds { get; } = [];

    public ViewerPresentationRegistrationContext(ProcessPresentationViewModel presentation,
        FeatureAccessService access, ApplicationCatalogService? applicationCatalog,
        Func<InvestigationSessionPaths> sessionPaths)
    {
        Presentation = presentation;
        Access = access;
        ApplicationCatalog = applicationCatalog;
        SessionPaths = sessionPaths;
    }

    public void RegisterConsumers(Func<FeatureId?, IEnumerable<ISelectedProcessFanOutConsumer>> callback) => _consumers.Add(callback);
    public void RegisterWorkspaceCallback(Action<InvestigationSessionPaths?> callback) => _workspaceCallbacks.Add(callback);
    public void RegisterQuiesce(Func<CancellationToken, Task> callback) => _quiesceCallbacks.Add(callback);
    internal Task QuiesceAsync(CancellationToken token) => Task.WhenAll(_quiesceCallbacks.Select(callback => callback(token)));
    internal void AddConsumers(FeatureId? id, List<ISelectedProcessFanOutConsumer> consumers)
    {
        foreach (var callback in _consumers) consumers.AddRange(callback(id));
    }
    internal void BindWorkspace(InvestigationSessionPaths? paths)
    {
        foreach (var callback in _workspaceCallbacks) callback(paths);
    }
}

/// <summary>An exact validated snapshot/archive generation. Captured requests retain this value.</summary>
internal sealed record ViewerReadBinding(long CaptureGeneration, long SnapshotGeneration,
    SqliteStagingQueryService QueryService, ProcessListingService ListingService,
    TelemetryProjectionService Projection);

internal sealed record ViewerCaptureBinding(long CaptureGeneration, InvestigationSessionPaths Paths,
    AnnotationDatabaseService Annotations, SqliteStagingQueryService? Query, ProcessListingService? Listing);

internal sealed record ProcessListingSnapshotRequest(ProcessListingQuery Query, long QueryGeneration,
    string SelectedEntityId, string SelectedKey, ViewerProcessViewportAnchor? Viewport);

internal sealed record PreparedProcessListingSnapshot(ProcessListingSnapshotRequest Request,
    int Count, ProcessListingWindow FirstPage, int SelectedIndex, ProcessListingWindow? SelectedPage,
    int ViewportIndex, ProcessListingWindow? ViewportPage);

internal sealed record ViewerSelectedProcessTarget(string ProcessEntityId, string ProcessKey,
    int ProcessId, string ProcessName, DateTime? StartTime, long CaptureGeneration, long SelectionGeneration);

/// <summary>Neutral content and lifecycle owner; capture/write authority remains outside the host.</summary>
internal interface IViewerPresentationHost : IDisposable
{
    object Content { get; }
    ProcessPresentationViewModel? ActiveProcessPresentation { get; }
    InspectorPaneViewModel? ActiveDetailsPresentation { get; }
    long ContextRevision => 0;
    event Action? ActiveContextChanged { add { } remove { } }
    IReadOnlyList<ProcessPresentationViewModel> ProcessPresentations =>
        ActiveProcessPresentation is { } presentation ? [presentation] : [];
    void BindCapture(ViewerCaptureBinding binding)
    {
        foreach (var presentation in ProcessPresentations) presentation.BindCapture(binding);
    }
    void ResetCapture()
    {
        foreach (var presentation in ProcessPresentations) presentation.ResetCapture();
    }
    void ApplyExplorerMetadata(ExplorerCountRefreshPayload payload)
    {
        foreach (var presentation in ProcessPresentations) presentation.ApplyExplorerMetadata(payload);
    }
    Task<PreparedProcessListingSnapshot?> PrepareAsync(ViewerReadBinding candidate,
        ProcessListingSnapshotRequest? request, CancellationToken cancellationToken);
    Task QuiesceAsync(CancellationToken cancellationToken);
    void Publish(ViewerReadBinding binding);
    void CommitPublication();
    void Detach(long captureGeneration);
    void Abort();
    bool NavigateToDataTab(FeatureTabKey key, string action);
    bool NavigateToExplorerTab(FeatureTabKey key, string action);
    void NavigateToSearchResult(TelemetrySearchResult result) => ActiveProcessPresentation?.NavigateToSearchResult(result);
}

/// <summary>Registration stores a factory and never constructs a host during eligibility checks.</summary>
internal sealed class ViewerPresentationHostRegistration
{
    private Func<IViewerPresentationHost>? _factory;
    private bool _activationAttempted;
    public void Register(Func<IViewerPresentationHost> factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        if (_factory != null) throw new InvalidOperationException("A Viewer presentation host is already registered.");
        _factory = factory;
    }
    public IViewerPresentationHost Activate(Func<IViewerPresentationHost> defaultFactory)
    {
        if (_activationAttempted) throw new InvalidOperationException("Viewer presentation activation was already attempted.");
        _activationAttempted = true;
        return (_factory ?? defaultFactory)() ?? throw new InvalidOperationException("The Viewer presentation host factory returned no host.");
    }
}

/// <summary>Rolls the neutral participant back before existing capture orchestration restores its store/file owner.</summary>
internal static class ViewerPresentationPublication
{
    internal static void Publish(IViewerPresentationHost host, ViewerReadBinding binding, Action publishRemaining, Action restoreShared)
    {
        try
        {
            host.Publish(binding);
            publishRemaining();
            host.CommitPublication();
        }
        catch
        {
            try { host.Abort(); }
            finally { restoreShared(); }
            throw;
        }
    }
}
