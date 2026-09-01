using ProcInsider.Models.Features;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services;
using ProcInsider.Services.Features;

namespace ProcInsider.Features.Infrastructure;

/// <summary>
/// Package-composition inputs for the unpublished Infrastructure Viewer surface. The accessors
/// are evaluated only after an analyst opens or queries a case; registering or selecting the tab
/// never authenticates, reads grants, or creates a Server client.
/// </summary>
public sealed record InfrastructureCaseWorkspaceFeatureDependencies
{
    public InfrastructureCaseWorkspaceFeatureDependencies(
        Func<IInfrastructureCaseWorkspaceClient> clientFactory,
        Func<AuthenticatedInfrastructureViewerContext> viewerContextAccessor)
        : this(
            clientFactory,
            _ => Task.FromResult(viewerContextAccessor()))
    {
        ViewerContextAccessor = viewerContextAccessor ??
                                throw new ArgumentNullException(nameof(viewerContextAccessor));
    }

    public InfrastructureCaseWorkspaceFeatureDependencies(
        Func<IInfrastructureCaseWorkspaceClient> clientFactory,
        Func<CancellationToken, Task<AuthenticatedInfrastructureViewerContext>> viewerContextAccessorAsync)
    {
        ClientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
        ViewerContextAccessorAsync = viewerContextAccessorAsync ??
                                     throw new ArgumentNullException(nameof(viewerContextAccessorAsync));
    }

    public Func<IInfrastructureCaseWorkspaceClient> ClientFactory { get; }

    public Func<AuthenticatedInfrastructureViewerContext>? ViewerContextAccessor { get; }

    public Func<CancellationToken, Task<AuthenticatedInfrastructureViewerContext>> ViewerContextAccessorAsync { get; }

    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(ClientFactory);
        ArgumentNullException.ThrowIfNull(ViewerContextAccessorAsync);
    }
}

/// <summary>
/// Viewer-owned activation and presentation boundary for one Server-backed case revision.
/// Core owns publication and query contracts; the package composition supplies authenticated
/// transport without giving WPF, this module, or the Viewer a Postgres or direct-Agent path.
/// </summary>
public sealed class InfrastructureCaseWorkspaceFeatureModule : IDisposable
{
    private bool _disposed;

    private InfrastructureCaseWorkspaceFeatureModule(
        InfrastructureModeAccessService access,
        InfrastructureCaseWorkspaceFeatureDependencies dependencies)
    {
        dependencies.Validate();
        ViewModel = new InfrastructureCaseWorkspaceViewModel(access, dependencies);
    }

    public InfrastructureCaseWorkspaceViewModel ViewModel { get; }

    public static ViewerFeatureDefinition<InfrastructureCaseWorkspaceFeatureModule> CreateDefinition(
        Func<InfrastructureCaseWorkspaceFeatureModule> moduleFactory)
    {
        ArgumentNullException.ThrowIfNull(moduleFactory);
        return new ViewerFeatureDefinition<InfrastructureCaseWorkspaceFeatureModule>(
            FeatureIds.InfrastructureCaseWorkspaces,
            [FeatureIds.InfrastructureMode],
            moduleFactory,
            [
                new ViewerFeatureTabDefinition<InfrastructureCaseWorkspaceFeatureModule>(
                    ExplorerTabKeys.Infrastructure,
                    "Infrastructure",
                    700,
                    module => module.CreateExplorerView()),
                new ViewerFeatureTabDefinition<InfrastructureCaseWorkspaceFeatureModule>(
                    DataTabKeys.InfrastructureCase,
                    "Infrastructure Case",
                    2000,
                    module => module.CreateDataView())
            ],
            module => module.Dispose());
    }

    public static bool TryCreate(
        InfrastructureModeAccessService access,
        InfrastructureCaseWorkspaceFeatureDependencies dependencies,
        out InfrastructureCaseWorkspaceFeatureModule? module,
        out InfrastructureAccessDecision decision)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(dependencies);
        return access.TryCreate(
            InfrastructureEntryPointKind.UserInterfaceDescriptor,
            () => new InfrastructureCaseWorkspaceFeatureModule(access, dependencies),
            out module,
            out decision,
            InfrastructureFeatureArea.CaseWorkspaces,
            CurrentInfrastructureModeProfile.Definition.CreateIdentity(InfrastructureComponentKind.Server));
    }

    public InfrastructureCaseWorkspaceView CreateExplorerView()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new InfrastructureCaseWorkspaceView { DataContext = ViewModel };
    }

    public InfrastructureCaseWorkspaceDataView CreateDataView()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new InfrastructureCaseWorkspaceDataView { DataContext = ViewModel };
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ViewModel.Dispose();
    }
}
