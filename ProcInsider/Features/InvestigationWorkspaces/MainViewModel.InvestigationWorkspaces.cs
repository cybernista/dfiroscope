using ProcInsider.Features.InvestigationWorkspaces;
using ProcInsider.Services.Presentation;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public partial class MainViewModel
{
    partial void ConfigureCompiledViewerPresentation(ViewerPresentationHostRegistration registration,
        Func<ProcessPresentationViewModel> createPresentation)
    {
        if (InvestigationWorkspaceFeatureModule.IsAvailable(_featureAccess))
            registration.Register(() => new InvestigationWorkspaceFeatureModule(_featureAccess, createPresentation,
                LoadExplorerChildrenAsync, CreateWorkspaceSharedExplorerTabs(),
                () => (_featureModules.GetOrActivate<WindowsSecurityPresentationServices>(FeatureIds.WindowsSecurityEvents)
                    ?? throw new InvalidOperationException("Security definitions are unavailable.")).DetailsStore,
                inspector => new AiDetailsInvestigationViewModel(
                    _featureModules.GetOrActivate<Services.Ai.AiInvestigationService>(FeatureIds.AiAssistance)
                        ?? throw new InvalidOperationException("AI service is unavailable."), inspector, _annotationStore, _featureAccess),
                getProfiles: () => _featureAccess.IsPublished(FeatureIds.WindowsSecurityEvents)
                    ? (_featureModules.GetOrActivate<WindowsSecurityPresentationServices>(FeatureIds.WindowsSecurityEvents)
                        ?? throw new InvalidOperationException("Security profiles are unavailable.")).Profiles
                    : (_featureModules.GetOrActivate<EventTelemetryPresentationServices>(FeatureIds.EventTelemetry)
                        ?? throw new InvalidOperationException("Event telemetry profiles are unavailable.")).Profiles));
    }
    private IReadOnlyList<FeatureTabDescriptor> CreateWorkspaceSharedExplorerTabs()
    {
        List<FeatureTabDescriptor> tabs =
        [
            new(ExplorerTabKeys.Agents, "Agents", FeatureIds.AgentsAndCapture, 100, () => AgentsViewModel),
            new(ExplorerTabKeys.Sigma, "Sigma", FeatureIds.SearchAndSigma, 300, () => SigmaViewModel, showCount: true)
        ];
        tabs.AddRange(_viewerFeatures.CreateTabDescriptors(FeatureTabSurface.Explorer, _featureModules));
        return tabs.Where(t => _featureAccess.IsPublished(t.FeatureId)).ToArray();
    }
}
