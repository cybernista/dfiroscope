using ProcInsider.Models.Features;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

/// <summary>
/// Immutable XAML projection of the authoritative feature catalog.
/// </summary>
public sealed class FeaturePublicationViewModel
{
    private readonly FeatureAccessService _access;

    public FeaturePublicationViewModel(FeatureAccessService access)
    {
        _access = access;
    }

    public string ReleaseId => _access.Catalog.ReleaseId;
    public bool ProcessListing => IsPublished(FeatureIds.ProcessListing);
    public bool SelectedProcessDetails => IsPublished(FeatureIds.SelectedProcessDetails);
    public bool ProcessRiskScore => IsPublished(FeatureIds.ProcessRiskScore);
    public bool ApplicationComparison => IsPublished(FeatureIds.ApplicationComparison);
    public bool ModulesAndHandles => IsPublished(FeatureIds.ModulesAndHandles);
    public bool EventTelemetry => IsPublished(FeatureIds.EventTelemetry);
    public bool AgentsAndCapture => IsPublished(FeatureIds.AgentsAndCapture);
    public bool SearchAndSigma => IsPublished(FeatureIds.SearchAndSigma);
    public bool DumpsAndPeAnalysis => IsPublished(FeatureIds.DumpsAndPeAnalysis);
    public bool FilesystemArtifacts => IsPublished(FeatureIds.FilesystemArtifacts);
    public bool NetworkAndZeek => IsPublished(FeatureIds.NetworkAndZeek);
    public bool SystemMemoryAndVolatility => IsPublished(FeatureIds.SystemMemoryAndVolatility);
    public bool BaselineComparison => IsPublished(FeatureIds.BaselineComparison);
    public bool AiAssistance => IsPublished(FeatureIds.AiAssistance);
    public bool KnownFileReferenceData => IsPublished(FeatureIds.KnownFileReferenceData);
    public bool SecurityMonitoringConfiguration => IsPublished(FeatureIds.SecurityMonitoringConfiguration);

    public bool ArtifactEnrichmentMenu => ModulesAndHandles || DumpsAndPeAnalysis || FilesystemArtifacts;

    public bool IsPublished(FeatureId featureId) => _access.IsPublished(featureId);
}
