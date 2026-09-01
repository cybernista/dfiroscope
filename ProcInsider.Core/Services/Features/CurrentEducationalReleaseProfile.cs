using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

/// <summary>
/// Core-owned immutable, version-controlled public release profile. It is deliberately not
/// loaded from session state, user settings, environment variables, or IPC.
/// </summary>
public static class CurrentEducationalReleaseProfile
{
    public const string ReleaseId = "edu-2026.08-core-process-agent-infra-g1-readyhidden-r2";

    public static IFeatureCatalog Catalog { get; } = BuildCatalog();

    public static EducationalReleaseProfileReport Report { get; } =
        EducationalReleaseProfileValidator.Validate(
            Catalog,
            FeatureIds.All,
            CurrentInfrastructureModeProfile.Definition);

    private static readonly Lazy<IFeatureCatalog> CompiledRuntimeCatalog = new(
        () => CompiledFeatureCatalogResolver.Resolve(Catalog),
        LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>
    /// Catalog selected only by compile-time private composition. In a public
    /// build this is the exact same instance as <see cref="Catalog"/>.
    /// </summary>
    public static IFeatureCatalog RuntimeCatalog => CompiledRuntimeCatalog.Value;

    private static IFeatureCatalog BuildCatalog()
    {
        // The core release exposes process discovery, selected-process investigation,
        // and local agent/capture orchestration.
        // Later educational releases promote lesson-sized groups from ReadyHidden
        // while their code remains compiled and side-effect free until publication.
        var definitions = new[]
        {
            Published(FeatureIds.ProcessListing),
            Published(FeatureIds.SelectedProcessDetails, FeatureIds.ProcessListing),
            ReadyHidden(FeatureIds.ProcessRiskScore, FeatureIds.ProcessListing, FeatureIds.SelectedProcessDetails),
            ReadyHidden(FeatureIds.ApplicationComparison, FeatureIds.SelectedProcessDetails),
            ReadyHidden(FeatureIds.ModulesAndHandles, FeatureIds.SelectedProcessDetails),
            ReadyHidden(FeatureIds.EventTelemetry, FeatureIds.ProcessListing),
            Published(FeatureIds.AgentsAndCapture),
            ReadyHidden(FeatureIds.CommandLine),
            ReadyHidden(FeatureIds.SearchAndSigma, FeatureIds.ProcessListing, FeatureIds.EventTelemetry),
            ReadyHidden(FeatureIds.DumpsAndPeAnalysis, FeatureIds.SelectedProcessDetails),
            ReadyHidden(FeatureIds.FilesystemArtifacts),
            ReadyHidden(FeatureIds.NetworkAndZeek, FeatureIds.AgentsAndCapture),
            ReadyHidden(FeatureIds.SystemMemoryAndVolatility),
            ReadyHidden(FeatureIds.BaselineComparison, FeatureIds.ProcessListing),
            ReadyHidden(
                FeatureIds.AiAssistance,
                FeatureIds.SelectedProcessDetails,
                FeatureIds.ApplicationComparison),
            ReadyHidden(FeatureIds.KnownFileReferenceData, FeatureIds.SelectedProcessDetails),
            ReadyHidden(FeatureIds.SecurityMonitoringConfiguration, FeatureIds.AgentsAndCapture),
            ReadyHidden(FeatureIds.InfrastructureMode),
            ReadyHidden(FeatureIds.InfrastructureAgentManagement, FeatureIds.InfrastructureMode),
            ReadyHidden(FeatureIds.InfrastructureCaseWorkspaces, FeatureIds.InfrastructureMode),
            ReadyHidden(FeatureIds.InfrastructureAdministration, FeatureIds.InfrastructureMode)
        };

        return new FeatureCatalog(
            ReleaseId,
            CompiledFeatureInventoryComposition.CompleteFeatureDefinitions(definitions));
    }

    private static FeatureDefinition Published(FeatureId id, params FeatureId[] dependencies) =>
        new(id, FeatureReleaseState.Published, dependencies);

    private static FeatureDefinition ReadyHidden(FeatureId id, params FeatureId[] dependencies) =>
        new(id, FeatureReleaseState.ReadyHidden, dependencies);
}
