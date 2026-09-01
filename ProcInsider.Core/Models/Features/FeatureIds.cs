namespace ProcInsider.Models.Features;

/// <summary>
/// Core-owned authoritative stable IDs for the initial educational-release feature inventory.
/// </summary>
public static partial class FeatureIds
{
    public static readonly FeatureId ProcessListing = new("process-listing");
    public static readonly FeatureId SelectedProcessDetails = new("selected-process-details");
    public static readonly FeatureId ProcessRiskScore = new("process-risk-score");
    public static readonly FeatureId ApplicationComparison = new("application-comparison");
    public static readonly FeatureId ModulesAndHandles = new("modules-handles");
    public static readonly FeatureId EventTelemetry = new("event-telemetry");
    public static readonly FeatureId AgentsAndCapture = new("agents-capture");
    public static readonly FeatureId SearchAndSigma = new("search-sigma");
    public static readonly FeatureId DumpsAndPeAnalysis = new("dumps-pe-analysis");
    public static readonly FeatureId FilesystemArtifacts = new("filesystem-artifacts");
    public static readonly FeatureId NetworkAndZeek = new("network-zeek");
    public static readonly FeatureId SystemMemoryAndVolatility = new("system-memory-volatility");
    public static readonly FeatureId BaselineComparison = new("baseline-comparison");
    public static readonly FeatureId AiAssistance = new("ai-assistance");
    public static readonly FeatureId KnownFileReferenceData = new("known-file-reference-data");
    public static readonly FeatureId SecurityMonitoringConfiguration = new("security-monitoring-configuration");
    public static readonly FeatureId CommandLine = new("command-line");
    public static readonly FeatureId InfrastructureMode = new("infrastructure-mode");
    public static readonly FeatureId InfrastructureAgentManagement = new("infrastructure-agent-management");
    public static readonly FeatureId InfrastructureCaseWorkspaces = new("infrastructure-case-workspaces");
    public static readonly FeatureId InfrastructureAdministration = new("infrastructure-administration");

    public static IReadOnlyList<FeatureId> All { get; } =
        CompiledFeatureInventoryComposition.CompleteFeatureIds(
        [
            ProcessListing,
            SelectedProcessDetails,
            ProcessRiskScore,
            ApplicationComparison,
            ModulesAndHandles,
            EventTelemetry,
            AgentsAndCapture,
            SearchAndSigma,
            DumpsAndPeAnalysis,
            FilesystemArtifacts,
            NetworkAndZeek,
            SystemMemoryAndVolatility,
            BaselineComparison,
            AiAssistance,
            KnownFileReferenceData,
            SecurityMonitoringConfiguration,
            CommandLine,
            InfrastructureMode,
            InfrastructureAgentManagement,
            InfrastructureCaseWorkspaces,
            InfrastructureAdministration
        ]);
}
