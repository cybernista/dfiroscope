using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Viewer-only compatibility materialization for the retained legacy snapshot contract.
/// All SQLite reads remain owned by the infrastructure query service.
/// </summary>
public static class SqliteStagingQueryServiceCompatibilityExtensions
{
    public static TelemetryStoreSnapshot CreateSnapshotForAnalysis(
        this SqliteStagingQueryService queryService)
    {
        ArgumentNullException.ThrowIfNull(queryService);

        var input = queryService.CreateSnapshotAnalysisInput();
        return new TelemetryStoreSnapshot
        {
            Processes = input.Processes,
            Events = SigmaAnalysisEvaluator.CreateEvaluationEvents(input),
            Modules = input.Modules,
            Handles = input.Handles,
            NetworkCaptures = input.NetworkCaptures,
            ZeekNetworkArtifacts = input.ZeekNetworkArtifacts,
            FilesystemArtifacts = input.FilesystemArtifacts,
            MemoryImages = input.MemoryImages,
            VolatilityPluginRuns = input.VolatilityPluginRuns,
            MemoryProcesses = input.MemoryProcesses,
            Stats = queryService.GetStats()
        };
    }
}
