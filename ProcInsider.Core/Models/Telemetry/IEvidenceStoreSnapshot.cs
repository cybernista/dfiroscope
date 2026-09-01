namespace ProcInsider.Models;

public interface IEvidenceStoreSnapshot
{
    IReadOnlyList<ProcessRecord> Processes { get; }

    IReadOnlyList<TelemetryEventRecord> Events { get; }

    IReadOnlyList<ModuleObservationRecord> Modules { get; }

    IReadOnlyList<HandleObservationRecord> Handles { get; }

    IReadOnlyList<MemoryDumpRecord> MemoryDumps { get; }

    IReadOnlyList<PeAnalysisRecord> PeAnalyses { get; }

    IReadOnlyList<NetworkCaptureRecord> NetworkCaptures { get; }

    IReadOnlyList<ZeekNetworkRecord> ZeekNetworkArtifacts { get; }

    IReadOnlyList<FilesystemArtifactRecord> FilesystemArtifacts { get; }

    IReadOnlyList<MemoryImageRecord> MemoryImages { get; }

    IReadOnlyList<VolatilityPluginRunRecord> VolatilityPluginRuns { get; }

    IReadOnlyList<MemoryProcessRecord> MemoryProcesses { get; }
}
