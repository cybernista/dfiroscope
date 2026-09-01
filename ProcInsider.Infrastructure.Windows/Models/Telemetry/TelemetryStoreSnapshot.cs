using System;

namespace ProcInsider.Models;

public class TelemetryStoreSnapshot : IEvidenceStoreSnapshot
{
    public IReadOnlyList<ProcessRecord> Processes { get; set; } = Array.Empty<ProcessRecord>();
    public IReadOnlyList<TelemetryEventRecord> Events { get; set; } = Array.Empty<TelemetryEventRecord>();
    public IReadOnlyList<ModuleObservationRecord> Modules { get; set; } = Array.Empty<ModuleObservationRecord>();
    public IReadOnlyList<HandleObservationRecord> Handles { get; set; } = Array.Empty<HandleObservationRecord>();
    public IReadOnlyList<MemoryDumpRecord> MemoryDumps { get; set; } = Array.Empty<MemoryDumpRecord>();
    public IReadOnlyList<PeAnalysisRecord> PeAnalyses { get; set; } = Array.Empty<PeAnalysisRecord>();
    public IReadOnlyList<NetworkCaptureRecord> NetworkCaptures { get; set; } = Array.Empty<NetworkCaptureRecord>();
    public IReadOnlyList<ZeekNetworkRecord> ZeekNetworkArtifacts { get; set; } = Array.Empty<ZeekNetworkRecord>();
    public IReadOnlyList<FilesystemArtifactRecord> FilesystemArtifacts { get; set; } = Array.Empty<FilesystemArtifactRecord>();
    public IReadOnlyList<MemoryImageRecord> MemoryImages { get; set; } = Array.Empty<MemoryImageRecord>();
    public IReadOnlyList<VolatilityPluginRunRecord> VolatilityPluginRuns { get; set; } = Array.Empty<VolatilityPluginRunRecord>();
    public IReadOnlyList<MemoryProcessRecord> MemoryProcesses { get; set; } = Array.Empty<MemoryProcessRecord>();
    public TelemetryStoreStats Stats { get; set; } = new();
}
