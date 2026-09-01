namespace ProcInsider.Models;

/// <summary>
/// Identifies the kind of artifact currently being inspected.
/// </summary>
public enum InspectorArtifactKind
{
    None,
    ExplorerScope,
    Process,
    Module,
    Handle,
    Event,
    MemoryDump,
    PeAnalysis,
    ProcessStatistics,
    NetworkCapture,
    ZeekNetworkArtifact,
    FilesystemArtifact,
    MemoryImage,
    VolatilityPluginRun,
    MemoryProcess,
    CorrelationEvidence
}
