namespace ProcInsider.Models.Ai;

public enum AiEvidenceSourceKind
{
    ProcessProperties,
    ProcessDescription,
    Modules,
    Handles,
    RuntimeEvents,
    EtwEvents,
    SecurityEvents,
    PowerShellEvents,
    WindowsOtherEvents,
    SysmonEvents,
    MemoryDumps,
    PeOnDisk,
    PeFromMemoryDump,
    ZeekArtifacts,
    FilesystemArtifacts
}
