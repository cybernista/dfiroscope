using System;

namespace ProcInsider.Models;

public enum ModuleObservationState
{
    Loaded,
    Unloaded,
    Observed,
    NotFound,
    Failed
}

public class ModuleObservationInput : IHasProcessEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public string ModuleName { get; set; } = "<unknown>";
    public string FullPath { get; set; } = "<not available>";
    public string BaseAddress { get; set; } = "<not available>";
    public long ModuleMemorySize { get; set; }
    public string FileVersion { get; set; } = "<not available>";
    public string CompanyName { get; set; } = "<not available>";
    public string Description { get; set; } = "<not available>";
    public string Sha256Hash { get; set; } = "<not available>";
    public DateTime ObservedUtc { get; set; } = DateTime.UtcNow;
    public string Source { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
}

public class ModuleObservationRecord : IHasProcessEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public long SequenceId { get; set; }
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public string ModuleKey { get; set; } = string.Empty;
    public string ModuleName { get; set; } = "<unknown>";
    public string FullPath { get; set; } = "<not available>";
    public string BaseAddress { get; set; } = "<not available>";
    public long ModuleMemorySize { get; set; }
    public string FileVersion { get; set; } = "<not available>";
    public string CompanyName { get; set; } = "<not available>";
    public string Description { get; set; } = "<not available>";
    public string Sha256Hash { get; set; } = "<not available>";
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public DateTime? UnloadedUtc { get; set; }
    public ModuleObservationState State { get; set; } = ModuleObservationState.Loaded;
    public string Sources { get; set; } = string.Empty;
    public string LastSource { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;

    public ModuleInfo ToModuleInfo()
    {
        return new ModuleInfo
        {
            ProcessEntityId = ProcessEntityId,
            SourceRunId = SourceRunId,
            IngestionJobId = IngestionJobId,
            ModuleName = ModuleName,
            FullPath = FullPath,
            BaseAddress = BaseAddress,
            ModuleMemorySize = ModuleMemorySize,
            FileVersion = FileVersion,
            CompanyName = CompanyName,
            Description = Description,
            Sha256Hash = Sha256Hash,
            FirstSeenUtc = FirstSeenUtc,
            LastSeenUtc = LastSeenUtc,
            UnloadedUtc = UnloadedUtc,
            State = State
        };
    }
}
