using System;

namespace ProcInsider.Models;

public enum MemoryImageStatus
{
    Imported,
    Failed,
    Unsupported
}

public enum VolatilityPluginRunStatus
{
    Queued,
    Running,
    Completed,
    Failed,
    Unsupported
}

public enum MemoryProcessEvidenceKind
{
    Unknown,
    PsList,
    PsScan,
    PsTree,
    CmdLine
}

public enum MemoryProcessCorrelationState
{
    Unknown,
    Correlated,
    MemoryOnly,
    Weak
}

public sealed class MemoryImageRecord : IHasSourceRunEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public string ImageId { get; set; } = Guid.NewGuid().ToString("N");
    public Guid? JobId { get; set; }
    public MemoryImageStatus Status { get; set; } = MemoryImageStatus.Imported;
    public DateTime ImportedUtc { get; set; } = DateTime.UtcNow;
    public string SourcePath { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ImageFormat { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public string Sha256Hash { get; set; } = string.Empty;
    public string HostName { get; set; } = string.Empty;
    public string OsBuild { get; set; } = string.Empty;
    public string AcquisitionTool { get; set; } = string.Empty;
    public string AcquisitionToolVersion { get; set; } = string.Empty;
    public string AcquisitionCommandLine { get; set; } = string.Empty;
    public string PrivilegeState { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string Source { get; set; } = "AgentMemoryImageImport";
}

public sealed class VolatilityPluginRunRecord : IHasSourceRunEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public string RunId { get; set; } = Guid.NewGuid().ToString("N");
    public string ImageId { get; set; } = string.Empty;
    public Guid? JobId { get; set; }
    public string PluginName { get; set; } = string.Empty;
    public VolatilityPluginRunStatus Status { get; set; } = VolatilityPluginRunStatus.Queued;
    public DateTime RequestedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? StartedUtc { get; set; }
    public DateTime? CompletedUtc { get; set; }
    public string VolatilityPath { get; set; } = string.Empty;
    public string VolatilityVersion { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public string OutputDirectory { get; set; } = string.Empty;
    public string StdoutPath { get; set; } = string.Empty;
    public string StderrPath { get; set; } = string.Empty;
    public string RawOutputHash { get; set; } = string.Empty;
    public string SymbolsPath { get; set; } = string.Empty;
    public string ProfileOrLayer { get; set; } = string.Empty;
    public int NormalizedRowCount { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;
    public string Source { get; set; } = "AgentVolatility";
}

public sealed class MemoryProcessRecord : IHasSourceRunEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public string ArtifactId { get; set; } = Guid.NewGuid().ToString("N");
    public string ImageId { get; set; } = string.Empty;
    public string PluginRunId { get; set; } = string.Empty;
    public string PluginName { get; set; } = string.Empty;
    public MemoryProcessEvidenceKind EvidenceKind { get; set; } = MemoryProcessEvidenceKind.Unknown;
    public int RowNumber { get; set; }
    public string ObjectOffset { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ImagePath { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public DateTime? CreateTimeUtc { get; set; }
    public DateTime? ExitTimeUtc { get; set; }
    public int SessionId { get; set; }
    public int ThreadCount { get; set; }
    public int HandleCount { get; set; }
    public string Wow64 { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public MemoryProcessCorrelationState CorrelationState { get; set; } = MemoryProcessCorrelationState.Unknown;
    public string CorrelationMethod { get; set; } = string.Empty;
    public double CorrelationConfidence { get; set; }
    public string RawRowHash { get; set; } = string.Empty;
    public string RawJson { get; set; } = string.Empty;
    public string Source { get; set; } = "AgentVolatility";
}
