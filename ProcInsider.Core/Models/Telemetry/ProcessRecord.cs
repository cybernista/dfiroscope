using System;

namespace ProcInsider.Models;

public class ProcessRecord : IHasEvidenceIdentity
{
    public string ProcessEntityId { get; set; } = string.Empty;
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public DateTime? StartTimeUtc { get; set; }
    public DateTime? EndTimeUtc { get; set; }
    public ProcessStatus Status { get; set; } = ProcessStatus.Running;
    public ArtifactCaptureStatus ModuleCaptureStatus { get; set; } = ArtifactCaptureStatus.Pending;
    public int ModuleCount { get; set; }
    public DateTime? ModuleLastCapturedUtc { get; set; }
    public string ModuleCaptureError { get; set; } = string.Empty;
    public ArtifactCaptureStatus HandleCaptureStatus { get; set; } = ArtifactCaptureStatus.Pending;
    public int HandleCount { get; set; }
    public DateTime? HandleLastCapturedUtc { get; set; }
    public string HandleCaptureError { get; set; } = string.Empty;
    public int ParentProcessId { get; set; }
    public string ParentProcessKey { get; set; } = string.Empty;
    public string ParentProcessEntityId { get; set; } = string.Empty;
    public string ParentProcessName { get; set; } = "<unknown>";
    public string ProcessName { get; set; } = "<unknown>";
    public string ProcessPath { get; set; } = "<not available>";
    public string CommandLine { get; set; } = "<not available>";
    public string UserName { get; set; } = "<not available>";
    public int SessionId { get; set; }
    public string Architecture { get; set; } = "<not available>";
    public double CpuUsage { get; set; }
    public long MemoryUsageBytes { get; set; }
    public string CompanyName { get; set; } = "<not available>";
    public string FileDescription { get; set; } = "<not available>";
    public string Sha256Hash { get; set; } = "<not available>";
    public int TreeDepth { get; set; }
    public DateTime FirstObservedUtc { get; set; }
    public DateTime LastObservedUtc { get; set; }
    public string LastSource { get; set; } = string.Empty;
    public ProcessInfo ToProcessInfo()
    {
        return new ProcessInfo
        {
            ProcessEntityId = ProcessEntityId,
            ProcessKey = ProcessKey,
            ProcessId = ProcessId,
            StartTime = StartTimeUtc?.ToLocalTime(),
            ParentProcessId = ParentProcessId,
            ParentProcessKey = ParentProcessKey,
            ParentProcessEntityId = ParentProcessEntityId,
            ParentProcessName = ParentProcessName,
            ProcessName = ProcessName,
            ProcessGuid = ProcessGuid,
            ProcessPath = ProcessPath,
            CommandLine = CommandLine,
            UserName = UserName,
            SessionId = SessionId,
            Architecture = Architecture,
            EndTime = EndTimeUtc?.ToLocalTime(),
            Status = Status,
            ModuleCaptureStatus = ModuleCaptureStatus,
            ModuleCount = ModuleCount,
            ModuleLastCaptured = ModuleLastCapturedUtc?.ToLocalTime(),
            ModuleCaptureError = ModuleCaptureError,
            HandleCaptureStatus = HandleCaptureStatus,
            HandleCount = HandleCount,
            HandleLastCaptured = HandleLastCapturedUtc?.ToLocalTime(),
            HandleCaptureError = HandleCaptureError,
            CpuUsage = CpuUsage,
            MemoryUsageBytes = MemoryUsageBytes,
            CompanyName = CompanyName,
            FileDescription = FileDescription,
            Sha256Hash = Sha256Hash,
            CaseId = CaseId,
            EvidenceSessionId = EvidenceSessionId,
            CaptureId = CaptureId,
            SourceIdentityId = SourceIdentityId,
            HostId = HostId,
            ExecutionRootId = ExecutionRootId,
            TreeDepth = TreeDepth
        };
    }
}
