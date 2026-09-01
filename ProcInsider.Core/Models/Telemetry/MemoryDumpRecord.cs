using System;

namespace ProcInsider.Models;

public enum MemoryDumpKind
{
    Full,
    Mini
}

public enum MemoryDumpStatus
{
    Requested,
    Capturing,
    Captured,
    Failed,
    NotFound,
    Unsupported
}

public sealed class MemoryDumpRecord : IHasProcessEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string DumpId { get; set; } = Guid.NewGuid().ToString("N");
    public Guid? JobId { get; set; }
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public string ProcessName { get; set; } = "<unknown>";
    public MemoryDumpKind DumpKind { get; set; } = MemoryDumpKind.Full;
    public MemoryDumpStatus Status { get; set; } = MemoryDumpStatus.Requested;
    public DateTime RequestedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedUtc { get; set; }
    public string OutputDirectory { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public string Sha256Hash { get; set; } = string.Empty;
    public string ToolName { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
}
