using System;

namespace ProcInsider.Models;

public enum NetworkCaptureStatus
{
    Requested,
    Capturing,
    Stopping,
    Captured,
    Failed,
    Unsupported,
    Stale
}

public sealed class NetworkCaptureRecord : IHasSourceRunEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = Guid.NewGuid().ToString("N");
    public Guid? JobId { get; set; }
    public int SegmentIndex { get; set; } = 1;
    public NetworkCaptureStatus Status { get; set; } = NetworkCaptureStatus.Requested;
    public DateTime RequestedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? StartedUtc { get; set; }
    public DateTime? CompletedUtc { get; set; }
    public string OutputDirectory { get; set; } = string.Empty;
    public string EtlFilePath { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public string Sha256Hash { get; set; } = string.Empty;
    public string ToolName { get; set; } = "pktmon";
    public string CaptureSource { get; set; } = "LocalHost";
    public string FilterDescription { get; set; } = "Packet Monitor capture";
    public string ErrorMessage { get; set; } = string.Empty;
    public string Source { get; set; } = "AgentNetworkCapture";
}
