using System;

namespace ProcInsider.Models;

public enum ZeekArtifactStatus
{
    Imported,
    Failed
}

public sealed class ZeekNetworkRecord : IHasSourceRunEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public string ArtifactId { get; set; } = Guid.NewGuid().ToString("N");
    public string CaptureId { get; set; } = string.Empty;
    public Guid? JobId { get; set; }
    public ZeekArtifactStatus Status { get; set; } = ZeekArtifactStatus.Imported;
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public string LogType { get; set; } = string.Empty;
    public string ZeekUid { get; set; } = string.Empty;
    public string SourceIp { get; set; } = string.Empty;
    public int SourcePort { get; set; }
    public string DestinationIp { get; set; } = string.Empty;
    public int DestinationPort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string Service { get; set; } = string.Empty;
    public string DnsQuery { get; set; } = string.Empty;
    public string HttpMethod { get; set; } = string.Empty;
    public string HttpHost { get; set; } = string.Empty;
    public string HttpUri { get; set; } = string.Empty;
    public double DurationSeconds { get; set; }
    public long OrigBytes { get; set; }
    public long RespBytes { get; set; }
    public long OrigPackets { get; set; }
    public long RespPackets { get; set; }
    public long OrigIpBytes { get; set; }
    public long RespIpBytes { get; set; }
    public string ConnectionState { get; set; } = string.Empty;
    public string History { get; set; } = string.Empty;
    public string ServerName { get; set; } = string.Empty;
    public string ClientProtocol { get; set; } = string.Empty;
    public string TlsVersion { get; set; } = string.Empty;
    public string TlsCipher { get; set; } = string.Empty;
    public bool TlsEstablished { get; set; }
    public string WeirdName { get; set; } = string.Empty;
    public string WeirdAdditional { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string CorrelationMethod { get; set; } = string.Empty;
    public double CorrelationConfidence { get; set; }
    public EvidenceCorrelationState CorrelationState => string.IsNullOrWhiteSpace(ProcessKey)
        ? EvidenceCorrelationState.Unresolved
        : CorrelationConfidence >= 0.95
            ? EvidenceCorrelationState.Exact
            : CorrelationConfidence >= 0.50
                ? EvidenceCorrelationState.Inferred
                : EvidenceCorrelationState.Ambiguous;
    public string RawLogPath { get; set; } = string.Empty;
    public long RawLineNumber { get; set; }
    public string RawLineHash { get; set; } = string.Empty;
    public string RawText { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string Source { get; set; } = "AgentZeek";
}
