using System;

namespace ProcInsider.Models;

public enum PeAnalysisSourceKind
{
    ProcessImage,
    MemoryDumpFile,
    File
}

public enum PeAnalysisStatus
{
    Completed,
    Failed
}

public enum PeStringExtractionMode
{
    Deferred,
    Immediate
}

public enum PeStringAnalysisStatus
{
    Completed,
    Deferred,
    Failed
}

public enum AuthenticodeSignatureKind
{
    Unknown,
    None,
    Embedded,
    Catalog
}

public enum AuthenticodeVerificationStatus
{
    Unknown,
    Valid,
    Unsigned,
    Invalid,
    Untrusted,
    Expired,
    Revoked,
    RevocationUnavailable,
    AccessDenied,
    FileMissing,
    Unsupported,
    Error
}

public enum AuthenticodeRevocationMode
{
    Unknown,
    None,
    OfflineCacheOnly,
    Online
}

public enum AuthenticodeRevocationStatus
{
    Unknown,
    NotChecked,
    Good,
    Revoked,
    Unavailable
}

/// <summary>
/// One immutable verification observation for a process-image PE analysis.
/// Signature validity establishes publisher identity only; it never establishes benignness.
/// </summary>
public sealed class AuthenticodeVerificationRecord : IHasProcessEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string VerificationId { get; set; } = Guid.NewGuid().ToString("N");
    public string AnalysisId { get; set; } = string.Empty;
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public string ProcessName { get; set; } = "<unknown>";
    public string FilePath { get; set; } = string.Empty;
    public string Sha256Hash { get; set; } = string.Empty;
    public AuthenticodeSignatureKind SignatureKind { get; set; } = AuthenticodeSignatureKind.Unknown;
    public AuthenticodeVerificationStatus VerificationStatus { get; set; } = AuthenticodeVerificationStatus.Unknown;
    public string SignerSubject { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public string CertificateThumbprint { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public bool HasTimestamp { get; set; }
    public string TimestampSubject { get; set; } = string.Empty;
    public DateTime? TimestampUtc { get; set; }
    public string VerificationPolicy { get; set; } = string.Empty;
    public DateTime VerificationTimeUtc { get; set; } = DateTime.UtcNow;
    public AuthenticodeRevocationMode RevocationMode { get; set; } = AuthenticodeRevocationMode.Unknown;
    public AuthenticodeRevocationStatus RevocationStatus { get; set; } = AuthenticodeRevocationStatus.Unknown;
    public string NativeStatusCode { get; set; } = string.Empty;
    public string DiagnosticCode { get; set; } = string.Empty;
    public string DiagnosticText { get; set; } = string.Empty;
    public string Source { get; set; } = "AgentAuthenticodeVerification";
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
}

public sealed class PeAnalysisRecord : IHasProcessEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string AnalysisId { get; set; } = Guid.NewGuid().ToString("N");
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public string ProcessName { get; set; } = "<unknown>";
    public PeAnalysisSourceKind SourceKind { get; set; } = PeAnalysisSourceKind.ProcessImage;
    public string SourceArtifactId { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public PeAnalysisStatus Status { get; set; } = PeAnalysisStatus.Completed;
    public DateTime AnalyzedUtc { get; set; } = DateTime.UtcNow;
    public long FileSizeBytes { get; set; }
    public DateTime? FileLastWriteUtc { get; set; }
    public string Sha256Hash { get; set; } = string.Empty;
    public string Md5Hash { get; set; } = string.Empty;
    public string Machine { get; set; } = string.Empty;
    public string Subsystem { get; set; } = string.Empty;
    public string PeKind { get; set; } = string.Empty;
    public DateTime? LinkerTimestampUtc { get; set; }
    public string EntryPoint { get; set; } = string.Empty;
    public string ImageBase { get; set; } = string.Empty;
    public int SectionCount { get; set; }
    public int ImportCount { get; set; }
    public int ExportCount { get; set; }
    public int PrintableStringCount { get; set; }
    public PeStringAnalysisStatus StringAnalysisStatus { get; set; } = PeStringAnalysisStatus.Completed;
    public string SectionsJson { get; set; } = "[]";
    public string ImportsJson { get; set; } = "[]";
    public string ExportsJson { get; set; } = "[]";
    public string VersionInfoJson { get; set; } = "{}";
    public string StringSummaryJson { get; set; } = "[]";
    public string ErrorMessage { get; set; } = string.Empty;
    public string PerformanceJson { get; set; } = "{}";
    public string Source { get; set; } = "PEAnalysis";
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public AuthenticodeVerificationRecord? AuthenticodeVerification { get; set; }
}

public sealed class PeAnalysisPerformance
{
    public bool ReusedAnalysis { get; set; }
    public double FileOpenMilliseconds { get; set; }
    public double StreamScanMilliseconds { get; set; }
    public double HashFinalizationMilliseconds { get; set; }
    public double StringExtractionMilliseconds { get; set; }
    public double PeParsingMilliseconds { get; set; }
    public double VersionMetadataMilliseconds { get; set; }
    public double QueueDelayMilliseconds { get; set; }
    public double? PersistenceMilliseconds { get; set; }
    public double TotalMilliseconds { get; set; }
}
