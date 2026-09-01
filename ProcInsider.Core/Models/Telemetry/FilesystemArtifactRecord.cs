using System;
using System.Collections.Generic;

namespace ProcInsider.Models;

public enum FilesystemArtifactKind
{
    Unknown,
    NtfsMft,
    NtfsUsnJournal,
    NtfsLogFile,
    Prefetch,
    FileMetadata
}

public enum FilesystemArtifactStatus
{
    Imported,
    Failed
}

public sealed class FilesystemArtifactRecord : IHasSourceRunEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public string ParentArtifactId { get; set; } = string.Empty;
    public string ArtifactId { get; set; } = Guid.NewGuid().ToString("N");
    public Guid? JobId { get; set; }
    public FilesystemArtifactKind Kind { get; set; } = FilesystemArtifactKind.Unknown;
    public FilesystemArtifactStatus Status { get; set; } = FilesystemArtifactStatus.Imported;
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public string Name { get; set; } = string.Empty;
    public string SourcePath { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public DateTime? CreatedUtc { get; set; }
    public DateTime? LastModifiedUtc { get; set; }
    public string Sha256Hash { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int RunCount { get; set; }
    public DateTime? LastRunUtc { get; set; }
    public string RawRecordId { get; set; } = string.Empty;
    public string RawPayloadHash { get; set; } = string.Empty;
    public string RawText { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string Source { get; set; } = "AgentArtifactImport";
    public IReadOnlyDictionary<string, string> Properties { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
