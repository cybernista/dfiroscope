namespace ProcInsider.Models;

/// <summary>
/// Immutable identity and bounded metadata for one acquisition, import, enrichment, or analyzer execution.
/// <c>Sources</c> remains the compatibility provider/definition catalog; this record identifies one run.
/// </summary>
public sealed record SourceRunDescriptor
{
    public string SourceRunId { get; init; } = string.Empty;
    public Guid? IngestionJobId { get; init; }
    public string CaseId { get; init; } = string.Empty;
    public string EvidenceSessionId { get; init; } = string.Empty;
    public string CaptureId { get; init; } = string.Empty;
    public string SourceIdentityId { get; init; } = string.Empty;
    public string HostId { get; init; } = string.Empty;
    public string ExecutionRootId { get; init; } = string.Empty;
    public string SourceType { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string SourcePath { get; init; } = string.Empty;
    public string Provider { get; init; } = string.Empty;
    public string Channel { get; init; } = string.Empty;
    public string ConfigurationHash { get; init; } = string.Empty;
    public bool IsLive { get; init; }
    public string ToolVersion { get; init; } = string.Empty;
    public string ParserVersion { get; init; } = string.Empty;
    public string MetadataJson { get; init; } = "{}";
    public string ParentSourceRunId { get; init; } = string.Empty;
    public string InputArtifactId { get; init; } = string.Empty;
    public string InputPath { get; init; } = string.Empty;
    public string InputHash { get; init; } = string.Empty;
    public DateTime StartedUtc { get; init; } = DateTime.UtcNow;
}

public sealed record SourceRunRegistration(int SourceId, string SourceRunId);

/// <summary>Exact provenance captured by an agent writer work item.</summary>
public sealed record EvidenceWriteProvenance(string SourceRunId, Guid IngestionJobId);

public sealed class SourceRunSummary
{
    public string SourceRunId { get; set; } = string.Empty;
    public int SourceId { get; set; }
    public Guid? IngestionJobId { get; set; }
    public string SourceType { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public DateTime? StartedUtc { get; set; }
    public DateTime? EndedUtc { get; set; }
    public string SourcePath { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public string Channel { get; set; } = string.Empty;
    public string ToolVersion { get; set; } = string.Empty;
    public string ParserVersion { get; set; } = string.Empty;
    public string ParentSourceRunId { get; set; } = string.Empty;
    public string InputArtifactId { get; set; } = string.Empty;
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
}

public sealed class SourceRunDiagnostics
{
    public int SourceRunCount { get; set; }
    public int LegacySourceRunCount { get; set; }
    public int MissingEvidenceLinkCount { get; set; }
    public int MissingJobLinkCount { get; set; }
}
