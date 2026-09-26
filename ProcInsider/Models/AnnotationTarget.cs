namespace ProcInsider.Models;

public sealed class AnnotationTarget
{
    public string TargetKind { get; init; } = string.Empty;
    public string TargetTable { get; init; } = string.Empty;
    public string TargetId { get; init; } = string.Empty;
    public string ArtifactId { get; init; } = string.Empty;
    public string CaseId { get; init; } = string.Empty;
    public string EvidenceSessionId { get; init; } = string.Empty;
    public string CaptureId { get; init; } = string.Empty;
    public string SourceIdentityId { get; init; } = string.Empty;
    public string HostId { get; init; } = string.Empty;
    public string ProcessKey { get; init; } = string.Empty;
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string Label { get; init; } = string.Empty;
    public string DisplayPath { get; init; } = string.Empty;
}
