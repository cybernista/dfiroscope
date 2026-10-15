namespace ProcInsider.Models;

public record EvidenceIdentity
{
    public string CaseId { get; init; } = string.Empty;
    public string EvidenceSessionId { get; init; } = string.Empty;
    public string CaptureId { get; init; } = string.Empty;
    public string SourceIdentityId { get; init; } = string.Empty;
    public string HostId { get; init; } = string.Empty;
    public string ExecutionRootId { get; init; } = string.Empty;

    /// <summary>Compatibility between capture-root evidence and its qualified execution roots.</summary>
    public static bool ExecutionRootsCompatible(string? selectedRoot, string? relatedRoot,
        string evidenceSessionId) =>
        selectedRoot == relatedRoot ||
        string.IsNullOrEmpty(selectedRoot) ||
        string.IsNullOrEmpty(relatedRoot) ||
        (selectedRoot == evidenceSessionId &&
            relatedRoot.StartsWith(evidenceSessionId + "-execution-", StringComparison.Ordinal)) ||
        (relatedRoot == evidenceSessionId &&
            selectedRoot.StartsWith(evidenceSessionId + "-execution-", StringComparison.Ordinal));
}

public interface IHasEvidenceIdentity
{
    string CaseId { get; set; }
    string EvidenceSessionId { get; set; }
    string CaptureId { get; set; }
    string SourceIdentityId { get; set; }
    string HostId { get; set; }
    string ExecutionRootId { get; set; }
}

public interface IHasSourceRunEvidenceLink : IHasEvidenceIdentity
{
    string SourceRunId { get; set; }
    string IngestionJobId { get; set; }
}

public interface IHasProcessEvidenceLink : IHasSourceRunEvidenceLink
{
    string ProcessEntityId { get; set; }
    string ProcessKey { get; set; }
}
