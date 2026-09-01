using System.Collections.Generic;

namespace ProcInsider.Models;

public enum ExplorerScopeKind
{
    Placeholder,
    Branch,
    CaseSessionRoot,
    EvidenceRoot,
    ProcessTrees,
    AllProcesses,
    RunningProcesses,
    ExitedProcesses,
    NotFoundProcesses,
    ProcessOwners,
    ProcessOwner,
    ProcessExecutionRoot,
    ProcessBranch,
    FilesystemRoot,
    FilesystemEvidenceRoots,
    FilesystemArtifacts,
    FilesystemFolder,
    NetworkRoot,
    NetworkCaptures,
    NetworkCapture,
    ZeekArtifacts,
    AnalysisRoot,
    SearchResults,
    SigmaFindings,
    CorrelationEvidence,
    UnresolvedEvidence,
    AmbiguousEvidence,
    CorrelationEvidenceGroup,
    ArtifactRoot,
    MemoryDumps,
    PeAnalyses,
    Modules,
    Handles,
    RuntimeEvents,
    EtwEvents,
    SecurityEvents,
    PowerShellEvents,
    WindowsOtherEvents,
    SysmonEvents,
    SystemActivityRoot,
    ActivityAuthentication,
    ActivitySuccessfulLogons,
    ActivityFailedLogons,
    ActivityRemoteInteractive,
    ActivityExplicitCredentialUse,
    ActivityPrivilegedLogons,
    ActivityAccounts,
    ActivityCreatedUsers,
    ActivityDisabledDeletedUsers,
    ActivityPasswordChanges,
    ActivityGroups,
    ActivityLocalAdministratorsChanges,
    ActivitySecurityGroupMembershipChanges,
    ActivityPolicyAudit,
    ActivityAuditPolicyChanged,
    ActivityLogIntegrity,
    ActivitySecurityLogCleared,
    ActivityServicesTasks,
    ActivityServicesInstalled,
    ActivityScheduledTasksChanged,
    UsersRoot,
    UserAccount,
    Bookmarked
}

public enum ExplorerArtifactScope
{
    None,
    Modules,
    Handles
}

public sealed class ExplorerScope
{
    public string ScopeId { get; init; } = string.Empty;
    public ExplorerScopeKind Kind { get; init; }
    public string Title { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string StableId => string.IsNullOrWhiteSpace(ScopeId) ? Kind.ToString() : ScopeId;
    public ProcessStatus? Status { get; init; }
    public ExplorerArtifactScope ArtifactScope { get; init; }
    /// <summary>
    /// Optional PE-analysis source predicate for process-listing Explorer scopes.
    /// </summary>
    public PeAnalysisSourceKind? RequiredPeAnalysisSourceKind { get; init; }
    public string? EventSource { get; init; }
    public string? CaseId { get; init; }
    public string? EvidenceSessionId { get; init; }
    public string? CaptureId { get; init; }
    public string? SourceIdentityId { get; init; }
    public string? HostId { get; init; }
    public string? ExecutionRootId { get; init; }
    public string? ProcessKey { get; init; }
    public string? OwnerKey { get; init; }
    public string? OwnerDisplayName { get; init; }
    public string? OwnerDomain { get; init; }
    public string? OwnerSid { get; init; }
    public string? FilesystemPath { get; init; }
    public SystemActivityScopeKind? SystemActivityScope { get; init; }
    public string? AccountKey { get; init; }
    public string? AccountDisplayName { get; init; }
    public string? AccountDomain { get; init; }
    public string? AccountSid { get; init; }
    public EvidenceCorrelationState? CorrelationState { get; init; }
    public EvidenceReferenceKind? CorrelationEvidenceKind { get; init; }
    public string? CorrelationSource { get; init; }
}

public sealed class ExplorerScopeCounts
{
    public int TotalProcesses { get; init; }
    public int RunningProcesses { get; init; }
    public int ExitedProcesses { get; init; }
    public int NotFoundProcesses { get; init; }
    public int ModuleProcesses { get; init; }
    public int HandleProcesses { get; init; }
    public int BookmarkedProcesses { get; init; }
    public int MemoryDumpCount { get; init; }
    public int MemoryImageCount { get; init; }
    public int PeAnalysisCount { get; init; }
    public int NetworkCaptureCount { get; init; }
    public int ZeekNetworkArtifactCount { get; init; }
    public int FilesystemArtifactCount { get; init; }
    public int SearchResultCount { get; init; }
    public int SigmaFindingCount { get; init; }
    public int UnresolvedEvidenceCount { get; init; }
    public int AmbiguousEvidenceCount { get; init; }
    public int SystemActivityCount { get; init; }
    public int SystemActivityAccountCount { get; init; }
    public IReadOnlyDictionary<SystemActivityScopeKind, int> SystemActivityCountsByScope { get; init; } =
        new Dictionary<SystemActivityScopeKind, int>();
    public IReadOnlyDictionary<string, int> EventProcessesBySource { get; init; } = new Dictionary<string, int>();
}

public sealed record ExplorerScopeCountStageTiming(
    string Stage,
    TimeSpan Elapsed,
    int RowCount);

public sealed record ExplorerScopeCountReadResult(
    ExplorerScopeCounts Counts,
    IReadOnlyList<ExplorerScopeCountStageTiming> Stages,
    TimeSpan TotalElapsed);

public sealed class ExplorerProcessNodeSummary
{
    public string ProcessKey { get; init; } = string.Empty;
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string ProcessPath { get; init; } = string.Empty;
    public ProcessStatus Status { get; init; }
    public string ParentProcessKey { get; init; } = string.Empty;
    /// <summary>
    /// Total number of distinct reachable descendants at every depth, excluding this process.
    /// Lazy expansion remains limited to immediate children.
    /// </summary>
    public int DescendantProcessCount { get; init; }
    public string CaseId { get; init; } = string.Empty;
    public string EvidenceSessionId { get; init; } = string.Empty;
    public string CaptureId { get; init; } = string.Empty;
    public string SourceIdentityId { get; init; } = string.Empty;
    public string HostId { get; init; } = string.Empty;
    public string ExecutionRootId { get; init; } = string.Empty;
}

public sealed class ExplorerProcessOwnerSummary
{
    public string OwnerKey { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string Domain { get; init; } = string.Empty;
    public string Sid { get; init; } = string.Empty;
    public int ProcessCount { get; init; }
    public string CaseId { get; init; } = string.Empty;
    public string EvidenceSessionId { get; init; } = string.Empty;
    public string CaptureId { get; init; } = string.Empty;
    public string SourceIdentityId { get; init; } = string.Empty;
    public string HostId { get; init; } = string.Empty;
    public string ExecutionRootId { get; init; } = string.Empty;
}

public sealed class ExplorerFilesystemNodeSummary
{
    public string FolderPath { get; init; } = string.Empty;
    public int ArtifactCount { get; init; }
    public int ChildFolderCount { get; init; }
    public string CaseId { get; init; } = string.Empty;
    public string EvidenceSessionId { get; init; } = string.Empty;
    public string CaptureId { get; init; } = string.Empty;
    public string SourceIdentityId { get; init; } = string.Empty;
    public string HostId { get; init; } = string.Empty;
    public string ExecutionRootId { get; init; } = string.Empty;
}
