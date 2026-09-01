namespace ProcInsider.Models;

/// <summary>
/// Sortable columns for a DB-backed process listing query.
/// Unknown is the safe default: implementations should fall back to
/// process tree / name ordering when the column is not supported.
/// </summary>
public enum ProcessListingSortColumn
{
    Unknown = 0,
    ProcessName,
    ProcessId,
    ParentProcessId,
    ParentProcessName,
    ProcessPath,
    CommandLine,
    UserName,
    SessionId,
    Architecture,
    StartTime,
    EndTime,
    Status,
    CpuUsage,
    MemoryUsage,
    CompanyName,
    FileDescription,
    Sha256Hash,
    ProcessRisk,
    Tree
}

public enum ProcessListingSortDirection
{
    Ascending,
    Descending
}

public enum ProcessListingPagingMode
{
    Offset,
    Cursor
}

public class ProcessListingSortDescriptor
{
    public ProcessListingSortColumn Column { get; set; } = ProcessListingSortColumn.Unknown;
    public ProcessListingSortDirection Direction { get; set; } = ProcessListingSortDirection.Ascending;
}

/// <summary>
/// Typed filter fields matching the process-grid filters in MainViewModel
/// and the display fields in ProcessRowViewModel.
/// All properties are null by default (no filter applied).
/// </summary>
public class ProcessListingFilterSet
{
    public string? ProcessNameContains { get; set; }
    public string? ProcessIdContains { get; set; }
    public int? ProcessIdEquals { get; set; }
    public string? ParentProcessIdContains { get; set; }
    public int? ParentProcessIdEquals { get; set; }
    public string? ParentProcessNameContains { get; set; }
    public string? ProcessPathContains { get; set; }
    public string? CommandLineContains { get; set; }
    public string? UserNameContains { get; set; }
    public int? SessionIdEquals { get; set; }
    public string? ArchitectureContains { get; set; }

    /// <summary>
    /// Typed status filter. Null returns all processes.
    /// Prefer this over a bool flag — ProcessStatus distinguishes Running, Exited, and NotFound.
    /// </summary>
    public ProcessStatus? Status { get; set; }
    public string? StatusContains { get; set; }

    public string? CompanyNameContains { get; set; }
    public string? FileDescriptionContains { get; set; }
    public string? Sha256HashContains { get; set; }
    public string? CaseId { get; set; }
    public string? EvidenceSessionId { get; set; }
    public string? CaptureId { get; set; }
    public string? SourceIdentityId { get; set; }
    public string? HostId { get; set; }
    public string? ExecutionRootId { get; set; }
    public string? ProcessSubtreeRootKey { get; set; }
    public string? OwnerKey { get; set; }
    public bool RequireModules { get; set; }
    public bool RequireHandles { get; set; }
    public string? RequireEventSource { get; set; }
    public bool RequireBookmarked { get; set; }

    /// <summary>
    /// Optional transient green/exclude selectors for forensic scoped selection.
    /// These filter the view only; they do not delete or mutate staged records.
    /// Exclusions are applied after inclusions by query services.
    /// </summary>
    public IReadOnlyList<ExplorerScope> IncludedScopes { get; set; } = [];
    public IReadOnlyList<ExplorerScope> ExcludedScopes { get; set; } = [];
    public IReadOnlyList<string> IncludedProcessKeys { get; set; } = [];
    public IReadOnlyList<string> ExcludedProcessKeys { get; set; } = [];
    public IReadOnlyList<ExplorerScope> SelectedScopes { get; set; } = [];
    public IReadOnlyList<ExplorerScope> SelectedDirectChildScopes { get; set; } = [];
}

public class ProcessListingQuery
{
    public ProcessListingFilterSet Filters { get; set; } = new();
    public ProcessListingSortDescriptor Sort { get; set; } = new();

    /// <summary>
    /// Zero-based row offset used for the first page, random access, Tree ordering,
    /// and other cases where a preceding cursor is unavailable.
    /// </summary>
    public int Offset { get; set; } = 0;
    public int PageSize { get; set; } = 100;

    /// <summary>
    /// Opaque cursor returned by the preceding page. The query service validates
    /// that its version, sort column, and direction match this query before use.
    /// </summary>
    public string? Cursor { get; set; }

    /// <summary>
    /// Compatibility switch for callers that still need count and rows together.
    /// Virtualized listing callers keep this false and issue one separate count.
    /// </summary>
    public bool IncludeTotalCount { get; set; } = true;
}

public class ProcessListingPage
{
    public IReadOnlyList<ProcessRecord> Rows { get; set; } = [];
    public int TotalCount { get; set; } = -1;
    public string? NextCursor { get; set; }
    public bool HasMore { get; set; }
    public ProcessListingPagingMode PagingMode { get; set; } = ProcessListingPagingMode.Offset;
}
