using ProcInsider.Models;
using ProcInsider.Models.Persistence;
using ProcInsider.Services;

namespace ProcInsider.Features.PersistenceWorkspace;

public enum PersistenceView { Current, Changes }
public enum PersistenceColumn { Type, Name, Location, TargetCommand, Principal, FirstObservedUtc, LastChangedUtc, LastConfirmedUtc, ObservedUtc, Change, Freshness, Generation }
public sealed record PersistenceColumnFilter(PersistenceColumn Column, ColumnFilterCriteria Criteria);
public sealed record PersistenceSelector(PersistenceView? View = null, string? Category = null, bool Excluded = false,
    string? PeriodId = null, EvidenceIdentity? Scope = null);
public sealed record PersistenceWorkspaceQuery(EvidenceIdentity Scope, PersistenceView View = PersistenceView.Current,
    string? Category = null, IReadOnlyList<PersistenceSelector>? Selectors = null,
    IReadOnlyList<PersistenceColumnFilter>? Filters = null, PersistenceColumn Sort = PersistenceColumn.Name,
    bool Descending = false, long Offset = 0, int PageSize = 128, string? PeriodId = null,
    PersistenceObjectReference? ExactObject = null);
public sealed record PersistencePeriod(string PeriodId, DateTime? StartedUtc, DateTime LastObservedUtc,
    string? BaselineCollectionId, bool Active, bool CoherentBoundary);
public sealed record PersistenceWorkspaceRow(EvidenceIdentity Scope, string PartitionKey, string ArtifactKey,
    PersistenceArtifact Artifact, PersistenceCollection Collection, PersistenceVersion? Version,
    DateTime? FirstObservedUtc, DateTime? LastChangedUtc, DateTime? LastConfirmedUtc, bool Stale)
{
    public string Type => Artifact.Category;
    public string Name => Artifact.NativeName;
    public string Location => Artifact.NativeLocation;
    public string? TargetCommand => Artifact.Command ?? Artifact.Target;
    public string? Principal => Artifact.Principal;
    public DateTime ObservedUtc => Collection.CompletedUtc;
    public string Change => Version?.Kind == PersistenceChangeKind.ObservedIncomplete ? "Observed incomplete" : Version?.Kind.ToString() ?? "";
    public string Freshness => Version?.Kind == PersistenceChangeKind.ObservedIncomplete
        ? "Observed incomplete / unconfirmed" : Stale ? "Stale / latest known" : "Confirmed for declared coverage";
    public string Generation => Collection.StateGenerationId;
    public string Identity => string.Join("/", PersistenceComparisonPolicy.ScopeKey(Scope), PartitionKey, ArtifactKey, Collection.CollectionId);
}
public sealed record PersistenceCoverageRow(PersistenceCollection Collection, PersistenceCollectorResult Result);
// CategoryCounts and the requested ViewCounts entry use the full effective query before
// paging. Other ViewCounts entries are unfiltered inventory totals, never an authority
// for a sibling UI view with its own retained criteria; query that view independently.
public sealed record PersistenceWorkspacePage(IReadOnlyList<PersistenceWorkspaceRow> Rows, long MatchingRows,
    IReadOnlyDictionary<string, long> CategoryCounts, IReadOnlyDictionary<PersistenceView, long> ViewCounts,
    IReadOnlyList<PersistenceCoverageRow> Coverage, string Diagnostic);
public sealed record PersistenceObjectReference(EvidenceIdentity Scope, string PartitionKey, string ArtifactKey, string CollectionId, string? PeriodId = null);
public sealed record PersistenceHistoryQuery(PersistenceObjectReference Object, IReadOnlyList<PersistenceColumnFilter>? Filters = null,
    PersistenceColumn Sort = PersistenceColumn.ObservedUtc, bool Descending = true, long Offset = 0, int PageSize = 128);
public sealed record PersistenceHistoryPage(IReadOnlyList<PersistenceWorkspaceRow> Rows, long MatchingRows);
public sealed record PersistenceObjectDetail(PersistenceWorkspaceRow Row, PersistenceArtifact? Before, PersistenceArtifact? After);
public interface IPersistenceWorkspaceQueryService
{
    IReadOnlyList<EvidenceIdentity> Scopes(string evidenceSessionId, CancellationToken token = default);
    IReadOnlyList<PersistencePeriod> Periods(EvidenceIdentity scope, long offset = 0, int pageSize = 128, CancellationToken token = default);
    bool IsJobAccepted(EvidenceIdentity scope, Guid jobId, CancellationToken token = default);
    PersistenceWorkspacePage Query(PersistenceWorkspaceQuery query, CancellationToken token = default);
    ColumnFilterValuePage Values(PersistenceWorkspaceQuery query, PersistenceColumn column, string? search,
        ColumnFilterValueSort sort, CancellationToken token = default);
    PersistenceHistoryPage History(PersistenceHistoryQuery query, CancellationToken token = default);
    ColumnFilterValuePage HistoryValues(PersistenceHistoryQuery query, PersistenceColumn column, string? search, ColumnFilterValueSort sort, CancellationToken token = default);
    PersistenceObjectDetail Detail(PersistenceObjectReference reference, CancellationToken token = default);
}
