using ProcInsider.Models;
using ProcInsider.Models.Features;
using System.Runtime.CompilerServices;
using ProcInsider.Services;

[assembly: InternalsVisibleTo("DFIRoscope.Infrastructure.Windows")]

namespace ProcInsider.Features.InvestigationWorkspaces;

internal enum EventIdentityRole { Subject, Actor, Target, Account, Service, Logon }
internal enum EventIdentityStatus { Sid, MissingSid, InvalidSid, Unknown, NotApplicable, Unavailable }
internal enum EventIdentityScope { HostAccount, DomainNamedUnverified, WellKnown, Service, Unknown }
internal enum EventSort { Timestamp, Provider, Channel, EventId, Sequence, Description, Actor, TargetIdentity, Details, Host, Correlation }
internal enum EventAggregateDimension { Identity, Provider, Channel, EventId, Auditing, IdentitySession, AuditSubcategory }

internal sealed record EventGreenSelector(EventAggregateDimension Dimension, string Key,
    EventIdentityRole Role = EventIdentityRole.Actor, bool AllValues = false, bool IsExcluded = false, string? ChildKey = null)
{
    internal bool Covers(EventGreenSelector other) => Dimension == other.Dimension && Role == other.Role &&
        (AllValues || !other.AllValues && Key == other.Key && (ChildKey == null || ChildKey == other.ChildKey));
}

internal static class EventGreenSelection
{
    internal static bool Includes(IEnumerable<EventGreenSelector> selectors, EventGreenSelector value) =>
        selectors.Where(s => s.Covers(value)).OrderBy(s => s.AllValues).ThenBy(s => s.ChildKey == null)
            .ThenByDescending(s => s.IsExcluded).FirstOrDefault() is { IsExcluded: false };
    internal static bool HasDescendant(IEnumerable<EventGreenSelector> selectors, EventGreenSelector parent) =>
        selectors.Any(s => !s.IsExcluded && s != parent && parent.Covers(s));
}

internal sealed record EventsReadBinding(string? CaseId, string EvidenceSessionId, string? CaptureId,
    long CaptureGeneration, long SnapshotGeneration);
internal sealed record EventReference(string CaseId, string EvidenceSessionId, string CaptureId,
    string SourceIdentityId, string HostId, string SourceRunId, long SequenceId);
internal sealed record EventIdentity(string Key, EventIdentityRole Role, EventIdentityStatus Status,
    EventIdentityScope Scope, string Sid, string Domain, string Name, string LogonId, string NativePrefix)
{
    public string Display => (string.IsNullOrEmpty(Name) ? Status.ToString() : string.IsNullOrEmpty(Domain) ? Name : Domain + "\\" + Name) +
        (string.IsNullOrEmpty(Sid) ? "" : $" [{Sid}]");
}
/// <summary>Immutable, headless formatting snapshot supplied by the presentation's definition owner.</summary>
internal interface IEventsTextProjection
{
    /// <summary>Resolves a label only for the exact recorded provider/channel/event identity.</summary>
    string Description(int? eventId, string? provider = null, string? channel = null);
    string Details(int? eventId, string nativeText, string? provider = null, string? channel = null);
}
internal sealed record EventsFilter
{
    public IReadOnlyList<EventGreenSelector> GreenSelectors { get; init; } = [];
    /// <summary>Curated Sysmon Event IDs selected through the Explorer green controls; alternatives are ORed.</summary>
    public IReadOnlyList<int> GreenSysmonEventIds { get; init; } = [];
    public string? Provider { get; init; }
    public string? Channel { get; init; }
    public int? EventId { get; init; }
    /// <summary>Exact catalog-published source discriminator for a curated Events navigation scope.</summary>
    public string? Source { get; init; }
    /// <summary>Exact Event IDs for a curated Events navigation scope; alternatives are ORed.</summary>
    public IReadOnlyList<int> EventIds { get; init; } = [];
    public bool MissingEventId { get; init; }
    public string? IdentityKey { get; init; }
    public string? IdentitySessionKey { get; init; }
    public EventIdentityRole IdentityRole { get; init; } = EventIdentityRole.Actor;
    public string? AuditCategoryKey { get; init; }
    public string? AuditSubcategoryKey { get; init; }
    public EventReference? ExactEvent { get; init; }
    public IReadOnlyDictionary<EventSort, ColumnFilterCriteria> Columns { get; init; } = new Dictionary<EventSort, ColumnFilterCriteria>();
    public IReadOnlyList<ExtractedEventColumnFilter> ExtractedColumns { get; init; } = [];
    public IEventsTextProjection? TextProjection { get; init; }
}
internal sealed record EventsQuery
{
    public EventsFilter Filter { get; init; } = new();
    public EventSort Sort { get; init; } = EventSort.Timestamp;
    public NativeEventColumnIdentity? ExtractedSort { get; init; }
    public bool Descending { get; init; } = true;
    public long Offset { get; init; }
    public int PageSize { get; init; } = 128;
}
internal sealed record EventsCompleteness(long EligibleStoredEvents, long IdentityUnavailableEvents,
    long MissingSourceRunEvents, bool StoredQueryComplete, string AcquisitionCoverage,
    long? ObservedAuthorizedSources, long? SourcesWithoutHealthyStatus);
internal sealed record EventsPreparation(long ParsedEvents, long DerivedIndexBytes, TimeSpan Elapsed,
    int MaximumXmlCharacters);
internal sealed record EventsRow(EventReference Reference, TelemetryEventRecord Native,
    IReadOnlyList<EventIdentity> Identities, string CanonicalProcessEntityId,
    EvidenceCorrelationState CorrelationState, int CandidateCount, string CorrelationDiagnostics, EventAuditProjection? Audit = null);
/// <summary>
/// A read-only navigation membership. One Security event can intentionally have several of
/// these when Windows documents the same Event ID under more than one audit subcategory.
/// </summary>
internal sealed record EventAuditMembership(string CategoryKey, string Category,
    string SubcategoryKey, string Subcategory);

internal sealed record EventAuditProjection(IReadOnlyList<EventAuditMembership> Memberships, string Description)
{
    // These concise values keep the existing Properties display useful without claiming that
    // a shared Event ID has one forensically verified audit-policy origin.
    public string CategoryKey => Memberships.Select(membership => membership.CategoryKey).Distinct().Take(2).ToArray() is [var category]
        ? category : "Unknown";
    public string SubcategoryKey => Memberships.Count == 1 ? Memberships[0].SubcategoryKey : "Unknown";
}
internal sealed record EventsPage(EventsReadBinding Binding, IReadOnlyList<EventsRow> Rows,
    long MatchingEvents, EventsCompleteness Completeness, EventsPreparation Preparation);
internal sealed record EventAggregate(string Key, long EventCount, EventIdentity? Identity,
    string? ParentKey = null, string? Label = null, string? Description = null);
internal sealed record EventsAggregates(EventsReadBinding Binding, IReadOnlyList<EventAggregate> Groups,
    long MatchingEvents, long TotalGroups, EventsCompleteness Completeness);
internal sealed record SysmonEventCounts(EventsReadBinding Binding, IReadOnlyDictionary<int, long> Counts);

internal enum EventsStatisticsScope { CurrentFilteredDataset, EntireCapture }
internal sealed record EventFieldFrequency(string Value, long EventCount)
{
    public string DisplayValue => Value.Length == 0 ? "<empty>" : Value;
}
internal sealed record EventFieldStatistics(ProcInsider.Services.Events.NativeEventType EventType, string Path,
    long PresentEvents, long UniqueValues, IReadOnlyList<EventFieldFrequency> TopValues)
{
    public string Identity => $"{EventType.Provider} / {EventType.Channel} / {EventType.EventId} v{EventType.Version?.ToString() ?? "unknown"} / {Path}";
}
internal sealed record EventsStatisticsProgress(long ProcessedEvents, long EligibleEvents);
internal sealed record EventsFieldStatistics(EventsReadBinding Binding, EventsStatisticsScope Scope,
    long EligibleEvents, long AvailableEvents, long PartialEvents, long FailedEvents,
    IReadOnlyList<EventFieldStatistics> Fields, long DerivedBytes, TimeSpan Elapsed,
    string ExtractorVersion, EventsCompleteness Completeness);

/// <summary>Exact equality filters; no WPF, selected process, or CLI grammar dependency.</summary>
internal interface IEventsWorkspaceQueryService : IAsyncDisposable
{
    Task<ColumnFilterValuePage> ColumnValuesAsync(EventsFilter filter, NativeEventColumnIdentity column, string search,
        CancellationToken cancellationToken = default, ColumnFilterValueSort sort = ColumnFilterValueSort.ValueAscending);
    Task<EventsFieldStatistics> FieldStatisticsAsync(EventsFilter filter, EventsStatisticsScope scope,
        IProgress<EventsStatisticsProgress>? progress = null, CancellationToken cancellationToken = default);
    Task<EventsPage> QueryAsync(EventsQuery query, CancellationToken cancellationToken = default);
    Task<ColumnFilterValuePage> ColumnValuesAsync(EventsFilter filter, EventSort column, string search,
        CancellationToken cancellationToken = default, ColumnFilterValueSort sort = ColumnFilterValueSort.ValueAscending);
    Task<EventsAggregates> AggregateAsync(EventsFilter filter, EventAggregateDimension dimension,
        EventIdentityRole role = EventIdentityRole.Actor, long offset = 0, int pageSize = 128,
        CancellationToken cancellationToken = default);
    Task<SysmonEventCounts> SysmonCountsAsync(CancellationToken cancellationToken = default);
}

internal sealed record ExtractedEventColumnFilter(NativeEventColumnIdentity Identity, ColumnFilterCriteria Criteria);

internal static class EventsWorkspaceFeatureComposition
{
    internal static FeatureId Id => FeatureIds.EventsWorkspace;
}
