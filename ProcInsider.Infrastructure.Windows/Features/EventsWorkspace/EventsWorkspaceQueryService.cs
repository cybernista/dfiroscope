using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Features.InvestigationWorkspaces;
using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;
using ProcInsider.Services.Events;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("DFIRoscope.Live")]
[assembly: InternalsVisibleTo("InvestigationWorkspacesSelfTest")]

namespace ProcInsider.Services;

/// <summary>
/// One immutable validated read generation. Dispose/drain it before snapshot replacement.
/// TEMP contains interpretations only; main is always opened read-only by the assessed facade.
/// </summary>
internal sealed partial class EventsWorkspaceQueryService : IEventsWorkspaceQueryService
{
    public const int MaximumPageSize = 512;
    private readonly SqliteReadQueryContext _context;
    private readonly EventsReadBinding _binding;
    private readonly Func<bool> _isCurrent;
    private readonly string _publishedSources;
    private readonly HashSet<string> _publishedSourceNames;
    private readonly bool _hasWindowsSecurityFacets;
    private readonly bool _hasSysmonPresentation;
    private readonly SemaphoreSlim _gate = new(1);
    private SqliteConnection? _connection;
    private SqliteTransaction? _transaction;
    private EventsCompleteness? _completeness;
    private EventsPreparation? _preparation;
    private bool _disposed;
    private string _nativeColumns = "";
    private readonly CaptureWorkspaceMode _statisticsMode;

    public EventsWorkspaceQueryService(IFeatureCatalog access, SqliteStagingQueryService query,
        EventsReadBinding binding, Func<bool> isCurrent)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(isCurrent);
        if (!access.IsPublished(new FeatureId("events-workspace")) ||
            !access.IsPublished(FeatureIds.InvestigationWorkspaces) ||
            !access.IsPublished(FeatureIds.ProcessListing) || !access.IsPublished(FeatureIds.SelectedProcessDetails))
            throw new InvalidOperationException("Events queries are unavailable in this publication.");
        var publishedSources = EventSourceFamilyOwnershipCatalog.Definitions
            .Where(definition => definition.Family != EventSourceFamilyKind.Runtime &&
                                 access.IsPublished(definition.PresentationFeatureId))
            .Select(definition => definition.ProjectionSource)
            .OrderBy(source => source, StringComparer.Ordinal)
            .ToArray();
        if (publishedSources.Length == 0)
            throw new InvalidOperationException("Events queries require an authorized event presentation source.");
        _publishedSources = JsonSerializer.Serialize(publishedSources);
        _publishedSourceNames = publishedSources.ToHashSet(StringComparer.OrdinalIgnoreCase);
        _hasWindowsSecurityFacets = access.IsPublished(FeatureIds.WindowsSecurityEvents);
        _hasSysmonPresentation = access.IsPublished(EventSourceFamilyOwnershipCatalog.Definitions
            .Single(definition => definition.Family == EventSourceFamilyKind.Sysmon).PresentationFeatureId);
        if (query.CompatibilityAssessment.Context is not (CaptureOpenContext.ViewerLiveSnapshot or CaptureOpenContext.ViewerArchivedReadOnly))
            throw new InvalidOperationException("Events queries require a validated viewer snapshot or archive.");
        if (string.IsNullOrWhiteSpace(binding.EvidenceSessionId)) throw new ArgumentException("An exact session binding is required.");
        _context = query.ReadContext;
        _statisticsMode = query.CompatibilityAssessment.Context == CaptureOpenContext.ViewerArchivedReadOnly
            ? CaptureWorkspaceMode.ArchivedCapture : CaptureWorkspaceMode.LiveCapture;
        _binding = binding;
        _isCurrent = isCurrent;
    }

    public Task<EventsPage> QueryAsync(EventsQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        Validate(query.Filter, query.Offset, query.PageSize);
        if (!Enum.IsDefined(query.Sort)) throw new ArgumentOutOfRangeException(nameof(query));
        if (query.ExtractedSort != null) ValidateExtractedColumn(query.ExtractedSort);
        return RunAsync(() =>
        {
            ConfigureColumns(query.Filter, cancellationToken, query.ExtractedSort);
            var matching = Count(query.Filter);
            var sort = query.ExtractedSort is { } sortIdentity ? ExtractedColumnExpression(NativeColumnIndex(query.Filter, sortIdentity)) : ColumnExpression(query.Sort);
            using var command = Command($"SELECT {_nativeColumns} FROM ew_events e WHERE {Predicate(query.Filter)} " +
                $"ORDER BY {sort} {(query.Descending ? "DESC" : "ASC")}, e.SequenceId {(query.Descending ? "DESC" : "ASC")} LIMIT $take OFFSET $skip;", query.Filter);
            command.Parameters.AddWithValue("$take", query.PageSize);
            command.Parameters.AddWithValue("$skip", query.Offset);
            var records = SelectedProcessEvidenceQueryService.ReadEvents(command);
            var rows = new List<EventsRow>(records.Count);
            foreach (var native in records)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var identitiesCommand = Command("SELECT Payload FROM ew_identities WHERE SequenceId=$sequence ORDER BY Role;");
                identitiesCommand.Parameters.AddWithValue("$sequence", native.SequenceId);
                using var identitiesReader = identitiesCommand.ExecuteReader();
                var identities = new List<EventIdentity>(6);
                while (identitiesReader.Read()) identities.Add(JsonSerializer.Deserialize<EventIdentity>(identitiesReader.GetString(0))!);
                identitiesReader.Close();
                using var correlation = Command("SELECT EWEntity FROM ew_events WHERE SequenceId=$sequence;");
                correlation.Parameters.AddWithValue("$sequence", native.SequenceId);
                var entity = Convert.ToString(correlation.ExecuteScalar(), CultureInfo.InvariantCulture) ?? "";
                EventAuditProjection? audit = null;
                if (_hasWindowsSecurityFacets && native.Source == "Security" && native.RawLogName == "Security")
                {
                    correlation.CommandText = "SELECT Payload FROM ew_audit WHERE SequenceId=$sequence LIMIT 1;";
                    audit = JsonSerializer.Deserialize<EventAuditProjection>((string)correlation.ExecuteScalar()!)!;
                }
                rows.Add(new(Reference(native), native, identities.AsReadOnly(), entity,
                    native.CorrelationState, native.CorrelationCandidateCount, native.CorrelationDiagnostics,
                    audit));
            }
            return new EventsPage(_binding, rows.AsReadOnly(), matching, _completeness!, _preparation!);
        }, cancellationToken);
    }

    private static string ValueOrder(ColumnFilterValueSort sort) => sort switch
    {
        ColumnFilterValueSort.ValueAscending => "Value COLLATE BINARY ASC",
        ColumnFilterValueSort.ValueDescending => "Value COLLATE BINARY DESC",
        ColumnFilterValueSort.CountAscending => "MatchingCount ASC, Value COLLATE BINARY ASC",
        ColumnFilterValueSort.CountDescending => "MatchingCount DESC, Value COLLATE BINARY ASC",
        _ => throw new ArgumentOutOfRangeException(nameof(sort))
    };

    public Task<ColumnFilterValuePage> ColumnValuesAsync(EventsFilter filter, EventSort column, string search,
        CancellationToken cancellationToken = default, ColumnFilterValueSort sort = ColumnFilterValueSort.ValueAscending)
    {
        Validate(filter, 0, 256);
        var expression = ColumnExpression(column);
        var alternatives = filter with { Columns = filter.Columns.Where(p => p.Key != column).ToDictionary() };
        return RunAsync(() =>
        {
            ConfigureColumns(alternatives, cancellationToken);
            using var command = Command($"SELECT CAST({expression} AS TEXT) AS Value, COUNT(*) AS MatchingCount FROM ew_events e WHERE {Predicate(alternatives)} " +
                $"AND ew_text_match(CAST({expression} AS TEXT),$search) GROUP BY Value COLLATE BINARY ORDER BY {ValueOrder(sort)} LIMIT 257;", alternatives);
            command.Parameters.AddWithValue("$search", search);
            using var reader = command.ExecuteReader();
            var values = new List<ColumnFilterValue>();
            while (reader.Read()) { cancellationToken.ThrowIfCancellationRequested(); values.Add(new(reader.IsDBNull(0) ? null : reader.GetString(0), reader.GetInt64(1))); }
            return new ColumnFilterValuePage(values.Take(256).ToArray(), values.Count > 256);
        }, cancellationToken);
    }

    public Task<ColumnFilterValuePage> ColumnValuesAsync(EventsFilter filter, NativeEventColumnIdentity column, string search,
        CancellationToken cancellationToken = default, ColumnFilterValueSort sort = ColumnFilterValueSort.ValueAscending)
    {
        Validate(filter, 0, 256); ValidateExtractedColumn(column);
        var alternatives = filter with { ExtractedColumns = filter.ExtractedColumns.Where(f => f.Identity != column).ToArray() };
        return RunAsync(() =>
        {
            ConfigureColumns(alternatives, cancellationToken, column);
            var expression = ExtractedColumnExpression(alternatives.ExtractedColumns.Count);
            using var command = Command($"SELECT {expression} AS Value, COUNT(*) AS MatchingCount FROM ew_events e WHERE {Predicate(alternatives)} " +
                $"AND ew_text_match({expression},$search) GROUP BY Value COLLATE BINARY ORDER BY {ValueOrder(sort)} LIMIT 257;", alternatives);
            command.Parameters.AddWithValue("$search", search);
            using var reader = command.ExecuteReader();
            var values = new List<ColumnFilterValue>();
            while (reader.Read()) { cancellationToken.ThrowIfCancellationRequested(); values.Add(new(reader.IsDBNull(0) ? null : reader.GetString(0), reader.GetInt64(1))); }
            return new ColumnFilterValuePage(values.Take(256).ToArray(), values.Count > 256);
        }, cancellationToken);
    }

    public Task<EventsAggregates> AggregateAsync(EventsFilter filter, EventAggregateDimension dimension,
        EventIdentityRole role = EventIdentityRole.Actor, long offset = 0, int pageSize = 128,
        CancellationToken cancellationToken = default)
    {
        Validate(filter, offset, pageSize);
        if (!Enum.IsDefined(dimension) || !Enum.IsDefined(role)) throw new ArgumentOutOfRangeException(nameof(dimension));
        if (dimension == EventAggregateDimension.IdentitySession && (filter.IdentityKey == null || filter.IdentityRole != role) ||
            dimension == EventAggregateDimension.AuditSubcategory && filter.AuditCategoryKey == null)
            throw new ArgumentException("A child aggregate requires its exact parent scope.", nameof(filter));
        if (!(_hasWindowsSecurityFacets || _hasSysmonPresentation) &&
                dimension is (EventAggregateDimension.Identity or EventAggregateDimension.IdentitySession) ||
            !_hasWindowsSecurityFacets &&
                dimension is (EventAggregateDimension.Auditing or EventAggregateDimension.AuditSubcategory))
            throw new InvalidOperationException("Identity or Security audit aggregates are unavailable in this publication.");
        return RunAsync(() =>
        {
            ConfigureColumns(filter, cancellationToken);
            var key = dimension switch { EventAggregateDimension.Identity => "i.IdentityKey", EventAggregateDimension.IdentitySession => "i.SessionKey",
                EventAggregateDimension.Auditing => "a.CategoryKey", EventAggregateDimension.AuditSubcategory => "a.SubcategoryKey", EventAggregateDimension.Provider => ColumnExpression(EventSort.Provider),
                EventAggregateDimension.Channel => ColumnExpression(EventSort.Channel), _ => "COALESCE(CAST(e.EventCode AS TEXT),'Unknown')" };
            var identityDimension = dimension is EventAggregateDimension.Identity or EventAggregateDimension.IdentitySession;
            var auditDimension = dimension is EventAggregateDimension.Auditing or EventAggregateDimension.AuditSubcategory;
            var join = identityDimension ? "JOIN ew_identities i ON i.SequenceId=e.SequenceId AND i.Role=$role" :
                auditDimension ? "JOIN ew_audit a ON a.SequenceId=e.SequenceId" : "";
            var securityOnly = auditDimension ? " AND e.Source='Security'" : "";
            var grouped = $"SELECT {key} AS GroupKey, COUNT(DISTINCT e.SequenceId) AS N, MIN(e.SequenceId) AS Representative FROM ew_events e {join} WHERE {Predicate(filter)}{securityOnly} GROUP BY {key}";
            using var total = Command($"SELECT COUNT(*) FROM ({grouped});", filter);
            total.Parameters.AddWithValue("$role", (int)role);
            var totalGroups = (long)total.ExecuteScalar()!;
            using var command = Command($"SELECT GroupKey,N,Representative FROM ({grouped}) ORDER BY N DESC, GroupKey COLLATE BINARY ASC LIMIT $take OFFSET $skip;", filter);
            command.Parameters.AddWithValue("$role", (int)role);
            command.Parameters.AddWithValue("$take", auditDimension ? MaximumPageSize : pageSize);
            command.Parameters.AddWithValue("$skip", auditDimension ? 0 : offset);
            var groups = new List<EventAggregate>();
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                EventIdentity? identity = null;
                EventSessionProjection? session = null;
                if (identityDimension)
                {
                    using var detail = Command("SELECT Payload FROM ew_identities WHERE SequenceId=$sequence AND Role=$role;");
                    detail.Parameters.AddWithValue("$sequence", reader.GetInt64(2));
                    detail.Parameters.AddWithValue("$role", (int)role);
                    identity = JsonSerializer.Deserialize<EventIdentity>((string)detail.ExecuteScalar()!)!;
                    if (dimension == EventAggregateDimension.IdentitySession)
                    {
                        detail.CommandText = "SELECT SessionLabel,SessionDescription FROM ew_identities WHERE SequenceId=$sequence AND Role=$role;";
                        using var sessionReader = detail.ExecuteReader(); sessionReader.Read();
                        session = new("", sessionReader.GetString(0), sessionReader.GetString(1));
                    }
                }
                groups.Add(new(reader.GetString(0), reader.GetInt64(1), identity,
                    dimension == EventAggregateDimension.IdentitySession ? identity!.Key :
                    dimension == EventAggregateDimension.AuditSubcategory ? filter.AuditCategoryKey : null, session?.Label, session?.Description));
            }
            reader.Close();
            if (auditDimension)
            {
                var counts = groups.ToDictionary(g => g.Key, g => g.EventCount);
                var folders = EventsAuditProjection.Folders(dimension, filter.AuditCategoryKey);
                totalGroups = folders.Count;
                groups = folders.Select(g => g with { EventCount = counts.GetValueOrDefault(g.Key) })
                    .Skip((int)Math.Min(offset, int.MaxValue)).Take(pageSize).ToList();
            }
            return new EventsAggregates(_binding, groups.AsReadOnly(), auditDimension ? CountAudit(filter) : Count(filter), totalGroups, _completeness!);
        }, cancellationToken);
    }

    public Task<SysmonEventCounts> SysmonCountsAsync(CancellationToken cancellationToken = default)
    {
        if (!_hasSysmonPresentation || !_publishedSourceNames.Contains(SysmonEventTaxonomy.Source))
            throw new InvalidOperationException("Sysmon presentation is unavailable in this publication.");
        return RunAsync(() =>
        {
            var counts = SysmonEventTaxonomy.EventIds.ToDictionary(id => id, _ => 0L);
            using var command = Command("""
                SELECT e.EventCode, COUNT(*)
                FROM ew_events e
                WHERE e.Source=$sysmonSource
                  AND ($case IS NULL OR COALESCE(e.CaseId,'')=$case)
                  AND COALESCE(e.EvidenceSessionId,'')=$session
                  AND ($capture IS NULL OR COALESCE(e.CaptureId,'')=$capture)
                  AND e.EventCode IN (SELECT value FROM json_each($sysmonIds))
                GROUP BY e.EventCode;
                """, new());
            command.Parameters.AddWithValue("$sysmonSource", SysmonEventTaxonomy.Source);
            command.Parameters.AddWithValue("$sysmonIds", JsonSerializer.Serialize(SysmonEventTaxonomy.EventIds));
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!reader.IsDBNull(0) && counts.ContainsKey(reader.GetInt32(0)))
                    counts[reader.GetInt32(0)] = reader.GetInt64(1);
            }
            return new SysmonEventCounts(_binding, new ReadOnlyDictionary<int, long>(counts));
        }, cancellationToken);
    }

    private async Task<T> RunAsync<T>(Func<T> action, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            Check(token);
            return await Task.Run(() =>
            {
                using var scope = new SqliteWorkScope(token, stage: "Events workspace query");
                try
                {
                    Prepare(token);
                    // A retained connection must receive the current operation's cancellation callback.
                    SqliteWorkScope.Install(_connection!);
                    var result = _context.MeasureRead("EventsWorkspaceQuery", action);
                    Check(token);
                    return result;
                }
                // SQLite reports interruption as9; managed UDF cancellation is wrapped as error1.
                catch (SqliteException ex) when (ex.SqliteErrorCode is 1 or 9 && token.IsCancellationRequested)
                { throw new OperationCanceledException("Events workspace query canceled.", ex, token); }
                finally { ClearProgressCallback(); }
            }, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private void Check(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_isCurrent()) throw new InvalidOperationException("The Events capture binding is stale.");
    }

    private void Prepare(CancellationToken token)
    {
        if (_preparation != null) return;
        var watch = Stopwatch.StartNew();
        try
        {
            _connection = _context.OpenReadOnlyConnection();
            Execute("PRAGMA temp_store=MEMORY;");
            _transaction = _connection.BeginTransaction(deferred: true);
            var columns = Columns("ProcessEvents");
            var relation = Columns("EvidenceRelations");
            string Optional(string name) => columns.Contains(name) ? $"COALESCE(e.{name},'')" : "''";
            var entity = Optional("ProcessEntityId");
            var hasDecisions = new[] { "DecisionKey", "Status", "UpdatedUtc", "RelationId", "CorrelationState", "ToKind", "ToId", "FromKind", "FromId" }.All(relation.Contains);
            var state = hasDecisions ? $"COALESCE(r.CorrelationState, CASE WHEN {entity}<>'' THEN 'Asserted' ELSE 'Unresolved' END)" : $"CASE WHEN {entity}<>'' THEN 'Asserted' ELSE 'Unresolved' END";
            var decisionEntity = hasDecisions ? $"CASE WHEN r.RelationId IS NULL THEN {entity} WHEN r.ToKind='ProcessEntity' THEN COALESCE(r.ToId,'') WHEN r.FromKind='ProcessEntity' THEN COALESCE(r.FromId,'') ELSE '' END" : entity;
            var canonical = $"CASE WHEN {state} IN ('Exact','Asserted','Confirmed') THEN {decisionEntity} ELSE '' END";
            var candidates = hasDecisions && relation.Contains("CandidateCount") ? "COALESCE(r.CandidateCount,0)" : "0";
            var diagnostics = hasDecisions && relation.Contains("CorrelationDiagnostics") ? "COALESCE(r.CorrelationDiagnostics,'')" : "''";
            var method = hasDecisions && relation.Contains("CorrelationMethod") ? "COALESCE(r.CorrelationMethod,e.CorrelationMethod,'')" : "COALESCE(e.CorrelationMethod,'')";
            var join = hasDecisions ? "LEFT JOIN EvidenceRelations r ON r.RelationId=(SELECT active.RelationId FROM EvidenceRelations active WHERE active.DecisionKey='event:'||e.SequenceId||':process' AND active.Status='Active' ORDER BY active.UpdatedUtc DESC,active.RelationId DESC LIMIT 1)" : "";
            Execute($"CREATE TEMP VIEW ew_events AS SELECT e.*, {Optional("SourceRunId")} AS EWSourceRun, {Optional("IngestionJobId")} AS EWJob, {entity} AS EWNativeEntity, {canonical} AS EWEntity, {state} AS EWState, {candidates} AS EWCandidates, {diagnostics} AS EWDiagnostics, {method} AS EWMethod FROM main.ProcessEvents e {join};");
            _nativeColumns = "e.SequenceId,e.TimestampUtc,e.Source,e.ProcessKey,e.ProcessId,e.ProcessGuid,e.ProcessStartTimeUtc,e.ProcessName,e.ParentProcessId,e.EventCode,e.Category,e.Action,e.Target,e.Summary,e.Details,e.RiskFlags,e.IsInteresting,e.RepeatCount,e.RawProvider,e.RawLogName,e.RawRecordIdText,e.CorrelationMethod,e.CaseId,e.EvidenceSessionId,e.CaptureId,e.SourceIdentityId,e.HostId,e.ExecutionRootId,e.EWNativeEntity,e.EWState,e.EWMethod,e.EWCandidates,e.EWDiagnostics,e.EWSourceRun,e.EWJob";
            Execute("CREATE TEMP TABLE ew_identities(SequenceId INTEGER NOT NULL, Role INTEGER NOT NULL, IdentityKey TEXT NOT NULL, Status INTEGER NOT NULL, Payload TEXT NOT NULL, SessionKey TEXT NOT NULL, SessionLabel TEXT NOT NULL, SessionDescription TEXT NOT NULL, PRIMARY KEY(SequenceId,Role)) WITHOUT ROWID;");
            Execute("CREATE TEMP TABLE ew_audit(SequenceId INTEGER NOT NULL, CategoryKey TEXT NOT NULL, SubcategoryKey TEXT NOT NULL, Payload TEXT NOT NULL, PRIMARY KEY(SequenceId,CategoryKey,SubcategoryKey)) WITHOUT ROWID;");
            var sourceColumns = Columns("SourceRuns");
            var liveContext = new[] { "SourceRunId", "CaseId", "EvidenceSessionId", "CaptureId", "HostId", "SourceIdentityId", "ExecutionRootId", "IsLive", "SourceType" }.All(sourceColumns.Contains)
                ? "EXISTS(SELECT 1 FROM SourceRuns sr WHERE sr.SourceRunId=e.EWSourceRun AND sr.IsLive=1 AND sr.SourceType='AgentLiveCapture' " +
                  "AND sr.CaseId=e.CaseId AND sr.EvidenceSessionId=e.EvidenceSessionId AND sr.CaptureId=e.CaptureId AND sr.HostId=e.HostId AND sr.SourceIdentityId=e.SourceIdentityId AND sr.ExecutionRootId=e.ExecutionRootId)" : "0";
            using var scan = Command($"SELECT e.SequenceId,e.CaseId,e.EvidenceSessionId,e.CaptureId,e.SourceIdentityId,e.HostId,e.EWSourceRun,e.EventCode,COALESCE(e.RawProvider,''),COALESCE(e.Details,''),COALESCE(e.RawLogName,''),COALESCE(e.ExecutionRootId,''),{liveContext},e.Source,COALESCE(e.ProcessKey,'') FROM ew_events e WHERE {Predicate(new())} ORDER BY e.SequenceId;", new());
            using var reader = scan.ExecuteReader();
            using var insert = Command("INSERT INTO ew_identities VALUES($sequence,$role,$key,$status,$payload,$sessionKey,$sessionLabel,$sessionDescription);");
            foreach (var name in new[] { "$sequence", "$role", "$key", "$status", "$payload", "$sessionKey", "$sessionLabel", "$sessionDescription" }) insert.Parameters.Add(new SqliteParameter(name, ""));
            using var auditInsert = Command("INSERT INTO ew_audit VALUES($sequence,$category,$subcategory,$payload);");
            foreach (var name in new[] { "$sequence", "$category", "$subcategory", "$payload" }) auditInsert.Parameters.Add(new SqliteParameter(name, ""));
            long parsed = 0, unavailable = 0;
            while (reader.Read())
            {
                Check(token);
                string S(int i) => reader.IsDBNull(i) ? "" : reader.GetString(i);
                var reference = new EventReference(S(1), S(2), S(3), S(4), S(5), S(6), reader.GetInt64(0));
                int? eventId = reader.IsDBNull(7) ? null : reader.GetInt32(7);
                var native = EventsNativeXml.Parse(eventId, S(8), S(9));
                var securityEvent = _hasWindowsSecurityFacets && string.Equals(S(13), "Security", StringComparison.Ordinal) && S(10) == "Security";
                var sysmonEvent = _hasSysmonPresentation && S(13) == SysmonEventTaxonomy.Source &&
                    S(8) == SysmonEventTaxonomy.Provider && S(10) == SysmonEventTaxonomy.Channel;
                IReadOnlyList<EventIdentity> identities = securityEvent
                    ? EventsIdentityProjection.Project(reference, eventId, S(8), S(9), native,
                        matchedLiveProcess: reader.GetInt64(12) == 1 && !string.IsNullOrWhiteSpace(S(14)))
                    : sysmonEvent ? EventsIdentityProjection.ProjectSysmon(reference, native,
                        nativeChannelMatches: native.Channel == SysmonEventTaxonomy.Channel) : [];
                var audit = securityEvent
                    ? EventsAuditProjection.Project(eventId, S(13), S(8), S(10), native)
                    : null;
                if (audit != null)
                {
                    var payload = JsonSerializer.Serialize(audit);
                    foreach (var membership in audit.Memberships)
                    {
                        auditInsert.Parameters["$sequence"].Value = reference.SequenceId;
                        auditInsert.Parameters["$category"].Value = membership.CategoryKey;
                        auditInsert.Parameters["$subcategory"].Value = membership.SubcategoryKey;
                        auditInsert.Parameters["$payload"].Value = payload;
                        auditInsert.ExecuteNonQuery();
                    }
                }
                if (identities.Any(i => i.Status == EventIdentityStatus.Unavailable)) unavailable++;
                foreach (var identity in identities)
                {
                    insert.Parameters["$sequence"].Value = reference.SequenceId;
                    insert.Parameters["$role"].Value = (int)identity.Role;
                    insert.Parameters["$key"].Value = identity.Key;
                    insert.Parameters["$status"].Value = (int)identity.Status;
                    insert.Parameters["$payload"].Value = JsonSerializer.Serialize(identity);
                    var session = EventsSessionProjection.Project(reference, S(11), identity, eventId, S(8), native, reader.GetInt64(12) == 1);
                    insert.Parameters["$sessionKey"].Value = session.Key;
                    insert.Parameters["$sessionLabel"].Value = session.Label;
                    insert.Parameters["$sessionDescription"].Value = session.Description;
                    insert.ExecuteNonQuery();
                }
                parsed++;
            }
            reader.Close();
            Execute("CREATE INDEX temp.ew_identity_lookup ON ew_identities(Role,IdentityKey,SequenceId);");
            Execute("CREATE INDEX temp.ew_session_lookup ON ew_identities(Role,IdentityKey,SessionKey,SequenceId);");
            Execute("CREATE INDEX temp.ew_audit_lookup ON ew_audit(CategoryKey,SubcategoryKey,SequenceId);");
            var sourceExists = new[] { "SourceRunId", "CaseId", "EvidenceSessionId", "CaptureId", "HostId", "SourceIdentityId" }.All(sourceColumns.Contains)
                ? "EXISTS(SELECT 1 FROM SourceRuns sr WHERE sr.SourceRunId=e.EWSourceRun AND COALESCE(sr.CaseId,'')=COALESCE(e.CaseId,'') AND COALESCE(sr.EvidenceSessionId,'')=COALESCE(e.EvidenceSessionId,'') AND COALESCE(sr.CaptureId,'')=COALESCE(e.CaptureId,'') AND COALESCE(sr.HostId,'')=COALESCE(e.HostId,'') AND COALESCE(sr.SourceIdentityId,'')=COALESCE(e.SourceIdentityId,''))" : "0";
            using var gaps = Command($"SELECT COUNT(*) FROM ew_events e WHERE {Predicate(new())} AND (e.EWSourceRun='' OR NOT ({sourceExists}));", new());
            var missingRuns = (long)gaps.ExecuteScalar()!;
            long? observedSources = null, sourcesWithoutHealthyStatus = null;
            if (new[] { "SourceRunId", "CaseId", "EvidenceSessionId", "CaptureId", "SourceType", "Channel", "Status", "MetadataJson" }.All(sourceColumns.Contains))
            {
                var healthBySource = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                using var sources = Command("SELECT COALESCE(sr.SourceType,''),COALESCE(sr.Channel,''),COALESCE(sr.Status,''),COALESCE(sr.MetadataJson,'{}') FROM SourceRuns sr WHERE ($case IS NULL OR COALESCE(sr.CaseId,'')=$case) AND COALESCE(sr.EvidenceSessionId,'')=$session AND ($capture IS NULL OR COALESCE(sr.CaptureId,'')=$capture);", new());
                using var sourceReader = sources.ExecuteReader();
                while (sourceReader.Read())
                {
                    var sourceType = sourceReader.GetString(0);
                    var channel = sourceReader.GetString(1);
                    var status = sourceReader.GetString(2);
                    if (string.Equals(sourceType, "AgentLiveCapture", StringComparison.Ordinal))
                        AddLiveCaptureHealth(sourceReader.GetString(3), healthBySource);
                    else
                    {
                        AddSourceHealth(sourceType, status, healthBySource);
                        AddSourceHealth(channel, status, healthBySource);
                    }
                }
                observedSources = healthBySource.Count;
                sourcesWithoutHealthyStatus = _publishedSourceNames.Count(source =>
                    !healthBySource.TryGetValue(source, out var statuses) || statuses.Any(status => !IsHealthySourceStatus(status)));
            }
            _completeness = new(parsed, unavailable, missingRuns, true, "Unknown: stored records do not establish acquisition coverage or absence of Windows activity.", observedSources, sourcesWithoutHealthyStatus);
            using var pages = Command("PRAGMA temp.page_count;");
            using var size = Command("PRAGMA temp.page_size;");
            var bytes = (long)pages.ExecuteScalar()! * (long)size.ExecuteScalar()!;
            Check(token);
            _preparation = new(parsed, bytes, watch.Elapsed, EventsIdentityProjection.MaximumXmlCharacters);
        }
        catch { ReleaseConnection(); throw; }
    }

    private long Count(EventsFilter filter)
    {
        using var command = Command($"SELECT COUNT(*) FROM ew_events e WHERE {Predicate(filter)};", filter);
        return (long)command.ExecuteScalar()!;
    }
    private long CountAudit(EventsFilter filter)
    {
        // ew_audit has one temporary row per eligible static membership. Count the stored event
        // identity, not memberships, so the audit root is Security-only and overlap-safe.
        using var command = Command($"SELECT COUNT(DISTINCT e.SequenceId) FROM ew_events e JOIN ew_audit a ON a.SequenceId=e.SequenceId WHERE {Predicate(filter)} AND e.Source='Security';", filter);
        return (long)command.ExecuteScalar()!;
    }
    private string Predicate(EventsFilter filter)
    {
        var sql = "e.Source IN (SELECT value FROM json_each($publishedSources)) AND ($case IS NULL OR COALESCE(e.CaseId,'')=$case) AND COALESCE(e.EvidenceSessionId,'')=$session AND ($capture IS NULL OR COALESCE(e.CaptureId,'')=$capture)";
        if (filter.Source != null)
        {
            if (!_publishedSourceNames.Contains(filter.Source)) throw new InvalidOperationException("The requested event source is not published.");
            sql += " AND e.Source=$source";
        }
        if (filter.Provider != null) sql += $" AND {ColumnExpression(EventSort.Provider)}=$provider";
        if (filter.Channel != null) sql += $" AND {ColumnExpression(EventSort.Channel)}=$channel";
        if (filter.EventId.HasValue) sql += " AND e.EventCode=$eventId";
        if (filter.EventIds.Count > 0) sql += " AND e.EventCode IN (SELECT value FROM json_each($eventIds))";
        if (filter.GreenSysmonEventIds.Count > 0)
        {
            if (!_hasSysmonPresentation || !_publishedSourceNames.Contains(SysmonEventTaxonomy.Source))
                throw new InvalidOperationException("Sysmon presentation is unavailable in this publication.");
            sql += " AND e.Source=$greenSysmonSource AND e.EventCode IN (SELECT value FROM json_each($greenSysmonEventIds))";
        }
        if (filter.MissingEventId) sql += " AND e.EventCode IS NULL";
        if (filter.IdentityKey != null) sql += " AND EXISTS(SELECT 1 FROM ew_identities f WHERE f.SequenceId=e.SequenceId AND f.Role=$identityRole AND f.IdentityKey=$identity" +
            (filter.IdentitySessionKey != null ? " AND f.SessionKey=$identitySession" : "") + ")";
        if (filter.AuditCategoryKey != null) sql += " AND e.Source='Security' AND EXISTS(SELECT 1 FROM ew_audit a WHERE a.SequenceId=e.SequenceId AND a.CategoryKey=$auditCategory" +
            (filter.AuditSubcategoryKey != null ? " AND a.SubcategoryKey=$auditSubcategory" : "") + ")";
        foreach (var group in filter.GreenSelectors.GroupBy(s => s.Dimension))
        {
            if (group.Key == EventAggregateDimension.Identity)
            {
                // The most specific matching selector wins within a role; roles remain OR alternatives.
                var values = $"json_each($green{(int)group.Key})";
                sql += " AND EXISTS(SELECT 1 FROM ew_identities f WHERE f.SequenceId=e.SequenceId AND " +
                    $"(SELECT json_extract(g.value,'$.IsExcluded') FROM {values} g WHERE f.Role=json_extract(g.value,'$.Role') AND " +
                    "(json_extract(g.value,'$.AllValues')=1 OR (f.IdentityKey=json_extract(g.value,'$.Key') AND (json_extract(g.value,'$.ChildKey') IS NULL OR f.SessionKey=json_extract(g.value,'$.ChildKey')))) " +
                    "ORDER BY json_extract(g.value,'$.AllValues'), json_extract(g.value,'$.ChildKey') IS NULL, json_extract(g.value,'$.IsExcluded') DESC LIMIT 1)=0)";
                continue;
            }
            if (group.Key == EventAggregateDimension.Auditing)
            {
                var values = $"json_each($green{(int)group.Key})";
                sql += " AND EXISTS(SELECT 1 FROM ew_audit a WHERE a.SequenceId=e.SequenceId AND " +
                    $"(SELECT json_extract(g.value,'$.IsExcluded') FROM {values} g WHERE " +
                    "(json_extract(g.value,'$.AllValues')=1 OR (a.CategoryKey=json_extract(g.value,'$.Key') AND (json_extract(g.value,'$.ChildKey') IS NULL OR a.SubcategoryKey=json_extract(g.value,'$.ChildKey')))) " +
                    "ORDER BY json_extract(g.value,'$.AllValues'), json_extract(g.value,'$.ChildKey') IS NULL, json_extract(g.value,'$.IsExcluded') DESC LIMIT 1)=0)";
                continue;
            }
            string Match(string selection)
            {
                var values = $"(SELECT value FROM json_each($green{(int)group.Key}) WHERE {selection})";
                return group.Key switch
                {
                    EventAggregateDimension.Provider => $"{ColumnExpression(EventSort.Provider)} IN (SELECT json_extract(value,'$.Key') FROM {values})",
                    EventAggregateDimension.Channel => $"{ColumnExpression(EventSort.Channel)} IN (SELECT json_extract(value,'$.Key') FROM {values})",
                    EventAggregateDimension.EventId => $"COALESCE(CAST(e.EventCode AS TEXT),'Unknown') IN (SELECT json_extract(value,'$.Key') FROM {values})",
                    _ => throw new ArgumentOutOfRangeException(nameof(filter))
                };
            }
            if (!group.Any(s => s.AllValues)) sql += $" AND ({Match("json_extract(value,'$.IsExcluded')=0")})";
            if (group.Any(s => s.IsExcluded)) sql += $" AND NOT ({Match("json_extract(value,'$.IsExcluded')=1")})";
        }
        if (filter.ExactEvent != null) sql += " AND e.SequenceId=$sequence AND COALESCE(e.CaseId,'')=$refCase AND COALESCE(e.EvidenceSessionId,'')=$refSession AND COALESCE(e.CaptureId,'')=$refCapture AND COALESCE(e.SourceIdentityId,'')=$refSource AND COALESCE(e.HostId,'')=$refHost AND e.EWSourceRun=$refRun";
        foreach (var pair in filter.Columns.Where(p => p.Value.IsActive))
            sql += $" AND ew_column_match({(int)pair.Key},CAST({ColumnExpression(pair.Key)} AS TEXT))";
        for (var i = 0; i < filter.ExtractedColumns.Count; i++)
            if (filter.ExtractedColumns[i].Criteria.IsActive) sql += $" AND ew_extracted_match({i},{ExtractedColumnExpression(i)})";
        return sql;
    }
    private void AddLiveCaptureHealth(string metadataJson, Dictionary<string, List<string>> healthBySource)
    {
        try
        {
            using var document = JsonDocument.Parse(metadataJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("sources", out var sources) || sources.ValueKind != JsonValueKind.Array) return;
            foreach (var report in sources.EnumerateArray())
            {
                if (report.ValueKind != JsonValueKind.Object || !report.TryGetProperty("source", out var source) ||
                    !report.TryGetProperty("status", out var status) || source.ValueKind != JsonValueKind.String ||
                    status.ValueKind != JsonValueKind.String) continue;
                AddSourceHealth(source.GetString()!, status.GetString()!, healthBySource);
            }
        }
        catch (JsonException) { }
    }
    private void AddSourceHealth(string source, string status, Dictionary<string, List<string>> healthBySource)
    {
        if (!_publishedSourceNames.Contains(source)) return;
        if (!healthBySource.TryGetValue(source, out var statuses)) healthBySource[source] = statuses = [];
        statuses.Add(status);
    }
    private static bool IsHealthySourceStatus(string status) =>
        string.Equals(status, "Active", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "Stopped", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "Completed", StringComparison.OrdinalIgnoreCase);

    private static string MetadataExpression(string column) =>
        $"CASE WHEN ew_etw_metadata_missing(e.Source,CAST(COALESCE({column},'') AS BLOB)) THEN '{TelemetryEventRecord.EtwDisplayName}' ELSE COALESCE({column},'') END";

    private static string ColumnExpression(EventSort column) => column switch
    {
        EventSort.Timestamp => "e.TimestampUtc", EventSort.EventId => "e.EventCode", EventSort.Sequence => "e.SequenceId",
        EventSort.Provider => MetadataExpression("e.RawProvider"), EventSort.Channel => MetadataExpression("e.RawLogName"),
        EventSort.Host => "COALESCE(e.HostId,'')", EventSort.Correlation => "e.EWState || ' (' || e.EWCandidates || ')'",
        EventSort.Description => "ew_description(e.EventCode,COALESCE(e.RawProvider,''),COALESCE(e.RawLogName,''))", EventSort.Details => "ew_details(e.EventCode,COALESCE(e.Details,''),COALESCE(e.RawProvider,''),COALESCE(e.RawLogName,''))",
        EventSort.Actor => $"(SELECT json_extract(Payload,'$.Display') FROM ew_identities WHERE SequenceId=e.SequenceId AND Role={(int)EventIdentityRole.Actor})",
        EventSort.TargetIdentity => $"(SELECT json_extract(Payload,'$.Display') FROM ew_identities WHERE SequenceId=e.SequenceId AND Role={(int)EventIdentityRole.Target})",
        _ => throw new ArgumentOutOfRangeException(nameof(column))
    };

    private static int NativeColumnIndex(EventsFilter filter, NativeEventColumnIdentity column)
    {
        for (var i = 0; i < filter.ExtractedColumns.Count; i++) if (filter.ExtractedColumns[i].Identity == column) return i;
        return filter.ExtractedColumns.Count;
    }
    private static string ExtractedColumnExpression(int index) =>
        $"ew_native_value(e.SequenceId,e.EventCode,substr(CAST(COALESCE(e.Details,'') AS BLOB),1,{NativeEventFieldExtractor.MaximumCharacters * 4 + 4}),CAST(COALESCE(e.RawProvider,'') AS BLOB),CAST(COALESCE(e.RawLogName,'') AS BLOB),{index})";
    private static void ValidateExtractedColumn(NativeEventColumnIdentity column)
    {
        column.Validate();
        if (column.BuiltIn != null) throw new ArgumentException("An extracted column requires a native path.", nameof(column));
    }
    private void ConfigureColumns(EventsFilter filter, CancellationToken token, NativeEventColumnIdentity? extraColumn = null)
    {
        var native = filter.ExtractedColumns.Select(f => f.Identity).Concat(extraColumn == null ? [] : new[] { extraColumn }).Distinct().ToArray();
        using var encodingQuery = Command("PRAGMA encoding;");
        var encoding = (encodingQuery.ExecuteScalar() as string) switch
        {
            "UTF-8" => System.Text.Encoding.UTF8,
            "UTF-16le" => System.Text.Encoding.Unicode,
            "UTF-16be" => System.Text.Encoding.BigEndianUnicode,
            _ => throw new InvalidOperationException("Unrecognized evidence text encoding.")
        };
        // One row per request, never a dataset-sized managed cache. All fields for that row share parsing.
        long? lastSequence = null;
        EventFieldExtraction? extraction = null;
        // Blob arguments preserve embedded NULs across SQLite's callback marshaler; a string argument
        // can truncate at NUL and make a malformed XML suffix or source identity appear valid.
        _connection!.CreateFunction<long, int?, byte[], byte[], byte[], int, string>("ew_native_value", (sequence, id, xml, provider, channel, index) =>
        {
            token.ThrowIfCancellationRequested();
            if (lastSequence != sequence)
            {
                extraction = NativeEventFieldExtractor.Extract(encoding.GetString(xml), id,
                    encoding.GetString(provider), encoding.GetString(channel), token);
                lastSequence = sequence;
            }
            return native[index].DisplayValue(extraction);
        }, isDeterministic: true);
        _connection.CreateFunction<int, string, bool>("ew_extracted_match", (index, value) =>
        {
            token.ThrowIfCancellationRequested();
            return filter.ExtractedColumns[index].Criteria.Matches(value);
        }, isDeterministic: true);
        // Only return the missing flag through the callback. Actual names stay in SQLite, preserving NULs.
        _connection!.CreateFunction<string?, byte[], bool>("ew_etw_metadata_missing",
            (source, value) => string.Equals(source, "ETW", StringComparison.OrdinalIgnoreCase) &&
                string.IsNullOrWhiteSpace(encoding.GetString(value)), isDeterministic: true);
        _connection!.CreateFunction<string?, string?, bool>("ew_text_match", ColumnTextFilter.Matches, isDeterministic: true);
        _connection.CreateFunction<int, string?, bool>("ew_column_match", (key, value) =>
        {
            token.ThrowIfCancellationRequested();
            var column = (EventSort)key;
            DateTime? timestamp = column == EventSort.Timestamp && DateTime.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var time) ? time : null;
            return filter.Columns[column].Matches(value, timestampUtc: timestamp);
        }, isDeterministic: true);
        _connection.CreateFunction<int?, string, string, string>("ew_description", (id, provider, channel) =>
        {
            token.ThrowIfCancellationRequested();
            return (filter.TextProjection ?? throw new InvalidOperationException("Event text projection is unavailable.")).Description(id, provider, channel);
        }, isDeterministic: true);
        _connection.CreateFunction<int?, string, string, string, string>("ew_details", (id, native, provider, channel) =>
        {
            token.ThrowIfCancellationRequested();
            return (filter.TextProjection ?? throw new InvalidOperationException("Event text projection is unavailable.")).Details(id, native, provider, channel);
        }, isDeterministic: true);
    }
    private SqliteCommand Command(string sql, EventsFilter? filter = null)
    {
        var command = _connection!.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = sql;
        if (filter == null) return command;
        command.Parameters.AddWithValue("$case", (object?)_binding.CaseId ?? DBNull.Value);
        command.Parameters.AddWithValue("$session", _binding.EvidenceSessionId);
        command.Parameters.AddWithValue("$capture", (object?)_binding.CaptureId ?? DBNull.Value);
        command.Parameters.AddWithValue("$publishedSources", _publishedSources);
        foreach (var group in filter.GreenSelectors.GroupBy(s => s.Dimension))
            command.Parameters.AddWithValue($"$green{(int)group.Key}", JsonSerializer.Serialize(group.ToArray()));
        if (filter.Provider != null) command.Parameters.AddWithValue("$provider", filter.Provider);
        if (filter.Channel != null) command.Parameters.AddWithValue("$channel", filter.Channel);
        if (filter.EventId.HasValue) command.Parameters.AddWithValue("$eventId", filter.EventId.Value);
        if (filter.Source != null) command.Parameters.AddWithValue("$source", filter.Source);
        if (filter.EventIds.Count > 0) command.Parameters.AddWithValue("$eventIds", JsonSerializer.Serialize(filter.EventIds));
        if (filter.GreenSysmonEventIds.Count > 0)
        {
            command.Parameters.AddWithValue("$greenSysmonSource", SysmonEventTaxonomy.Source);
            command.Parameters.AddWithValue("$greenSysmonEventIds", JsonSerializer.Serialize(filter.GreenSysmonEventIds));
        }
        if (filter.IdentityKey != null)
        {
            command.Parameters.AddWithValue("$identity", filter.IdentityKey);
            command.Parameters.AddWithValue("$identityRole", (int)filter.IdentityRole);
            if (filter.IdentitySessionKey != null) command.Parameters.AddWithValue("$identitySession", filter.IdentitySessionKey);
        }
        if (filter.AuditCategoryKey != null) command.Parameters.AddWithValue("$auditCategory", filter.AuditCategoryKey);
        if (filter.AuditSubcategoryKey != null) command.Parameters.AddWithValue("$auditSubcategory", filter.AuditSubcategoryKey);
        if (filter.ExactEvent is { } r)
        {
            command.Parameters.AddWithValue("$sequence", r.SequenceId);
            command.Parameters.AddWithValue("$refCase", r.CaseId);
            command.Parameters.AddWithValue("$refSession", r.EvidenceSessionId);
            command.Parameters.AddWithValue("$refCapture", r.CaptureId);
            command.Parameters.AddWithValue("$refSource", r.SourceIdentityId);
            command.Parameters.AddWithValue("$refHost", r.HostId);
            command.Parameters.AddWithValue("$refRun", r.SourceRunId);
        }
        return command;
    }
    private void Execute(string sql) { using var command = Command(sql); command.ExecuteNonQuery(); }
    private HashSet<string> Columns(string table)
    {
        using var command = Command($"PRAGMA main.table_info({table});");
        using var reader = command.ExecuteReader();
        var columns = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read()) columns.Add(reader.GetString(1));
        return columns;
    }
    private static EventReference Reference(TelemetryEventRecord e) => new(e.CaseId, e.EvidenceSessionId,
        e.CaptureId, e.SourceIdentityId, e.HostId, e.SourceRunId, e.SequenceId);
    private static void Validate(EventsFilter filter, long offset, int size)
    {
        ArgumentNullException.ThrowIfNull(filter);
        if (offset < 0 || size is < 1 or > MaximumPageSize || !Enum.IsDefined(filter.IdentityRole))
            throw new ArgumentOutOfRangeException(nameof(size));
        if (filter.IdentitySessionKey != null && filter.IdentityKey == null || filter.AuditSubcategoryKey != null && filter.AuditCategoryKey == null)
            throw new ArgumentException("A session/subcategory filter requires its parent.", nameof(filter));
        if ((filter.Source != null && string.IsNullOrWhiteSpace(filter.Source)) || filter.EventIds.Any(id => id < 0) ||
            filter.EventIds.Distinct().Count() != filter.EventIds.Count || filter.EventIds.Count > 0 &&
            (filter.Source != SysmonEventTaxonomy.Source || filter.EventId != null || filter.MissingEventId ||
             filter.EventIds.Any(id => !SysmonEventTaxonomy.EventIds.Contains(id))) ||
            filter.GreenSysmonEventIds.Any(id => !SysmonEventTaxonomy.EventIds.Contains(id)) ||
            filter.GreenSysmonEventIds.Distinct().Count() != filter.GreenSysmonEventIds.Count)
            throw new ArgumentException("Invalid curated Events source scope.", nameof(filter));
        foreach (var pair in filter.Columns) { _ = ColumnExpression(pair.Key); pair.Value.Validate(); }
        foreach (var column in filter.ExtractedColumns) { ValidateExtractedColumn(column.Identity); column.Criteria.Validate(); }
        if (filter.ExtractedColumns.Select(c => c.Identity).Distinct().Count() != filter.ExtractedColumns.Count)
            throw new ArgumentException("Duplicate extracted column criteria.", nameof(filter));
        foreach (var selector in filter.GreenSelectors)
            if (!Enum.IsDefined(selector.Dimension) || selector.Dimension is EventAggregateDimension.IdentitySession or EventAggregateDimension.AuditSubcategory || !Enum.IsDefined(selector.Role) || selector.Key == null ||
                (selector.Dimension != EventAggregateDimension.Identity && selector.Role != EventIdentityRole.Actor) ||
                (selector.ChildKey != null && selector.Dimension is not (EventAggregateDimension.Identity or EventAggregateDimension.Auditing)) ||
                (selector.AllValues && (selector.Key != "" || selector.IsExcluded || selector.ChildKey != null)) ||
                (selector.IsExcluded && !filter.GreenSelectors.Any(s => !s.IsExcluded && s != (selector with { IsExcluded = false }) && s.Covers(selector))) ||
                (!selector.AllValues && selector.Dimension == EventAggregateDimension.EventId && selector.Key != "Unknown" &&
                    (!int.TryParse(selector.Key, NumberStyles.None, CultureInfo.InvariantCulture, out var id) ||
                        id < 0 || id.ToString(CultureInfo.InvariantCulture) != selector.Key)))
                throw new ArgumentException("Invalid Events green selector.", nameof(filter));
    }
    private void ReleaseConnection()
    {
        _statisticsCache = null;
        ClearProgressCallback();
        _transaction?.Dispose(); _transaction = null;
        _connection?.Dispose(); _connection = null;
        _preparation = null; _completeness = null;
    }
    private void ClearProgressCallback()
    {
        if (_connection?.Handle is { } handle)
            SQLitePCL.raw.sqlite3_progress_handler(handle, 0, null!, null!);
    }
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { _disposed = true; ReleaseConnection(); }
        finally { _gate.Release(); }
    }
}
