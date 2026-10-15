using System.Text.Json;
using System.Globalization;
using Microsoft.Data.Sqlite;
using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal sealed class NetworkEndpointQueryService(SqliteReadQueryContext context) : INetworkEndpointQueryService
{
    private static bool Supported(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('NetworkEndpointPolls','NetworkEndpointObservations');";
        return Convert.ToInt64(command.ExecuteScalar()) == 2;
    }
    public IReadOnlyList<NetworkEndpointPoll> GetPolls(long offset, int pageSize, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        using var connection = context.OpenReadOnlyConnection();
        if (!Supported(connection)) return [];
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Payload FROM NetworkEndpointPolls WHERE IncludesConnections=1 AND SnapshotId IN
                (SELECT SnapshotId FROM NetworkEndpointPolls WHERE IncludesConnections=1
                 GROUP BY SnapshotId ORDER BY MAX(SnapshotStartTicks) DESC,SnapshotId LIMIT $limit OFFSET $offset)
            ORDER BY SnapshotStartTicks DESC,SnapshotId,Family;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(pageSize,1,512)); command.Parameters.AddWithValue("$offset",Math.Max(0,offset));
        using var registration = token.Register(command.Cancel);
        using var reader = command.ExecuteReader();
        var result = new List<NetworkEndpointPoll>();
        while (reader.Read()) { token.ThrowIfCancellationRequested(); result.Add(JsonSerializer.Deserialize<NetworkEndpointPoll>(reader.GetString(0))!); }
        return result;
    }
    public NetworkEndpointPage Query(NetworkEndpointQuery query, CancellationToken token = default) => Execute(query, token).Page;
    public NetworkEndpointPage QueryForHostCapture(NetworkEndpointQuery query, bool includeCompatibleExecutionRoots = false,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (query.Scope is not { } scope || string.IsNullOrWhiteSpace(scope.EvidenceSessionId) ||
            string.IsNullOrWhiteSpace(scope.CaptureId) || string.IsNullOrWhiteSpace(scope.HostId) ||
            query.ExactObservationId is not null)
            throw new ArgumentException("A host endpoint query requires a host/capture scope and no exact object locator.", nameof(query));
        return Execute(query with { Scope = null }, token, hostScope: scope,
            compatibleExecutionRoots: includeCompatibleExecutionRoots).Page;
    }
    public NetworkEndpointPage QueryForProcess(NetworkEndpointProcessQuery query, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(query.Scope);
        if (string.IsNullOrWhiteSpace(query.ProcessEntityId) ||
            string.IsNullOrWhiteSpace(query.Scope.EvidenceSessionId) || string.IsNullOrWhiteSpace(query.Scope.CaptureId) ||
            string.IsNullOrWhiteSpace(query.Scope.HostId))
            throw new ArgumentException("A process endpoint query requires an exact durable process and capture scope.", nameof(query));
        if (query.FromUtcTicks >= query.ToUtcTicks)
            throw new ArgumentOutOfRangeException(nameof(query));
        using var execution = new SqliteWorkScope(token, stage: "Loading selected process network endpoints");
        var effectiveToken = execution.CancellationToken;
        try
        {
            return Execute(new NetworkEndpointQuery(EndpointScopeKind.ListenerHistory,
                FromUtcTicks: query.FromUtcTicks, ToUtcTicks: query.ToUtcTicks,
                PageSize: Math.Clamp(query.MaxRows, 1, 100)), effectiveToken, process: query).Page;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 9 && effectiveToken.IsCancellationRequested)
        {
            throw new OperationCanceledException("SQLite process endpoint query canceled.", ex, effectiveToken);
        }
    }
    public ColumnFilterValuePage Values(NetworkEndpointQuery query, EndpointSort column, string? search, ColumnFilterValueSort sort, CancellationToken token = default) =>
        Execute(query with { Columns = (query.Columns ?? []).Where(f => f.Column != column).ToArray() }, token, column, search, sort).Values!;
    private (NetworkEndpointPage Page, ColumnFilterValuePage? Values) Execute(NetworkEndpointQuery query, CancellationToken token,
        EndpointSort? valueColumn = null, string? search = null, ColumnFilterValueSort valueSort = ColumnFilterValueSort.CountDescending,
        NetworkEndpointProcessQuery? process = null, EvidenceIdentity? hostScope = null,
        bool compatibleExecutionRoots = false)
    {
        token.ThrowIfCancellationRequested();
        using var connection = context.OpenReadOnlyConnection();
        if (!Supported(connection)) return (new([],0,false,"This supported older capture has no recorded OS endpoint inventory; it is not upgraded by browsing."), new([],false));
        using var command = connection.CreateCommand();
        if (process != null) command.CommandTimeout = 10;
        var where = """
            FROM NetworkEndpointObservations o JOIN NetworkEndpointPolls p ON p.PollId=o.PollId
            WHERE p.Outcome=0 AND ($processQuery=1 OR o.Kind=$kind)
              AND ($family=0 OR ($family=1 AND p.Family IN (0,1)) OR ($family=2 AND p.Family IN (2,3)))
              AND ($poll IS NULL OR p.PollId=$poll) AND ($snapshot IS NULL OR p.SnapshotId=$snapshot) AND ($from IS NULL OR CASE WHEN ($processQuery=1 AND o.Kind=2) OR ($processQuery=0 AND $kind=2) THEN COALESCE(p.SnapshotStartTicks,p.WindowStartTicks) ELSE p.WindowStartTicks END >= $from)
              AND ($to IS NULL OR CASE WHEN ($processQuery=1 AND o.Kind=2) OR ($processQuery=0 AND $kind=2) THEN COALESCE(p.SnapshotStartTicks,p.WindowStartTicks) ELSE p.WindowStartTicks END < $to)
              AND ($text IS NULL OR instr(lower(o.Payload),lower($text))>0)
              AND ($run IS NULL OR p.SourceRunId=$run)
              AND ($exactObservation IS NULL OR o.ObservationId=$exactObservation)
              AND ($scoped=0 OR (p.CaseId=$case AND p.EvidenceSessionId=$session AND p.CaptureId=$capture
                  AND p.HostId=$host AND p.ExecutionRootId=$root AND p.SourceIdentityId=$source))
            """;
        var hostPredicate = string.Empty;
        if (hostScope is not null)
        {
            hostPredicate = """
                  AND p.CaseId=$hostCase AND p.EvidenceSessionId=$hostSession
                  AND p.CaptureId=$hostCapture AND p.HostId=$hostHost
                  AND ($hostSource='' OR p.SourceIdentityId=$hostSource)
                  AND ($hostRoot='' OR p.ExecutionRootId=$hostRoot OR
                      ($hostCompatible=1 AND endpoint_host_root_matches(p.ExecutionRootId)))
                """;
            where += hostPredicate;
            connection.CreateFunction<string?, bool>("endpoint_host_root_matches", root =>
                EvidenceIdentity.ExecutionRootsCompatible(hostScope.ExecutionRootId, root, hostScope.EvidenceSessionId), true);
            foreach (var (key, value) in new[] { ("Case", hostScope.CaseId), ("Session", hostScope.EvidenceSessionId),
                ("Capture", hostScope.CaptureId), ("Host", hostScope.HostId), ("Source", hostScope.SourceIdentityId),
                ("Root", hostScope.ExecutionRootId) }) command.Parameters.AddWithValue("$host" + key, value);
            command.Parameters.AddWithValue("$hostCompatible", compatibleExecutionRoots ? 1 : 0);
        }
        if (process != null)
        {
            where += """
                  AND o.Kind IN (0,2) AND json_extract(o.Payload,'$.Native.Ownership')=0
                  AND json_extract(o.Payload,'$.Native.ProcessEntityId')=$processEntity
                  AND p.CaseId=$processCase AND p.EvidenceSessionId=$processSession
                  AND p.CaptureId=$processCapture AND p.HostId=$processHost
                  AND ($processRoot IS NULL OR p.ExecutionRootId=$processRoot)
                  AND ($processSource IS NULL OR p.SourceIdentityId=$processSource)
                """;
            command.Parameters.AddWithValue("$processEntity", process.ProcessEntityId);
            command.Parameters.AddWithValue("$processCase", process.Scope.CaseId);
            command.Parameters.AddWithValue("$processSession", process.Scope.EvidenceSessionId);
            command.Parameters.AddWithValue("$processCapture", process.Scope.CaptureId);
            command.Parameters.AddWithValue("$processHost", process.Scope.HostId);
            command.Parameters.AddWithValue("$processRoot", string.IsNullOrWhiteSpace(process.Scope.ExecutionRootId) ? DBNull.Value : process.Scope.ExecutionRootId);
            command.Parameters.AddWithValue("$processSource", string.IsNullOrWhiteSpace(process.SourceIdentityId) ? DBNull.Value : process.SourceIdentityId);
        }
        command.Parameters.AddWithValue("$kind", query.Kind==EndpointScopeKind.ConnectionSnapshots?2:0);
        command.Parameters.AddWithValue("$exactObservation", query.ExactObservationId is null ? DBNull.Value : query.ExactObservationId);
        command.Parameters.AddWithValue("$processQuery", process == null ? 0 : 1);
        command.Parameters.AddWithValue("$family",query.Kind==EndpointScopeKind.UdpEndpoints?2:query.Kind==EndpointScopeKind.TcpListeners?1:0);
        foreach (var (key,value) in new (string,object?)[] { ("poll",query.PollId),("snapshot",query.SnapshotId),("from",query.FromUtcTicks),("to",query.ToUtcTicks),("text",query.Text),("run",query.SourceRunId) })
            command.Parameters.AddWithValue("$"+key,value??DBNull.Value);
        command.Parameters.AddWithValue("$scoped",query.Scope==null?0:1);
        foreach (var (key,value) in new[] { ("case",query.Scope?.CaseId),("session",query.Scope?.EvidenceSessionId),("capture",query.Scope?.CaptureId),
            ("host",query.Scope?.HostId),("root",query.Scope?.ExecutionRootId),("source",query.Scope?.SourceIdentityId) }) command.Parameters.AddWithValue("$"+key,value??"");
        if (query.GreenSelectors is { Count: > 0 } selectors)
        {
            string Predicate(NetworkEndpointGreenSelector selector, int index)
            {
                var selected = selector.Query;
                var prefix = "$green" + index;
                foreach (var (key, value) in new (string, object?)[] { ("from", selected.FromUtcTicks), ("to", selected.ToUtcTicks),
                    ("snapshot", selected.SnapshotId), ("run", selected.SourceRunId), ("poll", selected.PollId) })
                    command.Parameters.AddWithValue(prefix + key, value ?? DBNull.Value);
                var family = selected.Kind == EndpointScopeKind.TcpListeners ? "p.Family IN (0,1)" :
                    selected.Kind == EndpointScopeKind.UdpEndpoints ? "p.Family IN (2,3)" : "1=1";
                var time = "CASE WHEN o.Kind=2 THEN COALESCE(p.SnapshotStartTicks,p.WindowStartTicks) ELSE p.WindowStartTicks END";
                var scope = "";
                if (selected.Scope is { } identity)
                {
                    foreach (var (column, value) in new[] { ("CaseId", identity.CaseId), ("EvidenceSessionId", identity.EvidenceSessionId),
                        ("CaptureId", identity.CaptureId), ("HostId", identity.HostId), ("ExecutionRootId", identity.ExecutionRootId), ("SourceIdentityId", identity.SourceIdentityId) })
                    { command.Parameters.AddWithValue(prefix + column, value); scope += $" AND p.{column}={prefix}{column}"; }
                }
                return $"({family} AND ({prefix}from IS NULL OR {time}>={prefix}from) AND ({prefix}to IS NULL OR {time}<{prefix}to)" +
                    $" AND ({prefix}snapshot IS NULL OR p.SnapshotId={prefix}snapshot) AND ({prefix}run IS NULL OR p.SourceRunId={prefix}run)" +
                    $" AND ({prefix}poll IS NULL OR p.PollId={prefix}poll){scope})";
            }
            var clauses = selectors.Select((selector, index) => (Selector: selector, Sql: Predicate(selector,index))).ToArray();
            var included = clauses.Where(c => !c.Selector.IsExcluded).Select(c => c.Sql +
                string.Concat(clauses.Where(e => e.Selector.IsExcluded &&
                    (!e.Selector.Covers(c.Selector) || c.Selector.Covers(e.Selector))).Select(e => " AND NOT " + e.Sql))).ToArray();
            if (included.Length > 0) where += " AND (" + string.Join(" OR ", included.Select(s => "(" + s + ")")) + ")";
            else foreach (var excluded in clauses) where += " AND NOT " + excluded.Sql;
        }
        var history = """
            SELECT o.Payload AS ObservationPayload,p.Payload AS PollPayload,o.ObservationId,p.WindowStartTicks,p.WindowEndTicks,
              (SELECT MIN(a.WindowStartTicks) FROM NetworkEndpointObservations d JOIN NetworkEndpointPolls a ON a.PollId=d.PollId
                WHERE d.EpisodeId=o.EpisodeId AND d.Kind=1 AND a.Outcome=0) AS AbsentStart,
              (SELECT MIN(a.WindowEndTicks) FROM NetworkEndpointObservations d JOIN NetworkEndpointPolls a ON a.PollId=d.PollId
                WHERE d.EpisodeId=o.EpisodeId AND d.Kind=1 AND a.Outcome=0) AS AbsentEnd,
              (SELECT MAX(c.WindowEndTicks) FROM NetworkEndpointPolls c WHERE c.SegmentId=p.SegmentId AND c.Family=p.Family AND c.Outcome=0
                AND c.WindowEndTicks < COALESCE((SELECT MIN(a.WindowStartTicks) FROM NetworkEndpointObservations d JOIN NetworkEndpointPolls a ON a.PollId=d.PollId
                  WHERE d.EpisodeId=o.EpisodeId AND d.Kind=1 AND a.Outcome=0),9223372036854775807)) AS LastTicks,
              (EXISTS(SELECT 1 FROM NetworkEndpointPolls c WHERE c.EvidenceSessionId=p.EvidenceSessionId AND c.HostId=p.HostId AND c.CaptureId=p.CaptureId AND c.Family=p.Family
                AND c.WindowStartTicks>p.WindowEndTicks AND (c.SegmentId<>p.SegmentId OR c.Outcome<>0))
                OR EXISTS(SELECT 1 FROM SourceRuns r WHERE r.SourceRunId=p.SourceRunId AND r.Status<>'Active')) AS Gap
            """ + " " + where;
        connection.CreateFunction<string?,long?,long?,string?>("endpoint_display", (address,port,scope) =>
            address == null ? null : NetworkAddressPresentation.Endpoint(address, port == null ? null : (int)port, scope == null ? null : (uint)scope), true);
        connection.CreateFunction<long?,string?>("endpoint_time", ticks => ticks == null ? null : new DateTime(ticks.Value,DateTimeKind.Utc).ToString("O",CultureInfo.InvariantCulture), true);
        var expressions = Enum.GetValues<EndpointSort>().ToDictionary(c => c, ColumnExpression);
        var projection = "WITH history AS (" + history + "), projected AS (SELECT history.*," +
            string.Join(",", expressions.Select(p => p.Value + " AS v" + (int)p.Key)) + " FROM history) ";
        var filters = query.Columns ?? [];
        if (filters.Count > expressions.Count) throw new ArgumentOutOfRangeException(nameof(query));
        var predicates = new List<string>();
        for(var i=0;i<filters.Count;i++)
        {
            var filter=filters[i];filter.Criteria.Validate();var criteria=filter.Criteria;var column=filter.Column;
            var function="endpoint_filter"+i;
            connection.CreateFunction<string?,bool>(function, value => criteria.Matches(ValueText(column,value),
                IsNumber(column) && long.TryParse(value,out var n)?n:null,
                IsTimestamp(column) && long.TryParse(value,out var t)?new DateTime(t,DateTimeKind.Utc):null), true);
            predicates.Add(function+"(CAST(v"+(int)column+" AS TEXT))");
        }
        var filtered=" FROM projected"+(predicates.Count==0?"":" WHERE "+string.Join(" AND ",predicates));
        using var registration=token.Register(command.Cancel);
        if(valueColumn is { } choices)
        {
            if(!expressions.ContainsKey(choices))throw new ArgumentOutOfRangeException(nameof(valueColumn));
            var value=IsTimestamp(choices)?$"endpoint_time(v{(int)choices})":$"CAST(v{(int)choices} AS TEXT)";
            connection.CreateFunction<string?,bool>("endpoint_value_search",text=>ColumnTextFilter.Matches(text,search),true);
            var order=valueSort switch
            {
                ColumnFilterValueSort.ValueAscending=>"Value ASC",ColumnFilterValueSort.ValueDescending=>"Value DESC",
                ColumnFilterValueSort.CountAscending=>"Occurrences ASC,Value ASC",ColumnFilterValueSort.CountDescending=>"Occurrences DESC,Value ASC",
                _=>throw new ArgumentOutOfRangeException(nameof(valueSort))
            };
            command.CommandText=projection+$"SELECT Value,COUNT(*) AS Occurrences FROM (SELECT {value} AS Value{filtered}) WHERE endpoint_value_search(Value) GROUP BY Value ORDER BY {order} LIMIT 257;";
            using var valuesReader=command.ExecuteReader();var values=new List<ColumnFilterValue>();
            while(valuesReader.Read()){token.ThrowIfCancellationRequested();values.Add(new(valuesReader.IsDBNull(0)?null:valuesReader.GetString(0),valuesReader.GetInt64(1)));}
            return (new([],0,true,""),new(values.Take(256).ToArray(),values.Count>256));
        }
        if(!expressions.ContainsKey(query.Sort))throw new ArgumentOutOfRangeException(nameof(query.Sort));
        command.CommandText=projection+"SELECT COUNT(*)"+filtered;
        var count=Convert.ToInt64(command.ExecuteScalar());
        command.Parameters.AddWithValue("$limit",Math.Clamp(query.PageSize,1,512));command.Parameters.AddWithValue("$offset",Math.Max(0,query.Offset));
        var sortCollation=query.Sort is EndpointSort.ProcessName or EndpointSort.ImagePath or EndpointSort.CommandLine?" COLLATE NOCASE":"";
        command.CommandText=projection+"SELECT ObservationPayload,PollPayload,AbsentStart,AbsentEnd,LastTicks,Gap"+filtered+
            $" ORDER BY v{(int)query.Sort}{sortCollation} {(query.Descending?"DESC":"ASC")},ObservationId LIMIT $limit OFFSET $offset;";
        using var reader=command.ExecuteReader(); var rows=new List<NetworkEndpointHistoryRow>();
        while(reader.Read())
        {
            token.ThrowIfCancellationRequested();
            var observation=JsonSerializer.Deserialize<NetworkEndpointObservation>(reader.GetString(0))!;
            var poll=JsonSerializer.Deserialize<NetworkEndpointPoll>(reader.GetString(1))!;
            DateTime? Date(int n)=>reader.IsDBNull(n)?null:new DateTime(reader.GetInt64(n),DateTimeKind.Utc);
            rows.Add(new(observation,poll,poll.WindowStartUtc,
                observation.Kind==EndpointObservationKind.ConnectionSnapshot?poll.WindowEndUtc:Date(4)??poll.WindowEndUtc,
                Date(3),Date(2),reader.GetInt64(5)!=0));
        }
        reader.Dispose();
        var coverageScope = process == null ? "" : """
              AND p.CaseId=$processCase AND p.EvidenceSessionId=$processSession
              AND p.CaptureId=$processCapture AND p.HostId=$processHost
              AND ($processRoot IS NULL OR p.ExecutionRootId=$processRoot)
              AND ($processSource IS NULL OR p.SourceIdentityId=$processSource)
            """;
        coverageScope += hostPredicate;
        var coverageTime = process == null
            ? """
                AND ($from IS NULL OR CASE WHEN $kind=2 THEN COALESCE(p.SnapshotStartTicks,p.WindowStartTicks) ELSE p.WindowStartTicks END >= $from)
                AND ($to IS NULL OR CASE WHEN $kind=2 THEN COALESCE(p.SnapshotStartTicks,p.WindowStartTicks) ELSE p.WindowStartTicks END < $to)
                """
            : """
                AND ((($from IS NULL OR p.WindowStartTicks >= $from) AND ($to IS NULL OR p.WindowStartTicks < $to))
                  OR (p.IncludesConnections=1 AND ($from IS NULL OR COALESCE(p.SnapshotStartTicks,p.WindowStartTicks) >= $from)
                    AND ($to IS NULL OR COALESCE(p.SnapshotStartTicks,p.WindowStartTicks) < $to)))
                """;
        command.CommandText="""
            SELECT p.Payload, s.Status FROM NetworkEndpointPolls p JOIN SourceRuns s ON s.SourceRunId=p.SourceRunId WHERE
              ($family=0 OR ($family=1 AND p.Family IN(0,1)) OR ($family=2 AND p.Family IN(2,3))) AND
              ($poll IS NULL OR p.PollId=$poll) AND ($snapshot IS NULL OR p.SnapshotId=$snapshot)
              AND ($run IS NULL OR p.SourceRunId=$run)
              AND ($scoped=0 OR (p.CaseId=$case AND p.EvidenceSessionId=$session AND p.CaptureId=$capture
                  AND p.HostId=$host AND p.ExecutionRootId=$root AND p.SourceIdentityId=$source))
            """ + coverageScope + coverageTime + " ORDER BY p.WindowEndTicks DESC LIMIT 16;";
        using var coverageReader=command.ExecuteReader();var coverage=new List<NetworkEndpointPoll>();var ended=false;
        while(coverageReader.Read()){token.ThrowIfCancellationRequested();coverage.Add(JsonSerializer.Deserialize<NetworkEndpointPoll>(coverageReader.GetString(0))!);ended|=coverageReader.GetString(1)!="Active";}
        var relevant=query.Kind switch
        {
            EndpointScopeKind.ListenerHistory=>new[]{EndpointFamily.TcpV4,EndpointFamily.TcpV6,EndpointFamily.UdpV4,EndpointFamily.UdpV6},
            EndpointScopeKind.UdpEndpoints=>new[]{EndpointFamily.UdpV4,EndpointFamily.UdpV6},
            _=>new[]{EndpointFamily.TcpV4,EndpointFamily.TcpV6}
        };
        var detail=string.Join("; ",relevant.Select(f=>coverage.FirstOrDefault(p=>p.Family==f) is { } p?$"{f}: {p.Outcome} [{p.WindowStartUtc:O}, {p.WindowEndUtc:O}] {p.Diagnostic}":$"{f}: coverage unknown / unavailable"));
        return (new(rows,count,true,detail+(ended?". Recorded source coverage ended; current presence is unknown":"")+". Sampled OS tables: 5-second listeners / UDP bindings; 5-minute TCP snapshots. Gaps and tuple reuse prevent exact socket lifetime or traffic-direction conclusions."),null);
    }
    internal static bool IsTimestamp(EndpointSort column) => column is EndpointSort.ObservedUtc or EndpointSort.LastObservedUtc or EndpointSort.FirstAbsentUtc;
    internal static bool IsNumber(EndpointSort column) => column is EndpointSort.LocalPort or EndpointSort.ProcessId or EndpointSort.TcpState;
    private static string? ValueText(EndpointSort column,string? value) => IsTimestamp(column) && long.TryParse(value,out var ticks)
        ? new DateTime(ticks,DateTimeKind.Utc).ToString("O",CultureInfo.InvariantCulture) : value;
    private static string ColumnExpression(EndpointSort column) => column switch
    {
        EndpointSort.ObservedUtc => "WindowStartTicks",
        EndpointSort.LastObservedUtc => "CASE WHEN json_extract(ObservationPayload,'$.Kind')=2 THEN WindowEndTicks ELSE COALESCE(LastTicks,WindowEndTicks) END",
        EndpointSort.FirstAbsentUtc => "AbsentEnd",
        EndpointSort.Family => "CASE json_extract(ObservationPayload,'$.Native.Family') WHEN 0 THEN 'TcpV4' WHEN 1 THEN 'TcpV6' WHEN 2 THEN 'UdpV4' WHEN 3 THEN 'UdpV6' END",
        EndpointSort.LocalAddress => "endpoint_display(json_extract(ObservationPayload,'$.Native.LocalAddress'),json_extract(ObservationPayload,'$.Native.LocalPort'),json_extract(ObservationPayload,'$.Native.LocalScopeId'))",
        EndpointSort.RemoteEndpoint => "endpoint_display(json_extract(ObservationPayload,'$.Native.RemoteAddress'),json_extract(ObservationPayload,'$.Native.RemotePort'),json_extract(ObservationPayload,'$.Native.RemoteScopeId'))",
        EndpointSort.LocalPort => "json_extract(ObservationPayload,'$.Native.LocalPort')",
        EndpointSort.ProcessId => "json_extract(ObservationPayload,'$.Native.ProcessId')",
        EndpointSort.TcpState => "json_extract(ObservationPayload,'$.Native.TcpState')",
        EndpointSort.ProcessName => Metadata("ProcessName","NameState"),
        EndpointSort.ImagePath => Metadata("ImagePath","ImageState"),
        EndpointSort.CommandLine => Metadata("CommandLine","CommandLineState"),
        EndpointSort.Ownership => "CASE json_extract(ObservationPayload,'$.Native.Ownership') WHEN 0 THEN 'VerifiedLifetime' ELSE 'Unresolved' END",
        EndpointSort.CoverageGap => "CASE Gap WHEN 0 THEN 'False' ELSE 'True' END",
        _ => throw new ArgumentOutOfRangeException(nameof(column))
    };
    private static string Metadata(string field,string state) => $"COALESCE(json_extract(ObservationPayload,'$.Native.Metadata.{field}'),CASE json_extract(ObservationPayload,'$.Native.Metadata.{state}') WHEN 0 THEN 'NotRecorded' WHEN 1 THEN 'Available' WHEN 2 THEN 'AccessDenied' WHEN 3 THEN 'Unavailable' WHEN 4 THEN 'Exited' WHEN 5 THEN 'Timeout' WHEN 6 THEN 'Unsupported' ELSE 'Not recorded' END)";
}
