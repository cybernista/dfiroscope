using System.Globalization;
using System.Text.Json;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Models;

namespace ProcInsider.Services.NetworkWorkspace;

/// <summary>
/// Capture-scoped, on-demand examination index for supported recorded Sysmon and Security events.
/// The source is always an assessed snapshot/archive facade; this service never opens live evidence.
/// A complete binding generation is published only after its bounded reconciliation scan succeeds.
/// </summary>
public sealed class NetworkAnalysisService : IAsyncDisposable
{
    private const int SchemaVersion = 3;
    private const int BatchSize = 128;
    private readonly SqliteStagingQueryService _source;
    private readonly NetworkAnalysisBinding _binding;
    private readonly string _analysisPath;
    private readonly string _readBindingId = Guid.NewGuid().ToString("N");
    private bool _completed;
    private readonly string _sourceFingerprint;
    private readonly SemaphoreSlim _gate;
    private readonly Func<bool> _isCurrent;
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> CaptureGates = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    private NetworkAnalysisService(SqliteStagingQueryService source, NetworkAnalysisBinding binding, string analysisPath, Func<bool> isCurrent, CancellationToken cancellationToken)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _binding = binding ?? throw new ArgumentNullException(nameof(binding));
        _binding.Validate();
        if (_source.CompatibilityAssessment.Context is not (CaptureOpenContext.ViewerLiveSnapshot or CaptureOpenContext.ViewerArchivedReadOnly))
            throw new InvalidOperationException("Network analysis requires an assessed Viewer snapshot or read-only archive.");
        if (!string.Equals(Path.GetFullPath(_binding.SourceDatabasePath), _source.ReadContext.DatabasePath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Network analysis binding does not match the assessed source database.");
        if (_source.CompatibilityAssessment.Context == CaptureOpenContext.ViewerLiveSnapshot &&
            string.Equals(Path.GetFileName(_source.ReadContext.DatabasePath), "procinsider-live.sqlite3", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("A ViewerLiveSnapshot analysis binding cannot point at authoritative live evidence.");
        if (string.IsNullOrWhiteSpace(analysisPath)) throw new ArgumentException("A persistent analysis path is required.", nameof(analysisPath));
        _analysisPath = Path.GetFullPath(analysisPath);
        if (string.Equals(_analysisPath, _source.ReadContext.DatabasePath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Network analysis must remain separate from primary evidence.");
        _isCurrent = isCurrent ?? throw new ArgumentNullException(nameof(isCurrent));
        _sourceFingerprint = Fingerprint(_source.ReadContext.DatabasePath, cancellationToken);
        _gate = CaptureGates.GetOrAdd(_analysisPath, _ => new SemaphoreSlim(1, 1));
    }

    /// <summary>Only path-authority construction is supported; it never allocates the store eagerly.</summary>
    public static Task<NetworkAnalysisService> CreateAsync(SqliteStagingQueryService source, NetworkAnalysisBinding binding,
        InvestigationSessionPaths paths, Func<bool>? isCurrent = null, CancellationToken cancellationToken = default) =>
        Task.Run(() => { cancellationToken.ThrowIfCancellationRequested(); var service = CreateCore(source, binding, paths, isCurrent, cancellationToken); cancellationToken.ThrowIfCancellationRequested(); return service; }, cancellationToken);

    private static NetworkAnalysisService CreateCore(SqliteStagingQueryService source, NetworkAnalysisBinding binding,
        InvestigationSessionPaths paths, Func<bool>? isCurrent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(binding);
        var context = source.CompatibilityAssessment.Context;
        var package = SessionPathService.InspectCapturePackage(paths.SessionRoot, context,
            SqliteStagingStore.AssessExistingDatabase);
        var selected = SessionPathService.OpenExistingCapturePackage(package.ManifestPath, context,
            SqliteStagingStore.AssessExistingDatabase);
        if (!string.Equals(selected.SessionId, paths.SessionId, StringComparison.Ordinal) ||
            !string.Equals(selected.SessionId, binding.EvidenceSessionId, StringComparison.Ordinal))
            throw new InvalidOperationException("Network analysis session must match the selected manifest.");
        var expectedSource = context == CaptureOpenContext.ViewerLiveSnapshot ? selected.SnapshotDatabasePath : selected.LiveDatabasePath;
        if (!string.Equals(Path.GetFullPath(expectedSource), source.ReadContext.DatabasePath, StringComparison.OrdinalIgnoreCase) ||
            (context == CaptureOpenContext.ViewerLiveSnapshot && string.Equals(expectedSource, selected.LiveDatabasePath, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Network source must be the exact manifest-owned snapshot or archive database.");
        CaptureCompatibilityPolicy.EnsureAllowed(SqliteStagingStore.AssessExistingDatabase(expectedSource, context,
            package.CompatibilityMetadata, selected.SessionId), CaptureOpenCapability.ReadEvidence);
        using (var evidence = source.ReadContext.OpenReadOnlyConnection())
        {
            using var identity = evidence.CreateCommand();
            identity.CommandText = "SELECT Value FROM SchemaInfo WHERE Key='EvidenceSessionId';";
            if (!string.Equals(identity.ExecuteScalar() as string, selected.SessionId, StringComparison.Ordinal))
                throw new InvalidOperationException("Network source has no verified evidence-session identity.");
        }
        if (!string.Equals(binding.PackageContextId, GetPackageContextId(selected), StringComparison.Ordinal))
            throw new InvalidOperationException("Network package identity must match the selected manifest location.");
        return new NetworkAnalysisService(source, binding,
            SessionPathService.GetNetworkAnalysisStorePath(selected, binding.PackageContextId), isCurrent ?? (() => true), cancellationToken);
    }

    public static string GetPackageContextId(InvestigationSessionPaths paths) => NetworkAnalysisBinding.Hash("package",
        paths.SessionId, Path.GetFullPath(Path.Combine(paths.SessionRoot, SessionPathService.CapturePackageManifestFileName)).ToUpperInvariant());

    /// <summary>Runs an explicit bounded scan of one fixed evidence read binding; it is never a timer or ingest worker.</summary>
    public async Task<NetworkAnalysisStatus> ReconcileAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Check(cancellationToken);
            _completed = false;
            return await Task.Run(() =>
            {
                try { CheckSource(cancellationToken); var result = ReconcileCore(cancellationToken); Check(cancellationToken); return result; }
                catch { _completed = false; try { MarkBindingState("Failed"); } catch { /* preserve original failure */ } throw; }
            }, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    public async Task<NetworkAnalysisPage> QueryAsync(NetworkAnalysisQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (query.Offset < 0 || query.PageSize is < 1 or > 512) throw new ArgumentOutOfRangeException(nameof(query));
        ThrowIfDisposed();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Check(cancellationToken);
            var page = await Task.Run(() => { CheckSource(cancellationToken); var result = QueryCore(query, cancellationToken); CheckSource(cancellationToken); return result; }, cancellationToken).ConfigureAwait(false);
            Check(cancellationToken);
            return page;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Returns bounded source-resolvable diagnostics for the completed current binding, without payload copies.</summary>
    public async Task<IReadOnlyList<NetworkSourceDiagnostic>> QueryDiagnosticsAsync(long offset = 0, int pageSize = 128,
        CancellationToken cancellationToken = default)
    {
        if (offset < 0 || pageSize is < 1 or > 512) throw new ArgumentOutOfRangeException(nameof(pageSize));
        ThrowIfDisposed();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var page = await Task.Run<IReadOnlyList<NetworkSourceDiagnostic>>(() =>
            {
                CheckSource(cancellationToken);
                if (!_completed) throw new InvalidOperationException("This read binding has no completed reconciliation.");
                using var connection = OpenAnalysis();
                var status = EnsureSchema(connection);
                if (status.State != NetworkProcessingState.Ready || BindingStatus(connection, status).State != NetworkProcessingState.Ready)
                    throw new InvalidOperationException("This read binding has no completed compatible reconciliation.");
                using var command = connection.CreateCommand();
                command.CommandText = "SELECT o.SourceReferenceJson,o.Outcome,o.Diagnostic FROM NetworkBindingMembers m JOIN NetworkBindings b ON b.BindingId=m.BindingId AND b.ActiveGeneration=m.Generation JOIN NetworkOutcomes o ON o.SourceKey=m.SourceKey AND o.InputHash=m.InputHash WHERE m.BindingId=$binding AND o.Diagnostic<>'' ORDER BY m.SourceKey LIMIT $take OFFSET $skip;";
                command.Parameters.AddWithValue("$binding", _readBindingId);
                command.Parameters.AddWithValue("$take", pageSize);
                command.Parameters.AddWithValue("$skip", offset);
                using var reader = command.ExecuteReader();
                var result = new List<NetworkSourceDiagnostic>();
                while (reader.Read())
                {
                    Check(cancellationToken);
                    var reference = JsonSerializer.Deserialize<NetworkSourceReference>(reader.GetString(0))
                        ?? throw new InvalidDataException("Network outcome source reference is unavailable.");
                    result.Add(new(reference, Enum.Parse<NetworkSourceOutcome>(reader.GetString(1)), reader.GetString(2)));
                }
                CheckSource(cancellationToken);
                return result;
            }, cancellationToken).ConfigureAwait(false);
            Check(cancellationToken);
            return page;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Deletes only this replaceable Network index; evidence, annotations, and other analysis remain untouched.</summary>
    public async Task ResetAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Check(cancellationToken);
            _completed = false;
            await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                CheckSource(cancellationToken);
                using var connection = OpenAnalysis();
                var status = EnsureSchema(connection);
                if (status.State is NetworkProcessingState.UnsupportedSchema or NetworkProcessingState.NewerSchema)
                    throw new InvalidOperationException(status.Detail);
                using var transaction = connection.BeginTransaction();
                Execute(connection, transaction, "DELETE FROM NetworkBindingMembers; DELETE FROM NetworkBindings; DELETE FROM NetworkObservations; DELETE FROM NetworkOutcomes;");
                transaction.Commit();
                Check(cancellationToken);
            }, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private NetworkAnalysisStatus ReconcileCore(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var analysis = OpenAnalysis();
        var initial = EnsureSchema(analysis);
        if (initial.State is NetworkProcessingState.UnsupportedSchema or NetworkProcessingState.NewerSchema) return initial;
        MarkBindingState(analysis, "Processing");
        var generation = Guid.NewGuid().ToString("N");
        long? afterSequenceId = null;
        using var evidence = _source.ReadContext.OpenReadOnlyConnection();
        using var evidenceTransaction = evidence.BeginTransaction(); // fixes the page set; SequenceId is only page ordering.
        while (true)
        {
            Check(cancellationToken);
            var batch = ReadSourcePage(evidence, afterSequenceId, cancellationToken);
            if (batch.Count == 0) break;
            using var transaction = analysis.BeginTransaction();
            foreach (var source in batch)
            {
                Check(cancellationToken);
                var sourceKey = source.Reference.PersistentIdentity;
                var inputHash = InputHash(source);
                var known = ReadOutcomeHash(analysis, transaction, sourceKey);
                if (!string.Equals(known, inputHash, StringComparison.Ordinal))
                {
                    var result = SysmonNetworkNormalizer.Normalize(source, cancellationToken);
                    SaveOutcome(analysis, transaction, sourceKey, inputHash, source.Reference, result);
                    if (result.Observation is { } observation) SaveObservation(analysis, transaction, sourceKey, inputHash, observation);
                }
                SaveMembership(analysis, transaction, generation, sourceKey, inputHash, source);
            }
            transaction.Commit();
            afterSequenceId = batch[^1].Reference.SequenceId;
        }
        evidenceTransaction.Commit();
        Check(cancellationToken);
        CheckSource(cancellationToken);
        using (var transaction = analysis.BeginTransaction())
        {
            SaveBinding(analysis, transaction, generation);
            Execute(analysis, transaction, "DELETE FROM NetworkBindingMembers WHERE BindingId = $binding AND Generation <> $generation;", ("$binding", _readBindingId), ("$generation", generation));
            transaction.Commit();
        }
        _completed = true;
        return GetStatus(analysis);
    }

    private NetworkAnalysisPage QueryCore(NetworkAnalysisQuery query, CancellationToken cancellationToken)
    {
        using var analysis = OpenAnalysis();
        var status = EnsureSchema(analysis);
        if (status.State is NetworkProcessingState.UnsupportedSchema or NetworkProcessingState.NewerSchema)
            return new([], 0, status);
        status = BindingStatus(analysis, status);
        if (!_completed || status.State != NetworkProcessingState.Ready)
            return new([], 0, status with { State = NetworkProcessingState.Failed, Detail = "This read binding has no completed reconciliation." });
        var where = QueryWhere(query);
        var sort = query.Sort switch
        {
            NetworkSort.LocalEndpoint => "network_address_display(o.LocalAddress) COLLATE NOCASE " + (query.Descending ? "DESC" : "ASC") + ", o.LocalPort",
            NetworkSort.Provider => "o.Provider COLLATE NOCASE", NetworkSort.ObservationKind => "network_observation_display(o.ObservationKind) COLLATE NOCASE",
            NetworkSort.QueryName => "json_extract(o.ObservationJson,'$.QueryName') COLLATE NOCASE", NetworkSort.QueryStatus => "json_extract(o.ObservationJson,'$.QueryStatus')", NetworkSort.QueryResults => "json_extract(o.ObservationJson,'$.QueryResults')",
            NetworkSort.Process => "m.ProcessName COLLATE NOCASE",
            NetworkSort.ProcessId => "o.ProcessId", NetworkSort.SourcePort => "o.SourcePort", NetworkSort.DestinationPort => "o.DestinationPort",
            NetworkSort.Protocol => "o.Protocol COLLATE NOCASE",
            NetworkSort.Direction => "o.Direction",
            NetworkSort.SourceEndpoint => "network_address_display(o.SourceAddress) COLLATE NOCASE " + (query.Descending ? "DESC" : "ASC") + ", o.SourcePort",
            NetworkSort.DestinationEndpoint => "network_address_display(o.DestinationAddress) COLLATE NOCASE " + (query.Descending ? "DESC" : "ASC") + ", o.DestinationPort",
            _ => "o.CapturedUtc"
        };
        var direction = query.Descending ? "DESC" : "ASC";
        long count;
        using (var countCommand = analysis.CreateCommand())
        {
            countCommand.CommandText = $"SELECT COUNT(*) FROM NetworkBindingMembers m JOIN NetworkBindings b ON b.BindingId = m.BindingId JOIN NetworkObservations o ON o.SourceKey = m.SourceKey AND o.InputHash = m.InputHash WHERE {where};";
            BindQuery(countCommand, query);
            count = Convert.ToInt64(countCommand.ExecuteScalar(), CultureInfo.InvariantCulture);
        }
        var records = new List<NetworkObservation>();
        using (var command = analysis.CreateCommand())
        {
            command.CommandText = $"SELECT o.*, m.ProcessEntityId AS BindingProcessEntityId, m.ProcessGuid AS BindingProcessGuid, m.ProcessId AS BindingProcessId, m.ProcessName AS BindingProcessName FROM NetworkBindingMembers m JOIN NetworkBindings b ON b.BindingId = m.BindingId JOIN NetworkObservations o ON o.SourceKey = m.SourceKey AND o.InputHash = m.InputHash WHERE {where} ORDER BY {sort} {direction}, o.SourceKey {direction} LIMIT $take OFFSET $skip;";
            BindQuery(command, query);
            command.Parameters.AddWithValue("$take", query.PageSize);
            command.Parameters.AddWithValue("$skip", query.Offset);
            using var reader = command.ExecuteReader();
            while (reader.Read()) { cancellationToken.ThrowIfCancellationRequested(); records.Add(ReadObservation(reader)); }
        }
        return new(records, count, status);
    }

    private void BindQuery(SqliteCommand command, NetworkAnalysisQuery query)
    {
        command.Parameters.AddWithValue("$binding", _readBindingId);
        if (!string.IsNullOrWhiteSpace(query.ProcessEntityId)) command.Parameters.AddWithValue("$entity", query.ProcessEntityId);
        if (!string.IsNullOrWhiteSpace(query.Text)) command.Parameters.AddWithValue("$text", query.Text);
        if (query.ProcessScope is { } scope)
        {
            var values = new[] { scope.CaseId, scope.EvidenceSessionId, scope.CaptureId, scope.HostId, scope.ExecutionRootId, scope.ProcessEntityId };
            for (var i = 0; i < values.Length; i++) command.Parameters.AddWithValue("$scope" + i, values[i]);
        }
        if (query.FacetScope is { } facet) BindFacet(command, facet, "$facet");
        foreach (var (selector, index) in (query.GreenSelectors ?? []).Select((s, i) => (s, i)))
        {
            if (selector.Facet is { } greenFacet) BindFacet(command, greenFacet, "$gf" + index);
            if (selector.Scope is not { } selected) continue;
            var values = new[] { selected.CaseId, selected.EvidenceSessionId, selected.CaptureId, selected.HostId, selected.ExecutionRootId, selected.ProcessEntityId };
            for (var i = 0; i < values.Length; i++) command.Parameters.AddWithValue($"$green{index}_{i}", values[i]);
        }
        var filters = query.Columns ?? [];
        for (var i = 0; i < filters.Count; i++)
        {
            var criteria=filters[i].Criteria;
            for (var j = 0; j < criteria.Values.Count; j++) if(criteria.Values[j]!=null) command.Parameters.AddWithValue($"$c{i}v{j}", criteria.Values[j]!);
            if (ColumnTextFilter.Normalize(criteria.Text) != null) command.Parameters.AddWithValue("$c" + i + "text", criteria.Text!);
            if(criteria.Minimum.HasValue) command.Parameters.AddWithValue("$c"+i+"min",criteria.Minimum.Value);
            if(criteria.Maximum.HasValue) command.Parameters.AddWithValue("$c"+i+"max",criteria.Maximum.Value);
            if(criteria.FromUtc.HasValue) command.Parameters.AddWithValue("$c"+i+"from",criteria.FromUtc.Value.ToString("O",CultureInfo.InvariantCulture));
            if(criteria.ToUtc.HasValue) command.Parameters.AddWithValue("$c"+i+"to",criteria.ToUtc.Value.ToString("O",CultureInfo.InvariantCulture));
        }
    }

    private static string ColumnExpression(NetworkColumn column) => column switch
    {
        NetworkColumn.LocalEndpoint => "network_endpoint_display(o.LocalAddress,o.LocalPort)",
        NetworkColumn.Provider => "o.Provider", NetworkColumn.ObservationKind => "network_observation_display(o.ObservationKind)",
        NetworkColumn.QueryName => "json_extract(o.ObservationJson,'$.QueryName')", NetworkColumn.QueryStatus => "json_extract(o.ObservationJson,'$.QueryStatus')", NetworkColumn.QueryResults => "json_extract(o.ObservationJson,'$.QueryResults')",
        NetworkColumn.Process => "m.ProcessName", NetworkColumn.ProcessId => "o.ProcessId",
        NetworkColumn.CapturedUtc => "o.CapturedUtc", NetworkColumn.Protocol => "o.Protocol",
        NetworkColumn.Direction => "o.Direction", NetworkColumn.SourceAddress => "network_address_display(o.SourceAddress)",
        NetworkColumn.SourcePort => "o.SourcePort", NetworkColumn.DestinationAddress => "network_address_display(o.DestinationAddress)",
        NetworkColumn.DestinationPort => "o.DestinationPort", _ => throw new ArgumentOutOfRangeException(nameof(column))
    };
    private static string QueryWhere(NetworkAnalysisQuery query)
    {
        var where = "b.BindingId=$binding AND b.ActiveGeneration<>'' AND m.Generation=b.ActiveGeneration";
        if (!string.IsNullOrWhiteSpace(query.ProcessEntityId)) where += " AND m.ProcessEntityId=$entity";
        if (ColumnTextFilter.Normalize(query.Text) != null) where += " AND (network_text_match(m.ProcessName,$text) OR network_text_match(o.Provider,$text) OR network_text_match(network_observation_display(o.ObservationKind),$text) OR network_text_match(json_extract(o.ObservationJson,'$.QueryName'),$text) OR network_text_match(json_extract(o.ObservationJson,'$.QueryResults'),$text) OR network_text_match(o.Protocol,$text) OR network_text_match(o.SourceAddress,$text) OR network_text_match(o.DestinationAddress,$text))";
        if (query.ProcessScope != null)
        {
            var columns = new[] { "o.CaseId", "o.EvidenceSessionId", "o.CaptureId", "o.HostId", "o.ExecutionRootId", "m.ProcessEntityId" };
            for (var i=0;i<columns.Length;i++) where += " AND " + columns[i] + "=$scope" + i;
        }
        if (query.ResolvedProcessesOnly) where += " AND m.ProcessEntityId<>''";
        if (query.FacetScope is { } facet) where += " AND " + FacetPredicate(facet, "$facet");
        var selectors = query.GreenSelectors ?? [];
        string SelectionPredicate(NetworkGreenSelector selector, int index) => selector.Facet != null ? FacetPredicate(selector.Facet, "$gf" + index) : selector.Scope != null
            ? "(" + string.Join(" AND ", new[] { "o.CaseId", "o.EvidenceSessionId", "o.CaptureId", "o.HostId", "o.ExecutionRootId", "m.ProcessEntityId" }.Select((column, i) => $"{column}=$green{index}_{i}")) + ")"
            : selector.ResolvedProcessesOnly ? "m.ProcessEntityId<>''" : "1=1";
        foreach (var dimension in selectors.Select((s, i) => (s, i)).Where(p => !p.s.IsExcluded).GroupBy(p => p.s.Dimension))
            where += " AND (" + string.Join(" OR ", dimension.Select(p => SelectionPredicate(p.s, p.i))) + ")";
        foreach (var (selector, index) in selectors.Select((s, i) => (s, i)).Where(p => p.s.IsExcluded))
            where += " AND NOT (" + SelectionPredicate(selector, index) + ")";
        var filters = query.Columns ?? [];
        if (filters.Count > Enum.GetValues<NetworkColumn>().Length) throw new ArgumentOutOfRangeException(nameof(query));
        for (var i=0;i<filters.Count;i++)
        {
            var filter=filters[i];var criteria=filter.Criteria;criteria.Validate();
            var expression="CAST("+ColumnExpression(filter.Column)+" AS TEXT)";
            var selected=Enumerable.Range(0,criteria.Values.Count).Where(j=>criteria.Values[j]!=null).Select(j=>$"$c{i}v{j}").ToArray();
            var choices=selected.Length>0?expression+" IN ("+string.Join(",",selected)+")":"0";
            if(criteria.Values.Contains(null))choices="("+choices+" OR "+expression+" IS NULL)";
            else choices="COALESCE(("+choices+"),0)";
            if(!criteria.AllValues || criteria.Values.Count>0)where+=" AND "+(criteria.AllValues?"NOT ("+choices+")":"("+choices+")");
            if(ColumnTextFilter.Normalize(criteria.Text)!=null)where+=" AND network_text_match("+expression+",$c"+i+"text)";
            var range=new List<string>();var native=ColumnExpression(filter.Column);
            if(criteria.Minimum.HasValue)range.Add(native+">=$c"+i+"min");if(criteria.Maximum.HasValue)range.Add(native+"<=$c"+i+"max");
            if(criteria.FromUtc.HasValue)range.Add(native+">=$c"+i+"from");if(criteria.ToUtc.HasValue)range.Add(native+"<=$c"+i+"to");
            if(range.Count>0)where+=" AND ("+string.Join(" AND ",range)+(criteria.IncludeMissing?" OR "+native+" IS NULL":"")+")";
        }
        return where;
    }

    private const string ObservationJoin = " FROM NetworkBindingMembers m JOIN NetworkBindings b ON b.BindingId=m.BindingId JOIN NetworkObservations o ON o.SourceKey=m.SourceKey AND o.InputHash=m.InputHash ";
    private static string FacetExpression(NetworkDimension dimension) => dimension switch
    {
        NetworkDimension.Provider => "o.Provider",
        NetworkDimension.DestinationPort => "COALESCE(CAST(o.DestinationPort AS TEXT),'')",
        NetworkDimension.Protocol => "COALESCE(NULLIF(lower(trim(o.Protocol)),''),'')",
        NetworkDimension.Direction => "o.Direction",
        NetworkDimension.AddressScope => "network_address_scope(o.RemoteAddress)",
        NetworkDimension.Conversation => "CASE WHEN o.ObservationKind NOT IN ('CapturedSysmonNetworkConnection','CapturedDroppedPacket') THEN '' ELSE json_array(o.CaseId,o.EvidenceSessionId,o.CaptureId,o.HostId,o.ExecutionRootId,COALESCE(lower(trim(o.Protocol)),''),o.SourceAddress,o.SourcePort,o.DestinationAddress,o.DestinationPort) END",
        _ => throw new ArgumentOutOfRangeException(nameof(dimension))
    };
    private static string FacetPredicate(NetworkFacet facet, string prefix)
    {
        if (facet.Key == null) return "1=1";
        if (facet.Dimension == NetworkDimension.Time)
        {
            if (facet.FromUtcTicks == null || facet.ToUtcTicks == null || facet.FromUtcTicks >= facet.ToUtcTicks) throw new ArgumentException("Invalid Network UTC interval.");
            return $"(network_ticks(o.CapturedUtc)>={prefix}from AND network_ticks(o.CapturedUtc)<{prefix}to)";
        }
        return $"({FacetExpression(facet.Dimension)}={prefix}key)";
    }
    private static void BindFacet(SqliteCommand command, NetworkFacet facet, string prefix)
    {
        if (facet.Key == null) return;
        if (facet.Dimension == NetworkDimension.Time)
        {
            command.Parameters.AddWithValue(prefix + "from", facet.FromUtcTicks!.Value);
            command.Parameters.AddWithValue(prefix + "to", facet.ToUtcTicks!.Value);
        }
        else command.Parameters.AddWithValue(prefix + "key", facet.Key);
    }

    public async Task<IReadOnlyList<NetworkFacetCount>> QueryFacetsAsync(NetworkAnalysisQuery query, NetworkDimension dimension, CancellationToken token = default)
    {
        if (query.Offset < 0 || query.PageSize is < 1 or > 512) throw new ArgumentOutOfRangeException(nameof(query));
        query = AdaptiveQuery(query, dimension);
        if (dimension == NetworkDimension.Time)
        {
            var extent = await ReadDirectoryAsync(new(PageSize: 1), "MIN(network_ticks(o.CapturedUtc)),MAX(network_ticks(o.CapturedUtc))", "",
                r => r.IsDBNull(0) ? null : NetworkTimeBuckets.Choose(r.GetInt64(0), r.GetInt64(1)), token).ConfigureAwait(false);
            if (extent[0] is not { } plan) return [];
            var expression = $"((network_ticks(o.CapturedUtc)-{plan.OriginTicks})/{plan.SpanTicks})";
            var counts = await ReadDirectoryAsync(query, expression + ",COUNT(*)", " GROUP BY " + expression + " ORDER BY " + expression,
                r => (Index: r.GetInt32(0), Count: r.GetInt64(1)), token).ConfigureAwait(false);
            var byIndex = counts.ToDictionary(c => c.Index, c => c.Count);
            return Enumerable.Range(0, plan.Count).Skip((int)Math.Min(query.Offset, plan.Count)).Take(query.PageSize).Select(index =>
            {
                var from = plan.OriginTicks + index * plan.SpanTicks;
                var to = from + plan.SpanTicks;
                var facet = new NetworkFacet(dimension, from.ToString(CultureInfo.InvariantCulture), from, to);
                return new NetworkFacetCount(facet, FacetTitle(facet), byIndex.GetValueOrDefault(index));
            }).ToArray();
        }
        var value = FacetExpression(dimension);
        return await ReadDirectoryAsync(query, value + ",COUNT(*)", " GROUP BY " + value + " ORDER BY " +
            (dimension == NetworkDimension.DestinationPort ? "CAST(" + value + " AS INTEGER)," + value : value) + " LIMIT $take OFFSET $skip",
            r => new NetworkFacetCount(new(dimension, r.GetString(0)), FacetTitle(new(dimension, r.GetString(0))), r.GetInt64(1)), token).ConfigureAwait(false);
    }
    public static NetworkAnalysisQuery AdaptiveQuery(NetworkAnalysisQuery query, NetworkDimension dimension) => query with
    {
        ProcessScope = dimension == NetworkDimension.Process ? null : query.ProcessScope,
        ResolvedProcessesOnly = dimension == NetworkDimension.Process ? false : query.ResolvedProcessesOnly,
        FacetScope = query.FacetScope?.Dimension == dimension ? null : query.FacetScope,
        GreenSelectors = (query.GreenSelectors ?? []).Where(s => s.Dimension != dimension).ToArray()
    };
    public static string FacetTitle(NetworkFacet facet)
    {
        if (facet.Dimension == NetworkDimension.Time && facet.FromUtcTicks is { } from && facet.ToUtcTicks is { } to)
            return $"{new DateTime(from, DateTimeKind.Utc):yyyy-MM-dd HH:mm} – {(to <= DateTime.MaxValue.Ticks ? new DateTime(to, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) : "end of supported time")} UTC";
        if (facet.Dimension != NetworkDimension.Conversation) return string.IsNullOrEmpty(facet.Key) ? "Unknown / unavailable" : facet.Key;
        if (string.IsNullOrEmpty(facet.Key)) return "Not applicable / unavailable";
        using var json = JsonDocument.Parse(facet.Key!);
        var fields = json.RootElement.EnumerateArray().ToArray();
        string Text(int i) => fields[i].ValueKind == JsonValueKind.Null ? "?" : fields[i].ToString();
        var source = new NetworkEndpoint(fields[6].GetString(), fields[7].ValueKind == JsonValueKind.Null ? null : fields[7].GetInt32());
        var destination = new NetworkEndpoint(fields[8].GetString(), fields[9].ValueKind == JsonValueKind.Null ? null : fields[9].GetInt32());
        return $"{(source.Presentation.Length == 0 ? "?" : source.Presentation)} → {(destination.Presentation.Length == 0 ? "?" : destination.Presentation)} [{Text(5)}; host {Text(3)}; execution {Text(4)}]";
    }
    private async Task<IReadOnlyList<T>> ReadDirectoryAsync<T>(NetworkAnalysisQuery query, string projection, string suffix,
        Func<SqliteDataReader,T> read, CancellationToken token)
    {
        ThrowIfDisposed(); await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var result=await Task.Run<IReadOnlyList<T>>(() =>
            {
                CheckSource(token);
                if(!_completed) throw new InvalidOperationException("This read binding has no completed reconciliation.");
                using var connection=OpenAnalysis(); var status=EnsureSchema(connection);
                if(status.State!=NetworkProcessingState.Ready || BindingStatus(connection,status).State!=NetworkProcessingState.Ready) throw new InvalidOperationException(status.Detail);
                using var command=connection.CreateCommand(); command.CommandText="SELECT "+projection+ObservationJoin+"WHERE "+QueryWhere(query)+suffix;
                BindQuery(command,query); command.Parameters.AddWithValue("$take",query.PageSize); command.Parameters.AddWithValue("$skip",query.Offset);
                using var reader=command.ExecuteReader(); var rows=new List<T>();
                while(reader.Read()) { Check(token);rows.Add(read(reader)); }
                CheckSource(token);return rows;
            },token).ConfigureAwait(false);
            Check(token);return result;
        }
        finally { _gate.Release(); }
    }
    public Task<IReadOnlyList<NetworkValueCount>> QueryValuesAsync(NetworkAnalysisQuery query, NetworkColumn column, CancellationToken token=default,
        string? search=null,ColumnFilterValueSort sort=ColumnFilterValueSort.CountDescending)
    {
        if(query.Offset<0 || query.PageSize is <1 or >512) throw new ArgumentOutOfRangeException(nameof(query));
        var expression="CAST("+ColumnExpression(column)+" AS TEXT)";
        query=query with{Columns=(query.Columns??[]).Where(f=>f.Column!=column).Concat(ColumnTextFilter.Normalize(search)==null?[]:new[]{new NetworkColumnFilter(column,new(){Text=search})}).ToArray()};
        var order=sort switch{ColumnFilterValueSort.ValueAscending=>expression+" ASC",ColumnFilterValueSort.ValueDescending=>expression+" DESC",ColumnFilterValueSort.CountAscending=>"COUNT(*) ASC,"+expression,_=>"COUNT(*) DESC,"+expression};
        return ReadDirectoryAsync(query,expression+",COUNT(*)"," GROUP BY "+expression+" ORDER BY "+order+" LIMIT $take OFFSET $skip",r=>new NetworkValueCount(r.IsDBNull(0)?null:r.GetString(0),r.GetInt64(1)),token);
    }
    public Task<IReadOnlyList<NetworkProcessActivity>> QueryProcessesAsync(long offset=0,int pageSize=128,CancellationToken token=default,NetworkAnalysisQuery? query=null)
    {
        if(offset<0 || pageSize is <1 or >512) throw new ArgumentOutOfRangeException(nameof(pageSize));
        return ReadDirectoryAsync(AdaptiveQuery(query ?? new(),NetworkDimension.Process) with {Offset=offset,PageSize=pageSize},"o.CaseId,o.EvidenceSessionId,o.CaptureId,o.HostId,o.ExecutionRootId,m.ProcessEntityId,MAX(m.ProcessName),COUNT(*)",
            " AND m.ProcessEntityId<>'' GROUP BY o.CaseId,o.EvidenceSessionId,o.CaptureId,o.HostId,o.ExecutionRootId,m.ProcessEntityId ORDER BY MAX(m.ProcessName),o.CaseId,o.EvidenceSessionId,o.CaptureId,o.HostId,o.ExecutionRootId,m.ProcessEntityId LIMIT $take OFFSET $skip",
            r=>new NetworkProcessActivity(new(r.GetString(0),r.GetString(1),r.GetString(2),r.GetString(3),r.GetString(4),r.GetString(5)),r.GetString(6),r.GetInt64(7)),token);
    }

    private SqliteConnection OpenAnalysis()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_analysisPath) ?? throw new InvalidOperationException("Analysis path has no parent."));
        if (File.Exists(_analysisPath) && new FileInfo(_analysisPath).Length > 0)
        {
            var readOnly = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _analysisPath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
            readOnly.Open();
            readOnly.CreateFunction<string?,string?,bool>("network_text_match",ColumnTextFilter.Matches,isDeterministic:true);
            RegisterFacetFunctions(readOnly);
            if (AssessStore(readOnly) is not null) return readOnly;
            readOnly.Dispose();
        }
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _analysisPath, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString());
        connection.Open();
        connection.CreateFunction<string?,string?,bool>("network_text_match",ColumnTextFilter.Matches,isDeterministic:true);
        RegisterFacetFunctions(connection);
        using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;";
        pragma.ExecuteNonQuery();
        return connection;
    }
    private static void RegisterFacetFunctions(SqliteConnection connection)
    {
        connection.CreateFunction<string?,string?>("network_address_display",address=>address==null?null:NetworkAddressPresentation.Address(address),isDeterministic:true);
        connection.CreateFunction<string?,int?,string?>("network_endpoint_display", (address, port) => string.IsNullOrWhiteSpace(address) ? null : new NetworkEndpoint(address, port).Presentation, isDeterministic:true);
        connection.CreateFunction<string,string>("network_observation_display", kind => Enum.TryParse<NetworkObservationKind>(kind, out var parsed) ? NetworkObservation.DisplayKind(parsed) : "Unknown observation", isDeterministic:true);
        connection.CreateFunction<string?,string>("network_address_scope", NetworkAddressScopes.Classify, isDeterministic:true);
        connection.CreateFunction<string,long>("network_ticks", value => DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).Ticks, isDeterministic:true);
    }

    private NetworkAnalysisStatus? AssessStore(SqliteConnection connection)
    {
        NetworkAnalysisStatus Unsupported(string detail) => new(NetworkProcessingState.UnsupportedSchema, detail, 0, 0, SysmonNetworkNormalizer.ProcessorVersion);
        if (!TableExists(connection, "NetworkStoreMetadata") || !new[] { "Key", "Value" }.All(Columns(connection, "NetworkStoreMetadata").Contains))
            return Unsupported("The existing Network store is unrecognized and was not changed.");
        if (!int.TryParse(ReadMetadata(connection, "SchemaVersion"), out var version) || version < SchemaVersion)
            return Unsupported("The Network schema is unsupported and was not changed.");
        if (version > SchemaVersion) return new(NetworkProcessingState.NewerSchema, "The Network schema is newer and was not changed.", 0, 0, SysmonNetworkNormalizer.ProcessorVersion);
        var shapes = new Dictionary<string, string[]>
        {
            ["NetworkOutcomes"] = ["SourceKey", "InputHash", "Outcome", "Diagnostic", "UpdatedUtc", "SourceReferenceJson"],
            ["NetworkObservations"] = ["SourceKey", "InputHash", "CaseId", "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId", "SequenceId", "SourceRunId", "IngestionJobId", "RawRecordIdText", "CapturedUtc", "ProcessEntityId", "ProcessGuid", "ProcessId", "ProcessName", "ProcessImage", "UserName", "Protocol", "SourceAddress", "SourcePort", "DestinationAddress", "DestinationPort", "Direction", "LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "Diagnostic", "Provider", "ObservationKind", "ObservationJson"],
            ["NetworkBindings"] = ["BindingId", "Generation", "ActiveGeneration", "State", "UpdatedUtc"],
            ["NetworkBindingMembers"] = ["BindingId", "Generation", "SourceKey", "InputHash", "ProcessEntityId", "ProcessGuid", "ProcessId", "ProcessName"]
        };
        if (shapes.Any(shape => !TableExists(connection, shape.Key) || !shape.Value.All(Columns(connection, shape.Key).Contains)))
            return Unsupported("The Network store is incomplete and was not changed.");
        if (!string.Equals(ReadMetadata(connection, "EvidenceIdentity"), _binding.PersistentIdentity, StringComparison.Ordinal))
            return Unsupported("The Network store evidence/package identity is different or unverified.");
        return null;
    }
    private NetworkAnalysisStatus EnsureSchema(SqliteConnection connection)
    {
        if (new SqliteConnectionStringBuilder(connection.ConnectionString).Mode == SqliteOpenMode.ReadOnly) return AssessStore(connection)!;
        if (!TableExists(connection, "NetworkStoreMetadata") && TableExists(connection, "NetworkOutcomes"))
            return new(NetworkProcessingState.UnsupportedSchema, "The existing Network analysis store is not recognized and was not changed.", 0, 0, SysmonNetworkNormalizer.ProcessorVersion);
        Execute(connection, null, "CREATE TABLE IF NOT EXISTS NetworkStoreMetadata (Key TEXT PRIMARY KEY, Value TEXT NOT NULL);");
        var existing = ReadMetadata(connection, "SchemaVersion");
        if (existing != null && (!int.TryParse(existing, out var version) || version < SchemaVersion))
            return new(NetworkProcessingState.UnsupportedSchema, "The Network analysis schema is older than this processor supports; reset is required.", 0, 0, SysmonNetworkNormalizer.ProcessorVersion);
        if (existing != null && int.Parse(existing, CultureInfo.InvariantCulture) > SchemaVersion)
            return new(NetworkProcessingState.NewerSchema, "The Network analysis schema is newer than this processor; it was not changed.", 0, 0, SysmonNetworkNormalizer.ProcessorVersion);
        Execute(connection, null, """
            CREATE TABLE IF NOT EXISTS NetworkOutcomes (SourceKey TEXT PRIMARY KEY, InputHash TEXT NOT NULL, Outcome TEXT NOT NULL, Diagnostic TEXT NOT NULL, UpdatedUtc TEXT NOT NULL, SourceReferenceJson TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS NetworkObservations (
                SourceKey TEXT NOT NULL, InputHash TEXT NOT NULL, CaseId TEXT NOT NULL, EvidenceSessionId TEXT NOT NULL, CaptureId TEXT NOT NULL,
                SourceIdentityId TEXT NOT NULL, HostId TEXT NOT NULL, ExecutionRootId TEXT NOT NULL, SequenceId INTEGER NOT NULL,
                SourceRunId TEXT NOT NULL, IngestionJobId TEXT NOT NULL, RawRecordIdText TEXT NOT NULL, CapturedUtc TEXT NOT NULL,
                ProcessEntityId TEXT NOT NULL, ProcessGuid TEXT NOT NULL, ProcessId INTEGER, ProcessName TEXT NOT NULL, ProcessImage TEXT NOT NULL, UserName TEXT NOT NULL,
                Protocol TEXT, SourceAddress TEXT, SourcePort INTEGER, DestinationAddress TEXT, DestinationPort INTEGER, Direction TEXT NOT NULL,
                LocalAddress TEXT, LocalPort INTEGER, RemoteAddress TEXT, RemotePort INTEGER, Diagnostic TEXT NOT NULL, Provider TEXT NOT NULL, ObservationKind TEXT NOT NULL, ObservationJson TEXT NOT NULL,
                PRIMARY KEY(SourceKey, InputHash));
            CREATE TABLE IF NOT EXISTS NetworkBindings (BindingId TEXT PRIMARY KEY, Generation TEXT NOT NULL, ActiveGeneration TEXT NOT NULL, State TEXT NOT NULL, UpdatedUtc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS NetworkBindingMembers (BindingId TEXT NOT NULL, Generation TEXT NOT NULL, SourceKey TEXT NOT NULL, InputHash TEXT NOT NULL, ProcessEntityId TEXT NOT NULL, ProcessGuid TEXT NOT NULL, ProcessId INTEGER NOT NULL, ProcessName TEXT NOT NULL, PRIMARY KEY(BindingId, Generation, SourceKey));
            CREATE INDEX IF NOT EXISTS IX_NetworkBindingMembers_Active ON NetworkBindingMembers(BindingId, Generation, SourceKey, InputHash);
            CREATE INDEX IF NOT EXISTS IX_NetworkObservations_Process ON NetworkObservations(ProcessEntityId, CapturedUtc DESC);
            """);
        if (existing == null) SaveMetadata(connection, "SchemaVersion", SchemaVersion.ToString(CultureInfo.InvariantCulture));
        if (existing == null) SaveMetadata(connection, "EvidenceIdentity", _binding.PersistentIdentity);
        var processor = ReadMetadata(connection, "ProcessorVersion");
        if (processor != null && !string.Equals(processor, SysmonNetworkNormalizer.ProcessorVersion, StringComparison.Ordinal))
        {
            using var transaction = connection.BeginTransaction();
            Execute(connection, transaction, "DELETE FROM NetworkBindingMembers; DELETE FROM NetworkBindings; DELETE FROM NetworkObservations; DELETE FROM NetworkOutcomes;");
            SaveMetadata(connection, "ProcessorVersion", SysmonNetworkNormalizer.ProcessorVersion, transaction);
            transaction.Commit();
        }
        else if (processor == null) SaveMetadata(connection, "ProcessorVersion", SysmonNetworkNormalizer.ProcessorVersion);
        return GetStatus(connection);
    }

    private NetworkAnalysisStatus GetStatus(SqliteConnection connection)
    {
        var normalized = Count(connection, "Normalized");
        var malformed = Count(connection, "Malformed");
        return new(NetworkProcessingState.Ready, "Bounded reconciliation scans each accepted snapshot; unchanged source inputs reuse persisted outcomes.", normalized, malformed, ReadMetadata(connection, "ProcessorVersion") ?? SysmonNetworkNormalizer.ProcessorVersion);
    }

    private NetworkAnalysisStatus BindingStatus(SqliteConnection connection, NetworkAnalysisStatus status)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT State FROM NetworkBindings WHERE BindingId=$binding;";
        command.Parameters.AddWithValue("$binding", _readBindingId);
        var state = command.ExecuteScalar() as string;
        return string.Equals(state, "Ready", StringComparison.Ordinal)
            ? status
            : status with { State = NetworkProcessingState.Failed, Detail = string.IsNullOrWhiteSpace(state) ? "No completed Network analysis binding is available." : "Network analysis binding is " + state + "." };
    }

    private void MarkBindingState(string state)
    {
        using var connection = OpenAnalysis();
        var status = EnsureSchema(connection);
        if (status.State is NetworkProcessingState.UnsupportedSchema or NetworkProcessingState.NewerSchema) return;
        MarkBindingState(connection, state);
    }

    private void MarkBindingState(SqliteConnection connection, string state)
    {
        using var transaction = connection.BeginTransaction();
        using var active = connection.CreateCommand();
        active.Transaction = transaction;
        active.CommandText = "SELECT ActiveGeneration FROM NetworkBindings WHERE BindingId=$binding;";
        active.Parameters.AddWithValue("$binding", _readBindingId);
        var activeGeneration = active.ExecuteScalar() as string ?? string.Empty;
        Execute(connection, transaction, "INSERT INTO NetworkBindings(BindingId,Generation,ActiveGeneration,State,UpdatedUtc) VALUES($binding,'',$active,$state,$utc) ON CONFLICT(BindingId) DO UPDATE SET State=excluded.State, UpdatedUtc=excluded.UpdatedUtc;", ("$binding", _readBindingId), ("$active", activeGeneration), ("$state", state), ("$utc", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture)));
        transaction.Commit();
    }

    private long Count(SqliteConnection connection, string outcome)
    {
        using var command = connection.CreateCommand(); command.CommandText = "SELECT COUNT(*) FROM NetworkBindingMembers m JOIN NetworkBindings b ON b.BindingId=m.BindingId AND b.ActiveGeneration=m.Generation JOIN NetworkOutcomes o ON o.SourceKey=m.SourceKey AND o.InputHash=m.InputHash WHERE m.BindingId=$binding AND o.Outcome=$outcome;"; command.Parameters.AddWithValue("$binding", _readBindingId); command.Parameters.AddWithValue("$outcome", outcome); return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private List<NetworkSourceEvent> ReadSourcePage(SqliteConnection connection, long? afterSequenceId, CancellationToken cancellationToken)
    {
        var columns = Columns(connection, "ProcessEvents");
        string Optional(string name) => columns.Contains(name) ? $"COALESCE(e.{name}, '')" : "''";
        string Column(string name) => Optional(name) + " AS " + name;
        var relations = Columns(connection, "EvidenceRelations");
        var hasDecisions = new[] { "DecisionKey", "Status", "UpdatedUtc", "RelationId", "CorrelationState", "ToKind", "ToId", "FromKind", "FromId" }.All(relations.Contains);
        var nativeEntity = Optional("ProcessEntityId");
        var state = hasDecisions ? $"COALESCE(r.CorrelationState, CASE WHEN {nativeEntity}<>'' THEN 'Asserted' ELSE 'Unresolved' END)" : $"CASE WHEN {nativeEntity}<>'' THEN 'Asserted' ELSE 'Unresolved' END";
        var decisionEntity = hasDecisions ? $"CASE WHEN r.RelationId IS NULL THEN {nativeEntity} WHEN r.ToKind='ProcessEntity' THEN COALESCE(r.ToId,'') WHEN r.FromKind='ProcessEntity' THEN COALESCE(r.FromId,'') ELSE '' END" : nativeEntity;
        var entityColumns = Columns(connection, "ProcessEntities");
        var entityScope = new[] { "CaseId", "EvidenceSessionId", "HostId", "ExecutionRootId" };
        var reliableEntity = entityScope.Append("ProcessEntityId").All(entityColumns.Contains)
            ? $"EXISTS(SELECT 1 FROM ProcessEntities p WHERE p.ProcessEntityId=({decisionEntity}) AND " +
                string.Join(" AND ", entityScope.Select(field => $"COALESCE(p.{field},'')=COALESCE(e.{field},'')")) + ")"
            : "0";
        // Match the retained Process tree read path for records predating durable attachment.
        // A unique scoped ProcessKey is a compatibility alias, never a PID association.
        // Explicit ambiguous/rejected decisions and invalid durable assertions remain authoritative.
        var processTable = entityColumns.Count > 0 ? "ProcessEntities" : "Processes";
        var processColumns = processTable == "ProcessEntities" ? entityColumns : Columns(connection, processTable);
        var fallbackColumns = new[] { "ProcessKey", "ProcessEntityId", "CaseId", "EvidenceSessionId", "CaptureId", "HostId", "ExecutionRootId" };
        var legacyEntity = fallbackColumns.All(processColumns.Contains) && fallbackColumns.Where(field => field != "ProcessEntityId").All(columns.Contains)
            ? $"COALESCE((SELECT p.ProcessEntityId FROM {processTable} p WHERE COALESCE(p.ProcessEntityId,'')<>'' AND " +
                ProcessEventAttachmentSql.BuildBranches("e", "p", processTable, columns.Contains("ProcessEntityId"), true).Fallback + "),'')"
            : "''";
        var canonical = $"CASE WHEN {state} IN ('Exact','Asserted','Confirmed') AND {reliableEntity} THEN {decisionEntity} " +
            $"WHEN {nativeEntity}='' AND {state}='Unresolved' AND ({decisionEntity})='' THEN {legacyEntity} ELSE '' END AS ProcessEntityId";
        var resolvedPid = processColumns.Contains("ProcessId") && processColumns.Contains("ProcessEntityId")
            ? "(SELECT p.ProcessId FROM " + processTable + " p WHERE p.ProcessEntityId=(" + canonical[..canonical.LastIndexOf(" AS ProcessEntityId", StringComparison.Ordinal)] + ") LIMIT 1) AS ResolvedProcessId"
            : "NULL AS ResolvedProcessId";
        var join = hasDecisions ? "LEFT JOIN EvidenceRelations r ON r.RelationId=(SELECT active.RelationId FROM EvidenceRelations active WHERE active.DecisionKey='event:'||e.SequenceId||':process' AND active.Status='Active' ORDER BY active.UpdatedUtc DESC,active.RelationId DESC LIMIT 1)" : "";
        if (hasDecisions)
        {
            var scopeFields = new[] { "CaseId", "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId" };
            var scopeMatch = string.Join(" AND ", scopeFields.Where(field => relations.Contains(field) && columns.Contains(field))
                .Select(field => $"COALESCE(active.{field},'')=COALESCE(e.{field},'')"));
            if (scopeMatch.Length > 0) join = join.Replace("AND active.Status='Active'", "AND active.Status='Active' AND " + scopeMatch);
        }
        using var command = connection.CreateCommand();
        var scope = "((lower(COALESCE(e.Source, '')) = 'sysmon' AND e.EventCode IN (3,22)) OR (lower(COALESCE(e.Source, '')) = 'security' AND e.EventCode IN (5152,5153,5154,5155,5158,5159))) AND COALESCE(e.EvidenceSessionId, '') = $session";
        if (!string.IsNullOrWhiteSpace(_binding.CaseId)) scope += " AND COALESCE(e.CaseId, '') = $case";
        if (!string.IsNullOrWhiteSpace(_binding.CaptureId)) scope += " AND COALESCE(e.CaptureId, '') = $capture";
        if (afterSequenceId.HasValue) scope += " AND e.SequenceId > $after";
        command.CommandText = $"SELECT {string.Join(", ", new[] { "e.SequenceId", "e.TimestampUtc", "e.Source", "e.EventCode", "e.Details", "e.ProcessId", "e.ProcessName", "e.CaseId", "e.EvidenceSessionId", "e.CaptureId", "e.SourceIdentityId", "e.HostId", "e.ExecutionRootId", Column("RawProvider"), Column("RawLogName"), canonical, resolvedPid, Column("ProcessGuid"), Column("SourceRunId"), Column("IngestionJobId"), Column("RawRecordIdText") })} FROM ProcessEvents e {join} WHERE {scope} ORDER BY e.SequenceId ASC LIMIT $take;";
        command.Parameters.AddWithValue("$session", _binding.EvidenceSessionId);
        if (!string.IsNullOrWhiteSpace(_binding.CaseId)) command.Parameters.AddWithValue("$case", _binding.CaseId);
        if (!string.IsNullOrWhiteSpace(_binding.CaptureId)) command.Parameters.AddWithValue("$capture", _binding.CaptureId);
        command.Parameters.AddWithValue("$take", BatchSize); if (afterSequenceId.HasValue) command.Parameters.AddWithValue("$after", afterSequenceId.Value);
        using var reader = command.ExecuteReader(); var result = new List<NetworkSourceEvent>();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            string Text(string name) => reader[name] is DBNull ? string.Empty : Convert.ToString(reader[name], CultureInfo.InvariantCulture) ?? string.Empty;
            var reference = new NetworkSourceReference(Text("CaseId"), Text("EvidenceSessionId"), Text("CaptureId"), Text("SourceIdentityId"), Text("HostId"), Text("ExecutionRootId"), Convert.ToInt64(reader["SequenceId"], CultureInfo.InvariantCulture), Text("SourceRunId"), Text("IngestionJobId"), Text("RawRecordIdText"));
            var timestamp = reader["TimestampUtc"] is DateTime utc ? (utc.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(utc, DateTimeKind.Utc) : utc.ToUniversalTime()) : DateTime.Parse(Text("TimestampUtc"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            result.Add(new(reference, timestamp, Text("Source"), reader["EventCode"] is DBNull ? null : Convert.ToInt32(reader["EventCode"], CultureInfo.InvariantCulture), Text("RawProvider"), Text("RawLogName"), Text("Details"), Text("ProcessEntityId"), Text("ProcessGuid"), reader["ProcessId"] is DBNull ? 0 : Convert.ToInt32(reader["ProcessId"], CultureInfo.InvariantCulture), Text("ProcessName"), string.Empty, string.Empty, reader["ResolvedProcessId"] is DBNull ? null : Convert.ToInt32(reader["ResolvedProcessId"], CultureInfo.InvariantCulture)));
        }
        return result;
    }

    private static HashSet<string> Columns(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand(); command.CommandText = "PRAGMA table_info(" + table + ");"; using var reader = command.ExecuteReader(); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase); while (reader.Read()) names.Add(reader.GetString(1)); return names;
    }

    private static bool TableExists(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = $name LIMIT 1;";
        command.Parameters.AddWithValue("$name", table);
        return command.ExecuteScalar() != null;
    }

    private static string InputHash(NetworkSourceEvent source) => NetworkAnalysisBinding.Hash("input", source.Reference.PersistentIdentity, source.TimestampUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture), source.Source, source.EventId?.ToString(CultureInfo.InvariantCulture), source.RawProvider, source.RawLogName, source.Details, source.Reference.SourceRunId, source.Reference.IngestionJobId, source.Reference.RawRecordIdText, source.ProcessGuid, source.ProcessId.ToString(CultureInfo.InvariantCulture), source.ProcessName);
    private static string? ReadOutcomeHash(SqliteConnection connection, SqliteTransaction transaction, string sourceKey) { using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = "SELECT InputHash FROM NetworkOutcomes WHERE SourceKey = $source;"; command.Parameters.AddWithValue("$source", sourceKey); return command.ExecuteScalar() as string; }
    private static void SaveOutcome(SqliteConnection connection, SqliteTransaction transaction, string sourceKey, string inputHash, NetworkSourceReference reference, NetworkNormalizationResult result) => Execute(connection, transaction, "INSERT INTO NetworkOutcomes(SourceKey, InputHash, Outcome, Diagnostic, UpdatedUtc, SourceReferenceJson) VALUES($source,$hash,$outcome,$diagnostic,$utc,$reference) ON CONFLICT(SourceKey) DO UPDATE SET InputHash=excluded.InputHash, Outcome=excluded.Outcome, Diagnostic=excluded.Diagnostic, UpdatedUtc=excluded.UpdatedUtc, SourceReferenceJson=excluded.SourceReferenceJson;", ("$source", sourceKey), ("$hash", inputHash), ("$outcome", result.Outcome.ToString()), ("$diagnostic", result.Diagnostic), ("$reference", JsonSerializer.Serialize(reference)), ("$utc", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture)));
    private void SaveMembership(SqliteConnection connection, SqliteTransaction transaction, string generation, string sourceKey, string inputHash, NetworkSourceEvent source)
    {
        using var identity = connection.CreateCommand(); identity.Transaction = transaction;
        identity.CommandText = "SELECT ProcessId FROM NetworkObservations WHERE SourceKey=$source AND InputHash=$hash;";
        identity.Parameters.AddWithValue("$source", sourceKey); identity.Parameters.AddWithValue("$hash", inputHash);
        var nativePid = identity.ExecuteScalar();
        var conflict = nativePid is not null and not DBNull && source.ResolvedProcessId.HasValue && Convert.ToInt32(nativePid, CultureInfo.InvariantCulture) != source.ResolvedProcessId.Value;
        var entity = conflict ? "" : source.ProcessEntityId;
        Execute(connection, transaction, "INSERT INTO NetworkBindingMembers(BindingId,Generation,SourceKey,InputHash,ProcessEntityId,ProcessGuid,ProcessId,ProcessName) VALUES($binding,$generation,$source,$hash,$entity,$guid,$pid,$name) ON CONFLICT(BindingId,Generation,SourceKey) DO UPDATE SET InputHash=excluded.InputHash, ProcessEntityId=excluded.ProcessEntityId, ProcessGuid=excluded.ProcessGuid, ProcessId=excluded.ProcessId, ProcessName=excluded.ProcessName;", ("$binding", _readBindingId), ("$generation", generation), ("$source", sourceKey), ("$hash", inputHash), ("$entity", entity), ("$guid", source.ProcessGuid), ("$pid", source.ProcessId), ("$name", source.ProcessName));
    }

    private void SaveBinding(SqliteConnection connection, SqliteTransaction transaction, string generation) => Execute(connection, transaction, "INSERT INTO NetworkBindings(BindingId,Generation,ActiveGeneration,State,UpdatedUtc) VALUES($binding,$generation,$generation,'Ready',$utc) ON CONFLICT(BindingId) DO UPDATE SET Generation=excluded.Generation, ActiveGeneration=excluded.ActiveGeneration, State=excluded.State, UpdatedUtc=excluded.UpdatedUtc;", ("$binding", _readBindingId), ("$generation", generation), ("$utc", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture)));
    private static string? ReadMetadata(SqliteConnection connection, string key) { using var command = connection.CreateCommand(); command.CommandText = "SELECT Value FROM NetworkStoreMetadata WHERE Key=$key;"; command.Parameters.AddWithValue("$key", key); return command.ExecuteScalar() as string; }
    private static void SaveMetadata(SqliteConnection connection, string key, string value, SqliteTransaction? transaction = null) => Execute(connection, transaction, "INSERT INTO NetworkStoreMetadata(Key,Value) VALUES($key,$value) ON CONFLICT(Key) DO UPDATE SET Value=excluded.Value;", ("$key", key), ("$value", value));
    private static void Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object Value)[] parameters) { using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = sql; foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value); command.ExecuteNonQuery(); }
    private static NetworkObservation ReadObservation(SqliteDataReader row)
    {
        string Value(string name) => row[name] is DBNull ? string.Empty : Convert.ToString(row[name], CultureInfo.InvariantCulture) ?? string.Empty;
        var native = JsonSerializer.Deserialize<NetworkObservation>(Value("ObservationJson")) ?? throw new InvalidDataException("Network observation payload unavailable.");
        return native with { ProcessEntityId = Value("BindingProcessEntityId"), ProcessName = Value("BindingProcessName") };
    }
    private void SaveObservation(SqliteConnection connection, SqliteTransaction transaction, string sourceKey, string inputHash, NetworkObservation observation) => Execute(connection, transaction, """INSERT INTO NetworkObservations(SourceKey,InputHash,CaseId,EvidenceSessionId,CaptureId,SourceIdentityId,HostId,ExecutionRootId,SequenceId,SourceRunId,IngestionJobId,RawRecordIdText,CapturedUtc,ProcessEntityId,ProcessGuid,ProcessId,ProcessName,ProcessImage,UserName,Protocol,SourceAddress,SourcePort,DestinationAddress,DestinationPort,Direction,LocalAddress,LocalPort,RemoteAddress,RemotePort,Diagnostic,Provider,ObservationKind,ObservationJson) VALUES($source,$hash,$case,$session,$capture,$identity,$host,$root,$sequence,$sourceRun,$job,$raw,$utc,$entity,$guid,$pid,$name,$image,$user,$protocol,$sourceAddress,$sourcePort,$destinationAddress,$destinationPort,$direction,$localAddress,$localPort,$remoteAddress,$remotePort,$diagnostic,$provider,$kind,$json) ON CONFLICT(SourceKey,InputHash) DO UPDATE SET ProcessEntityId=excluded.ProcessEntityId, ProcessGuid=excluded.ProcessGuid, ProcessId=excluded.ProcessId, ProcessName=excluded.ProcessName, ProcessImage=excluded.ProcessImage, UserName=excluded.UserName, Protocol=excluded.Protocol, SourceAddress=excluded.SourceAddress, SourcePort=excluded.SourcePort, DestinationAddress=excluded.DestinationAddress, DestinationPort=excluded.DestinationPort, Direction=excluded.Direction, LocalAddress=excluded.LocalAddress, LocalPort=excluded.LocalPort, RemoteAddress=excluded.RemoteAddress, RemotePort=excluded.RemotePort, Diagnostic=excluded.Diagnostic;""", ("$source",sourceKey),("$hash",inputHash),("$case",observation.Source.CaseId),("$session",observation.Source.EvidenceSessionId),("$capture",observation.Source.CaptureId),("$identity",observation.Source.SourceIdentityId),("$host",observation.Source.HostId),("$root",observation.Source.ExecutionRootId),("$sequence",observation.Source.SequenceId),("$sourceRun",observation.Source.SourceRunId),("$job",observation.Source.IngestionJobId),("$raw",observation.Source.RawRecordIdText),("$utc",observation.CapturedUtc.ToUniversalTime().ToString("O",CultureInfo.InvariantCulture)),("$entity",observation.ProcessEntityId),("$guid",observation.ProcessGuid),("$pid",(object?)observation.ProcessId ?? DBNull.Value),("$name",observation.ProcessName),("$image",observation.ProcessImage),("$user",observation.UserName),("$protocol",(object?)observation.Protocol ?? DBNull.Value),("$sourceAddress",(object?)observation.SourceEndpoint.Address ?? DBNull.Value),("$sourcePort",(object?)observation.SourceEndpoint.Port ?? DBNull.Value),("$destinationAddress",(object?)observation.DestinationEndpoint.Address ?? DBNull.Value),("$destinationPort",(object?)observation.DestinationEndpoint.Port ?? DBNull.Value),("$direction",observation.Direction.ToString()),("$localAddress",(object?)observation.LocalEndpoint?.Address ?? DBNull.Value),("$localPort",(object?)observation.LocalEndpoint?.Port ?? DBNull.Value),("$remoteAddress",(object?)observation.RemoteEndpoint?.Address ?? DBNull.Value),("$remotePort",(object?)observation.RemoteEndpoint?.Port ?? DBNull.Value),("$diagnostic",observation.Diagnostic),("$provider",observation.Provider),("$kind",observation.ObservationKind),("$json",JsonSerializer.Serialize(observation)));
    private void ThrowIfDisposed() { if (_disposed) throw new ObjectDisposedException(nameof(NetworkAnalysisService)); }
    private void Check(CancellationToken token) { token.ThrowIfCancellationRequested(); ThrowIfDisposed(); if (!_isCurrent()) throw new OperationCanceledException("The Network read binding is stale."); }
    private static string Fingerprint(string path, CancellationToken token = default)
    {
        using var stream = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete); using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[65536]; int read;
        while ((read = stream.Read(buffer)) > 0) { token.ThrowIfCancellationRequested(); hash.AppendData(buffer, 0, read); }
        return Convert.ToHexString(hash.GetHashAndReset());
    }
    private void CheckSource(CancellationToken token) { if (!string.Equals(_sourceFingerprint, Fingerprint(_source.ReadContext.DatabasePath, token), StringComparison.Ordinal)) throw new OperationCanceledException("The assessed Network source file changed; create a new read binding."); }
    public async ValueTask DisposeAsync()
    {
        _disposed = true;
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            await Task.Run(() =>
            {
                if (!File.Exists(_analysisPath) || new FileInfo(_analysisPath).Length == 0) return;
                using var connection = OpenAnalysis();
                if (AssessStore(connection) != null || !string.Equals(ReadMetadata(connection, "ProcessorVersion"), SysmonNetworkNormalizer.ProcessorVersion, StringComparison.Ordinal)) return;
                using var transaction = connection.BeginTransaction();
                Execute(connection, transaction, "DELETE FROM NetworkBindingMembers WHERE BindingId=$binding; DELETE FROM NetworkBindings WHERE BindingId=$binding;", ("$binding", _readBindingId));
                transaction.Commit();
            }).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
}
