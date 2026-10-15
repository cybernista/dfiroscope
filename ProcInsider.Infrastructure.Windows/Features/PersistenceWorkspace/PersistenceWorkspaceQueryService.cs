using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Features.PersistenceWorkspace;
using ProcInsider.Models;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services;

/// <summary>Read-only, capture-qualified projection over assessed persistence evidence. No analysis store.</summary>
internal sealed class PersistenceWorkspaceQueryService(SqliteReadQueryContext context) : IPersistenceWorkspaceQueryService
{
    public bool IsJobAccepted(EvidenceIdentity scope, Guid jobId, CancellationToken token = default)
    {
        if (jobId == Guid.Empty) throw new ArgumentException("An exact collection job is required.", nameof(jobId));
        using var connection = Open(scope, token); using var transaction = connection.BeginTransaction();
        using var command = Prepare(connection, transaction, new(scope), token);
        using var cancellation = token.Register(command.Cancel);
        command.Parameters.AddWithValue("$job", jobId.ToString("D"));
        command.CommandText = "SELECT EXISTS(SELECT 1 FROM PersistenceCollections WHERE ScopeKey=$scope AND IngestionJobId=$job)";
        return Convert.ToInt64(command.ExecuteScalar()) != 0;
    }
    public IReadOnlyList<PersistencePeriod> Periods(EvidenceIdentity scope, long offset = 0, int pageSize = 128, CancellationToken token = default)
    {
        if (offset < 0 || pageSize is < 1 or > 512) throw new ArgumentOutOfRangeException(nameof(pageSize));
        using var connection = Open(scope, token); using var transaction = connection.BeginTransaction();
        using var command = Prepare(connection, transaction, new(scope), token);
        using var cancellation = token.Register(command.Cancel);
        command.Parameters.AddWithValue("$offset", offset); command.Parameters.AddWithValue("$limit", pageSize);
        command.CommandText = """
            SELECT GenerationId,(SELECT json_extract(first.MetadataJson,'$.CompletedUtc') FROM PersistenceCollections first WHERE first.ScopeKey=c.ScopeKey AND first.GenerationId=c.GenerationId AND EXISTS(SELECT 1 FROM PersistenceCollectorResults r WHERE r.CollectionId=first.CollectionId AND json_extract(r.ResultJson,'$.Status')=0) ORDER BY Sequence LIMIT 1),MAX(json_extract(MetadataJson,'$.CompletedUtc')),
              (SELECT CollectionId FROM PersistenceCollections first WHERE first.ScopeKey=c.ScopeKey AND first.GenerationId=c.GenerationId AND EXISTS(SELECT 1 FROM PersistenceCollectorResults r WHERE r.CollectionId=first.CollectionId AND json_extract(r.ResultJson,'$.Status')=0) ORDER BY Sequence LIMIT 1),
              GenerationId=$period,MAX(CASE WHEN json_extract(MetadataJson,'$.BoundaryAcquisitionId')=CollectionId THEN 1 ELSE 0 END)
            FROM PersistenceCollections c WHERE ScopeKey=$scope GROUP BY GenerationId ORDER BY MIN(rowid) DESC LIMIT $limit OFFSET $offset
            """;
        using var reader = command.ExecuteReader(); var periods = new List<PersistencePeriod>();
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            periods.Add(new(reader.GetString(0), reader.IsDBNull(1) ? null : DateTime.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                DateTime.Parse(reader.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind), reader.IsDBNull(3) ? null : reader.GetString(3), reader.GetInt64(4) != 0, reader.GetInt64(5) != 0));
        }
        return periods;
    }
    private static readonly string[] Categories = ["Run", "RunOnce", "ScheduledTasks", "Services", "Drivers", "Startup", "WMI", "Winlogon", "IFEO", "AppInit", "LSA"];
    public IReadOnlyList<EvidenceIdentity> Scopes(string evidenceSessionId, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        using var connection = context.OpenReadOnlyConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        using var cancellation = token.Register(command.Cancel);
        command.CommandText = "SELECT Key,Value FROM SchemaInfo WHERE Key IN ('EvidenceSessionId','DefaultCaptureId','HostId','DefaultExecutionRootId','CaseId')";
        var identity = new Dictionary<string, string>(StringComparer.Ordinal);
        using (var reader = command.ExecuteReader()) while (reader.Read()) identity.Add(reader.GetString(0), reader.GetString(1));
        if (!identity.TryGetValue("EvidenceSessionId", out var session) || session != evidenceSessionId ||
            new[] { "HostId", "DefaultExecutionRootId" }.Any(k => !identity.TryGetValue(k, out var v) || string.IsNullOrWhiteSpace(v)))
            throw new InvalidDataException("Assessed persistence capture identity is unavailable or mismatched.");
        command.CommandText = "SELECT ScopeKey,MetadataJson,MetadataHash,CollectionId,SourceRunId,IngestionJobId,GenerationId,Sequence FROM PersistenceCollections ORDER BY ScopeKey,rowid";
        var scopes = new HashSet<EvidenceIdentity>();
        var previous = new Dictionary<string, PersistenceCollection>(StringComparer.Ordinal);
        using (var reader = command.ExecuteReader()) while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            var collection = Decode<PersistenceCollection>(Verify(reader.GetString(1), reader.GetString(2)));
            var scope = collection.EvidenceIdentity;
            if (PersistenceComparisonPolicy.ScopeKey(scope) != reader.GetString(0) || scope.EvidenceSessionId != session ||
                string.IsNullOrWhiteSpace(scope.CaptureId) || string.IsNullOrWhiteSpace(scope.SourceIdentityId) || scope.HostId != identity["HostId"] ||
                (scope.ExecutionRootId != identity["DefaultExecutionRootId"] && !(scope.SourceIdentityId == PersistenceCollection.LocalSourceIdentityId && scope.ExecutionRootId == session)) ||
                collection.CollectionId != reader.GetString(3) || collection.SourceRunId != reader.GetString(4) || collection.IngestionJobId != reader.GetString(5) ||
                collection.StateGenerationId != reader.GetString(6) || collection.CollectionSequence != reader.GetInt64(7) || !Enum.IsDefined(collection.Reason) ||
                scope.CaseId != identity.GetValueOrDefault("CaseId", "")) throw new InvalidDataException("Recorded persistence scope contradicts the assessed capture.");
            scopes.Add(scope);
            var key = PersistenceComparisonPolicy.ScopeKey(scope);
            var prior = previous.GetValueOrDefault(key);
            if (collection.ExpectedPredecessorCollectionId != prior?.CollectionId ||
                (prior?.StateGenerationId == collection.StateGenerationId ? collection.CollectionSequence != prior.CollectionSequence + 1 : collection.CollectionSequence != 1))
                throw new InvalidDataException("Persistence recorded period sequence is contradictory.");
            PersistenceComparisonPolicy.ValidateBoundaryUse(prior, collection);
            previous[key] = collection;
            if (scopes.Count > 128) throw new InvalidDataException("Persistence scope directory exceeds its explicit bound.");
        }
        if (previous.Values.Any(c => c.BoundaryAcquisitionId != null && c.CollectionId != c.BoundaryAcquisitionId))
            throw new InvalidDataException("Persistence history contains an incomplete boundary.");
        foreach (var scope in scopes)
        {
            using var provenance = Prepare(connection, transaction, new(scope), token);
        }
        ValidateHistory(connection, transaction, token);
        foreach (var scope in scopes) ValidateCurrent(connection, transaction, scope, token);
        return scopes.OrderBy(PersistenceComparisonPolicy.ScopeKey, StringComparer.Ordinal).ToArray();
    }
    private static void ValidateCurrent(SqliteConnection connection, SqliteTransaction transaction, EvidenceIdentity scope, CancellationToken token)
    {
        // Current is a rebuildable projection, never authority for presence or confirmation.
        const string expected = """
            WITH history AS (
              SELECT v.*,c.GenerationId,c.rowid Ordinal,
                ROW_NUMBER() OVER(PARTITION BY v.PartitionKey,v.ArtifactKey ORDER BY c.rowid DESC) Position
              FROM PersistenceVersions v JOIN PersistenceCollections c ON c.CollectionId=v.CollectionId
              WHERE c.ScopeKey=$scope AND json_extract(v.VersionJson,'$.Kind')<>4),
            expected AS (
              SELECT h.* FROM history h WHERE Position=1 AND json_extract(h.VersionJson,'$.Kind')<>3
              AND NOT EXISTS(SELECT 1 FROM PersistenceCollectorResults r JOIN PersistenceCollections c ON c.CollectionId=r.CollectionId
                WHERE c.ScopeKey=$scope AND r.PartitionKey=h.PartitionKey AND c.rowid>h.Ordinal AND c.GenerationId<>h.GenerationId
                  AND json_extract(r.ResultJson,'$.Status')=0 AND json_extract(r.ResultJson,'$.Coverage.SourceAvailability')=0))
            """;
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        using var cancellation = token.Register(command.Cancel);
        command.Parameters.AddWithValue("$scope", PersistenceComparisonPolicy.ScopeKey(scope));
        command.CommandText = expected + """
            SELECT h.VersionJson,h.GenerationId,h.PartitionKey,h.ArtifactKey,p.ArtifactJson,p.Fingerprint,p.GenerationId,p.LastConfirmedUtc,
              (SELECT json_extract(c.MetadataJson,'$.CompletedUtc') FROM PersistenceCollectorResults r JOIN PersistenceCollections c ON c.CollectionId=r.CollectionId
                WHERE c.ScopeKey=$scope AND r.PartitionKey=h.PartitionKey AND c.GenerationId=h.GenerationId AND c.rowid>=h.Ordinal
                  AND json_extract(r.ResultJson,'$.Status')=0 AND json_extract(r.ResultJson,'$.Coverage.SourceAvailability')=0 ORDER BY c.rowid DESC LIMIT 1)
            FROM expected h LEFT JOIN PersistenceCurrent p ON p.ScopeKey=$scope AND p.PartitionKey=h.PartitionKey AND p.ArtifactKey=h.ArtifactKey
            """;
        using (var reader = command.ExecuteReader()) while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            var version = Decode<PersistenceVersion>(reader.GetString(0));
            if (reader.IsDBNull(4) || reader.IsDBNull(8)) throw new InvalidDataException("Persistence Current is missing verified present evidence or confirmation.");
            var artifact = Decode<PersistenceArtifact>(reader.GetString(4)); RequireScope(artifact.EvidenceIdentity, scope);
            if (version.After == null || reader.GetString(6) != reader.GetString(1) ||
                PersistenceComparisonPolicy.CanonicalJson(reader.GetString(4)) != PersistenceComparisonPolicy.CanonicalJson(JsonSerializer.Serialize(version.After)) ||
                PersistenceComparisonPolicy.ArtifactKey(artifact) != reader.GetString(3) || PersistenceComparisonPolicy.PartitionKey(artifact.CollectorId, artifact.Coverage) != reader.GetString(2) ||
                PersistenceComparisonPolicy.Fingerprint(artifact) != reader.GetString(5) ||
                DateTime.Parse(reader.GetString(7), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime() != DateTime.Parse(reader.GetString(8), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime())
                throw new InvalidDataException("Persistence Current contradicts immutable native evidence, generation or accepted confirmation.");
        }
        command.CommandText = expected + """
            SELECT EXISTS(SELECT 1 FROM PersistenceCurrent p WHERE p.ScopeKey=$scope AND NOT EXISTS(
              SELECT 1 FROM expected h WHERE h.PartitionKey=p.PartitionKey AND h.ArtifactKey=p.ArtifactKey))
            """;
        if (Convert.ToInt64(command.ExecuteScalar()) != 0) throw new InvalidDataException("Persistence Current contains evidence absent from verified present history.");
    }
    private static void ValidateHistory(SqliteConnection connection, SqliteTransaction transaction, CancellationToken token)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        using var cancellation = token.Register(command.Cancel);
        command.CommandText = """
            SELECT EXISTS(SELECT 1 FROM PersistenceVersions v WHERE NOT EXISTS(SELECT 1 FROM PersistenceCollections c WHERE c.CollectionId=v.CollectionId))
              OR EXISTS(SELECT 1 FROM PersistenceCollectorResults r WHERE NOT EXISTS(SELECT 1 FROM PersistenceCollections c WHERE c.CollectionId=r.CollectionId))
              OR EXISTS(SELECT 1 FROM PersistenceSequenceState s WHERE NOT EXISTS(SELECT 1 FROM PersistenceCollections c WHERE c.CollectionId=s.CollectionId AND c.ScopeKey=s.ScopeKey))
              OR EXISTS(SELECT 1 FROM PersistenceCollections c WHERE c.VersionCount<>(SELECT COUNT(*) FROM PersistenceVersions v WHERE v.CollectionId=c.CollectionId))
              OR EXISTS(SELECT 1 FROM PersistenceCollections c WHERE json_array_length(c.MetadataJson,'$.Results')<>(SELECT COUNT(*) FROM PersistenceCollectorResults r WHERE r.CollectionId=c.CollectionId))
              OR EXISTS(SELECT 1 FROM PersistenceCurrent p WHERE NOT EXISTS(SELECT 1 FROM PersistenceVersions v JOIN PersistenceCollections c ON c.CollectionId=v.CollectionId WHERE c.ScopeKey=p.ScopeKey AND v.PartitionKey=p.PartitionKey AND v.ArtifactKey=p.ArtifactKey))
            """;
        if (Convert.ToInt64(command.ExecuteScalar()) != 0) throw new InvalidDataException("Persistence retained history has missing parents, versions or current attribution.");
        command.CommandText = "SELECT v.VersionJson,v.VersionHash,v.CollectionId,v.PartitionKey,v.ArtifactKey,c.MetadataJson,c.MetadataHash,r.ResultJson,r.ResultHash FROM PersistenceVersions v JOIN PersistenceCollections c ON c.CollectionId=v.CollectionId LEFT JOIN PersistenceCollectorResults r ON r.CollectionId=v.CollectionId AND r.PartitionKey=v.PartitionKey";
        using (var reader = command.ExecuteReader()) while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            var version = Decode<PersistenceVersion>(Verify(reader.GetString(0), reader.GetString(1)));
            var collection = Decode<PersistenceCollection>(Verify(reader.GetString(5), reader.GetString(6)));
            if (!Enum.IsDefined(version.Kind) || version.CollectionId != reader.GetString(2) || version.CollectionId != collection.CollectionId ||
                version.StateGenerationId != collection.StateGenerationId || version.ArtifactKey != reader.GetString(4) ||
                PersistenceComparisonPolicy.PartitionKey(version.CollectorId, version.Coverage) != reader.GetString(3) ||
                (version.Kind == PersistenceChangeKind.Removed ? version.Before == null || version.After != null : version.After == null) ||
                ((version.Kind is PersistenceChangeKind.Added or PersistenceChangeKind.Baseline or PersistenceChangeKind.ObservedIncomplete) && version.Before != null) ||
                (version.Kind == PersistenceChangeKind.Modified && version.Before == null))
                throw new InvalidDataException("Persistence immutable version identity is contradictory.");
            if (version.Kind == PersistenceChangeKind.ObservedIncomplete)
            {
                if (reader.IsDBNull(7)) throw new InvalidDataException("Incomplete observation lacks its source result.");
                var result = Decode<PersistenceCollectorResult>(Verify(reader.GetString(7), reader.GetString(8)));
                if (result.CollectorId != "persistence.services-drivers.v1" || result.Status != PersistenceCollectionStatus.Partial ||
                    result.Coverage.SourceAvailability != PersistenceSourceAvailability.Unavailable)
                    throw new InvalidDataException("Incomplete observation lacks its partial service/driver source result.");
            }
            foreach (var artifact in new[] { version.Before, version.After }.OfType<PersistenceArtifact>())
            {
                RequireScope(artifact.EvidenceIdentity, collection.EvidenceIdentity);
                if (artifact.CollectorId != version.CollectorId || artifact.Coverage != version.Coverage || !Enum.IsDefined(artifact.Coverage.SourceAvailability) ||
                    artifact.Configuration.Values.Any(value => !Enum.IsDefined(value.State)) || PersistenceComparisonPolicy.PartitionKey(artifact.CollectorId, artifact.Coverage) != reader.GetString(3) ||
                    PersistenceComparisonPolicy.ArtifactKey(artifact) != version.ArtifactKey)
                    throw new InvalidDataException("Persistence immutable native artifact identity is contradictory.");
            }
        }
        command.CommandText = "SELECT r.ResultJson,r.ResultHash,r.PartitionKey,c.MetadataJson,c.MetadataHash FROM PersistenceCollectorResults r JOIN PersistenceCollections c ON c.CollectionId=r.CollectionId";
        using (var reader = command.ExecuteReader()) while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            var json = Verify(reader.GetString(0), reader.GetString(1)); var result = Decode<PersistenceCollectorResult>(json);
            using var acceptedResult = JsonDocument.Parse(json);
            var collection = Decode<PersistenceCollection>(Verify(reader.GetString(3), reader.GetString(4)));
            var matching = collection.Results.Where(candidate => PersistenceComparisonPolicy.PartitionKey(candidate.CollectorId, candidate.Coverage) == reader.GetString(2)).ToArray();
            if (!Enum.IsDefined(result.Status) || !Enum.IsDefined(result.Coverage.SourceAvailability) || PersistenceComparisonPolicy.PartitionKey(result.CollectorId, result.Coverage) != reader.GetString(2) ||
                matching.Length != 1 || matching[0].CollectorId != result.CollectorId || matching[0].Coverage != result.Coverage ||
                matching[0].Status != result.Status || matching[0].Duration != result.Duration || matching[0].DiagnosticSummary != result.DiagnosticSummary ||
                matching[0].Artifacts.Count != 0 || !acceptedResult.RootElement.TryGetProperty("Count", out var count) || !count.TryGetInt32(out var countValue) || countValue < 0)
                throw new InvalidDataException("Persistence accepted result metadata is contradictory.");
        }
    }
    private const string Cte = """
        WITH collections AS MATERIALIZED (
          SELECT CollectionId,GenerationId,Sequence,SourceRunId,IngestionJobId,
            persistence_verify(MetadataJson,MetadataHash) AS MetadataJson,rowid AS Ordinal
          FROM PersistenceCollections WHERE ScopeKey=$scope AND rowid<=(SELECT MAX(rowid) FROM PersistenceCollections WHERE ScopeKey=$scope AND GenerationId=$period)),
        versions AS MATERIALIZED (
          SELECT v.CollectionId,v.PartitionKey,v.ArtifactKey,persistence_verify(v.VersionJson,v.VersionHash) AS VersionJson,
            c.MetadataJson,c.GenerationId,c.Ordinal,
            json_extract(c.MetadataJson,'$.CompletedUtc') AS ObservedUtc,
            json_extract(c.MetadataJson,'$.StartedUtc') AS StartedUtc
          FROM PersistenceVersions v JOIN collections c ON c.CollectionId=v.CollectionId),
        history AS MATERIALIZED (
          SELECT *,COALESCE(json_extract(VersionJson,'$.After'),json_extract(VersionJson,'$.Before')) AS ArtifactJson,
            (SELECT MIN(ObservedUtc) FROM versions first WHERE first.PartitionKey=versions.PartitionKey AND first.ArtifactKey=versions.ArtifactKey) AS FirstObservedUtc,
            ObservedUtc AS LastChangedUtc,NULL AS LastConfirmedUtc,
            CASE WHEN json_extract(VersionJson,'$.Kind')=4 THEN 2 ELSE 0 END AS Stale
          FROM versions),
        confirmedCurrent AS MATERIALIZED (
          SELECT h.CollectionId,h.PartitionKey,h.ArtifactKey,h.VersionJson,h.MetadataJson,h.GenerationId,h.Ordinal,h.ObservedUtc,h.StartedUtc,
            h.ArtifactJson,h.FirstObservedUtc,h.LastChangedUtc,
            (SELECT json_extract(confirmed.MetadataJson,'$.CompletedUtc') FROM PersistenceCollectorResults result JOIN collections confirmed ON confirmed.CollectionId=result.CollectionId
              WHERE result.PartitionKey=h.PartitionKey AND confirmed.GenerationId=h.GenerationId AND json_extract(persistence_verify(result.ResultJson,result.ResultHash),'$.Status')=0
              ORDER BY confirmed.Ordinal DESC LIMIT 1) AS LastConfirmedUtc,
            CASE WHEN NOT EXISTS(SELECT 1 FROM PersistenceCollectorResults result JOIN collections latest ON latest.CollectionId=result.CollectionId
              WHERE result.PartitionKey=h.PartitionKey AND result.CollectionId=(SELECT CollectionId FROM collections ORDER BY Ordinal DESC LIMIT 1)
              AND latest.GenerationId=h.GenerationId AND json_extract(persistence_verify(result.ResultJson,result.ResultHash),'$.Status')=0
              AND json_extract(result.ResultJson,'$.Coverage.SourceAvailability')=0) THEN 1 ELSE 0 END AS Stale
          FROM history h WHERE json_extract(h.VersionJson,'$.Kind') NOT IN (3,4)
            AND h.Ordinal=(SELECT MAX(last.Ordinal) FROM history last WHERE last.PartitionKey=h.PartitionKey AND last.ArtifactKey=h.ArtifactKey
              AND json_extract(last.VersionJson,'$.Kind')<>4)
            AND NOT EXISTS(SELECT 1 FROM PersistenceCollectorResults result JOIN collections later ON later.CollectionId=result.CollectionId
              WHERE result.PartitionKey=h.PartitionKey AND later.Ordinal>h.Ordinal AND later.GenerationId<>h.GenerationId
                AND json_extract(persistence_verify(result.ResultJson,result.ResultHash),'$.Status')=0)),
        incompleteCurrent AS MATERIALIZED (
          SELECT h.CollectionId,h.PartitionKey,h.ArtifactKey,h.VersionJson,h.MetadataJson,h.GenerationId,h.Ordinal,h.ObservedUtc,h.StartedUtc,
            h.ArtifactJson,h.FirstObservedUtc,h.LastChangedUtc,NULL AS LastConfirmedUtc,2 AS Stale
          FROM history h WHERE json_extract(h.VersionJson,'$.Kind')=4
            AND h.Ordinal>COALESCE((SELECT MAX(done.Ordinal) FROM PersistenceCollectorResults result
              JOIN collections done ON done.CollectionId=result.CollectionId WHERE result.PartitionKey=h.PartitionKey
                AND json_extract(persistence_verify(result.ResultJson,result.ResultHash),'$.Status')=0),0)
            AND h.Ordinal=(SELECT MAX(last.Ordinal) FROM history last WHERE last.PartitionKey=h.PartitionKey
              AND last.ArtifactKey=h.ArtifactKey AND json_extract(last.VersionJson,'$.Kind')=4)),
        current AS MATERIALIZED (
          SELECT * FROM confirmedCurrent c WHERE NOT EXISTS(SELECT 1 FROM incompleteCurrent i
            WHERE i.PartitionKey=c.PartitionKey AND i.ArtifactKey=c.ArtifactKey)
          UNION ALL SELECT * FROM incompleteCurrent),
        rows AS MATERIALIZED (SELECT * FROM current WHERE $view=0 UNION ALL SELECT * FROM history WHERE $view=1 AND GenerationId=$period AND ($includeBaseline=1 OR json_extract(VersionJson,'$.Kind')<>0)),
        projected AS MATERIALIZED (
          SELECT *,json_extract(ArtifactJson,'$.Category') AS Type,json_extract(ArtifactJson,'$.NativeName') AS Name,
            json_extract(ArtifactJson,'$.NativeLocation') AS Location,
            COALESCE(json_extract(ArtifactJson,'$.Command'),json_extract(ArtifactJson,'$.Target')) AS TargetCommand,
            json_extract(ArtifactJson,'$.Principal') AS Principal,
            CASE json_extract(VersionJson,'$.Kind') WHEN 0 THEN 'Baseline' WHEN 1 THEN 'Added' WHEN 2 THEN 'Modified' WHEN 3 THEN 'Removed' WHEN 4 THEN 'Observed incomplete' END AS Change,
            CASE Stale WHEN 2 THEN 'Observed incomplete / unconfirmed' WHEN 1 THEN 'Stale / latest known' ELSE 'Confirmed for declared coverage' END AS Freshness,
            GenerationId AS Generation FROM rows)
        """;

    public PersistenceWorkspacePage Query(PersistenceWorkspaceQuery query, CancellationToken token = default)
    {
        using var connection = Open(query.Scope, token);
        using var transaction = connection.BeginTransaction();
        using var command = Prepare(connection, transaction, query, token);
        using var cancellation = token.Register(command.Cancel);
        var predicate = Predicate(connection, command, query);
        command.CommandText = Cte + " SELECT COUNT(*) FROM projected " + predicate;
        var count = Convert.ToInt64(command.ExecuteScalar());
        command.Parameters.AddWithValue("$offset", query.Offset);
        command.Parameters.AddWithValue("$limit", query.PageSize);
        command.CommandText = Cte + " SELECT ArtifactJson,MetadataJson,VersionJson,PartitionKey,ArtifactKey,FirstObservedUtc,LastChangedUtc,LastConfirmedUtc,Stale FROM projected " + predicate +
            $" ORDER BY {query.Sort} IS NULL,{query.Sort} COLLATE NOCASE {(query.Descending ? "DESC" : "ASC")},Ordinal,PartitionKey,ArtifactKey,CollectionId LIMIT $limit OFFSET $offset";
        var rows = ReadRows(command, query.Scope, token);
        var categoryCounts = Categories.ToDictionary(c => c, _ => 0L, StringComparer.Ordinal);
        var categoryPredicate = Predicate(connection, command, query, "facet");
        command.CommandText = Cte + " SELECT Type,COUNT(*) FROM projected " + categoryPredicate + " GROUP BY Type";
        using (var reader = command.ExecuteReader()) while (reader.Read()) categoryCounts[reader.GetString(0)] = reader.GetInt64(1);
        var viewCounts = new Dictionary<PersistenceView, long>();
        foreach (var view in Enum.GetValues<PersistenceView>())
        {
            command.Parameters["$view"].Value = (int)view;
            var viewPredicate = Predicate(connection, command, view == query.View ? query : query with { View = view, Category = null, Selectors = null, Filters = null }, "view" + (int)view);
            command.CommandText = Cte + " SELECT COUNT(*) FROM projected " + viewPredicate;
            viewCounts[view] = Convert.ToInt64(command.ExecuteScalar());
        }
        var coverage = new List<PersistenceCoverageRow>();
        command.CommandText = "SELECT MetadataJson,MetadataHash FROM PersistenceCollections WHERE ScopeKey=$scope AND GenerationId=$period ORDER BY rowid DESC LIMIT 1";
        using (var reader = command.ExecuteReader()) if (reader.Read())
        {
            var collection = Decode<PersistenceCollection>(Verify(reader.GetString(0), reader.GetString(1)));
            RequireScope(collection.EvidenceIdentity, query.Scope);
            coverage.AddRange(collection.Results.Select(result => new PersistenceCoverageRow(collection, result)));
        }
        token.ThrowIfCancellationRequested();
        return new(rows, count, categoryCounts, viewCounts, coverage, "Accepted observation times; changes between polls may be missed.");
    }

    public ColumnFilterValuePage Values(PersistenceWorkspaceQuery query, PersistenceColumn column, string? search, ColumnFilterValueSort sort, CancellationToken token = default)
    {
        if (!Enum.IsDefined(column) || !Enum.IsDefined(sort)) throw new ArgumentOutOfRangeException(nameof(column));
        using var connection = Open(query.Scope, token);
        using var transaction = connection.BeginTransaction();
        using var command = Prepare(connection, transaction, query, token);
        using var cancellation = token.Register(command.Cancel);
        var predicate = Predicate(connection, command, query with { Filters = query.Filters?.Where(f => f.Column != column).ToArray() });
        connection.CreateFunction<string?, bool>("persistence_value_search", value => ColumnTextFilter.Matches(value, search), true);
        var ordering = sort switch { ColumnFilterValueSort.ValueAscending => "Value ASC", ColumnFilterValueSort.ValueDescending => "Value DESC", ColumnFilterValueSort.CountAscending => "Occurrences ASC,Value ASC", _ => "Occurrences DESC,Value ASC" };
        command.CommandText = Cte + $" SELECT Value,COUNT(*) Occurrences FROM (SELECT CAST({column} AS TEXT) Value FROM projected {predicate}) WHERE persistence_value_search(Value) GROUP BY Value ORDER BY {ordering} LIMIT 257";
        using var reader = command.ExecuteReader();
        var rows = new List<ColumnFilterValue>();
        while (reader.Read()) { token.ThrowIfCancellationRequested(); rows.Add(new(reader.IsDBNull(0) ? null : reader.GetString(0), reader.GetInt64(1))); }
        return new(rows.Take(256).ToArray(), rows.Count > 256);
    }

    public PersistenceHistoryPage History(PersistenceHistoryQuery history, CancellationToken token = default)
    {
        var reference = history.Object;
        // First prove that the exact selected version belongs to the requested object and scope.
        var selected = Detail(reference, token).Row;
        var query = new PersistenceWorkspaceQuery(reference.Scope, PersistenceView.Changes, Filters: history.Filters, Sort: history.Sort, Descending: history.Descending, Offset: history.Offset, PageSize: history.PageSize, PeriodId: reference.PeriodId ?? selected.Generation);
        using var connection = Open(reference.Scope, token);
        using var transaction = connection.BeginTransaction();
        using var command = Prepare(connection, transaction, query, token);
        command.Parameters["$includeBaseline"].Value = 1;
        using var cancellation = token.Register(command.Cancel);
        command.Parameters.AddWithValue("$partition", reference.PartitionKey); command.Parameters.AddWithValue("$artifact", reference.ArtifactKey);
        command.Parameters.AddWithValue("$offset", history.Offset); command.Parameters.AddWithValue("$limit", history.PageSize);
        var predicate = Predicate(connection, command, query);
        var where = (predicate.Length == 0 ? " WHERE " : predicate + " AND ") + "PartitionKey=$partition AND ArtifactKey=$artifact";
        command.CommandText = Cte + " SELECT COUNT(*) FROM projected" + where;
        var count = Convert.ToInt64(command.ExecuteScalar());
        command.CommandText = Cte + " SELECT ArtifactJson,MetadataJson,VersionJson,PartitionKey,ArtifactKey,FirstObservedUtc,LastChangedUtc,LastConfirmedUtc,Stale FROM projected" + where + $" ORDER BY {query.Sort} IS NULL,{query.Sort} COLLATE NOCASE {(query.Descending ? "DESC" : "ASC")},Ordinal,CollectionId LIMIT $limit OFFSET $offset";
        return new(ReadRows(command, reference.Scope, token), count);
    }

    public ColumnFilterValuePage HistoryValues(PersistenceHistoryQuery history, PersistenceColumn column, string? search, ColumnFilterValueSort sort, CancellationToken token = default)
    {
        if (!Enum.IsDefined(column) || !Enum.IsDefined(sort)) throw new ArgumentOutOfRangeException(nameof(column));
        var selected = Detail(history.Object, token).Row;
        var reference = history.Object;
        var query = new PersistenceWorkspaceQuery(reference.Scope, PersistenceView.Changes, Filters: history.Filters?.Where(f => f.Column != column).ToArray(), PeriodId: reference.PeriodId ?? selected.Generation);
        using var connection = Open(reference.Scope, token); using var transaction = connection.BeginTransaction();
        using var command = Prepare(connection, transaction, query, token); using var cancellation = token.Register(command.Cancel);
        command.Parameters["$includeBaseline"].Value = 1;
        command.Parameters.AddWithValue("$partition", reference.PartitionKey); command.Parameters.AddWithValue("$artifact", reference.ArtifactKey);
        var predicate = Predicate(connection, command, query);
        var where = (predicate.Length == 0 ? " WHERE " : predicate + " AND ") + "PartitionKey=$partition AND ArtifactKey=$artifact";
        connection.CreateFunction<string?, bool>("persistence_history_search", value => ColumnTextFilter.Matches(value, search), true);
        var order = sort switch { ColumnFilterValueSort.ValueAscending => "Value ASC", ColumnFilterValueSort.ValueDescending => "Value DESC", ColumnFilterValueSort.CountAscending => "Occurrences ASC,Value ASC", _ => "Occurrences DESC,Value ASC" };
        command.CommandText = Cte + $" SELECT Value,COUNT(*) Occurrences FROM (SELECT CAST({column} AS TEXT) Value FROM projected{where}) WHERE persistence_history_search(Value) GROUP BY Value ORDER BY {order} LIMIT 257";
        using var reader = command.ExecuteReader(); var values = new List<ColumnFilterValue>();
        while (reader.Read()) { token.ThrowIfCancellationRequested(); values.Add(new(reader.IsDBNull(0) ? null : reader.GetString(0), reader.GetInt64(1))); }
        return new(values.Take(256).ToArray(), values.Count > 256);
    }

    public PersistenceObjectDetail Detail(PersistenceObjectReference reference, CancellationToken token = default)
    {
        if (string.IsNullOrWhiteSpace(reference.PartitionKey) || string.IsNullOrWhiteSpace(reference.ArtifactKey) || string.IsNullOrWhiteSpace(reference.CollectionId)) throw new ArgumentException("Exact persistence object/version identity required.");
        var query = new PersistenceWorkspaceQuery(reference.Scope, PersistenceView.Changes, PeriodId: reference.PeriodId);
        using var connection = Open(reference.Scope, token);
        using var transaction = connection.BeginTransaction();
        using var command = Prepare(connection, transaction, query, token);
        command.Parameters["$includeBaseline"].Value = 1;
        if (reference.PeriodId == null)
        {
            command.CommandText = "SELECT GenerationId FROM PersistenceCollections WHERE ScopeKey=$scope AND CollectionId=$exact";
            command.Parameters.AddWithValue("$exact", reference.CollectionId);
            command.Parameters["$period"].Value = command.ExecuteScalar() as string ?? throw new InvalidDataException("Persistence reference collection is unavailable.");
        }
        using var cancellation = token.Register(command.Cancel);
        command.Parameters.AddWithValue("$partition", reference.PartitionKey); command.Parameters.AddWithValue("$artifact", reference.ArtifactKey); command.Parameters.AddWithValue("$collection", reference.CollectionId);
        command.CommandText = Cte + " SELECT ArtifactJson,MetadataJson,VersionJson,PartitionKey,ArtifactKey,FirstObservedUtc,LastChangedUtc,LastConfirmedUtc,Stale FROM projected WHERE PartitionKey=$partition AND ArtifactKey=$artifact AND CollectionId=$collection";
        var row = ReadRows(command, reference.Scope, token).SingleOrDefault() ?? throw new InvalidDataException("The exact persistence version is unavailable in this read binding.");
        return new(row, row.Version?.Before, row.Version?.After);
    }

    private SqliteConnection Open(EvidenceIdentity scope, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (new[] { scope.EvidenceSessionId, scope.CaptureId, scope.SourceIdentityId, scope.HostId, scope.ExecutionRootId }.Any(string.IsNullOrWhiteSpace)) throw new ArgumentException("Full persistence evidence scope required.");
        if (!Scopes(scope.EvidenceSessionId, token).Contains(scope)) throw new InvalidDataException("The selected producer scope is not admitted by this assessed capture.");
        var connection = context.OpenReadOnlyConnection();
        connection.CreateFunction<string, string, string>("persistence_verify", Verify, true);
        connection.CreateFunction<string, string, string, string>("persistence_artifact", (json, fingerprint, key) =>
        {
            var artifact = Decode<PersistenceArtifact>(json); RequireScope(artifact.EvidenceIdentity, scope);
            if (PersistenceComparisonPolicy.Fingerprint(artifact) != fingerprint || PersistenceComparisonPolicy.ArtifactKey(artifact) != key) throw new InvalidDataException("Persistence current projection integrity failed.");
            return json;
        }, true);
        return connection;
    }
    private static SqliteCommand Prepare(SqliteConnection connection, SqliteTransaction transaction, PersistenceWorkspaceQuery query, CancellationToken token)
    {
        if (!Enum.IsDefined(query.View) || !Enum.IsDefined(query.Sort) || query.Offset < 0 || query.PageSize is < 1 or > 512 || query.Filters?.Count > Enum.GetValues<PersistenceColumn>().Length || query.Selectors?.Count > 128) throw new ArgumentOutOfRangeException(nameof(query));
        if (query.Selectors?.Any(selector => selector.View is { } view && !Enum.IsDefined(view)) == true) throw new ArgumentException("Unknown view selector.", nameof(query));
        var command = connection.CreateCommand(); command.Transaction = transaction;
        command.Parameters.AddWithValue("$scope", PersistenceComparisonPolicy.ScopeKey(query.Scope)); command.Parameters.AddWithValue("$view", (int)query.View);
        command.Parameters.AddWithValue("$includeBaseline", 0);
        command.CommandText = "SELECT GenerationId FROM PersistenceCollections WHERE ScopeKey=$scope " + (query.PeriodId == null ? "ORDER BY rowid DESC LIMIT 1" : "AND GenerationId=$requested LIMIT 1");
        if (query.PeriodId != null) command.Parameters.AddWithValue("$requested", query.PeriodId);
        var period = command.ExecuteScalar() as string;
        if (query.PeriodId != null && period == null) throw new InvalidDataException("Persistence period is unavailable in this read binding.");
        command.Parameters.AddWithValue("$period", period ?? "");
        // Every authoritative collection must retain its exact source and job links; missing attribution is an error, not an empty result.
        command.CommandText = """
            SELECT COUNT(*) FROM PersistenceCollections c WHERE ScopeKey=$scope AND
             (NOT EXISTS(SELECT 1 FROM SourceRuns r WHERE r.SourceRunId=c.SourceRunId AND r.IngestionJobId=c.IngestionJobId AND COALESCE(r.CaseId,'')=$case AND r.EvidenceSessionId=$session AND r.CaptureId=$capture AND r.SourceIdentityId=$source AND r.HostId=$host AND r.ExecutionRootId=$root)
              OR NOT EXISTS(SELECT 1 FROM IngestionJobs j JOIN SourceRuns r ON r.SourceRunId=j.SourceRunId WHERE j.JobId=c.IngestionJobId AND j.SourceRunId=c.SourceRunId AND (j.SourceId IS NULL OR j.SourceId=r.SourceId) AND COALESCE(j.CaseId,'')=$case AND j.EvidenceSessionId=$session AND j.CaptureId=$capture AND j.HostId=$host AND j.ExecutionRootId=$root))
            """;
        var s = query.Scope;
        foreach (var (name, value) in new[] { ("$case", s.CaseId), ("$session", s.EvidenceSessionId), ("$capture", s.CaptureId), ("$source", s.SourceIdentityId), ("$host", s.HostId), ("$root", s.ExecutionRootId) }) command.Parameters.AddWithValue(name, value);
        if (Convert.ToInt64(command.ExecuteScalar()) != 0) { command.Dispose(); throw new InvalidDataException("Persistence source-run/job attribution is unavailable or mismatched."); }
        token.ThrowIfCancellationRequested();
        return command;
    }
    private static string Predicate(SqliteConnection connection, SqliteCommand command, PersistenceWorkspaceQuery query, string suffix = "filter")
    {
        var terms = new List<string>();
        if (query.ExactObject is { } exact)
        {
            if (exact.Scope != query.Scope || string.IsNullOrWhiteSpace(exact.PartitionKey) ||
                string.IsNullOrWhiteSpace(exact.ArtifactKey) || string.IsNullOrWhiteSpace(exact.CollectionId))
                throw new ArgumentException("Exact persistence navigation requires the same qualified scope.");
            foreach (var (column, value) in new[] { ("PartitionKey", exact.PartitionKey), ("ArtifactKey", exact.ArtifactKey), ("CollectionId", exact.CollectionId) })
            {
                var name = "$exact" + column + suffix;
                command.Parameters.AddWithValue(name, value);
                terms.Add(column + "=" + name);
            }
        }
        if (query.Category != null) { var name = "$category" + suffix; command.Parameters.AddWithValue(name, query.Category); terms.Add("Type=" + name); }
        var selectors = (query.Selectors ?? []).Where(s => s.View == null || s.View == query.View).ToArray();
        foreach (var family in new[] { 0, 1 })
        {
            var relevant = selectors.Where(s => family == 0
                ? s.View != null && (!s.Excluded || s.Category == null)
                : s.Category != null && (s.View == null || s.View == query.View)).ToArray();
            if (family == 1 && selectors.Any(s => !s.Excluded && s.Category == null && (s.View == null || s.View == query.View)))
                relevant = relevant.Where(s => s.Excluded).ToArray();
            var includes = new List<string>(); var excludes = new List<string>();
            for (var i = 0; i < relevant.Length; i++)
            {
                var selector = relevant[i]; var name = "$selector" + suffix + family + "_" + i;
                if (family == 0) { if (!Enum.IsDefined(selector.View!.Value)) throw new ArgumentException("Unknown view selector."); command.Parameters.AddWithValue(name, (int)selector.View.Value); }
                else command.Parameters.AddWithValue(name, selector.Category!);
                (selector.Excluded ? excludes : includes).Add((family == 0 ? "$view=" : "Type=") + name);
            }
            if (includes.Count != 0) terms.Add("(" + string.Join(" AND ", includes) + ")");
            if (excludes.Count != 0) terms.Add("NOT (" + string.Join(" OR ", excludes) + ")");
        }
        var filters = query.Filters ?? [];
        for (var i = 0; i < filters.Count; i++)
        {
            var filter = filters[i]; if (!Enum.IsDefined(filter.Column)) throw new ArgumentException("Unknown persistence column."); filter.Criteria.Validate();
            var function = "persistence_" + suffix + i;
            connection.CreateFunction<string?, bool>(function, value => filter.Criteria.Matches(value, timestampUtc: DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var utc) && utc.Kind == DateTimeKind.Utc ? utc : null), true);
            terms.Add(function + "(CAST(" + filter.Column + " AS TEXT))");
        }
        return terms.Count == 0 ? "" : " WHERE " + string.Join(" AND ", terms);
    }
    private static IReadOnlyList<PersistenceWorkspaceRow> ReadRows(SqliteCommand command, EvidenceIdentity scope, CancellationToken token)
    {
        using var cancellation = token.Register(command.Cancel);
        using var reader = command.ExecuteReader(); var rows = new List<PersistenceWorkspaceRow>();
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            var artifact = Decode<PersistenceArtifact>(reader.GetString(0)); var collection = Decode<PersistenceCollection>(reader.GetString(1)); var version = Decode<PersistenceVersion>(reader.GetString(2));
            RequireScope(artifact.EvidenceIdentity, scope); RequireScope(collection.EvidenceIdentity, scope);
            if (collection.CollectionId != version.CollectionId || collection.StateGenerationId != version.StateGenerationId || version.ArtifactKey != reader.GetString(4) || PersistenceComparisonPolicy.PartitionKey(artifact.CollectorId, artifact.Coverage) != reader.GetString(3)) throw new InvalidDataException("Persistence version identity is contradictory.");
            DateTime? Date(int column) => reader.IsDBNull(column) ? null : DateTime.Parse(reader.GetString(column), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
            rows.Add(new(scope, reader.GetString(3), reader.GetString(4), artifact, collection, version, Date(5), Date(6), Date(7), reader.GetInt64(8) != 0));
        }
        return rows;
    }
    private static void RequireScope(EvidenceIdentity actual, EvidenceIdentity expected) { if (actual != expected) throw new InvalidDataException("Persistence evidence scope mismatch."); }
    private static T Decode<T>(string json) => JsonSerializer.Deserialize<T>(json) ?? throw new InvalidDataException("Missing persistence payload.");
    private static string Verify(string json, string hash) => PersistenceComparisonPolicy.Hash(json) == hash ? json : throw new InvalidDataException("Persistence immutable history integrity failed.");
}
