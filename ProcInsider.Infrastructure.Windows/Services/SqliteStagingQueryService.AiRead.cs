using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed record AiSnapshotReadPage<T>(IReadOnlyList<T> Rows, long MatchingRows, bool Supported, string Diagnostic);
public sealed record AiSourceRunRow(EvidenceIdentity Identity, string SourceRunId, string SourceType,
    string DisplayName, string Status, DateTime? StartedUtc, DateTime? EndedUtc, string Provider,
    string Channel, string ToolVersion, string ParserVersion, string IngestionJobId);
public sealed record AiProcessObservationRow(EvidenceIdentity Identity, string ObservationId, string ProcessEntityId,
    string AdapterId, string ObservationKind, string SourceRunId, string IngestionJobId, string RawRecordId,
    string SourceNativeAlias, DateTime? ObservedUtc, DateTime? ValidFromUtc, DateTime? ValidToUtc,
    string StatusAssertion, string CorrelationMethod, double CorrelationConfidence, string ParserVersion);
public sealed record AiSourceRunLineageRow(EvidenceIdentity Identity, long LineageId, string SourceRunId, string ParentSourceRunId,
    string InputArtifactId, string InputPath, string InputHash, string RelationType, DateTime? CreatedUtc);
public sealed record AiProjectionWinnerRow(EvidenceIdentity Identity, string ProcessEntityId,
    ProcessProjectionFieldWinner Winner, string ProjectionVersion, DateTime? UpdatedUtc);
public sealed record AiCorrelationGroupRow(string State, string EvidenceKind, string Source, long InputCount, string AnchorInputId);

public sealed partial class SqliteStagingQueryService
{
    public AiSnapshotReadPage<AiCorrelationGroupRow> GetCorrelationGroupPageForAi(EvidenceIdentity scope,
        bool compatibleRoots = false, long offset = 0, int pageSize = 50, CancellationToken cancellationToken = default) =>
        _readContext.MeasureRead("GetCorrelationGroupPageForAi", () =>
    {
        ValidateAiPage(scope, offset, pageSize);
        if (!GetCorrelationInputPageForAi(scope, compatibleRoots, pageSize: 1, cancellationToken: cancellationToken).Supported)
            return new AiSnapshotReadPage<AiCorrelationGroupRow>([], 0, false, "Correlation group schema unavailable.");
        using var connection = OpenReadOnlyConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var predicate = AiReadPredicate(connection, command, scope, compatibleRoots);
        var cte = "WITH admitted_inputs AS (SELECT * FROM EvidenceCorrelationInputs WHERE " + predicate +
            "), admitted_decisions AS (SELECT * FROM EvidenceRelations WHERE " + predicate +
            "), groups AS (SELECT COALESCE(r.CorrelationState,'Unresolved') AS State,i.EvidenceKind,i.Source,COUNT(*) AS InputCount,MIN(i.InputId) AS AnchorInputId" +
            " FROM admitted_inputs i LEFT JOIN admitted_decisions r ON r.RelationId=(SELECT active.RelationId FROM admitted_decisions active WHERE active.DecisionKey=" +
            CorrelationDecisionKeySql("i") + " AND active.Status='Active' ORDER BY active.UpdatedUtc DESC,active.RelationId DESC LIMIT 1)" +
            " GROUP BY COALESCE(r.CorrelationState,'Unresolved'),i.EvidenceKind,i.Source) ";
        using var cancellation = cancellationToken.Register(command.Cancel);
        cancellationToken.ThrowIfCancellationRequested();
        command.CommandText = cte + "SELECT COUNT(*) FROM groups";
        var matching = Convert.ToInt64(command.ExecuteScalar());
        command.CommandText = cte + "SELECT State,EvidenceKind,Source,InputCount,AnchorInputId FROM groups ORDER BY InputCount DESC,State ASC,EvidenceKind ASC,Source ASC LIMIT $take OFFSET $skip";
        command.Parameters.AddWithValue("$take", pageSize);
        command.Parameters.AddWithValue("$skip", offset);
        var rows = new List<AiCorrelationGroupRow>();
        using var reader = command.ExecuteReader();
        while (reader.Read()) { cancellationToken.ThrowIfCancellationRequested(); rows.Add(new(GetString(reader, 0), GetString(reader, 1), GetString(reader, 2), reader.GetInt64(3), GetString(reader, 4))); }
        return new AiSnapshotReadPage<AiCorrelationGroupRow>(rows.AsReadOnly(), matching, true,
            "Derived scoped state/kind/source groups of recorded inputs, including no-decision rows; count is groups and each group cites a recorded input anchor, not a persisted group object.");
    });

    public AiSnapshotReadPage<EvidenceCorrelationInput> GetCorrelationInputPageForAi(EvidenceIdentity scope,
        bool compatibleRoots = false, long offset = 0, int pageSize = 50, EvidenceCorrelationState? state = null,
        EvidenceReferenceKind? evidenceKind = null, string? source = null, string? exactInputId = null,
        CancellationToken cancellationToken = default) => _readContext.MeasureRead("GetCorrelationInputPageForAi", () =>
    {
        ValidateAiPage(scope, offset, pageSize);
        if (state.HasValue && !Enum.IsDefined(state.Value) || evidenceKind.HasValue && !Enum.IsDefined(evidenceKind.Value))
            throw new ArgumentException("A defined correlation state and evidence kind are required.");
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = OpenReadOnlyConnection();
        string[] inputColumns = ["InputId", "EvidenceKind", "EvidenceId", "EvidenceType", "Source", "RelationType",
            "CaseId", "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId", "SourceRunId",
            "IngestionJobId", "RawInputId", "ProcessId", "ProcessStartTimeUtc", "ProcessGuid", "ProcessName", "ProcessPath",
            "SourceNativeId", "SourceEndpoint", "DestinationEndpoint", "ObservedUtc", "CreatedUtc"];
        if (!AiColumnsAvailable(connection, "EvidenceCorrelationInputs", inputColumns) || !AiColumnsAvailable(connection,
            "EvidenceRelations", ["RelationId", "DecisionKey", "Status", "UpdatedUtc", "CorrelationState", "FromKind", "FromId",
                "ToKind", "ToId", "CorrelationMethod", "Confidence", "CandidateCount", "CorrelationDiagnostics", "ResolverVersion",
                "CaseId", "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId"]))
            return new AiSnapshotReadPage<EvidenceCorrelationInput>([], 0, false, "Correlation input/decision schema unavailable.");
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var scopePredicate = AiReadPredicate(connection, command, scope, compatibleRoots);
        var cte = "WITH admitted_inputs AS (SELECT * FROM EvidenceCorrelationInputs WHERE " + scopePredicate +
            "), admitted_decisions AS (SELECT * FROM EvidenceRelations WHERE " + scopePredicate + ") ";
        var from = " FROM admitted_inputs i LEFT JOIN admitted_decisions r ON r.RelationId=(SELECT active.RelationId FROM admitted_decisions active WHERE active.DecisionKey=" +
            CorrelationDecisionKeySql("i") + " AND active.Status='Active' ORDER BY active.UpdatedUtc DESC,active.RelationId DESC LIMIT 1)";
        var filters = new List<string>();
        if (state.HasValue) { filters.Add("COALESCE(r.CorrelationState,'Unresolved')=$state"); command.Parameters.AddWithValue("$state", state.Value.ToString()); }
        if (evidenceKind.HasValue) { filters.Add("i.EvidenceKind=$kind"); command.Parameters.AddWithValue("$kind", evidenceKind.Value.ToString()); }
        if (!string.IsNullOrEmpty(source)) { filters.Add("i.Source=$source"); command.Parameters.AddWithValue("$source", source); }
        if (exactInputId is not null) { filters.Add("i.InputId=$input"); command.Parameters.AddWithValue("$input", exactInputId); }
        var where = filters.Count == 0 ? "" : " WHERE " + string.Join(" AND ", filters);
        using var cancellation = cancellationToken.Register(command.Cancel);
        command.CommandText = cte + "SELECT COUNT(*)" + from + where;
        var matching = Convert.ToInt64(command.ExecuteScalar());
        command.CommandText = cte + "SELECT " + string.Join(',', inputColumns.Select(column => "i." + column)) +
            ",COALESCE(r.CorrelationState,'Unresolved'),CASE WHEN r.ToKind='ProcessEntity' THEN COALESCE(r.ToId,'') WHEN r.FromKind='ProcessEntity' THEN COALESCE(r.FromId,'') ELSE '' END," +
            "COALESCE(r.CorrelationMethod,''),COALESCE(r.Confidence,0),COALESCE(r.CandidateCount,0),COALESCE(r.CorrelationDiagnostics,''),COALESCE(r.ResolverVersion,'')" +
            from + where + " ORDER BY i.ObservedUtc DESC,i.InputId ASC LIMIT $take OFFSET $skip";
        command.Parameters.AddWithValue("$take", pageSize);
        command.Parameters.AddWithValue("$skip", offset);
        var rows = new List<EvidenceCorrelationInput>();
        using var reader = command.ExecuteReader();
        while (reader.Read()) { cancellationToken.ThrowIfCancellationRequested(); rows.Add(ReadEvidenceCorrelationInput(reader)); }
        return new AiSnapshotReadPage<EvidenceCorrelationInput>(rows.AsReadOnly(), matching, true,
            "Scoped immutable correlation inputs, including inputs without any recorded active decision. State/candidate count comes from the latest scoped active decision; absence is Unresolved, not a negative process match.");
    });

    public AiSnapshotReadPage<ProcessStatisticsRecord> GetProcessStatisticsPageForAi(EvidenceIdentity scope, string processEntityId,
        bool compatibleRoots = false, long offset = 0, int pageSize = 50, string? exactSampleId = null,
        CancellationToken cancellationToken = default) => _readContext.MeasureRead("GetProcessStatisticsPageForAi", () =>
    {
        ValidateAiPage(scope, offset, pageSize);
        ArgumentException.ThrowIfNullOrWhiteSpace(processEntityId);
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = OpenReadOnlyConnection();
        string[] columns = ["SampleId", "ProcessKey", "ProcessId", "ProcessGuid", "ProcessName", "Status", "ObservedUtc",
            "TotalProcessorTimeTicks", "UserProcessorTimeTicks", "PrivilegedProcessorTimeTicks", "ReadBytes", "WrittenBytes",
            "CollectionError", "Source", "CaseId", "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId",
            "ProcessEntityId", "SourceRunId", "IngestionJobId"];
        if (!AiColumnsAvailable(connection, "ProcessStatistics", columns)) return new AiSnapshotReadPage<ProcessStatisticsRecord>([], 0, false, "Recorded statistic identity schema unavailable.");
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var predicate = AiReadPredicate(connection, command, scope, compatibleRoots) + " AND ProcessEntityId=$entity";
        command.Parameters.AddWithValue("$entity", processEntityId);
        if (exactSampleId is not null) { predicate += " AND SampleId=$sample"; command.Parameters.AddWithValue("$sample", exactSampleId); }
        using var cancellation = cancellationToken.Register(command.Cancel);
        command.CommandText = "SELECT COUNT(*) FROM ProcessStatistics WHERE " + predicate;
        var matching = Convert.ToInt64(command.ExecuteScalar());
        command.CommandText = "SELECT " + string.Join(',', columns) + " FROM ProcessStatistics WHERE " + predicate +
            " ORDER BY ObservedUtc DESC, SampleId ASC LIMIT $take OFFSET $skip";
        command.Parameters.AddWithValue("$take", pageSize);
        command.Parameters.AddWithValue("$skip", offset);
        var rows = new List<ProcessStatisticsRecord>();
        using var reader = command.ExecuteReader();
        while (reader.Read()) { cancellationToken.ThrowIfCancellationRequested(); rows.Add(ReadProcessStatistics(reader)); }
        return new AiSnapshotReadPage<ProcessStatisticsRecord>(rows.AsReadOnly(), matching, true,
            "Recorded counter samples of this durable process; missing counters remain null, not zero. No live sampling or interval rate is inferred.");
    });

    public AiSnapshotReadPage<AiProjectionWinnerRow> GetProcessProjectionPageForAi(EvidenceIdentity scope, string processEntityId,
        bool compatibleRoots = false, long offset = 0, int pageSize = 50, string? exactFieldName = null,
        CancellationToken cancellationToken = default) => _readContext.MeasureRead("GetProcessProjectionPageForAi", () =>
    {
        ValidateAiPage(scope, offset, pageSize);
        ArgumentException.ThrowIfNullOrWhiteSpace(processEntityId);
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = OpenReadOnlyConnection();
        if (!AiColumnsAvailable(connection, "ProcessProjectionFields", ["ProcessEntityId", "FieldName", "ObservationId", "SourceRunId", "ValueQuality", "ResolutionReason", "ProjectionVersion", "UpdatedUtc"]) ||
            !AiColumnsAvailable(connection, "ProcessObservations", ["ObservationId", "ProcessEntityId", "SourceRunId", "CaseId", "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId"]))
            return new AiSnapshotReadPage<AiProjectionWinnerRow>([], 0, false, "Projection winner provenance schema unavailable.");
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var predicate = AiReadPredicate(connection, command, scope, compatibleRoots) + " AND ProcessEntityId=$entity";
        command.Parameters.AddWithValue("$entity", processEntityId);
        var cte = "WITH admitted_observations AS (SELECT * FROM ProcessObservations WHERE " + predicate + ") ";
        var from = " FROM ProcessProjectionFields p JOIN admitted_observations o ON p.ProcessEntityId=o.ProcessEntityId AND p.ObservationId=o.ObservationId AND COALESCE(p.SourceRunId,'')=COALESCE(o.SourceRunId,'')";
        var fieldPredicate = exactFieldName is null ? "" : " WHERE p.FieldName=$field";
        if (exactFieldName is not null) command.Parameters.AddWithValue("$field", exactFieldName);
        using var cancellation = cancellationToken.Register(command.Cancel);
        command.CommandText = cte + "SELECT COUNT(*)" + from + fieldPredicate;
        var matching = Convert.ToInt64(command.ExecuteScalar());
        command.CommandText = cte + "SELECT o.CaseId,o.EvidenceSessionId,o.CaptureId,o.SourceIdentityId,o.HostId,o.ExecutionRootId," +
            "p.ProcessEntityId,p.FieldName,p.ObservationId,p.SourceRunId,p.ValueQuality,p.ResolutionReason,p.ProjectionVersion,p.UpdatedUtc" +
            from + fieldPredicate + " ORDER BY p.FieldName ASC,p.ObservationId ASC LIMIT $take OFFSET $skip";
        command.Parameters.AddWithValue("$take", pageSize);
        command.Parameters.AddWithValue("$skip", offset);
        var rows = new List<AiProjectionWinnerRow>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            rows.Add(new(AiReadIdentity(reader), GetString(reader, 6),
                new(GetString(reader, 7), GetString(reader, 8), GetString(reader, 9), GetInt(reader, 10), GetString(reader, 11)),
                GetString(reader, 12), GetDateTime(reader, 13)));
        }
        return new AiSnapshotReadPage<AiProjectionWinnerRow>(rows.AsReadOnly(), matching, true,
            "Current stored projection winners linked to exact admitted source observations; unavailable or foreign observation links are excluded. This is field provenance, not conflict history or new acquisition.");
    });

    public IReadOnlyDictionary<string, object?>? GetProcessObservationRecordFieldsForAi(EvidenceIdentity scope,
        string processEntityId, string observationId, CancellationToken cancellationToken = default) =>
        ReadExactNativeProcessRecordForAi("ProcessObservations", "ObservationId", scope, processEntityId, observationId, cancellationToken);

    public IReadOnlyDictionary<string, object?>? GetProcessStatisticRecordFieldsForAi(EvidenceIdentity scope,
        string processEntityId, string sampleId, CancellationToken cancellationToken = default) =>
        ReadExactNativeProcessRecordForAi("ProcessStatistics", "SampleId", scope, processEntityId, sampleId, cancellationToken);

    public IReadOnlyDictionary<string, object?>? GetSourceRunRecordFieldsForAi(EvidenceIdentity scope,
        string sourceRunId, CancellationToken cancellationToken = default) =>
        ReadExactNativeProcessRecordForAi("SourceRuns", "SourceRunId", scope, null, sourceRunId, cancellationToken);

    public IReadOnlyDictionary<string, object?>? GetCorrelationInputRecordFieldsForAi(EvidenceIdentity scope,
        string inputId, string sourceRunId, CancellationToken cancellationToken = default) =>
        ReadExactNativeProcessRecordForAi("EvidenceCorrelationInputs", "InputId", scope, null, inputId,
            cancellationToken, sourceRunId);

    public IReadOnlyDictionary<string, object?>? GetEvidenceRelationRecordFieldsForAi(EvidenceIdentity scope,
        string relationId, string sourceRunId, CancellationToken cancellationToken = default) =>
        ReadExactNativeProcessRecordForAi("EvidenceRelations", "RelationId", scope, null, relationId,
            cancellationToken, sourceRunId);

    private IReadOnlyDictionary<string, object?>? ReadExactNativeProcessRecordForAi(string table, string idColumn,
        EvidenceIdentity scope, string? processEntityId, string observationId, CancellationToken cancellationToken,
        string? sourceRunId = null) =>
        _readContext.MeasureRead("GetExactNativeProcessRecordForAi", () =>
    {
        ValidateAiPage(scope, 0, 1);
        var processRecord = table is "ProcessObservations" or "ProcessStatistics";
        var runQualifiedRecord = table is "EvidenceCorrelationInputs" or "EvidenceRelations";
        if (!processRecord && !runQualifiedRecord && table != "SourceRuns")
            throw new ArgumentException("Unsupported native AI table.", nameof(table));
        if (processRecord) ArgumentException.ThrowIfNullOrWhiteSpace(processEntityId);
        if (runQualifiedRecord && sourceRunId is null)
            throw new ArgumentNullException(nameof(sourceRunId));
        ArgumentException.ThrowIfNullOrWhiteSpace(observationId);
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = OpenReadOnlyConnection();
        if (!AiColumnsAvailable(connection, table, ["CaseId", "EvidenceSessionId", "CaptureId",
            "SourceIdentityId", "HostId", "ExecutionRootId", idColumn]) ||
            processRecord && !ColumnExists(connection, table, "ProcessEntityId") ||
            runQualifiedRecord && !ColumnExists(connection, table, "SourceRunId")) return null;
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var predicate = AiReadPredicate(connection, command, scope, false) + " AND " + idColumn + "=$observation";
        if (processRecord) { predicate += " AND ProcessEntityId=$entity"; command.Parameters.AddWithValue("$entity", processEntityId!); }
        if (runQualifiedRecord)
        {
            predicate += " AND COALESCE(SourceIdentityId,'')=$nativeSource AND COALESCE(ExecutionRootId,'')=$nativeRoot" +
                " AND COALESCE(SourceRunId,'')=$nativeRun";
            command.Parameters.AddWithValue("$nativeSource", scope.SourceIdentityId);
            command.Parameters.AddWithValue("$nativeRoot", scope.ExecutionRootId);
            command.Parameters.AddWithValue("$nativeRun", sourceRunId!);
        }
        command.Parameters.AddWithValue("$observation", observationId);
        var columns = new List<string>();
        using (var schema = connection.CreateCommand())
        {
            schema.Transaction = transaction;
            schema.CommandText = "PRAGMA table_info('" + table + "')";
            using var metadata = schema.ExecuteReader();
            while (metadata.Read()) columns.Add(metadata.GetString(1));
        }
        using var cancellation = cancellationToken.Register(command.Cancel);
        var sizes = columns.Select(column => "COALESCE(length(CAST(\"" + column.Replace("\"", "\"\"") + "\" AS BLOB)),0)");
        command.CommandText = "SELECT " + string.Join(" + ", sizes) + " FROM " + table + " WHERE " + predicate + " LIMIT 2";
        var bytes = command.ExecuteScalar();
        if (bytes is not null && Convert.ToInt64(bytes) > 64_000)
            throw new ArgumentOutOfRangeException("recordSizeBytes", "The complete stored native record exceeds 64 KB.");
        command.CommandText = "SELECT * FROM " + table + " WHERE " + predicate + " LIMIT 2";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var fields = new Dictionary<string, object?>(StringComparer.Ordinal);
        for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fields.Add(reader.GetName(ordinal), reader.IsDBNull(ordinal) ? null : reader.GetValue(ordinal));
        }
        return reader.Read() ? null : (IReadOnlyDictionary<string, object?>)fields;
    });

    public AiSnapshotReadPage<EvidenceRelation> GetEvidenceRelationPageForAi(EvidenceIdentity scope, EvidenceReference target,
        bool compatibleRoots = false, long offset = 0, int pageSize = 50, string? exactRelationId = null,
        CancellationToken cancellationToken = default) => _readContext.MeasureRead("GetEvidenceRelationPageForAi", () =>
    {
        ValidateAiPage(scope, offset, pageSize);
        ArgumentNullException.ThrowIfNull(target);
        if (!Enum.IsDefined(target.Kind) || target.IsEmpty) throw new ArgumentException("An exact typed evidence endpoint is required.", nameof(target));
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = OpenReadOnlyConnection();
        string[] columns = ["RelationId", "DecisionKey", "FromKind", "FromId", "ToKind", "ToId", "RelationType",
            "CorrelationState", "CorrelationMethod", "Confidence", "CandidateCount", "CorrelationDiagnostics", "CaseId",
            "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId", "SourceRunId", "IngestionJobId",
            "RawInputId", "ObservedFromUtc", "ObservedToUtc", "ValidFromUtc", "ValidToUtc", "ResolverName", "ResolverVersion",
            "CreatedUtc", "UpdatedUtc", "Status", "SupersededByRelationId", "AnalystAnnotationId"];
        if (!AiColumnsAvailable(connection, "EvidenceRelations", columns)) return new AiSnapshotReadPage<EvidenceRelation>([], 0, false, "Recorded relation/candidate schema unavailable.");
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var predicate = AiReadPredicate(connection, command, scope, compatibleRoots);
        if (exactRelationId is not null)
        {
            predicate += " AND RelationId=$relation";
            command.Parameters.AddWithValue("$relation", exactRelationId);
        }
        else
        {
            predicate += " AND ((FromKind=$kind AND FromId=$endpoint) OR (ToKind=$kind AND ToId=$endpoint))";
            command.Parameters.AddWithValue("$kind", target.Kind.ToString());
            command.Parameters.AddWithValue("$endpoint", target.Id);
        }
        using var cancellation = cancellationToken.Register(command.Cancel);
        command.CommandText = "SELECT COUNT(*) FROM EvidenceRelations WHERE " + predicate;
        var matching = Convert.ToInt64(command.ExecuteScalar());
        command.CommandText = "SELECT " + string.Join(',', columns) + " FROM EvidenceRelations WHERE " + predicate +
            " ORDER BY ObservedFromUtc DESC, RelationId ASC LIMIT $take OFFSET $skip";
        command.Parameters.AddWithValue("$take", pageSize);
        command.Parameters.AddWithValue("$skip", offset);
        var rows = new List<EvidenceRelation>();
        using var reader = command.ExecuteReader();
        while (reader.Read()) { cancellationToken.ThrowIfCancellationRequested(); rows.Add(ReadEvidenceRelation(reader)); }
        return new AiSnapshotReadPage<EvidenceRelation>(rows.AsReadOnly(), matching, true,
            "Stored relation decisions, including superseded history; ambiguity/confidence remain recorded claims. Endpoint IDs do not independently prove an endpoint or causal relationship.");
    });

    public AiSnapshotReadPage<AiSourceRunLineageRow> GetSourceRunLineagePageForAi(EvidenceIdentity scope, string sourceRunId,
        long offset = 0, int pageSize = 50, long? exactLineageId = null, CancellationToken cancellationToken = default) => _readContext.MeasureRead("GetSourceRunLineagePageForAi", () =>
    {
        ValidateAiPage(scope, offset, pageSize);
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceRunId);
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = OpenReadOnlyConnection();
        if (!AiColumnsAvailable(connection, "SourceRunLineage", ["SourceRunId", "ParentSourceRunId", "InputArtifactId", "InputPath", "InputHash", "RelationType", "CreatedUtc"]) ||
            !AiColumnsAvailable(connection, "SourceRuns", ["CaseId", "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId", "SourceRunId"]))
            return new AiSnapshotReadPage<AiSourceRunLineageRow>([], 0, false, "Source-run lineage schema unavailable.");
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var predicate = AiReadPredicate(connection, command, scope, false) + " AND SourceRunId=$run";
        command.Parameters.AddWithValue("$run", sourceRunId);
        var cte = "WITH selected_run AS (SELECT * FROM SourceRuns WHERE " + predicate + ") ";
        var lineagePredicate = exactLineageId.HasValue ? " WHERE l.rowid=$lineage" : "";
        if (exactLineageId.HasValue) command.Parameters.AddWithValue("$lineage", exactLineageId.Value);
        using var cancellation = cancellationToken.Register(command.Cancel);
        command.CommandText = cte + "SELECT COUNT(*) FROM SourceRunLineage l JOIN selected_run r ON r.SourceRunId=l.SourceRunId" + lineagePredicate;
        var matching = Convert.ToInt64(command.ExecuteScalar());
        command.CommandText = cte + "SELECT r.CaseId,r.EvidenceSessionId,r.CaptureId,r.SourceIdentityId,r.HostId,r.ExecutionRootId," +
            "l.rowid,l.SourceRunId,l.ParentSourceRunId,l.InputArtifactId,l.InputPath,l.InputHash,l.RelationType,l.CreatedUtc " +
            "FROM SourceRunLineage l JOIN selected_run r ON r.SourceRunId=l.SourceRunId " + lineagePredicate +
            " ORDER BY l.CreatedUtc DESC,l.RelationType,l.ParentSourceRunId,l.InputArtifactId,l.InputPath,l.InputHash,l.rowid LIMIT $take OFFSET $skip";
        command.Parameters.AddWithValue("$take", pageSize);
        command.Parameters.AddWithValue("$skip", offset);
        var rows = new List<AiSourceRunLineageRow>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            rows.Add(new(AiReadIdentity(reader), reader.GetInt64(6), GetString(reader, 7), GetString(reader, 8), GetString(reader, 9),
                GetString(reader, 10), GetString(reader, 11), GetString(reader, 12), GetDateTime(reader, 13)));
        }
        return new AiSnapshotReadPage<AiSourceRunLineageRow>(rows.AsReadOnly(), matching, true,
            "Recorded lineage of this exact source run only; parent/input IDs and paths are recorded metadata, not independently resolved objects or filesystem reads.");
    });

    /// <summary>Count and page recorded producer runs in one assessed snapshot transaction.</summary>
    public AiSnapshotReadPage<AiSourceRunRow> GetSourceRunPageForAi(EvidenceIdentity scope,
        bool compatibleRoots = false, long offset = 0, int pageSize = 50, string? exactRunId = null,
        CancellationToken cancellationToken = default) => _readContext.MeasureRead("GetSourceRunPageForAi", () =>
    {
        ValidateAiPage(scope, offset, pageSize);
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = OpenReadOnlyConnection();
        string[] columns = ["CaseId", "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId",
            "SourceRunId", "SourceType", "DisplayName", "Status", "StartedUtc", "EndedUtc", "Provider", "Channel",
            "ToolVersion", "ParserVersion", "IngestionJobId"];
        if (!AiColumnsAvailable(connection, "SourceRuns", columns)) return new AiSnapshotReadPage<AiSourceRunRow>([], 0, false, "Source-run schema unavailable.");
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var predicate = AiReadPredicate(connection, command, scope, compatibleRoots);
        if (exactRunId is not null) { predicate += " AND SourceRunId=$exact"; command.Parameters.AddWithValue("$exact", exactRunId); }
        using var cancellation = cancellationToken.Register(command.Cancel);
        command.CommandText = "SELECT COUNT(*) FROM SourceRuns WHERE " + predicate;
        var matching = Convert.ToInt64(command.ExecuteScalar());
        command.CommandText = "SELECT " + string.Join(',', columns) + " FROM SourceRuns WHERE " + predicate +
            " ORDER BY StartedUtc DESC, SourceRunId ASC LIMIT $take OFFSET $skip";
        command.Parameters.AddWithValue("$take", pageSize);
        command.Parameters.AddWithValue("$skip", offset);
        var rows = new List<AiSourceRunRow>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            rows.Add(new(AiReadIdentity(reader), GetString(reader, 6), GetString(reader, 7), GetString(reader, 8),
                GetString(reader, 9), GetDateTime(reader, 10), GetDateTime(reader, 11), GetString(reader, 12),
                GetString(reader, 13), GetString(reader, 14), GetString(reader, 15), GetString(reader, 16)));
        }
        return new AiSnapshotReadPage<AiSourceRunRow>(rows.AsReadOnly(), matching, true,
            "Stored run status describes the recorded producer execution; it does not prove collection completeness or current health.");
    });

    /// <summary>Immutable observations of a checked durable process entity, never a PID-only query.</summary>
    public AiSnapshotReadPage<AiProcessObservationRow> GetProcessObservationPageForAi(EvidenceIdentity scope,
        string processEntityId, bool compatibleRoots = false, long offset = 0, int pageSize = 50,
        string? exactObservationId = null, CancellationToken cancellationToken = default) =>
        _readContext.MeasureRead("GetProcessObservationPageForAi", () =>
    {
        ValidateAiPage(scope, offset, pageSize);
        ArgumentException.ThrowIfNullOrWhiteSpace(processEntityId);
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = OpenReadOnlyConnection();
        string[] columns = ["CaseId", "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId",
            "ObservationId", "ProcessEntityId", "AdapterId", "ObservationKind", "SourceRunId", "IngestionJobId",
            "RawRecordId", "SourceNativeAlias", "ObservedUtc", "ValidFromUtc", "ValidToUtc", "StatusAssertion",
            "CorrelationMethod", "CorrelationConfidence", "ParserVersion"];
        if (!AiColumnsAvailable(connection, "ProcessObservations", columns)) return new AiSnapshotReadPage<AiProcessObservationRow>([], 0, false, "Process-observation schema unavailable.");
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var predicate = AiReadPredicate(connection, command, scope, compatibleRoots) + " AND ProcessEntityId=$entity";
        command.Parameters.AddWithValue("$entity", processEntityId);
        if (exactObservationId is not null) { predicate += " AND ObservationId=$exact"; command.Parameters.AddWithValue("$exact", exactObservationId); }
        using var cancellation = cancellationToken.Register(command.Cancel);
        command.CommandText = "SELECT COUNT(*) FROM ProcessObservations WHERE " + predicate;
        var matching = Convert.ToInt64(command.ExecuteScalar());
        command.CommandText = "SELECT " + string.Join(',', columns) + " FROM ProcessObservations WHERE " + predicate +
            " ORDER BY ObservedUtc DESC, ObservationId DESC LIMIT $take OFFSET $skip";
        command.Parameters.AddWithValue("$take", pageSize);
        command.Parameters.AddWithValue("$skip", offset);
        var rows = new List<AiProcessObservationRow>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            rows.Add(new(AiReadIdentity(reader), GetString(reader, 6), GetString(reader, 7), GetString(reader, 8),
                GetString(reader, 9), GetString(reader, 10), GetString(reader, 11), GetString(reader, 12),
                GetString(reader, 13), GetDateTime(reader, 14), GetDateTime(reader, 15), GetDateTime(reader, 16),
                GetString(reader, 17), GetString(reader, 18), GetDouble(reader, 19), GetString(reader, 20)));
        }
        return new AiSnapshotReadPage<AiProcessObservationRow>(rows.AsReadOnly(), matching, true,
            "Stored observation scalars only; payload, field-state map and metadata JSON are not included. An observation is not a new process entity.");
    });

    private void ValidateAiPage(EvidenceIdentity scope, long offset, int pageSize)
    {
        if (CompatibilityAssessment.Context is not (CaptureOpenContext.ViewerLiveSnapshot or CaptureOpenContext.ViewerArchivedReadOnly))
            throw new InvalidOperationException("AI evidence reads require an assessed Viewer snapshot or read-only archive.");
        ArgumentNullException.ThrowIfNull(scope);
        if (string.IsNullOrWhiteSpace(scope.EvidenceSessionId) || string.IsNullOrWhiteSpace(scope.CaptureId) ||
            string.IsNullOrWhiteSpace(scope.HostId)) throw new ArgumentException("An exact host/capture/session boundary is required.", nameof(scope));
        if (offset < 0 || pageSize is < 1 or > 50) throw new ArgumentOutOfRangeException(nameof(offset));
    }

    private static bool AiColumnsAvailable(SqliteConnection connection, string table, IReadOnlyList<string> columns) =>
        TableExists(connection, table) && columns.All(column => ColumnExists(connection, table, column));

    private static EvidenceIdentity AiReadIdentity(SqliteDataReader reader) => new() {
        CaseId = GetString(reader, 0), EvidenceSessionId = GetString(reader, 1), CaptureId = GetString(reader, 2),
        SourceIdentityId = GetString(reader, 3), HostId = GetString(reader, 4), ExecutionRootId = GetString(reader, 5) };

    private static string AiReadPredicate(SqliteConnection connection, SqliteCommand command,
        EvidenceIdentity scope, bool compatibleRoots)
    {
        var terms = new List<string>();
        foreach (var (column, value) in new[] { ("CaseId", scope.CaseId), ("EvidenceSessionId", scope.EvidenceSessionId),
            ("CaptureId", scope.CaptureId), ("HostId", scope.HostId) })
        {
            terms.Add("COALESCE(" + column + ",'')=$ai" + column);
            command.Parameters.AddWithValue("$ai" + column, value);
        }
        if (!string.IsNullOrEmpty(scope.SourceIdentityId))
        {
            terms.Add("COALESCE(SourceIdentityId,'')=$aiSource");
            command.Parameters.AddWithValue("$aiSource", scope.SourceIdentityId);
        }
        if (!string.IsNullOrEmpty(scope.ExecutionRootId))
        {
            if (compatibleRoots)
            {
                connection.CreateFunction<string?, bool>("ai_read_root_matches", root =>
                    EvidenceIdentity.ExecutionRootsCompatible(scope.ExecutionRootId, root, scope.EvidenceSessionId), true);
                terms.Add("ai_read_root_matches(ExecutionRootId)");
            }
            else
            {
                terms.Add("COALESCE(ExecutionRootId,'')=$aiRoot");
                command.Parameters.AddWithValue("$aiRoot", scope.ExecutionRootId);
            }
        }
        return string.Join(" AND ", terms);
    }
}
