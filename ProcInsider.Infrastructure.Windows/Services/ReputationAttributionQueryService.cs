using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum ReputationAttributionReadState
{
    Available = 0,
    Unsupported = 1,
    NotFound = 2,
    Failed = 3
}

public sealed record ReputationAttributionReadResult
{
    public ReputationAttributionReadState State { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public IReadOnlyList<ReputationProcessAttributionResult> Attributions { get; init; } =
        Array.Empty<ReputationProcessAttributionResult>();
}

public interface IReputationAttributionQueryService
{
    ReputationAttributionReadPage GetProcessPage(EvidenceIdentity scope, string processEntityId, long offset = 0, int pageSize = 50,
        CancellationToken cancellationToken = default);
    ReputationAttributionReadResult GetByProcessEntityId(
        string processEntityId,
        int maximumCount = 64);

    ReputationAttributionReadResult GetByAttributionHash(string attributionHashSha256);
}

public sealed record ReputationAttributionReadPage(ReputationAttributionReadState State,
    IReadOnlyList<ReputationProcessAttributionResult> Rows, long MatchingRows);

/// <summary>
/// Bounded read-only projection over canonical reputation attribution rows. It
/// returns explicit unsupported/not-found/failed states and never performs a
/// migration, provider lookup, cache access, evidence write, or score mapping.
/// </summary>
internal sealed class ReputationAttributionQueryService : IReputationAttributionQueryService
{
    private readonly SqliteReadQueryContext _context;

    internal ReputationAttributionQueryService(SqliteReadQueryContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public ReputationAttributionReadPage GetProcessPage(EvidenceIdentity scope, string processEntityId, long offset = 0, int pageSize = 50,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (string.IsNullOrWhiteSpace(scope.EvidenceSessionId) || string.IsNullOrWhiteSpace(scope.CaptureId) ||
            string.IsNullOrWhiteSpace(scope.HostId) || string.IsNullOrWhiteSpace(processEntityId) || offset < 0 || offset > int.MaxValue || pageSize is < 1 or > 50)
            throw new ArgumentException("Exact process/scope and bounded page are required.");
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var connection = _context.OpenReadOnlyConnection();
            if (!TableExists(connection, "ReputationAttributions") || !TableExists(connection, "SourceRuns"))
                return new(ReputationAttributionReadState.Unsupported, [], 0);
            using var snapshot = connection.BeginTransaction(deferred: true);
            using var command = connection.CreateCommand(); command.Transaction = snapshot;
            const string from = "ReputationAttributions r JOIN SourceRuns s ON s.SourceRunId=r.SourceRunId";
            const string where = """
                r.ProcessEntityId=$Entity AND COALESCE(s.CaseId,'')=$Case AND COALESCE(s.EvidenceSessionId,'')=$Session
                AND COALESCE(s.CaptureId,'')=$Capture AND COALESCE(s.SourceIdentityId,'')=$Source
                AND COALESCE(s.HostId,'')=$Host AND COALESCE(s.ExecutionRootId,'')=$Root
                """;
            command.Parameters.AddWithValue("$Entity", processEntityId); command.Parameters.AddWithValue("$Case", scope.CaseId);
            command.Parameters.AddWithValue("$Session", scope.EvidenceSessionId); command.Parameters.AddWithValue("$Capture", scope.CaptureId);
            command.Parameters.AddWithValue("$Source", scope.SourceIdentityId); command.Parameters.AddWithValue("$Host", scope.HostId);
            command.Parameters.AddWithValue("$Root", scope.ExecutionRootId);
            using var cancelled = cancellationToken.Register(command.Cancel);
            command.CommandText = "SELECT COUNT(*) FROM " + from + " WHERE " + where;
            var matching = Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
            command.CommandText = "SELECT " + string.Join(',', IndexedColumns.Split(',').Select(column => "r." + column.Trim())) +
                " FROM " + from + " WHERE " + where + " ORDER BY r.CompletedUtc DESC,r.AttributionHashSha256 ASC LIMIT $Take OFFSET $Skip";
            command.Parameters.AddWithValue("$Take", pageSize); command.Parameters.AddWithValue("$Skip", offset);
            using var reader = command.ExecuteReader(); var rows = new List<ReputationProcessAttributionResult>();
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var row = ReadAndValidate(reader);
                if (row.TargetRequest.EvidenceIdentity != scope || row.ProcessEntityId != processEntityId) throw new InvalidDataException("Attribution scope disagrees with source run.");
                rows.Add(row);
            }
            return new(ReputationAttributionReadState.Available, rows.AsReadOnly(), matching);
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or FormatException or OverflowException or InvalidCastException or SqliteException)
        { cancellationToken.ThrowIfCancellationRequested(); return new(ReputationAttributionReadState.Failed, [], 0); }
    }

    private const string IndexedColumns = """
        AttributionHashSha256, ProcessEntityId, ProcessKey, SourceKind,
        ProviderId, ProviderVersion, DatasetId, DatasetVersion, QueryMode,
        IndicatorSha256, SourceRunId, SourceEvidenceKind, SourceEvidenceId,
        RelationId, Availability, RecordFound, AnalyzedCount, PositiveCount,
        SuspiciousCount, UndetectedCount, RetrievedUtc, CompletedUtc,
        ReceiptHashSha256, CacheDecisionHashSha256, PayloadHashSha256, AttributionJson
        """;

    public ReputationAttributionReadResult GetByProcessEntityId(
        string processEntityId,
        int maximumCount = 64)
    {
        if (string.IsNullOrWhiteSpace(processEntityId))
        {
            return Result(ReputationAttributionReadState.Failed,
                "A durable process entity identity is required.");
        }

        var boundedCount = Math.Clamp(
            maximumCount,
            1,
            ReputationAttributionPersistencePolicy.MaximumReadRows);
        return Read(
            "ProcessEntityId = $Identity ORDER BY CompletedUtc DESC, AttributionHashSha256 LIMIT $MaximumCount",
            command =>
            {
                command.Parameters.AddWithValue("$Identity", processEntityId);
                command.Parameters.AddWithValue("$MaximumCount", boundedCount);
            });
    }

    public ReputationAttributionReadResult GetByAttributionHash(string attributionHashSha256)
    {
        if (!ValidLowerSha256(attributionHashSha256))
        {
            return Result(ReputationAttributionReadState.Failed,
                "A canonical lowercase attribution SHA-256 is required.");
        }

        return Read(
            "AttributionHashSha256 = $Identity ORDER BY AttributionHashSha256 LIMIT 2",
            command => command.Parameters.AddWithValue("$Identity", attributionHashSha256));
    }

    private ReputationAttributionReadResult Read(
        string predicateAndBound,
        Action<SqliteCommand> addParameters)
    {
        try
        {
            using var connection = _context.OpenReadOnlyConnection();
            if (!TableExists(connection, "ReputationAttributions"))
            {
                return Result(
                    ReputationAttributionReadState.Unsupported,
                    "This supported capture revision does not contain reputation attribution state.");
            }

            using var command = connection.CreateCommand();
            command.CommandText = $"""
                SELECT {IndexedColumns}
                FROM ReputationAttributions
                WHERE {predicateAndBound};
                """;
            addParameters(command);
            var rows = new List<ReputationProcessAttributionResult>();
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                rows.Add(ReadAndValidate(reader));
            }

            return rows.Count == 0
                ? Result(ReputationAttributionReadState.NotFound,
                    "No exact reputation attribution was found.")
                : new ReputationAttributionReadResult
                {
                    State = ReputationAttributionReadState.Available,
                    Attributions = rows
                };
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or
                                         FormatException or OverflowException or
                                         InvalidCastException or SqliteException)
        {
            return Result(
                ReputationAttributionReadState.Failed,
                "The persisted reputation attribution rows are malformed.");
        }
    }

    private static ReputationProcessAttributionResult ReadAndValidate(SqliteDataReader reader)
    {
        var json = reader.GetString(25);
        var attribution = JsonSerializer.Deserialize<ReputationProcessAttributionResult>(json) ??
            throw new InvalidDataException("The persisted reputation attribution is null.");
        var normalized = ReputationAttributionPersistencePolicy.Normalize(attribution);
        if (!ReputationAttributionPersistencePolicy.MatchesIndexedRow(reader, normalized))
        {
            throw new InvalidDataException(
                "A persisted reputation attribution disagrees with its indexed identity.");
        }

        return normalized.Attribution;
    }

    private static bool TableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$TableName;";
        command.Parameters.AddWithValue("$TableName", tableName);
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;
    }

    private static bool ValidLowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static ReputationAttributionReadResult Result(
        ReputationAttributionReadState state,
        string diagnostic) =>
        new()
        {
            State = state,
            Diagnostic = diagnostic
        };
}
