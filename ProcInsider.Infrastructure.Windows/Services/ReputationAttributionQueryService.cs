using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
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
    ReputationAttributionReadResult GetByProcessEntityId(
        string processEntityId,
        int maximumCount = 64);

    ReputationAttributionReadResult GetByAttributionHash(string attributionHashSha256);
}

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
                SELECT AttributionHashSha256, ProcessEntityId, ProcessKey, SourceKind,
                       ProviderId, ProviderVersion, DatasetId, DatasetVersion, QueryMode,
                       IndicatorSha256, SourceRunId, SourceEvidenceKind, SourceEvidenceId,
                       RelationId, Availability, RecordFound, AnalyzedCount, PositiveCount,
                       SuspiciousCount, UndetectedCount, RetrievedUtc, CompletedUtc,
                       ReceiptHashSha256, CacheDecisionHashSha256, PayloadHashSha256,
                       AttributionJson
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
