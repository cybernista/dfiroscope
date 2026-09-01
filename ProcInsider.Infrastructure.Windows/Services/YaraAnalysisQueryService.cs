using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum YaraAnalysisReadState
{
    Available = 0,
    Unsupported = 1,
    NotFound = 2,
    Corrupt = 3
}

public sealed record YaraAnalysisScanQuery
{
    public string ScanId { get; init; } = string.Empty;

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string SourceRunId { get; init; } = string.Empty;

    public YaraScanTargetKind TargetKind { get; init; }

    public EvidenceReference EvidenceReference { get; init; } =
        new(EvidenceReferenceKind.GenericArtifact, string.Empty);
}

public sealed record YaraAnalysisReadResult
{
    public YaraAnalysisReadState State { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public YaraPersistedScan? Scan { get; init; }
}

public interface IYaraAnalysisQueryService
{
    YaraAnalysisReadResult GetExactScan(YaraAnalysisScanQuery query);
}

/// <summary>
/// Bounded read-only owner for one exact normalized YARA scan and evidence scope.
/// It performs four set queries (scan, matches, tags, metadata) and never reads
/// source/staged paths, target bytes, scanner output, or annotations.
/// </summary>
internal sealed class YaraAnalysisQueryService : IYaraAnalysisQueryService
{
    private readonly SqliteReadQueryContext _context;

    internal YaraAnalysisQueryService(SqliteReadQueryContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public YaraAnalysisReadResult GetExactScan(YaraAnalysisScanQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        using var connection = _context.OpenReadOnlyConnection();
        if (!TableExists(connection, "YaraAnalysisScans") ||
            !TableExists(connection, "YaraAnalysisMatches") ||
            !TableExists(connection, "YaraAnalysisTags") ||
            !TableExists(connection, "YaraAnalysisMetadata"))
        {
            return Result(
                YaraAnalysisReadState.Unsupported,
                "This supported capture revision does not contain normalized YARA analysis state.");
        }

        try
        {
            var scan = ReadScan(connection, query);
            if (scan == null)
            {
                return Result(YaraAnalysisReadState.NotFound, "The exact YARA scan was not found.");
            }

            var matches = ReadMatches(connection, query);
            var tags = ReadTags(connection, query);
            var metadata = ReadMetadata(connection, query);
            if (matches.Count > YaraAnalysisContractPolicy.MaximumMatches ||
                tags.Count > YaraAnalysisContractPolicy.MaximumMatches *
                    YaraAnalysisContractPolicy.MaximumTagsPerMatch ||
                metadata.Count > YaraAnalysisContractPolicy.MaximumMatches *
                    YaraAnalysisContractPolicy.MaximumMetadataPerMatch)
            {
                return Result(YaraAnalysisReadState.Corrupt,
                    "The persisted YARA child collections exceed their bounds.");
            }

            var normalizedMatches = new List<YaraRuleMatch>(matches.Count);
            for (var index = 0; index < matches.Count; index++)
            {
                var match = matches[index];
                tags.TryGetValue(match.MatchId, out var matchTags);
                metadata.TryGetValue(match.MatchId, out var matchMetadata);
                matchTags ??= Array.Empty<(int Order, string Value)>();
                matchMetadata ??= Array.Empty<(int Order, string Key, string Value)>();
                if (match.Order != index ||
                    matchTags.Any(item => item.Order < 0) ||
                    matchMetadata.Any(item => item.Order < 0) ||
                    !IsSequential(matchTags.Select(item => item.Order)) ||
                    !IsSequential(matchMetadata.Select(item => item.Order)))
                {
                    return Result(YaraAnalysisReadState.Corrupt,
                        "The persisted YARA match/tag/metadata ordering is malformed.");
                }

                normalizedMatches.Add(new YaraRuleMatch
                {
                    MatchId = match.MatchId,
                    RuleNamespace = match.RuleNamespace,
                    RuleId = match.RuleId,
                    Tags = matchTags.Select(item => item.Value).ToArray(),
                    Metadata = matchMetadata
                        .Select(item => new YaraMatchMetadata(item.Key, item.Value))
                        .ToArray(),
                    StringMatches = Array.Empty<YaraStringMatch>()
                });
            }

            if (tags.Keys.Except(matches.Select(item => item.MatchId), StringComparer.Ordinal).Any() ||
                metadata.Keys.Except(matches.Select(item => item.MatchId), StringComparer.Ordinal).Any())
            {
                return Result(YaraAnalysisReadState.Corrupt,
                    "The persisted YARA child rows do not belong to an exact match.");
            }

            var result = scan.Result with { Matches = normalizedMatches };
            var validation = YaraAnalysisContractPolicy.Validate(result);
            if (!validation.Accepted || validation.Result == null)
            {
                return Result(YaraAnalysisReadState.Corrupt,
                    $"The persisted normalized YARA result is invalid ({validation.Failure}).");
            }

            var accepted = scan with { Result = validation.Result };
            if (!string.Equals(
                    accepted.PayloadHashSha256,
                    YaraAnalysisPersistencePolicy.ComputePayloadHash(accepted),
                    StringComparison.Ordinal))
            {
                return Result(YaraAnalysisReadState.Corrupt,
                    "The persisted YARA payload hash does not match its normalized rows.");
            }

            return new YaraAnalysisReadResult
            {
                State = YaraAnalysisReadState.Available,
                Scan = accepted
            };
        }
        catch (Exception ex) when (ex is InvalidDataException or FormatException or
                                         OverflowException or SqliteException)
        {
            return Result(YaraAnalysisReadState.Corrupt,
                "The persisted normalized YARA rows are malformed.");
        }
    }

    private static YaraPersistedScan? ReadScan(
        SqliteConnection connection,
        YaraAnalysisScanQuery query)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT RequestId, ResultSchemaVersion, Availability, TargetOffsetBytes,
                   TargetLengthBytes, TargetContentHashSha256, AdmissionProfileId,
                   AdmissionProfileVersion, ScannerId, ScannerVersion,
                   ScannerArtifactHashSha256, ScannerAdapterProtocolVersion,
                   RulesetId, RulesetVersion, RulesetHashSha256,
                   RulesetManifestHashSha256, RequestedUtc, CompletedUtc,
                   IsTruncated, Diagnostic, PayloadHashSha256
            FROM YaraAnalysisScans
            WHERE ScanId = $ScanId AND CaseId = $CaseId
              AND EvidenceSessionId = $EvidenceSessionId AND CaptureId = $CaptureId
              AND SourceIdentityId = $SourceIdentityId AND HostId = $HostId
              AND ExecutionRootId = $ExecutionRootId AND SourceRunId = $SourceRunId
              AND TargetKind = $TargetKind
              AND EvidenceReferenceKind = $EvidenceReferenceKind
              AND EvidenceReferenceId = $EvidenceReferenceId
            LIMIT 2;
            """;
        AddQueryParameters(command, query);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var schemaVersion = reader.GetInt32(1);
        var availabilityValue = reader.GetInt32(2);
        if (schemaVersion != YaraScanResult.CurrentSchemaVersion ||
            !Enum.IsDefined(typeof(AnalysisSourceAvailability), availabilityValue))
        {
            throw new InvalidDataException("The persisted YARA schema or availability is unknown.");
        }

        var requestedUtc = ParseUtc(reader.GetString(16));
        var completedUtc = ParseUtc(reader.GetString(17));
        var scan = new YaraPersistedScan
        {
            RequestId = reader.GetString(0),
            AdmissionProfileId = reader.GetString(6),
            AdmissionProfileVersion = reader.GetString(7),
            ScannerArtifactHashSha256 = reader.GetString(10),
            ScannerAdapterProtocolVersion = reader.GetInt32(11),
            RulesetManifestHashSha256 = reader.GetString(15),
            PayloadHashSha256 = reader.GetString(20),
            Result = new YaraScanResult
            {
                SchemaVersion = schemaVersion,
                ScanId = query.ScanId,
                Availability = (AnalysisSourceAvailability)availabilityValue,
                Target = new YaraScanTarget
                {
                    Kind = query.TargetKind,
                    EvidenceIdentity = query.EvidenceIdentity with { },
                    SourceRunId = query.SourceRunId,
                    EvidenceReference = query.EvidenceReference with { },
                    OffsetBytes = reader.GetInt64(3),
                    LengthBytes = reader.GetInt64(4),
                    ContentHashSha256 = reader.GetString(5)
                },
                Ruleset = new YaraRulesetIdentity
                {
                    ScannerId = reader.GetString(8),
                    ScannerVersion = reader.GetString(9),
                    RulesetId = reader.GetString(12),
                    RulesetVersion = reader.GetString(13),
                    RulesetHashSha256 = reader.GetString(14)
                },
                RequestedUtc = requestedUtc,
                CompletedUtc = completedUtc,
                IsTruncated = reader.GetInt64(18) != 0,
                Diagnostic = reader.GetString(19),
                Matches = Array.Empty<YaraRuleMatch>()
            }
        };
        if (reader.Read())
        {
            throw new InvalidDataException("The exact YARA scan scope is ambiguous.");
        }

        return scan;
    }

    private static IReadOnlyList<(int Order, string MatchId, string RuleNamespace, string RuleId)>
        ReadMatches(SqliteConnection connection, YaraAnalysisScanQuery query)
    {
        using var command = connection.CreateCommand();
        command.CommandText = ChildSql(
            "YaraAnalysisMatches",
            "MatchOrder, MatchId, RuleNamespace, RuleId",
            "ORDER BY MatchOrder LIMIT $Limit");
        AddQueryParameters(command, query);
        command.Parameters.AddWithValue("$Limit", YaraAnalysisContractPolicy.MaximumMatches + 1);
        var rows = new List<(int, string, string, string)>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add((reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
        }

        return rows;
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<(int Order, string Value)>> ReadTags(
        SqliteConnection connection,
        YaraAnalysisScanQuery query)
    {
        using var command = connection.CreateCommand();
        command.CommandText = ChildSql(
            "YaraAnalysisTags",
            "MatchId, TagOrder, Tag",
            "ORDER BY MatchId, TagOrder LIMIT $Limit");
        AddQueryParameters(command, query);
        command.Parameters.AddWithValue("$Limit",
            YaraAnalysisContractPolicy.MaximumMatches *
            YaraAnalysisContractPolicy.MaximumTagsPerMatch + 1);
        var rows = new Dictionary<string, List<(int, string)>>(StringComparer.Ordinal);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var matchId = reader.GetString(0);
            if (!rows.TryGetValue(matchId, out var values))
            {
                values = [];
                rows.Add(matchId, values);
            }

            values.Add((reader.GetInt32(1), reader.GetString(2)));
        }

        return rows.ToDictionary(
            item => item.Key,
            item => (IReadOnlyList<(int, string)>)item.Value,
            StringComparer.Ordinal);
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<(int Order, string Key, string Value)>>
        ReadMetadata(SqliteConnection connection, YaraAnalysisScanQuery query)
    {
        using var command = connection.CreateCommand();
        command.CommandText = ChildSql(
            "YaraAnalysisMetadata",
            "MatchId, MetadataOrder, MetadataKey, MetadataValue",
            "ORDER BY MatchId, MetadataOrder LIMIT $Limit");
        AddQueryParameters(command, query);
        command.Parameters.AddWithValue("$Limit",
            YaraAnalysisContractPolicy.MaximumMatches *
            YaraAnalysisContractPolicy.MaximumMetadataPerMatch + 1);
        var rows = new Dictionary<string, List<(int, string, string)>>(StringComparer.Ordinal);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var matchId = reader.GetString(0);
            if (!rows.TryGetValue(matchId, out var values))
            {
                values = [];
                rows.Add(matchId, values);
            }

            values.Add((reader.GetInt32(1), reader.GetString(2), reader.GetString(3)));
        }

        return rows.ToDictionary(
            item => item.Key,
            item => (IReadOnlyList<(int, string, string)>)item.Value,
            StringComparer.Ordinal);
    }

    private static string ChildSql(string table, string projection, string orderAndLimit) => $"""
        SELECT {projection}
        FROM {table}
        WHERE ScanId = $ScanId AND CaseId = $CaseId
          AND EvidenceSessionId = $EvidenceSessionId AND CaptureId = $CaptureId
          AND SourceIdentityId = $SourceIdentityId AND HostId = $HostId
          AND ExecutionRootId = $ExecutionRootId AND SourceRunId = $SourceRunId
        {orderAndLimit};
        """;

    private static void AddQueryParameters(SqliteCommand command, YaraAnalysisScanQuery query)
    {
        command.Parameters.AddWithValue("$ScanId", query.ScanId ?? string.Empty);
        command.Parameters.AddWithValue("$CaseId", query.EvidenceIdentity.CaseId);
        command.Parameters.AddWithValue("$EvidenceSessionId", query.EvidenceIdentity.EvidenceSessionId);
        command.Parameters.AddWithValue("$CaptureId", query.EvidenceIdentity.CaptureId);
        command.Parameters.AddWithValue("$SourceIdentityId", query.EvidenceIdentity.SourceIdentityId);
        command.Parameters.AddWithValue("$HostId", query.EvidenceIdentity.HostId);
        command.Parameters.AddWithValue("$ExecutionRootId", query.EvidenceIdentity.ExecutionRootId);
        command.Parameters.AddWithValue("$SourceRunId", query.SourceRunId ?? string.Empty);
        command.Parameters.AddWithValue("$TargetKind", (int)query.TargetKind);
        command.Parameters.AddWithValue("$EvidenceReferenceKind", (int)query.EvidenceReference.Kind);
        command.Parameters.AddWithValue("$EvidenceReferenceId", query.EvidenceReference.Id);
    }

    private static DateTime ParseUtc(string value)
    {
        if (!DateTime.TryParse(
                value,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind,
                out var parsed) || parsed.Kind != DateTimeKind.Utc)
        {
            throw new InvalidDataException("A persisted YARA timestamp is not UTC.");
        }

        return parsed;
    }

    private static bool IsSequential(IEnumerable<int> values) =>
        values.Select((value, index) => value == index).All(item => item);

    private static bool TableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$TableName;";
        command.Parameters.AddWithValue("$TableName", tableName);
        return Convert.ToInt32(command.ExecuteScalar()) == 1;
    }

    private static YaraAnalysisReadResult Result(YaraAnalysisReadState state, string diagnostic) =>
        new() { State = state, Diagnostic = diagnostic };
}
