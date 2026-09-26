using System.IO;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models.ApplicationCatalog;

namespace ProcInsider.Services;

public sealed class ApplicationCatalogService
{
    private readonly IReadOnlyList<ApplicationProfileDefinition> _publishedProfiles;
    private readonly IReadOnlyList<ApplicationProfileDefinition> _evaluationCandidateProfiles;

    private ApplicationCatalogService(
        string databasePath,
        string catalogRevision,
        IReadOnlyList<ApplicationProfileDefinition> profiles)
    {
        DatabasePath = databasePath;
        CatalogRevision = catalogRevision;
        _publishedProfiles = profiles
            .Where(profile =>
                profile.IsEnabled &&
                !profile.IsEvaluationCandidate &&
                profile.ReviewState == ApplicationProfileReviewState.CatalogReviewed)
            .ToList();
        _evaluationCandidateProfiles = profiles
            .Where(profile =>
                !profile.IsEnabled &&
                profile.IsEvaluationCandidate &&
                profile.ReviewState == ApplicationProfileReviewState.AiDraft)
            .ToList();
    }

    public string DatabasePath { get; }

    public string CatalogRevision { get; }

    public int ProfileCount => _publishedProfiles.Count;

    public int PublishedProfileCount => _publishedProfiles.Count;

    public int EvaluationCandidateProfileCount => _evaluationCandidateProfiles.Count;

    public int TotalProfileCount => PublishedProfileCount + EvaluationCandidateProfileCount;

    public static ApplicationCatalogService OpenReadOnly(string databasePath)
    {
        if (string.IsNullOrWhiteSpace(databasePath) || !File.Exists(databasePath))
        {
            throw new FileNotFoundException("Shipped application catalog database was not found.", databasePath);
        }

        var fullPath = Path.GetFullPath(databasePath);
        using var connection = OpenConnection(fullPath);
        var schemaVersion = ReadInfo(connection, "CatalogSchemaVersion");
        if (!string.Equals(
                schemaVersion,
                ApplicationCatalogBuilder.SupportedSchemaVersion.ToString(),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Unsupported application catalog database schema '{schemaVersion}'; expected '{ApplicationCatalogBuilder.SupportedSchemaVersion}'.");
        }

        var catalogRevision = ReadInfo(connection, "CatalogRevision");
        if (string.IsNullOrWhiteSpace(catalogRevision))
        {
            throw new InvalidDataException("Application catalog revision is missing.");
        }

        var profiles = ReadProfiles(connection);
        var runtimeDocument = new ApplicationCatalogDocument
        {
            SchemaVersion = ApplicationCatalogBuilder.SupportedSchemaVersion,
            CatalogRevision = catalogRevision,
            Profiles = profiles.ToList()
        };
        ApplicationCatalogBuilder.Validate(runtimeDocument);
        ValidateRuntimeContent(runtimeDocument);
        ValidateRuntimeCounts(connection, profiles);

        return new ApplicationCatalogService(fullPath, catalogRevision, profiles);
    }

    public ApplicationCatalogMatch? Resolve(ApplicationProfileLookupContext context)
    {
        return ResolveCandidates(context).FirstOrDefault();
    }

    public IReadOnlyList<ApplicationCatalogMatch> ResolveCandidates(ApplicationProfileLookupContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ResolveCandidates(context, _publishedProfiles);
    }

    public ApplicationCatalogMatch? ResolveEvaluation(ApplicationProfileLookupContext context)
    {
        var candidates = ResolveEvaluationCandidates(context);
        if (candidates.Count == 0)
        {
            return null;
        }

        return candidates.Count > 1 && HasEquivalentRank(candidates[0], candidates[1])
            ? null
            : candidates[0];
    }

    public IReadOnlyList<ApplicationCatalogMatch> ResolveEvaluationCandidates(
        ApplicationProfileLookupContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ResolveCandidates(context, _evaluationCandidateProfiles);
    }

    private IReadOnlyList<ApplicationCatalogMatch> ResolveCandidates(
        ApplicationProfileLookupContext context,
        IReadOnlyList<ApplicationProfileDefinition> profiles)
        => profiles
            .Where(profile => ApplicationPatternValidator.IsMatch(profile.Filename, context.ExecutableFilename))
            .Select(profile => Score(profile, context))
            .OrderByDescending(match => match.Score)
            .ThenByDescending(match => match.MatchedDiscriminatorCount)
            .ThenBy(match => match.Profile.ProfileId, StringComparer.Ordinal)
            .ToList();

    public ApplicationProfileDefinition? GetProfileById(string profileId)
        => string.IsNullOrWhiteSpace(profileId)
            ? null
            : _publishedProfiles.FirstOrDefault(profile =>
                string.Equals(profile.ProfileId, profileId, StringComparison.Ordinal));

    public ApplicationProfileDefinition? GetEvaluationCandidateById(string profileId)
        => string.IsNullOrWhiteSpace(profileId)
            ? null
            : _evaluationCandidateProfiles.FirstOrDefault(profile =>
                string.Equals(profile.ProfileId, profileId, StringComparison.Ordinal));

    private static bool HasEquivalentRank(
        ApplicationCatalogMatch left,
        ApplicationCatalogMatch right)
        => left.Score == right.Score &&
           left.MatchedDiscriminatorCount == right.MatchedDiscriminatorCount;

    private ApplicationCatalogMatch Score(
        ApplicationProfileDefinition profile,
        ApplicationProfileLookupContext context)
    {
        var score = profile.Filename.Kind == ApplicationFilenameMatchKind.Exact ? 1000 : 500;
        var matched = new List<string>();
        if (ContainsAny(context.ProcessPath, profile.Discriminators.PathPatterns))
        {
            score += 100;
            matched.Add("path");
        }

        if (MatchesFilename(context.OriginalFilename, profile.Discriminators.OriginalFilenames))
        {
            score += 80;
            matched.Add("original filename");
        }

        if (ContainsAny(context.Company, profile.Discriminators.Companies))
        {
            score += 60;
            matched.Add("company");
        }

        if (ContainsAny(context.Product, profile.Discriminators.Products))
        {
            score += 40;
            matched.Add("product");
        }

        if (ContainsAny(context.PackageFamilyName, profile.Discriminators.PackageFamilyNames))
        {
            score += 30;
            matched.Add("package");
        }

        var filenameReason = profile.Filename.Kind == ApplicationFilenameMatchKind.Exact
            ? "exact normalized filename"
            : "bounded regex filename";
        var discriminatorReason = matched.Count == 0
            ? "no optional discriminator matched"
            : $"matched {string.Join(", ", matched)}";
        return new ApplicationCatalogMatch
        {
            Profile = profile,
            CatalogRevision = CatalogRevision,
            Score = score,
            MatchedDiscriminatorCount = matched.Count,
            SelectionReason = $"{filenameReason}; {discriminatorReason}; deterministic score {score}"
        };
    }

    private static SqliteConnection OpenConnection(string databasePath)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Shared,
            Pooling = false
        }.ToString());
        connection.Open();
        using var queryOnly = connection.CreateCommand();
        queryOnly.CommandText = "PRAGMA query_only=ON;";
        queryOnly.ExecuteNonQuery();
        return connection;
    }

    private static string ReadInfo(SqliteConnection connection, string key)
    {
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Value FROM CatalogInfo WHERE Key = $Key LIMIT 1;";
            command.Parameters.AddWithValue("$Key", key);
            return Convert.ToString(command.ExecuteScalar()) ?? string.Empty;
        }
        catch (SqliteException ex)
        {
            throw new InvalidDataException($"Application catalog metadata is unreadable: {ex.Message}", ex);
        }
    }

    private static int ReadInfoCount(SqliteConnection connection, string key)
    {
        var value = ReadInfo(connection, key);
        if (!int.TryParse(value, out var count) || count < 0)
        {
            throw new InvalidDataException($"Application catalog metadata '{key}' is not a non-negative integer.");
        }

        return count;
    }

    private static void ValidateRuntimeCounts(
        SqliteConnection connection,
        IReadOnlyCollection<ApplicationProfileDefinition> profiles)
    {
        var publishedCount = profiles.Count(profile =>
            profile.IsEnabled &&
            !profile.IsEvaluationCandidate &&
            profile.ReviewState == ApplicationProfileReviewState.CatalogReviewed);
        var evaluationCandidateCount = profiles.Count(profile =>
            !profile.IsEnabled &&
            profile.IsEvaluationCandidate &&
            profile.ReviewState == ApplicationProfileReviewState.AiDraft);
        if (profiles.Count != publishedCount + evaluationCandidateCount ||
            ReadInfoCount(connection, "PublishedProfileCount") != publishedCount ||
            ReadInfoCount(connection, "EvaluationCandidateProfileCount") != evaluationCandidateCount ||
            ReadInfoCount(connection, "TotalProfileCount") != profiles.Count)
        {
            throw new InvalidDataException(
                "Application catalog published, evaluation-candidate, or total profile metadata does not match the typed rows.");
        }
    }

    private static void ValidateRuntimeContent(ApplicationCatalogDocument document)
    {
        var content = ApplicationCatalogBuilder.CreateContentQualityAssessment(document);
        var incompleteCandidates = content.Profiles
            .Where(profile => profile.IsEvaluationCandidate && !profile.ContentComplete)
            .Select(profile => profile.ProfileId)
            .OrderBy(profileId => profileId, StringComparer.Ordinal)
            .ToArray();
        if (incompleteCandidates.Length != 0)
        {
            throw new InvalidDataException(
                "Application catalog contains incomplete evaluation candidates: " +
                string.Join(", ", incompleteCandidates.Take(12)));
        }
    }

    private static IReadOnlyList<ApplicationProfileDefinition> ReadProfiles(SqliteConnection connection)
    {
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT ProfileId, ProfileRevision, DisplayName, Category,
                       IsEnabled, IsEvaluationCandidate, ReviewState, FilenameMatchKind, FilenamePattern, DiscriminatorsJson,
                       RoleSummary, ExpectedResponsibilitiesJson, NormalBehaviorJson,
                       LaunchTriggersJson, ExpectedContextJson, ObservableExpectationsJson,
                       NormalVariantsJson, AbuseNotesJson, AnalystValidationChecksJson,
                       Confidence, SourcesJson, DraftedUtc, LastReviewedUtc, Provenance
                FROM Profiles
                ORDER BY ProfileId;
                """;
            var profiles = new List<ApplicationProfileDefinition>();
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                profiles.Add(new ApplicationProfileDefinition
                {
                    ProfileId = reader.GetString(0),
                    ProfileRevision = reader.GetString(1),
                    DisplayName = reader.GetString(2),
                    Category = ParseEnum<ApplicationCategory>(reader.GetString(3), "category"),
                    IsEnabled = reader.GetInt32(4) == 1,
                    IsEvaluationCandidate = reader.GetInt32(5) == 1,
                    ReviewState = ParseEnum<ApplicationProfileReviewState>(reader.GetString(6), "review state"),
                    Filename = new ApplicationFilenameMatcher
                    {
                        Kind = ParseEnum<ApplicationFilenameMatchKind>(reader.GetString(7), "filename match kind"),
                        Pattern = reader.GetString(8)
                    },
                    Discriminators = Deserialize<ApplicationProfileDiscriminators>(reader.GetString(9), "discriminators"),
                    RoleSummary = reader.GetString(10),
                    ExpectedResponsibilities = Deserialize<List<string>>(reader.GetString(11), "expected responsibilities"),
                    NormalBehavior = Deserialize<List<string>>(reader.GetString(12), "normal behavior"),
                    LaunchTriggers = Deserialize<List<string>>(reader.GetString(13), "launch triggers"),
                    ExpectedContext = Deserialize<ApplicationExpectedContext>(reader.GetString(14), "expected context"),
                    ObservableExpectations = Deserialize<ApplicationObservableExpectations>(reader.GetString(15), "observable expectations"),
                    NormalVariants = Deserialize<List<string>>(reader.GetString(16), "normal variants"),
                    AbuseAndMasqueradingNotes = Deserialize<List<string>>(reader.GetString(17), "abuse notes"),
                    AnalystValidationChecks = Deserialize<List<string>>(reader.GetString(18), "analyst validation checks"),
                    Confidence = reader.GetDouble(19),
                    Sources = Deserialize<List<ApplicationProfileSourceReference>>(reader.GetString(20), "sources"),
                    DraftedUtc = ParseUtc(reader.GetString(21), "drafted timestamp"),
                    LastReviewedUtc = reader.IsDBNull(22)
                        ? null
                        : ParseUtc(reader.GetString(22), "last reviewed timestamp"),
                    Provenance = reader.GetString(23)
                });
            }

            return profiles;
        }
        catch (SqliteException ex)
        {
            throw new InvalidDataException($"Application catalog profiles are unreadable: {ex.Message}", ex);
        }
    }

    private static T Deserialize<T>(string json, string field)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(json, ApplicationCatalogBuilder.JsonOptions)
                ?? throw new InvalidDataException($"Application catalog {field} is null.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Application catalog {field} is malformed: {ex.Message}", ex);
        }
    }

    private static T ParseEnum<T>(string value, string field) where T : struct, Enum
    {
        if (!Enum.TryParse<T>(value, ignoreCase: false, out var result) || !Enum.IsDefined(result))
        {
            throw new InvalidDataException($"Application catalog {field} '{value}' is unknown.");
        }

        return result;
    }

    private static DateTime ParseUtc(string value, string field)
    {
        if (!DateTime.TryParse(value, null, System.Globalization.DateTimeStyles.RoundtripKind, out var result) ||
            result.Kind != DateTimeKind.Utc)
        {
            throw new InvalidDataException($"Application catalog {field} '{value}' is not UTC.");
        }

        return result;
    }

    private static bool ContainsAny(string actual, IReadOnlyList<string> expected)
    {
        if (string.IsNullOrWhiteSpace(actual))
        {
            return false;
        }

        return expected.Any(value => actual.Contains(value, StringComparison.OrdinalIgnoreCase));
    }

    private static bool MatchesFilename(string actual, IReadOnlyList<string> expected)
    {
        var normalized = ApplicationPatternValidator.NormalizeFilename(actual);
        return normalized.Length > 0 && expected.Any(value =>
            string.Equals(
                ApplicationPatternValidator.NormalizeFilename(value),
                normalized,
                StringComparison.Ordinal));
    }
}
