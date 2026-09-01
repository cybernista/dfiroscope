using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using ProcInsider.Models.ApplicationCatalog;

namespace ProcInsider.Services;

public static class ApplicationCatalogBuilder
{
    public const int SupportedSchemaVersion = 3;
    public const int SupportedSourceIndexSchemaVersion = 1;
    public const int RequiredPublishedProfileCount = 300;
    private const string SourceFormatVersion = "application-catalog-index-v1";
    private const string ProfilesDirectoryName = "Profiles";
    private const int MaximumSourceEntries = 20_000;
    private const long MaximumSourcePartBytes = 8L * 1024 * 1024;
    private static readonly string[] IncompleteDraftMarkers =
    [
        "classified provisionally",
        "maintainer must verify the exact",
        "family-level authoring source",
        "expose only the version-specific",
        "context-dependent; verify",
        "operation-dependent;",
        "replace or supplement the family-level source"
    ];
    private static readonly Regex StableIdPattern = new(
        "^[a-z0-9][a-z0-9._-]{2,127}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
        TimeSpan.FromMilliseconds(100));

    internal static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNameCaseInsensitive = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = false,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) }
    };

    public static ApplicationCatalogDocument ReadAndValidateSource(string sourcePath)
        => ReadAndValidateSourceWithHash(sourcePath, File.GetAttributes).Document;

    internal static ApplicationCatalogDocument ReadAndValidateSource(
        string sourcePath,
        Func<string, FileAttributes> attributesReader)
        => ReadAndValidateSourceWithHash(sourcePath, attributesReader).Document;

    private static ApplicationCatalogSourceReadResult ReadAndValidateSourceWithHash(
        string sourcePath,
        Func<string, FileAttributes> attributesReader)
    {
        ArgumentNullException.ThrowIfNull(attributesReader);
        if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
        {
            throw new FileNotFoundException("Application catalog source index JSON was not found.", sourcePath);
        }

        var fullIndexPath = Path.GetFullPath(sourcePath);
        RejectReparsePoint(fullIndexPath, "Application catalog source index", attributesReader);
        var indexText = ReadBoundedSourceText(fullIndexPath, "Application catalog source index");
        ApplicationCatalogSourceIndex sourceIndex;
        try
        {
            sourceIndex = JsonSerializer.Deserialize<ApplicationCatalogSourceIndex>(indexText, JsonOptions)
                ?? throw new InvalidDataException("Application catalog source index JSON is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Application catalog source index JSON is malformed: {ex.Message}", ex);
        }

        if (sourceIndex.SchemaVersion != SupportedSourceIndexSchemaVersion)
        {
            throw new InvalidDataException(
                $"Unsupported application catalog source index schema version {sourceIndex.SchemaVersion}; " +
                $"expected {SupportedSourceIndexSchemaVersion}.");
        }

        RequireText(sourceIndex.CatalogRevision, "catalogRevision", 128);
        if (sourceIndex.Entries.Count is 0 or > MaximumSourceEntries)
        {
            throw new InvalidDataException(
                $"Application catalog source index must contain 1..{MaximumSourceEntries} entries.");
        }

        var indexDirectory = Path.GetDirectoryName(fullIndexPath)
            ?? throw new InvalidDataException("Application catalog source index has no owning directory.");
        var profilesRoot = Path.GetFullPath(Path.Combine(indexDirectory, ProfilesDirectoryName));
        if (!Directory.Exists(profilesRoot))
        {
            throw new DirectoryNotFoundException(
                $"Application catalog Profiles directory was not found: {profilesRoot}");
        }

        RejectReparsePoint(profilesRoot, "Application catalog Profiles directory", attributesReader);
        if (Directory.EnumerateDirectories(profilesRoot, "*", SearchOption.TopDirectoryOnly).Any())
        {
            throw new InvalidDataException(
                "Application catalog Profiles directory must remain flat; nested directories are not indexed source.");
        }

        var profileIds = new HashSet<string>(StringComparer.Ordinal);
        var relativePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var indexedFullPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var loaded = new List<LoadedSourceProfile>(sourceIndex.Entries.Count);
        for (var index = 0; index < sourceIndex.Entries.Count; index++)
        {
            var entry = sourceIndex.Entries[index]
                ?? throw new InvalidDataException($"entries[{index}] is null.");
            var context = $"entries[{index}]";
            RequireStableId(entry.ProfileId, $"{context}.profileId");
            if (!profileIds.Add(entry.ProfileId))
            {
                throw new InvalidDataException($"Duplicate application catalog source profile ID '{entry.ProfileId}'.");
            }

            var relativePath = ValidateSourceEntryPath(entry, context);
            if (!relativePaths.Add(relativePath))
            {
                throw new InvalidDataException(
                    $"Duplicate or case-colliding application catalog source path '{relativePath}'.");
            }

            var fullProfilePath = Path.GetFullPath(Path.Combine(
                indexDirectory,
                relativePath.Replace('/', Path.DirectorySeparatorChar)));
            var relativeToProfiles = Path.GetRelativePath(profilesRoot, fullProfilePath)
                .Replace(Path.DirectorySeparatorChar, '/');
            if (relativeToProfiles.StartsWith("../", StringComparison.Ordinal) ||
                Path.IsPathRooted(relativeToProfiles) ||
            relativeToProfiles.Contains('/'))
            {
                throw new InvalidDataException(
                    $"{context}.path must resolve to one direct child of the owned Profiles directory.");
            }

            if (!File.Exists(fullProfilePath))
            {
                throw new FileNotFoundException(
                    $"Application catalog source profile '{entry.ProfileId}' was not found.",
                    fullProfilePath);
            }

            RejectReparsePoint(
                fullProfilePath,
                $"Application catalog source profile '{entry.ProfileId}'",
                attributesReader);
            var profileText = ReadBoundedSourceText(
                fullProfilePath,
                $"Application catalog source profile '{entry.ProfileId}'");
            ApplicationProfileDefinition profile;
            try
            {
                profile = JsonSerializer.Deserialize<ApplicationProfileDefinition>(profileText, JsonOptions)
                    ?? throw new InvalidDataException(
                        $"Application catalog source profile '{entry.ProfileId}' is empty.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException(
                    $"Application catalog source profile '{entry.ProfileId}' is malformed: {ex.Message}",
                    ex);
            }

            if (!string.Equals(entry.ProfileId, profile.ProfileId, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Application catalog source entry ID '{entry.ProfileId}' does not match profile ID '{profile.ProfileId}'.");
            }

            indexedFullPaths.Add(fullProfilePath);
            loaded.Add(new LoadedSourceProfile(entry, profile, profileText));
        }

        foreach (var profilePath in Directory.EnumerateFiles(profilesRoot, "*.json", SearchOption.TopDirectoryOnly))
        {
            var fullProfilePath = Path.GetFullPath(profilePath);
            RejectReparsePoint(
                fullProfilePath,
                "Application catalog Profiles directory member",
                attributesReader);
            if (!indexedFullPaths.Contains(fullProfilePath))
            {
                throw new InvalidDataException(
                    $"Unindexed application catalog profile JSON is not allowed: {Path.GetFileName(profilePath)}");
            }
        }

        var document = new ApplicationCatalogDocument
        {
            SchemaVersion = SupportedSchemaVersion,
            CatalogRevision = sourceIndex.CatalogRevision,
            Profiles = loaded.Select(item => item.Profile).ToList()
        };
        Validate(document);
        return new ApplicationCatalogSourceReadResult(
            document,
            ComputeAggregateSourceHash(indexText, loaded));
    }

    public static void Validate(ApplicationCatalogDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        if (document.SchemaVersion != SupportedSchemaVersion)
        {
            throw new InvalidDataException(
                $"Unsupported application catalog schema version {document.SchemaVersion}; expected {SupportedSchemaVersion}.");
        }

        RequireText(document.CatalogRevision, "catalogRevision", 128);
        if (document.Profiles.Count == 0)
        {
            throw new InvalidDataException("Application catalog must contain at least one profile.");
        }

        var profileIds = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < document.Profiles.Count; index++)
        {
            var profile = document.Profiles[index]
                ?? throw new InvalidDataException($"profiles[{index}] is null.");
            var context = $"profiles[{index}]";
            RequireStableId(profile.ProfileId, $"{context}.profileId");
            if (!profileIds.Add(profile.ProfileId))
            {
                throw new InvalidDataException($"Duplicate application profile ID '{profile.ProfileId}'.");
            }

            RequireText(profile.ProfileRevision, $"{context}.profileRevision", 128);
            RequireText(profile.DisplayName, $"{context}.displayName", 256);
            if (!Enum.IsDefined(profile.ReviewState) ||
                profile.ReviewState is ApplicationProfileReviewState.Unreviewed or
                    ApplicationProfileReviewState.AnalystReviewed)
            {
                throw new InvalidDataException(
                    $"{context}.reviewState must be catalogReviewed or aiDraft for built-in source content.");
            }

            if (profile.IsEnabled && profile.ReviewState != ApplicationProfileReviewState.CatalogReviewed)
            {
                throw new InvalidDataException(
                    $"{context} cannot be enabled until visible maintainer review marks it catalogReviewed.");
            }

            if (profile.IsEvaluationCandidate &&
                (profile.IsEnabled || profile.ReviewState != ApplicationProfileReviewState.AiDraft))
            {
                throw new InvalidDataException(
                    $"{context}.isEvaluationCandidate is permitted only for disabled aiDraft content.");
            }

            RequireUtc(profile.DraftedUtc, $"{context}.draftedUtc");
            if (profile.ReviewState == ApplicationProfileReviewState.CatalogReviewed)
            {
                if (!profile.LastReviewedUtc.HasValue)
                {
                    throw new InvalidDataException(
                        $"{context}.lastReviewedUtc is required for catalogReviewed content.");
                }

                RequireUtc(profile.LastReviewedUtc.Value, $"{context}.lastReviewedUtc");
                if (profile.LastReviewedUtc.Value < profile.DraftedUtc)
                {
                    throw new InvalidDataException(
                        $"{context}.lastReviewedUtc cannot precede draftedUtc.");
                }
            }
            else if (profile.LastReviewedUtc.HasValue)
            {
                throw new InvalidDataException(
                    $"{context}.lastReviewedUtc must remain null until the AI draft is visibly reviewed.");
            }

            if (profile.Category == ApplicationCategory.Unknown)
            {
                throw new InvalidDataException($"{context}.category must be a known typed category.");
            }

            ApplicationPatternValidator.Validate(profile.Filename, context);
            ValidateDiscriminators(profile.Discriminators, context);
            RequireText(profile.RoleSummary, $"{context}.roleSummary", 4000);
            RequireList(profile.ExpectedResponsibilities, $"{context}.expectedResponsibilities");
            RequireList(profile.NormalBehavior, $"{context}.normalBehavior");
            RequireList(profile.LaunchTriggers, $"{context}.launchTriggers");
            ValidateExpectedContext(profile.ExpectedContext, context);
            ValidateObservableExpectations(profile.ObservableExpectations, context);
            RequireList(profile.NormalVariants, $"{context}.normalVariants");
            RequireList(profile.AbuseAndMasqueradingNotes, $"{context}.abuseAndMasqueradingNotes");
            RequireList(profile.AnalystValidationChecks, $"{context}.analystValidationChecks");
            if (!double.IsFinite(profile.Confidence) || profile.Confidence <= 0 || profile.Confidence > 1)
            {
                throw new InvalidDataException($"{context}.confidence must be greater than 0 and at most 1.");
            }

            if (profile.Sources.Count == 0)
            {
                throw new InvalidDataException($"{context}.sources must contain at least one reference.");
            }

            for (var sourceIndex = 0; sourceIndex < profile.Sources.Count; sourceIndex++)
            {
                var source = profile.Sources[sourceIndex]
                    ?? throw new InvalidDataException($"{context}.sources[{sourceIndex}] is null.");
                RequireText(source.Title, $"{context}.sources[{sourceIndex}].title", 512);
                RequireText(source.Publisher, $"{context}.sources[{sourceIndex}].publisher", 256);
                if (!Uri.TryCreate(source.Uri, UriKind.Absolute, out var sourceUri) ||
                    (sourceUri.Scheme != Uri.UriSchemeHttps && sourceUri.Scheme != Uri.UriSchemeHttp))
                {
                    throw new InvalidDataException($"{context}.sources[{sourceIndex}].uri must be an absolute HTTP(S) URI.");
                }

                RequireUtc(source.RetrievedUtc, $"{context}.sources[{sourceIndex}].retrievedUtc");
                RequireText(source.SupportingNote, $"{context}.sources[{sourceIndex}].supportingNote", 1000);
            }

            RequireText(profile.Provenance, $"{context}.provenance", 1000);
        }
    }

    public static ApplicationCatalogQualityReport CreateQualityReport(string sourcePath)
    {
        var source = ReadAndValidateSourceWithHash(sourcePath, File.GetAttributes);
        var document = source.Document;
        var content = CreateContentQualityAssessment(document);
        var reviewCounts = document.Profiles
            .GroupBy(profile => profile.ReviewState.ToString())
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new ApplicationCatalogQualityCount
            {
                Name = group.Key,
                Count = group.Count()
            })
            .ToList();
        var publishedCount = document.Profiles.Count(profile =>
            profile.IsEnabled &&
            !profile.IsEvaluationCandidate &&
            profile.ReviewState == ApplicationProfileReviewState.CatalogReviewed);
        var evaluationCandidateCount = document.Profiles.Count(profile => profile.IsEvaluationCandidate);
        var blockers = new List<string>();
        var draftCount = document.Profiles.Count(profile =>
            profile.ReviewState == ApplicationProfileReviewState.AiDraft);
        if (draftCount != 0)
        {
            blockers.Add($"{draftCount} AI-authored profiles require visible maintainer review.");
        }

        if (publishedCount < RequiredPublishedProfileCount)
        {
            blockers.Add(
                $"Only {publishedCount} reviewed profiles are enabled; " +
                $"{RequiredPublishedProfileCount} are required for the initial publication.");
        }

        return new ApplicationCatalogQualityReport
        {
            CatalogRevision = document.CatalogRevision,
            SourceSha256 = source.SourceSha256,
            AuthoringProfileCount = document.Profiles.Count,
            PublishedProfileCount = publishedCount,
            EvaluationCandidateProfileCount = evaluationCandidateCount,
            RuntimeProfileCount = publishedCount + evaluationCandidateCount,
            SourceReferenceCount = document.Profiles.Sum(profile => profile.Sources.Count),
            ProfilesWithMultipleSources = document.Profiles.Count(profile => profile.Sources.Count > 1),
            DistinctSourceUriCount = document.Profiles
                .SelectMany(profile => profile.Sources)
                .Select(source => source.Uri)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(),
            ContentCompleteProfileCount = content.ContentCompleteProfileCount,
            ContentCompleteAiDraftCount = content.ContentCompleteAiDraftCount,
            IncompleteProfileCount = content.IncompleteProfileCount,
            DuplicateContentGroupCount = content.DuplicateContentGroupCount,
            ContentReadyForEvaluation = content.ContentReadyForEvaluation,
            ContentQualityBlockers = content.ContentQualityBlockers,
            SemanticSampleProfileIds = content.SemanticSampleProfileIds,
            Profiles = content.Profiles,
            PublicationReady = blockers.Count == 0,
            PublicationBlockers = blockers,
            Categories = ToCounts(document.Profiles.Select(profile => profile.Category.ToString())),
            Vendors = ToCounts(document.Profiles.SelectMany(profile =>
                profile.Discriminators.Companies.Count == 0
                    ? ["Unspecified"]
                    : profile.Discriminators.Companies.Distinct(StringComparer.OrdinalIgnoreCase))),
            ConfidenceBands = ToCounts(document.Profiles.Select(profile => profile.Confidence switch
            {
                >= 0.8 => "High (0.80-1.00)",
                >= 0.6 => "Medium (0.60-0.79)",
                _ => "Low (<0.60)"
            })),
            ReviewStates = reviewCounts,
            AmbiguousFilenames = document.Profiles
                .GroupBy(
                    profile => ApplicationPatternValidator.NormalizeFilename(profile.Filename.Pattern),
                    StringComparer.Ordinal)
                .Where(group => group.Count() > 1)
                .Select(group => group.Key)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToList()
        };
    }

    public static ApplicationCatalogContentQualityAssessment CreateContentQualityAssessment(
        ApplicationCatalogDocument document)
    {
        Validate(document);
        var rows = document.Profiles
            .OrderBy(profile => profile.ProfileId, StringComparer.Ordinal)
            .Select(CreateProfileQuality)
            .ToList();
        var draftsByHash = document.Profiles
            .Where(profile => profile.ReviewState == ApplicationProfileReviewState.AiDraft)
            .Select(profile => new
            {
                profile.ProfileId,
                ContentSha256 = ComputeProfileContentHash(profile)
            })
            .GroupBy(item => item.ContentSha256, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .ToArray();

        foreach (var duplicateGroup in draftsByHash)
        {
            var ids = duplicateGroup
                .Select(item => item.ProfileId)
                .OrderBy(profileId => profileId, StringComparer.Ordinal)
                .ToArray();
            var issue = $"Exact duplicated core content is shared by: {string.Join(", ", ids)}.";
            foreach (var profileId in ids)
            {
                var duplicateRow = rows.Single(row => string.Equals(row.ProfileId, profileId, StringComparison.Ordinal));
                duplicateRow.Issues.Add(issue);
                duplicateRow.ContentComplete = false;
            }
        }

        var blockers = rows
            .Where(row => !row.ContentComplete || row.Issues.Count != 0)
            .Select(row => $"{row.ProfileId}: {string.Join(" ", row.Issues)}")
            .ToList();
        var completeProfileCount = rows.Count(row => row.Issues.Count == 0);
        var completeAiDraftCount = rows.Count(row =>
            row.Issues.Count == 0 &&
            document.Profiles.Single(profile => profile.ProfileId == row.ProfileId).ReviewState ==
            ApplicationProfileReviewState.AiDraft);
        return new ApplicationCatalogContentQualityAssessment
        {
            ContentCompleteProfileCount = completeProfileCount,
            ContentCompleteAiDraftCount = completeAiDraftCount,
            IncompleteProfileCount = rows.Count - completeProfileCount,
            DuplicateContentGroupCount = draftsByHash.Length,
            ContentReadyForEvaluation = blockers.Count == 0 && draftsByHash.Length == 0,
            ContentQualityBlockers = blockers,
            SemanticSampleProfileIds = SelectSemanticSamples(document.Profiles),
            Profiles = rows
        };
    }

    private static ApplicationCatalogProfileQuality CreateProfileQuality(ApplicationProfileDefinition profile)
    {
        var statements = EnumerateContentStatements(profile)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();
        var issues = new List<string>();
        if (profile.ReviewState == ApplicationProfileReviewState.AiDraft)
        {
            if (string.Equals(profile.ProfileRevision, "1-draft", StringComparison.Ordinal))
            {
                issues.Add("Legacy placeholder revision remains.");
            }

            if (profile.RoleSummary.Length < 200)
            {
                issues.Add("Role summary is shorter than 200 characters.");
            }

            RequireMinimum(profile.ExpectedResponsibilities, 3, "responsibilities", issues);
            RequireMinimum(profile.NormalBehavior, 3, "normal-behavior statements", issues);
            RequireMinimum(profile.LaunchTriggers, 3, "launch triggers", issues);
            RequireMinimum(profile.NormalVariants, 3, "normal variants", issues);
            RequireMinimum(profile.AbuseAndMasqueradingNotes, 3, "abuse/masquerading notes", issues);
            RequireMinimum(profile.AnalystValidationChecks, 3, "analyst checks", issues);
            RequireMinimum(profile.ObservableExpectations.CommandLine, 2, "command-line expectations", issues);
            RequireMinimum(profile.ObservableExpectations.Filesystem, 2, "filesystem expectations", issues);
            RequireMinimum(profile.ObservableExpectations.Registry, 1, "registry expectations", issues);
            RequireMinimum(profile.ObservableExpectations.ChildProcesses, 2, "child-process expectations", issues);
            RequireMinimum(profile.ObservableExpectations.Network, 2, "network expectations", issues);
            if (profile.Sources.Count < 2 ||
                profile.Sources.Select(source => source.Uri).Distinct(StringComparer.OrdinalIgnoreCase).Count() < 2)
            {
                issues.Add("At least two distinct source references are required.");
            }

            var combined = string.Join('\n', statements);
            foreach (var marker in IncompleteDraftMarkers.Where(marker =>
                         combined.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            {
                issues.Add($"Placeholder marker remains: '{marker}'.");
            }

            var executable = profile.Filename.Pattern.Trim();
            if (!profile.RoleSummary.Contains(executable, StringComparison.OrdinalIgnoreCase))
            {
                issues.Add("Role summary does not name the executable.");
            }

            var stem = Path.GetFileNameWithoutExtension(executable);
            if (statements.Count(statement => statement.Contains(stem, StringComparison.OrdinalIgnoreCase)) < 3)
            {
                issues.Add("Fewer than three content statements are executable-specific.");
            }
        }

        var distinctStatementCount = statements
            .Select(NormalizeQualityText)
            .Distinct(StringComparer.Ordinal)
            .Count();
        if (distinctStatementCount != statements.Length)
        {
            issues.Add("The profile repeats one or more exact normalized statements.");
        }

        return new ApplicationCatalogProfileQuality
        {
            ProfileId = profile.ProfileId,
            IsEvaluationCandidate = profile.IsEvaluationCandidate,
            ContentComplete = issues.Count == 0,
            RoleSummaryLength = profile.RoleSummary.Length,
            StatementCount = statements.Length,
            DistinctStatementCount = distinctStatementCount,
            SourceReferenceCount = profile.Sources.Count,
            ContentSha256 = ComputeProfileContentHash(profile),
            Issues = issues
        };
    }

    private static IEnumerable<string> EnumerateContentStatements(ApplicationProfileDefinition profile)
    {
        yield return profile.RoleSummary;
        foreach (var value in profile.ExpectedResponsibilities) yield return value;
        foreach (var value in profile.NormalBehavior) yield return value;
        foreach (var value in profile.LaunchTriggers) yield return value;
        foreach (var value in profile.ExpectedContext.ParentExecutables) yield return value;
        foreach (var value in profile.ExpectedContext.Accounts) yield return value;
        foreach (var value in profile.ExpectedContext.Sessions) yield return value;
        foreach (var value in profile.ExpectedContext.PrivilegeLevels) yield return value;
        foreach (var value in profile.ExpectedContext.Lifetimes) yield return value;
        foreach (var value in profile.ObservableExpectations.CommandLine) yield return value;
        foreach (var value in profile.ObservableExpectations.Filesystem) yield return value;
        foreach (var value in profile.ObservableExpectations.Registry) yield return value;
        foreach (var value in profile.ObservableExpectations.ChildProcesses) yield return value;
        foreach (var value in profile.ObservableExpectations.Network) yield return value;
        foreach (var value in profile.NormalVariants) yield return value;
        foreach (var value in profile.AbuseAndMasqueradingNotes) yield return value;
        foreach (var value in profile.AnalystValidationChecks) yield return value;
    }

    private static void RequireMinimum(
        IReadOnlyCollection<string> values,
        int minimum,
        string label,
        ICollection<string> issues)
    {
        if (values.Count < minimum)
        {
            issues.Add($"Expected at least {minimum} {label}; found {values.Count}.");
        }
    }

    private static string ComputeProfileContentHash(ApplicationProfileDefinition profile)
    {
        var content = string.Join('\n', EnumerateContentStatements(profile).Select(NormalizeQualityText));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
    }

    private static string NormalizeQualityText(string value) =>
        string.Join(' ', value.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            .ToUpperInvariant();

    private static List<string> SelectSemanticSamples(IReadOnlyCollection<ApplicationProfileDefinition> profiles)
    {
        return profiles
            .GroupBy(profile => profile.ProfileId switch
            {
                var id when id.StartsWith("draft.windows.command.", StringComparison.Ordinal) => "windows-command",
                var id when id.StartsWith("draft.windows.system.", StringComparison.Ordinal) => "windows-system",
                var id when id.StartsWith("draft.sysinternals.", StringComparison.Ordinal) => "sysinternals",
                var id when id.StartsWith("draft.windows.application.", StringComparison.Ordinal) => "windows-application",
                var id when id.StartsWith("draft.vmware.", StringComparison.Ordinal) => "vmware",
                _ => "reviewed"
            }, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .SelectMany(group =>
            {
                var ordered = group.OrderBy(profile => profile.ProfileId, StringComparer.Ordinal).ToArray();
                return new[] { ordered[0], ordered[ordered.Length / 2], ordered[^1] }
                    .Select(profile => profile.ProfileId)
                    .Distinct(StringComparer.Ordinal);
            })
            .Distinct(StringComparer.Ordinal)
            .OrderBy(profileId => profileId, StringComparer.Ordinal)
            .ToList();
    }

    public static void WriteQualityReport(string sourcePath, string outputPath)
    {
        var report = CreateQualityReport(sourcePath);
        var options = new JsonSerializerOptions(JsonOptions)
        {
            WriteIndented = true
        };
        var json = JsonSerializer.Serialize(report, options).Replace("\r\n", "\n") + "\n";
        File.WriteAllText(outputPath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    public static void Build(string sourcePath, string outputPath, bool overwrite = false)
    {
        var document = ReadAndValidateSource(sourcePath);
        var fullOutputPath = Path.GetFullPath(outputPath);
        var outputDirectory = Path.GetDirectoryName(fullOutputPath)
            ?? throw new InvalidOperationException("Application catalog output path has no owning directory.");
        Directory.CreateDirectory(outputDirectory);
        if (File.Exists(fullOutputPath) && !overwrite)
        {
            throw new IOException($"Application catalog output already exists: {fullOutputPath}");
        }

        var temporaryPath = Path.Combine(
            outputDirectory,
            $".{Path.GetFileName(fullOutputPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            WriteDatabase(document, temporaryPath);
            File.Move(temporaryPath, fullOutputPath, overwrite);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static string ValidateSourceEntryPath(ApplicationCatalogSourceEntry entry, string context)
    {
        RequireText(entry.Path, $"{context}.path", 512);
        if (!string.Equals(entry.Path, entry.Path.Trim(), StringComparison.Ordinal) ||
            Path.IsPathRooted(entry.Path) ||
            entry.Path.Contains('\\') ||
            entry.Path.Contains(':') ||
            entry.Path.Split('/').Any(segment => segment is "" or "." or ".."))
        {
            throw new InvalidDataException(
                $"{context}.path must be a normalized relative JSON path beneath {ProfilesDirectoryName}.");
        }

        var expectedPath = $"{ProfilesDirectoryName}/{entry.ProfileId}.json";
        if (!string.Equals(entry.Path, expectedPath, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"{context}.path must be exactly '{expectedPath}'.");
        }

        return entry.Path;
    }

    private static string ReadBoundedSourceText(string path, string description)
    {
        var length = new FileInfo(path).Length;
        if (length > MaximumSourcePartBytes)
        {
            throw new InvalidDataException(
                $"{description} exceeds the {MaximumSourcePartBytes}-byte source-part limit.");
        }

        return File.ReadAllText(path, Encoding.UTF8);
    }

    private static void RejectReparsePoint(
        string path,
        string description,
        Func<string, FileAttributes> attributesReader)
    {
        if ((attributesReader(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"{description} cannot be a reparse point or symbolic link.");
        }
    }

    private static string ComputeAggregateSourceHash(
        string indexText,
        IReadOnlyCollection<LoadedSourceProfile> profiles)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendSourceHashPart(hash, "format", SourceFormatVersion);
        AppendSourceHashPart(hash, "index", NormalizeSourceText(indexText));
        foreach (var item in profiles.OrderBy(value => value.Entry.ProfileId, StringComparer.Ordinal))
        {
            AppendSourceHashPart(
                hash,
                $"profile:{item.Entry.ProfileId}:{item.Entry.Path}",
                NormalizeSourceText(item.SourceText));
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void AppendSourceHashPart(IncrementalHash hash, string label, string content)
    {
        var labelBytes = Encoding.UTF8.GetBytes(label);
        var contentBytes = Encoding.UTF8.GetBytes(content);
        Span<byte> lengthBytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, labelBytes.Length);
        hash.AppendData(lengthBytes);
        hash.AppendData(labelBytes);
        BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, contentBytes.Length);
        hash.AppendData(lengthBytes);
        hash.AppendData(contentBytes);
    }

    private static string NormalizeSourceText(string text) =>
        text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');

    private sealed record LoadedSourceProfile(
        ApplicationCatalogSourceEntry Entry,
        ApplicationProfileDefinition Profile,
        string SourceText);

    private sealed record ApplicationCatalogSourceReadResult(
        ApplicationCatalogDocument Document,
        string SourceSha256);

    private static void WriteDatabase(ApplicationCatalogDocument document, string outputPath)
    {
        var publishedProfiles = document.Profiles
            .Where(profile => profile.IsEnabled &&
                              !profile.IsEvaluationCandidate &&
                              profile.ReviewState == ApplicationProfileReviewState.CatalogReviewed)
            .OrderBy(profile => profile.ProfileId, StringComparer.Ordinal)
            .ToArray();
        if (publishedProfiles.Length == 0)
        {
            throw new InvalidDataException(
                "Application catalog has no enabled catalogReviewed profiles to publish.");
        }

        var evaluationCandidates = document.Profiles
            .Where(profile => profile.IsEvaluationCandidate)
            .OrderBy(profile => profile.ProfileId, StringComparer.Ordinal)
            .ToArray();
        var candidateIds = evaluationCandidates
            .Select(profile => profile.ProfileId)
            .ToHashSet(StringComparer.Ordinal);
        var content = CreateContentQualityAssessment(document);
        var incompleteCandidates = content.Profiles
            .Where(profile => candidateIds.Contains(profile.ProfileId) && !profile.ContentComplete)
            .Select(profile => profile.ProfileId)
            .OrderBy(profileId => profileId, StringComparer.Ordinal)
            .ToArray();
        if (incompleteCandidates.Length != 0)
        {
            throw new InvalidDataException(
                "Application catalog evaluation candidates must pass the complete content gate: " +
                string.Join(", ", incompleteCandidates.Take(12)));
        }

        var runtimeProfiles = publishedProfiles
            .Concat(evaluationCandidates)
            .OrderBy(profile => profile.ProfileId, StringComparer.Ordinal)
            .ToArray();

        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = outputPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString()))
        {
            connection.Open();
            using (var schema = connection.CreateCommand())
            {
                schema.CommandText = """
                    PRAGMA page_size=4096;
                    PRAGMA journal_mode=OFF;
                    PRAGMA synchronous=OFF;
                    PRAGMA auto_vacuum=NONE;
                    PRAGMA user_version=3;
                    CREATE TABLE CatalogInfo (
                        Key TEXT PRIMARY KEY,
                        Value TEXT NOT NULL
                    ) WITHOUT ROWID;
                    CREATE TABLE Profiles (
                        ProfileId TEXT PRIMARY KEY,
                        ProfileRevision TEXT NOT NULL,
                        DisplayName TEXT NOT NULL,
                        IsEnabled INTEGER NOT NULL CHECK (IsEnabled IN (0, 1)),
                        IsEvaluationCandidate INTEGER NOT NULL CHECK (IsEvaluationCandidate IN (0, 1)),
                        ReviewState TEXT NOT NULL CHECK (ReviewState IN ('CatalogReviewed', 'AiDraft')),
                        Category TEXT NOT NULL,
                        FilenameMatchKind TEXT NOT NULL,
                        FilenamePattern TEXT NOT NULL,
                        DiscriminatorsJson TEXT NOT NULL,
                        RoleSummary TEXT NOT NULL,
                        ExpectedResponsibilitiesJson TEXT NOT NULL,
                        NormalBehaviorJson TEXT NOT NULL,
                        LaunchTriggersJson TEXT NOT NULL,
                        ExpectedContextJson TEXT NOT NULL,
                        ObservableExpectationsJson TEXT NOT NULL,
                        NormalVariantsJson TEXT NOT NULL,
                        AbuseNotesJson TEXT NOT NULL,
                        AnalystValidationChecksJson TEXT NOT NULL,
                        Confidence REAL NOT NULL,
                        SourcesJson TEXT NOT NULL,
                        DraftedUtc TEXT NOT NULL,
                        LastReviewedUtc TEXT,
                        Provenance TEXT NOT NULL,
                        CHECK (
                            (IsEnabled = 1 AND IsEvaluationCandidate = 0 AND ReviewState = 'CatalogReviewed' AND LastReviewedUtc IS NOT NULL)
                            OR
                            (IsEnabled = 0 AND IsEvaluationCandidate = 1 AND ReviewState = 'AiDraft' AND LastReviewedUtc IS NULL)
                        )
                    ) WITHOUT ROWID;
                    CREATE INDEX IX_Profiles_Filename ON Profiles(FilenameMatchKind, FilenamePattern, ProfileId);
                    """;
                schema.ExecuteNonQuery();
            }

            using var transaction = connection.BeginTransaction();
            WriteInfo(connection, transaction, "CatalogSchemaVersion", SupportedSchemaVersion.ToString());
            WriteInfo(connection, transaction, "CatalogRevision", document.CatalogRevision);
            WriteInfo(connection, transaction, "SourceFormatVersion", SourceFormatVersion);
            WriteInfo(connection, transaction, "Builder", "DFIRoscope.ApplicationCatalogBuilder");
            WriteInfo(connection, transaction, "AuthoringProfileCount", document.Profiles.Count.ToString());
            WriteInfo(connection, transaction, "PublishedProfileCount", publishedProfiles.Length.ToString());
            WriteInfo(connection, transaction, "EvaluationCandidateProfileCount", evaluationCandidates.Length.ToString());
            WriteInfo(connection, transaction, "TotalProfileCount", runtimeProfiles.Length.ToString());

            foreach (var profile in runtimeProfiles)
            {
                using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO Profiles (
                        ProfileId, ProfileRevision, DisplayName, IsEnabled, IsEvaluationCandidate, ReviewState, Category,
                        FilenameMatchKind, FilenamePattern, DiscriminatorsJson,
                        RoleSummary, ExpectedResponsibilitiesJson, NormalBehaviorJson,
                        LaunchTriggersJson, ExpectedContextJson, ObservableExpectationsJson,
                        NormalVariantsJson, AbuseNotesJson, AnalystValidationChecksJson,
                        Confidence, SourcesJson, DraftedUtc, LastReviewedUtc, Provenance)
                    VALUES (
                        $ProfileId, $ProfileRevision, $DisplayName, $IsEnabled, $IsEvaluationCandidate, $ReviewState, $Category,
                        $FilenameMatchKind, $FilenamePattern, $DiscriminatorsJson,
                        $RoleSummary, $ExpectedResponsibilitiesJson, $NormalBehaviorJson,
                        $LaunchTriggersJson, $ExpectedContextJson, $ObservableExpectationsJson,
                        $NormalVariantsJson, $AbuseNotesJson, $AnalystValidationChecksJson,
                        $Confidence, $SourcesJson, $DraftedUtc, $LastReviewedUtc, $Provenance);
                    """;
                insert.Parameters.AddWithValue("$ProfileId", profile.ProfileId);
                insert.Parameters.AddWithValue("$ProfileRevision", profile.ProfileRevision);
                insert.Parameters.AddWithValue("$DisplayName", profile.DisplayName);
                insert.Parameters.AddWithValue("$IsEnabled", profile.IsEnabled ? 1 : 0);
                insert.Parameters.AddWithValue("$IsEvaluationCandidate", profile.IsEvaluationCandidate ? 1 : 0);
                insert.Parameters.AddWithValue("$ReviewState", profile.ReviewState.ToString());
                insert.Parameters.AddWithValue("$Category", profile.Category.ToString());
                insert.Parameters.AddWithValue("$FilenameMatchKind", profile.Filename.Kind.ToString());
                insert.Parameters.AddWithValue("$FilenamePattern", profile.Filename.Pattern.Trim());
                insert.Parameters.AddWithValue("$DiscriminatorsJson", Serialize(profile.Discriminators));
                insert.Parameters.AddWithValue("$RoleSummary", profile.RoleSummary.Trim());
                insert.Parameters.AddWithValue("$ExpectedResponsibilitiesJson", Serialize(profile.ExpectedResponsibilities));
                insert.Parameters.AddWithValue("$NormalBehaviorJson", Serialize(profile.NormalBehavior));
                insert.Parameters.AddWithValue("$LaunchTriggersJson", Serialize(profile.LaunchTriggers));
                insert.Parameters.AddWithValue("$ExpectedContextJson", Serialize(profile.ExpectedContext));
                insert.Parameters.AddWithValue("$ObservableExpectationsJson", Serialize(profile.ObservableExpectations));
                insert.Parameters.AddWithValue("$NormalVariantsJson", Serialize(profile.NormalVariants));
                insert.Parameters.AddWithValue("$AbuseNotesJson", Serialize(profile.AbuseAndMasqueradingNotes));
                insert.Parameters.AddWithValue("$AnalystValidationChecksJson", Serialize(profile.AnalystValidationChecks));
                insert.Parameters.AddWithValue("$Confidence", profile.Confidence);
                insert.Parameters.AddWithValue("$SourcesJson", Serialize(profile.Sources));
                insert.Parameters.AddWithValue("$DraftedUtc", profile.DraftedUtc.ToString("O"));
                insert.Parameters.AddWithValue(
                    "$LastReviewedUtc",
                    profile.LastReviewedUtc.HasValue
                        ? profile.LastReviewedUtc.Value.ToString("O")
                        : DBNull.Value);
                insert.Parameters.AddWithValue("$Provenance", profile.Provenance.Trim());
                insert.ExecuteNonQuery();
            }

            transaction.Commit();
            using var vacuum = connection.CreateCommand();
            vacuum.CommandText = "VACUUM;";
            vacuum.ExecuteNonQuery();
        }
    }

    private static void WriteInfo(SqliteConnection connection, SqliteTransaction transaction, string key, string value)
    {
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = "INSERT INTO CatalogInfo(Key, Value) VALUES($Key, $Value);";
        insert.Parameters.AddWithValue("$Key", key);
        insert.Parameters.AddWithValue("$Value", value);
        insert.ExecuteNonQuery();
    }

    private static string Serialize<T>(T value) => JsonSerializer.Serialize(value, JsonOptions);

    private static List<ApplicationCatalogQualityCount> ToCounts(IEnumerable<string> values)
        => values
            .GroupBy(value => value, StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Select(group => new ApplicationCatalogQualityCount
            {
                Name = group.Key,
                Count = group.Count()
            })
            .ToList();

    private static void ValidateDiscriminators(ApplicationProfileDiscriminators discriminators, string context)
    {
        ArgumentNullException.ThrowIfNull(discriminators);
        ValidateOptionalList(discriminators.PathPatterns, $"{context}.discriminators.pathPatterns");
        ValidateOptionalList(discriminators.OriginalFilenames, $"{context}.discriminators.originalFilenames");
        ValidateOptionalList(discriminators.Companies, $"{context}.discriminators.companies");
        ValidateOptionalList(discriminators.Products, $"{context}.discriminators.products");
        ValidateOptionalList(discriminators.FileDescriptions, $"{context}.discriminators.fileDescriptions");
        ValidateOptionalList(discriminators.PackageFamilyNames, $"{context}.discriminators.packageFamilyNames");
    }

    private static void ValidateExpectedContext(ApplicationExpectedContext expected, string context)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ValidateOptionalList(expected.ParentExecutables, $"{context}.expectedContext.parentExecutables");
        ValidateOptionalList(expected.Accounts, $"{context}.expectedContext.accounts");
        ValidateOptionalList(expected.Sessions, $"{context}.expectedContext.sessions");
        ValidateOptionalList(expected.PrivilegeLevels, $"{context}.expectedContext.privilegeLevels");
        ValidateOptionalList(expected.Lifetimes, $"{context}.expectedContext.lifetimes");
    }

    private static void ValidateObservableExpectations(ApplicationObservableExpectations expected, string context)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ValidateOptionalList(expected.CommandLine, $"{context}.observableExpectations.commandLine");
        if (expected.CommandLineRules == null)
        {
            throw new InvalidDataException($"{context}.observableExpectations.commandLineRules must be an array.");
        }

        if (expected.CommandLineRules.Count > 32)
        {
            throw new InvalidDataException($"{context}.observableExpectations.commandLineRules exceeds 32 entries.");
        }

        for (var index = 0; index < expected.CommandLineRules.Count; index++)
        {
            var rule = expected.CommandLineRules[index]
                ?? throw new InvalidDataException($"{context}.observableExpectations.commandLineRules[{index}] is null.");
            var ruleContext = $"{context}.observableExpectations.commandLineRules[{index}]";
            if (rule.Kind == ApplicationCommandLineRuleKind.Unknown || !Enum.IsDefined(rule.Kind))
            {
                throw new InvalidDataException($"{ruleContext}.kind must be a known typed rule.");
            }

            RequireList(rule.Markers, $"{ruleContext}.markers");
            RequireText(rule.Rationale, $"{ruleContext}.rationale", 1000);
        }

        ValidateOptionalList(expected.Filesystem, $"{context}.observableExpectations.filesystem");
        ValidateOptionalList(expected.Registry, $"{context}.observableExpectations.registry");
        ValidateOptionalList(expected.ChildProcesses, $"{context}.observableExpectations.childProcesses");
        ValidateOptionalList(expected.Network, $"{context}.observableExpectations.network");
    }

    private static void RequireList(IReadOnlyList<string> values, string field)
    {
        if (values == null || values.Count == 0)
        {
            throw new InvalidDataException($"{field} must contain at least one useful entry.");
        }

        ValidateOptionalList(values, field);
    }

    private static void ValidateOptionalList(IReadOnlyList<string> values, string field)
    {
        if (values == null)
        {
            throw new InvalidDataException($"{field} must be an array.");
        }

        if (values.Count > 128)
        {
            throw new InvalidDataException($"{field} exceeds 128 entries.");
        }

        for (var index = 0; index < values.Count; index++)
        {
            RequireText(values[index], $"{field}[{index}]", 4000);
        }
    }

    private static void RequireStableId(string value, string field)
    {
        RequireText(value, field, 128);
        if (!StableIdPattern.IsMatch(value))
        {
            throw new InvalidDataException($"{field} must use lowercase letters, digits, periods, underscores, or hyphens.");
        }
    }

    private static void RequireText(string value, string field, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException($"{field} is required.");
        }

        if (value.Length > maximumLength)
        {
            throw new InvalidDataException($"{field} exceeds {maximumLength} characters.");
        }
    }

    private static void RequireUtc(DateTime value, string field)
    {
        if (value == default || value.Kind != DateTimeKind.Utc)
        {
            throw new InvalidDataException($"{field} must be a UTC timestamp.");
        }
    }
}
