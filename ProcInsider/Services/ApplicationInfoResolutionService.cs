using System.IO;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.ApplicationCatalog;
using ProcInsider.Models.Telemetry;

namespace ProcInsider.Services;

public sealed class ApplicationInfoResolutionService
{
    private static readonly Dictionary<string, string> ImageLessWindowsProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Idle"] = "System Idle Process",
        ["Registry"] = "Registry",
        ["System"] = "System",
        ["System Idle Process"] = "System Idle Process"
    };

    public const string EvaluationCandidateWarning =
        "AI draft review candidate — unreviewed; not a benign verdict.";

    private readonly ApplicationCatalogService? _catalog;

    public ApplicationInfoResolutionService(ApplicationCatalogService? catalog)
    {
        _catalog = catalog;
    }

    public ApplicationMetadataRecord? Resolve(
        ProcessInfo process,
        ApplicationMetadataRecord? unsavedDraft,
        ApplicationMetadataRecord? sessionOverride)
        => ResolveDetailed(
                process,
                CreateLookupContext(process),
                unsavedDraft,
                sessionOverride)
            .Record;

    public ApplicationInfoResolutionResult ResolveDetailed(
        ProcessInfo process,
        ApplicationProfileLookupContext lookupContext,
        ApplicationMetadataRecord? unsavedDraft,
        ApplicationMetadataRecord? sessionOverride)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(lookupContext);
        var candidates = _catalog?.ResolveCandidates(lookupContext) ?? [];
        ApplicationMetadataRecord? record;
        if (unsavedDraft != null)
        {
            unsavedDraft.RecordOrigin = ApplicationProfileOrigin.UnsavedDraft;
            unsavedDraft.MatchReason = "unsaved in-memory draft for the selected process";
            record = unsavedDraft;
        }
        else if (sessionOverride != null)
        {
            if (sessionOverride.RecordOrigin is ApplicationProfileOrigin.None or ApplicationProfileOrigin.BuiltInCatalog)
            {
                sessionOverride.RecordOrigin = sessionOverride.IsAiGenerated
                    ? ApplicationProfileOrigin.SessionAiOverride
                    : ApplicationProfileOrigin.SessionAnalystOverride;
            }

            record = sessionOverride;
        }
        else
        {
            record = candidates.Count == 0 ? null : CreateCatalogRecord(candidates[0]);
        }

        var linkedCatalogProfile = record == null
            ? null
            : _catalog?.GetProfileById(record.BaseProfileId);
        if (linkedCatalogProfile == null && record?.RecordOrigin == ApplicationProfileOrigin.BuiltInCatalog)
        {
            linkedCatalogProfile = candidates.FirstOrDefault()?.Profile;
        }

        var baseRevisionMismatch = record != null &&
                                   record.RecordOrigin != ApplicationProfileOrigin.BuiltInCatalog &&
                                   linkedCatalogProfile != null &&
                                   !string.IsNullOrWhiteSpace(record.BaseProfileRevision) &&
                                   !string.Equals(
                                       record.BaseProfileRevision,
                                       linkedCatalogProfile.ProfileRevision,
                                       StringComparison.Ordinal);
        var catalogProfile = baseRevisionMismatch ? null : linkedCatalogProfile;

        var selectedCandidate = catalogProfile == null
            ? candidates.FirstOrDefault()
            : candidates.FirstOrDefault(candidate => string.Equals(
                candidate.Profile.ProfileId,
                catalogProfile.ProfileId,
                StringComparison.Ordinal));
        var selectionReason = baseRevisionMismatch
            ? $"{record!.RecordOrigin} references base profile {record.BaseProfileId} revision {record.BaseProfileRevision}, but the current catalog contains revision {linkedCatalogProfile!.ProfileRevision}; current typed expectations were not applied automatically"
            : BuildSelectionReason(record, catalogProfile, selectedCandidate);
        if (record != null && string.IsNullOrWhiteSpace(record.MatchReason))
        {
            record.MatchReason = selectionReason;
        }

        return new ApplicationInfoResolutionResult
        {
            Record = record,
            CatalogProfile = catalogProfile,
            Candidates = candidates,
            SelectionReason = selectionReason
        };
    }

    public ApplicationMetadataRecord? ResolveEvaluation(ProcessInfo process)
        => ResolveEvaluationDetailed(process, CreateLookupContext(process)).Record;

    public ApplicationInfoEvaluationResolutionResult ResolveEvaluationDetailed(
        ProcessInfo process,
        ApplicationProfileLookupContext lookupContext)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(lookupContext);
        var candidates = _catalog?.ResolveEvaluationCandidates(lookupContext) ?? [];
        var match = _catalog?.ResolveEvaluation(lookupContext);
        var isAmbiguous = candidates.Count > 0 && match == null;
        var selectionReason = match?.SelectionReason ?? (isAmbiguous
            ? $"AI-draft evaluation lookup is ambiguous between {string.Join(", ", candidates.Select(candidate => candidate.Profile.ProfileId))}; no candidate was selected."
            : "No explicit AI-draft evaluation candidate matched the normalized filename and lookup context.");

        return new ApplicationInfoEvaluationResolutionResult
        {
            Record = match == null ? null : CreateCatalogRecord(match),
            CatalogProfile = match?.Profile,
            Candidates = candidates,
            IsAmbiguous = isAmbiguous,
            SelectionReason = selectionReason
        };
    }

    public static ApplicationProfileLookupContext CreateLookupContext(ProcessInfo process)
    {
        ArgumentNullException.ThrowIfNull(process);

        return new ApplicationProfileLookupContext
        {
            ExecutableFilename = ResolveExecutableFilename(process),
            ProcessPath = Clean(process.ProcessPath),
            Company = Clean(process.CompanyName),
            Product = string.Empty
        };
    }

    public static string ResolveExecutableFilename(ProcessInfo process)
    {
        ArgumentNullException.ThrowIfNull(process);
        var pathFilename = Path.GetFileName(Clean(process.ProcessPath));
        if (!string.IsNullOrWhiteSpace(pathFilename))
        {
            return pathFilename;
        }

        var processName = Clean(process.ProcessName);
        if (string.IsNullOrWhiteSpace(processName) ||
            processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return processName;
        }

        if (ImageLessWindowsProcessNames.TryGetValue(processName, out var imageLessIdentity))
        {
            return imageLessIdentity;
        }

        return $"{processName}.exe";
    }

    public static ApplicationMetadataRecord CreateCatalogRecord(ApplicationCatalogMatch match)
    {
        ArgumentNullException.ThrowIfNull(match);
        var profile = match.Profile;
        var isPublished = profile.IsEnabled &&
                          !profile.IsEvaluationCandidate &&
                          profile.ReviewState == ApplicationProfileReviewState.CatalogReviewed;
        var isEvaluationCandidate = !profile.IsEnabled &&
                                    profile.IsEvaluationCandidate &&
                                    profile.ReviewState == ApplicationProfileReviewState.AiDraft &&
                                    profile.LastReviewedUtc is null;
        if (!isPublished && !isEvaluationCandidate)
        {
            throw new InvalidDataException(
                $"Application profile '{profile.ProfileId}' is neither published nor an explicit evaluation candidate.");
        }

        return new ApplicationMetadataRecord
        {
            ApplicationId = string.Empty,
            BaseProfileId = profile.ProfileId,
            BaseProfileRevision = profile.ProfileRevision,
            BaseCatalogRevision = match.CatalogRevision,
            RecordOrigin = ApplicationProfileOrigin.BuiltInCatalog,
            ReviewState = profile.ReviewState,
            DisplayName = profile.DisplayName,
            ExecutableNamePattern = profile.Filename.Pattern,
            IsRegexPattern = profile.Filename.Kind == ApplicationFilenameMatchKind.Regex,
            PackageFamilyName = FirstOrEmpty(profile.Discriminators.PackageFamilyNames),
            PathPattern = FirstOrEmpty(profile.Discriminators.PathPatterns),
            CompanyVendor = FirstOrEmpty(profile.Discriminators.Companies),
            ProductName = FirstOrEmpty(profile.Discriminators.Products),
            Description = profile.RoleSummary,
            ApplicationCategory = profile.Category.ToString(),
            ExpectedResponsibilities = FormatList(profile.ExpectedResponsibilities),
            NormalBehavior = FormatList(profile.NormalBehavior),
            LaunchTriggers = FormatList(profile.LaunchTriggers),
            ExpectedContext = FormatExpectedContext(profile.ExpectedContext),
            CommandLineExpectations = FormatList(profile.ObservableExpectations.CommandLine),
            FilesystemRegistryExpectations = FormatFilesystemRegistry(profile.ObservableExpectations),
            ChildProcessExpectations = FormatList(profile.ObservableExpectations.ChildProcesses),
            NetworkExpectations = FormatList(profile.ObservableExpectations.Network),
            NormalVariants = FormatList(profile.NormalVariants),
            KnownBenignNotes = isEvaluationCandidate
                ? EvaluationCandidateWarning
                : "Catalog expectations describe consistency with a role; they are not a benign verdict.",
            CybersecurityNotes = FormatList(profile.AbuseAndMasqueradingNotes),
            AnalystValidationChecks = FormatList(profile.AnalystValidationChecks),
            Source = isEvaluationCandidate
                ? "Bundled AI draft evaluation candidate"
                : "Built-in application catalog",
            Confidence = profile.Confidence,
            IsAiGenerated = isEvaluationCandidate,
            SourceReferences = profile.Sources.Select(CloneSource).ToList(),
            CatalogProvenance = profile.Provenance,
            ProfileLastReviewedUtc = profile.LastReviewedUtc,
            ReviewedUtc = profile.LastReviewedUtc,
            MatchReason = match.SelectionReason
        };
    }

    public static string SerializeSources(IReadOnlyList<ApplicationProfileSourceReference> sources)
        => JsonSerializer.Serialize(sources ?? [], ApplicationCatalogBuilder.JsonOptions);

    public static List<ApplicationProfileSourceReference> DeserializeSources(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<ApplicationProfileSourceReference>>(
                       json,
                       ApplicationCatalogBuilder.JsonOptions) ?? [];
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Application metadata source references are malformed: {ex.Message}", ex);
        }
    }

    private static ApplicationProfileSourceReference CloneSource(ApplicationProfileSourceReference source)
        => new()
        {
            Title = source.Title,
            Publisher = source.Publisher,
            Uri = source.Uri,
            RetrievedUtc = source.RetrievedUtc,
            SupportingNote = source.SupportingNote
        };

    private static string Clean(string value)
        => string.IsNullOrWhiteSpace(value) || value.StartsWith("<", StringComparison.Ordinal)
            ? string.Empty
            : value.Trim();

    private static string FirstOrEmpty(IReadOnlyList<string> values)
        => values.Count == 0 ? string.Empty : values[0];

    private static string FormatList(IReadOnlyList<string> values)
        => string.Join(Environment.NewLine, values.Select(value => $"- {value}"));

    private static string FormatExpectedContext(ApplicationExpectedContext expected)
    {
        var sections = new List<string>();
        AddSection(sections, "Parents", expected.ParentExecutables);
        AddSection(sections, "Accounts", expected.Accounts);
        AddSection(sections, "Sessions", expected.Sessions);
        AddSection(sections, "Privilege", expected.PrivilegeLevels);
        AddSection(sections, "Lifetime", expected.Lifetimes);
        return string.Join(Environment.NewLine, sections);
    }

    private static string FormatFilesystemRegistry(ApplicationObservableExpectations expected)
    {
        var sections = new List<string>();
        AddSection(sections, "Filesystem", expected.Filesystem);
        AddSection(sections, "Registry", expected.Registry);
        return string.Join(Environment.NewLine, sections);
    }

    private static void AddSection(List<string> output, string label, IReadOnlyList<string> values)
    {
        if (values.Count > 0)
        {
            output.Add($"{label}: {string.Join("; ", values)}");
        }
    }

    private static string BuildSelectionReason(
        ApplicationMetadataRecord? record,
        ApplicationProfileDefinition? catalogProfile,
        ApplicationCatalogMatch? selectedCandidate)
    {
        if (record == null)
        {
            return "No session override or normalized-filename catalog candidate matched.";
        }

        if (record.RecordOrigin == ApplicationProfileOrigin.BuiltInCatalog && selectedCandidate != null)
        {
            return selectedCandidate.SelectionReason;
        }

        if (catalogProfile != null)
        {
            var candidateContext = selectedCandidate == null
                ? "the current normalized filename did not independently select that catalog candidate"
                : selectedCandidate.SelectionReason;
            return $"{record.RecordOrigin} retains base profile {catalogProfile.ProfileId} revision {catalogProfile.ProfileRevision}; {candidateContext}";
        }

        return string.IsNullOrWhiteSpace(record.MatchReason)
            ? $"{record.RecordOrigin} has no linked built-in base profile."
            : record.MatchReason;
    }
}

public sealed class ApplicationInfoResolutionResult
{
    public ApplicationMetadataRecord? Record { get; init; }

    public ApplicationProfileDefinition? CatalogProfile { get; init; }

    public IReadOnlyList<ApplicationCatalogMatch> Candidates { get; init; } = [];

    public string SelectionReason { get; init; } = string.Empty;
}

public sealed class ApplicationInfoEvaluationResolutionResult
{
    public ApplicationMetadataRecord? Record { get; init; }

    public ApplicationProfileDefinition? CatalogProfile { get; init; }

    public IReadOnlyList<ApplicationCatalogMatch> Candidates { get; init; } = [];

    public bool IsAmbiguous { get; init; }

    public string SelectionReason { get; init; } = string.Empty;
}
