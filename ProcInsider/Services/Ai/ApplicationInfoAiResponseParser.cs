using System.Text.Json;
using ProcInsider.Models.Ai;
using ProcInsider.Models.ApplicationCatalog;

namespace ProcInsider.Services.Ai;

public static class ApplicationInfoAiResponseParser
{
    public const int MaxResponseCharacters = 65536;
    private const int MaxTextCharacters = 2000;
    private const int MaxItemCharacters = 500;
    private const int MaxListItems = 24;
    private const int MaxSources = 16;
    private const string Missing = "Not supplied by the AI provider.";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        MaxDepth = 8
    };

    public static ApplicationInfoAiDraftParseResult ParseDraft(string response)
    {
        var text = StripCodeFence(response).Trim();
        if (string.IsNullOrWhiteSpace(text))
        {
            return Fail("The provider returned an empty draft.");
        }

        if (text.Length > MaxResponseCharacters)
        {
            return Fail($"The provider response exceeded the {MaxResponseCharacters:N0}-character structured-draft limit.");
        }

        ApplicationInfoAiDraftDocument document;
        var warnings = new List<string>();
        var freeTextFallback = false;
        try
        {
            document = JsonSerializer.Deserialize<ApplicationInfoAiDraftDocument>(text, JsonOptions)
                       ?? new ApplicationInfoAiDraftDocument();
        }
        catch (JsonException)
        {
            if (text.StartsWith('{') || text.StartsWith('['))
            {
                return Fail("The provider returned malformed structured JSON. The saved profile and current edits were not changed.");
            }

            document = new ApplicationInfoAiDraftDocument
            {
                RoleSummary = Bound(text, MaxTextCharacters),
                Uncertainty = "The provider returned free text instead of the requested typed structure. Every other field is unavailable and this draft requires full analyst review.",
                Confidence = 0.1
            };
            freeTextFallback = true;
            warnings.Add("Free-text fallback: the provider did not return the requested typed JSON object.");
        }

        document.ExpectedResponsibilities ??= [];
        document.LaunchTriggers ??= [];
        document.TypicalContext ??= new ApplicationInfoAiTypicalContext();
        document.TypicalContext.Parents ??= [];
        document.TypicalContext.Accounts ??= [];
        document.TypicalContext.Sessions ??= [];
        document.TypicalContext.PrivilegeLevels ??= [];
        document.TypicalContext.Lifetimes ??= [];
        document.ExpectedBehavior ??= new ApplicationInfoAiExpectedBehavior();
        document.ExpectedBehavior.NormalBehavior ??= [];
        document.ExpectedBehavior.CommandLine ??= [];
        document.ExpectedBehavior.Filesystem ??= [];
        document.ExpectedBehavior.Registry ??= [];
        document.ExpectedBehavior.ChildProcesses ??= [];
        document.ExpectedBehavior.Network ??= [];
        document.NormalVariantsAndCaveats ??= [];
        document.CommonAbuseAndMasquerading ??= [];
        document.AnalystValidationChecks ??= [];
        document.ClaimedSources ??= [];

        var hasContent = !string.IsNullOrWhiteSpace(document.RoleSummary) ||
                         document.ExpectedResponsibilities.Count > 0 ||
                         document.ExpectedBehavior.NormalBehavior.Count > 0 ||
                         document.AnalystValidationChecks.Count > 0;
        if (!hasContent)
        {
            return Fail("The structured response did not contain any supported App Info content.");
        }

        var category = NormalizeCategory(document.ApplicationCategory, warnings);
        var sources = document.ClaimedSources
            .Where(source => source != null)
            .Take(MaxSources)
            .Select(source => new ApplicationInfoAiClaimedSource
            {
                Title = Bound(source.Title, MaxItemCharacters),
                Publisher = Bound(source.Publisher, MaxItemCharacters),
                Uri = NormalizeUri(source.Uri, warnings)
            })
            .Where(source => !string.IsNullOrWhiteSpace(source.Title) ||
                             !string.IsNullOrWhiteSpace(source.Publisher) ||
                             !string.IsNullOrWhiteSpace(source.Uri))
            .ToList();
        if (document.ClaimedSources.Count > MaxSources)
        {
            warnings.Add($"Claimed sources were bounded to {MaxSources} entries.");
        }

        warnings.Add(sources.Count == 0
            ? "No retrieved citations were supplied. Model memory is unverified reference material."
            : "Claimed sources were not retrieved or verified by DFIRoscope and remain unverified.");
        var requestedConfidence = Math.Clamp(document.Confidence ?? 0.2, 0, 1);
        var confidence = Math.Min(requestedConfidence, 0.3);
        if (requestedConfidence > confidence)
        {
            warnings.Add("Confidence was capped at 0.30 because no source was retrieved and verified by DFIRoscope.");
        }

        return new ApplicationInfoAiDraftParseResult
        {
            Success = true,
            Draft = new ApplicationInfoAiDraft
            {
                RoleSummary = OrMissing(document.RoleSummary),
                ApplicationCategory = category,
                ExpectedResponsibilities = FormatList(document.ExpectedResponsibilities),
                NormalBehavior = FormatList(document.ExpectedBehavior.NormalBehavior),
                LaunchTriggers = FormatList(document.LaunchTriggers),
                ExpectedContext = FormatSections(
                    ("Parents", document.TypicalContext.Parents),
                    ("Accounts", document.TypicalContext.Accounts),
                    ("Sessions", document.TypicalContext.Sessions),
                    ("Privilege", document.TypicalContext.PrivilegeLevels),
                    ("Lifetime", document.TypicalContext.Lifetimes)),
                CommandLineExpectations = FormatList(document.ExpectedBehavior.CommandLine),
                FilesystemRegistryExpectations = FormatSections(
                    ("Filesystem", document.ExpectedBehavior.Filesystem),
                    ("Registry", document.ExpectedBehavior.Registry)),
                ChildProcessExpectations = FormatList(document.ExpectedBehavior.ChildProcesses),
                NetworkExpectations = FormatList(document.ExpectedBehavior.Network),
                NormalVariants = FormatList(document.NormalVariantsAndCaveats),
                CommonAbuseAndMasquerading = FormatList(document.CommonAbuseAndMasquerading),
                AnalystValidationChecks = FormatList(document.AnalystValidationChecks),
                Uncertainty = OrMissing(document.Uncertainty),
                Confidence = confidence,
                ClaimedSources = sources,
                ValidationWarnings = warnings,
                IsFreeTextFallback = freeTextFallback
            }
        };
    }

    public static ApplicationSecurityAssessmentParseResult ParseAssessment(string response)
    {
        var text = StripCodeFence(response).Trim();
        if (string.IsNullOrWhiteSpace(text))
        {
            return AssessmentFail("The provider returned an empty security assessment.");
        }

        if (text.Length > MaxResponseCharacters)
        {
            return AssessmentFail($"The provider response exceeded the {MaxResponseCharacters:N0}-character assessment limit.");
        }

        ApplicationSecurityAssessmentDocument document;
        try
        {
            document = JsonSerializer.Deserialize<ApplicationSecurityAssessmentDocument>(text, JsonOptions)
                       ?? new ApplicationSecurityAssessmentDocument();
        }
        catch (JsonException)
        {
            return AssessmentFail("The provider did not return the required structured security-assessment JSON.");
        }

        document.Facts ??= [];
        document.Hypotheses ??= [];
        document.Uncertainty ??= [];
        document.BenignExplanations ??= [];
        document.RecommendedPivots ??= [];

        var warnings = new List<string>();
        var assessment = NormalizeAssessment(document.Assessment, warnings);
        var facts = BoundList(document.Facts);
        var hypotheses = BoundList(document.Hypotheses);
        var uncertainty = BoundList(document.Uncertainty);
        var benign = BoundList(document.BenignExplanations);
        var pivots = BoundList(document.RecommendedPivots);
        if (facts.Count + hypotheses.Count + uncertainty.Count + benign.Count + pivots.Count == 0)
        {
            return AssessmentFail("The structured assessment contained no facts, hypotheses, uncertainty, benign explanations, or pivots.");
        }

        return new ApplicationSecurityAssessmentParseResult
        {
            Success = true,
            Warnings = warnings,
            NormalizedText = string.Join(Environment.NewLine + Environment.NewLine, new[]
            {
                $"Assessment: {assessment}",
                FormatAssessmentSection("Facts from provided evidence", facts),
                FormatAssessmentSection("Hypotheses", hypotheses),
                FormatAssessmentSection("Uncertainty and evidence gaps", uncertainty),
                FormatAssessmentSection("Possible benign explanations", benign),
                FormatAssessmentSection("Recommended pivots", pivots),
                warnings.Count == 0 ? string.Empty : FormatAssessmentSection("Validation warnings", warnings)
            }.Where(section => !string.IsNullOrWhiteSpace(section)))
        };
    }

    private static string NormalizeCategory(string value, List<string> warnings)
    {
        var normalized = Bound(value, 80);
        if (Enum.TryParse<ApplicationCategory>(normalized, ignoreCase: true, out var category))
        {
            return category.ToString();
        }

        if (!string.IsNullOrWhiteSpace(normalized))
        {
            warnings.Add($"Unsupported application category '{normalized}' was normalized to Unknown.");
        }

        return ApplicationCategory.Unknown.ToString();
    }

    private static string NormalizeAssessment(string value, List<string> warnings)
    {
        var normalized = Bound(value, 100);
        var allowed = new[]
        {
            "Consistent with expected profile",
            "Deviations require review",
            "Suspicious based on provided evidence",
            "Inconclusive"
        };
        var match = allowed.FirstOrDefault(item => string.Equals(item, normalized, StringComparison.OrdinalIgnoreCase));
        if (match != null)
        {
            return match;
        }

        warnings.Add("Unsupported or missing assessment state was normalized to Inconclusive.");
        return "Inconclusive";
    }

    private static string NormalizeUri(string value, List<string> warnings)
    {
        var bounded = Bound(value, 1000);
        if (string.IsNullOrWhiteSpace(bounded))
        {
            return string.Empty;
        }

        if (Uri.TryCreate(bounded, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            return uri.AbsoluteUri;
        }

        warnings.Add("A claimed source URI was omitted because it was not an absolute HTTP(S) URI.");
        return string.Empty;
    }

    private static string FormatSections(params (string Label, List<string> Values)[] sections)
    {
        var output = sections
            .Select(section => (section.Label, Values: BoundList(section.Values)))
            .Where(section => section.Values.Count > 0)
            .Select(section => $"{section.Label}: {string.Join("; ", section.Values)}")
            .ToList();
        return output.Count == 0 ? Missing : string.Join(Environment.NewLine, output);
    }

    private static string FormatList(List<string> values)
    {
        var bounded = BoundList(values);
        return bounded.Count == 0
            ? Missing
            : string.Join(Environment.NewLine, bounded.Select(value => $"- {value}"));
    }

    private static List<string> BoundList(IEnumerable<string>? values) => (values ?? [])
        .Select(value => Bound(value, MaxItemCharacters))
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .Distinct(StringComparer.Ordinal)
        .Take(MaxListItems)
        .ToList();

    private static string FormatAssessmentSection(string title, IReadOnlyList<string> values)
        => values.Count == 0
            ? $"{title}:{Environment.NewLine}- None stated in the bounded response."
            : $"{title}:{Environment.NewLine}{string.Join(Environment.NewLine, values.Select(value => $"- {value}"))}";

    private static string OrMissing(string value)
    {
        var bounded = Bound(value, MaxTextCharacters);
        return string.IsNullOrWhiteSpace(bounded) ? Missing : bounded;
    }

    private static string Bound(string? value, int maximum)
    {
        var collapsed = value?.Trim() ?? string.Empty;
        return collapsed.Length <= maximum ? collapsed : collapsed[..maximum] + "…";
    }

    private static string StripCodeFence(string value)
    {
        var text = value?.Trim() ?? string.Empty;
        if (!text.StartsWith("```", StringComparison.Ordinal))
        {
            return text;
        }

        var firstBreak = text.IndexOf('\n');
        var lastFence = text.LastIndexOf("```", StringComparison.Ordinal);
        return firstBreak >= 0 && lastFence > firstBreak
            ? text[(firstBreak + 1)..lastFence]
            : text;
    }

    private static ApplicationInfoAiDraftParseResult Fail(string error) => new()
    {
        Error = error
    };

    private static ApplicationSecurityAssessmentParseResult AssessmentFail(string error) => new()
    {
        Error = error
    };
}
