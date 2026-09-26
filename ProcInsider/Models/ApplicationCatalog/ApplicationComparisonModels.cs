using System.Text;

namespace ProcInsider.Models.ApplicationCatalog;

public enum ApplicationComparisonPropertyKind
{
    ExecutableFilename = 0,
    ProcessPath = 1,
    OriginalFilename = 2,
    Company = 3,
    Product = 4,
    FileDescription = 5,
    ParentProcess = 6,
    Account = 7,
    Session = 8,
    Privilege = 9,
    CommandLine = 10,
    SignerPublisher = 11
}

public enum ApplicationComparisonOperator
{
    NormalizedFilename = 0,
    PathPatternAny = 1,
    ExactValueAny = 2,
    AccountContext = 3,
    SessionContext = 4,
    CommandLineMarkers = 5,
    EvidenceAvailability = 6
}

public enum ApplicationComparisonImportance
{
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Informational = 4
}

public enum ApplicationComparisonResult
{
    Match = 0,
    Mismatch = 1,
    Unknown = 2,
    NotApplicable = 3
}

public sealed class ApplicationObservedValue
{
    public string Value { get; init; } = string.Empty;

    public string Source { get; init; } = string.Empty;

    public string Availability { get; init; } = string.Empty;

    public bool IsAvailable => !string.IsNullOrWhiteSpace(Value);

    public static ApplicationObservedValue Available(string value, string source) => new()
    {
        Value = value,
        Source = source,
        Availability = "Available"
    };

    public static ApplicationObservedValue Unavailable(string source, string availability) => new()
    {
        Source = source,
        Availability = availability
    };
}

public sealed class ApplicationComparisonActualContext
{
    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public ApplicationObservedValue ExecutableFilename { get; init; } = new();

    public ApplicationObservedValue ProcessPath { get; init; } = new();

    public ApplicationObservedValue OriginalFilename { get; init; } = new();

    public ApplicationObservedValue Company { get; init; } = new();

    public ApplicationObservedValue Product { get; init; } = new();

    public ApplicationObservedValue FileDescription { get; init; } = new();

    public ApplicationObservedValue ParentProcess { get; init; } = new();

    public ApplicationObservedValue Account { get; init; } = new();

    public ApplicationObservedValue Session { get; init; } = new();

    public ApplicationObservedValue Privilege { get; init; } = new();

    public ApplicationObservedValue CommandLine { get; init; } = new();

    public ApplicationObservedValue SignerPublisher { get; init; } = new();

    public AuthenticodeSignatureKind SignatureKind { get; init; } = AuthenticodeSignatureKind.Unknown;

    public AuthenticodeVerificationStatus SignatureVerificationStatus { get; init; } = AuthenticodeVerificationStatus.Unknown;

    public string PeAvailability { get; init; } = string.Empty;

    public long? ProcessImageFileSizeBytes { get; init; }

    public ApplicationProfileLookupContext CreateLookupContext() => new()
    {
        ExecutableFilename = ExecutableFilename.Value,
        ProcessPath = ProcessPath.Value,
        OriginalFilename = OriginalFilename.Value,
        Company = Company.Value,
        Product = Product.Value
    };
}

public sealed class ApplicationComparisonRow
{
    public ApplicationComparisonPropertyKind PropertyKind { get; init; }

    public ApplicationComparisonOperator Operator { get; init; }

    public ApplicationComparisonImportance Importance { get; init; }

    public ApplicationComparisonResult Result { get; init; }

    public string ExpectedValue { get; init; } = string.Empty;

    public string ActualValue { get; init; } = string.Empty;

    public string Rationale { get; init; } = string.Empty;

    public string EvidenceSource { get; init; } = string.Empty;

    public string SourceAvailability { get; init; } = string.Empty;
}

public sealed class ApplicationComparisonReport
{
    public string SelectedProfileDisplay { get; init; } = string.Empty;

    public string SelectionReason { get; init; } = string.Empty;

    public string CandidateSummary { get; init; } = string.Empty;

    public bool HasAmbiguousCandidates { get; init; }

    public IReadOnlyList<ApplicationComparisonRow> Rows { get; init; } = [];

    public ApplicationComparisonEvidenceSource BuildEvidenceSource(
        int maxRows = 32,
        int maxCharacters = 12000)
    {
        var rowLimit = Math.Clamp(maxRows, 1, 128);
        var characterLimit = Math.Clamp(maxCharacters, 512, 65536);
        var builder = new StringBuilder();
        AppendBounded(builder, $"Selected profile: {SelectedProfileDisplay}", characterLimit);
        AppendBounded(builder, $"Selection reason: {SelectionReason}", characterLimit);
        if (!string.IsNullOrWhiteSpace(CandidateSummary))
        {
            AppendBounded(builder, $"Candidates: {Collapse(CandidateSummary)}", characterLimit);
        }

        var included = 0;
        foreach (var row in Rows.Take(rowLimit))
        {
            var line =
                $"{row.PropertyKind}: {row.Result}; importance={row.Importance}; expected={Collapse(row.ExpectedValue)}; actual={Collapse(row.ActualValue)}; rationale={Collapse(row.Rationale)}; source={Collapse(row.EvidenceSource)}; availability={Collapse(row.SourceAvailability)}";
            if (!AppendBounded(builder, line, characterLimit))
            {
                break;
            }

            included++;
        }

        return new ApplicationComparisonEvidenceSource
        {
            Text = builder.ToString().TrimEnd(),
            RowsAvailable = Rows.Count,
            RowsIncluded = included,
            IsTruncated = included < Rows.Count
        };
    }

    private static bool AppendBounded(StringBuilder builder, string value, int maxCharacters)
    {
        var remaining = maxCharacters - builder.Length;
        if (remaining <= 1)
        {
            return false;
        }

        var suffix = Environment.NewLine;
        if (value.Length + suffix.Length <= remaining)
        {
            builder.Append(value).Append(suffix);
            return true;
        }

        var take = Math.Max(0, remaining - suffix.Length - 1);
        if (take > 0)
        {
            builder.Append(value.AsSpan(0, Math.Min(take, value.Length))).Append('…').Append(suffix);
        }

        return false;
    }

    private static string Collapse(string value)
        => string.IsNullOrWhiteSpace(value)
            ? "<not available>"
            : string.Join(" ", value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
}

public sealed class ApplicationComparisonEvidenceSource
{
    public string Text { get; init; } = string.Empty;

    public int RowsAvailable { get; init; }

    public int RowsIncluded { get; init; }

    public bool IsTruncated { get; init; }
}
