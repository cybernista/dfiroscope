using System.Collections.ObjectModel;

namespace ProcInsider.Models.Analysis;

public enum YaraScanTargetKind
{
    Unknown = 0,
    FileArtifact = 1,
    MemoryDump = 2,
    MemoryImageRegion = 3
}

public enum YaraExcerptEncoding
{
    None = 0,
    Hex = 1,
    Base64 = 2
}

public enum YaraAnalysisFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    UnknownAvailability = 2,
    UnknownTargetKind = 3,
    InvalidIdentity = 4,
    InvalidScope = 5,
    InvalidSourceRun = 6,
    InvalidTargetReference = 7,
    InvalidTargetHash = 8,
    InvalidTargetRange = 9,
    InvalidScannerIdentity = 10,
    InvalidRulesetIdentity = 11,
    InvalidTimestamp = 12,
    InvalidDiagnostic = 13,
    ContradictoryAvailability = 14,
    MatchLimitExceeded = 15,
    InvalidMatch = 16,
    DuplicateMatch = 17,
    TagLimitExceeded = 18,
    InvalidTag = 19,
    MetadataLimitExceeded = 20,
    InvalidMetadata = 21,
    StringMatchLimitExceeded = 22,
    InvalidStringMatch = 23,
    DuplicateStringMatch = 24,
    UnknownExcerptEncoding = 25,
    InvalidExcerpt = 26
}

public sealed record YaraScanTarget
{
    public YaraScanTargetKind Kind { get; init; }

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string SourceRunId { get; init; } = string.Empty;

    public EvidenceReference EvidenceReference { get; init; } =
        new(EvidenceReferenceKind.GenericArtifact, string.Empty);

    public string ContentHashSha256 { get; init; } = string.Empty;

    public long OffsetBytes { get; init; }

    public long LengthBytes { get; init; }
}

public sealed record YaraRulesetIdentity
{
    public string ScannerId { get; init; } = string.Empty;

    public string ScannerVersion { get; init; } = string.Empty;

    public string RulesetId { get; init; } = string.Empty;

    public string RulesetVersion { get; init; } = string.Empty;

    public string RulesetHashSha256 { get; init; } = string.Empty;
}

public sealed record YaraMatchMetadata(string Key, string Value);

public sealed record YaraStringMatch
{
    public string Identifier { get; init; } = string.Empty;

    public long OffsetBytes { get; init; }

    public int LengthBytes { get; init; }

    public YaraExcerptEncoding ExcerptEncoding { get; init; }

    public string Excerpt { get; init; } = string.Empty;
}

public sealed record YaraRuleMatch
{
    public string MatchId { get; init; } = string.Empty;

    public string RuleNamespace { get; init; } = string.Empty;

    public string RuleId { get; init; } = string.Empty;

    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();

    public IReadOnlyList<YaraMatchMetadata> Metadata { get; init; } =
        Array.Empty<YaraMatchMetadata>();

    public IReadOnlyList<YaraStringMatch> StringMatches { get; init; } =
        Array.Empty<YaraStringMatch>();
}

/// <summary>
/// Package-free normalized output from one future bounded YARA scan. This contract
/// grants no authority to read a target, execute a scanner, persist results, or
/// translate a match into a risk score.
/// </summary>
public sealed record YaraScanResult
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string ScanId { get; init; } = string.Empty;

    public AnalysisSourceAvailability Availability { get; init; }

    public YaraScanTarget Target { get; init; } = new();

    public YaraRulesetIdentity Ruleset { get; init; } = new();

    public DateTime RequestedUtc { get; init; }

    public DateTime CompletedUtc { get; init; }

    public bool IsTruncated { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public IReadOnlyList<YaraRuleMatch> Matches { get; init; } = Array.Empty<YaraRuleMatch>();
}

public sealed record YaraScanValidationDecision
{
    public bool Accepted { get; init; }

    public YaraAnalysisFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public YaraScanResult? Result { get; init; }
}

/// <summary>
/// Pure fail-closed validation for normalized YARA results. Accepted collections
/// are copied into canonical order so later caller mutation cannot change output.
/// </summary>
public static class YaraAnalysisContractPolicy
{
    public const int MaximumMatches = 256;
    public const int MaximumTagsPerMatch = 32;
    public const int MaximumMetadataPerMatch = 32;
    public const int MaximumStringMatchesPerMatch = 256;
    public const int MaximumExcerptBytes = 256;
    public const long MaximumTargetBytes = 256L * 1024 * 1024;

    private const int MaximumIdentityLength = 512;
    private const int MaximumVersionLength = 256;
    private const int MaximumTagLength = 128;
    private const int MaximumMetadataKeyLength = 128;
    private const int MaximumMetadataValueLength = 1024;
    private const int MaximumDiagnosticLength = 8192;

    public static YaraScanValidationDecision Validate(YaraScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (result.SchemaVersion != YaraScanResult.CurrentSchemaVersion)
        {
            return Reject(YaraAnalysisFailure.InvalidSchemaVersion,
                "The YARA result schema version is unsupported.");
        }

        if (!IsKnownAvailability(result.Availability))
        {
            return Reject(YaraAnalysisFailure.UnknownAvailability,
                "The YARA result availability is unknown or unsupported.");
        }

        if (!IsRequiredIdentity(result.ScanId))
        {
            return Reject(YaraAnalysisFailure.InvalidIdentity,
                "The YARA scan identity is missing or exceeds the contract bound.");
        }

        var targetFailure = ValidateTarget(result.Target);
        if (targetFailure != YaraAnalysisFailure.None)
        {
            return Reject(targetFailure, Diagnostic(targetFailure));
        }

        var rulesetFailure = ValidateRuleset(result.Ruleset);
        if (rulesetFailure != YaraAnalysisFailure.None)
        {
            return Reject(rulesetFailure, Diagnostic(rulesetFailure));
        }

        if (!IsUtc(result.RequestedUtc) || !IsUtc(result.CompletedUtc) ||
            result.CompletedUtc < result.RequestedUtc)
        {
            return Reject(YaraAnalysisFailure.InvalidTimestamp,
                "YARA lifecycle timestamps must be coherent UTC values.");
        }

        if (!IsBoundedOptional(result.Diagnostic, MaximumDiagnosticLength))
        {
            return Reject(YaraAnalysisFailure.InvalidDiagnostic,
                "The YARA diagnostic exceeds the contract bound.");
        }

        if (result.Availability == AnalysisSourceAvailability.Available && result.IsTruncated &&
            string.IsNullOrWhiteSpace(result.Diagnostic))
        {
            return Reject(YaraAnalysisFailure.InvalidDiagnostic,
                "A truncated YARA result requires a bounded diagnostic.");
        }

        var matches = result.Matches;
        if (matches == null)
        {
            return Reject(YaraAnalysisFailure.InvalidMatch,
                "The YARA match collection is required.");
        }

        if (matches.Count > MaximumMatches)
        {
            return Reject(YaraAnalysisFailure.MatchLimitExceeded,
                "The YARA result exceeds the bounded match limit.");
        }

        if (result.Availability != AnalysisSourceAvailability.Available)
        {
            if (matches.Count != 0 || result.IsTruncated)
            {
                return Reject(YaraAnalysisFailure.ContradictoryAvailability,
                    "A non-available YARA result cannot contain matches or truncation state.");
            }

            if (string.IsNullOrWhiteSpace(result.Diagnostic))
            {
                return Reject(YaraAnalysisFailure.InvalidDiagnostic,
                    "A non-available YARA result requires a bounded diagnostic.");
            }
        }

        var canonicalMatches = new List<YaraRuleMatch>(matches.Count);
        var matchIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var match in matches)
        {
            var matchFailure = ValidateMatch(match, result.Target, out var accepted);
            if (matchFailure != YaraAnalysisFailure.None)
            {
                return Reject(matchFailure, Diagnostic(matchFailure));
            }

            if (!matchIds.Add(accepted!.MatchId))
            {
                return Reject(YaraAnalysisFailure.DuplicateMatch,
                    "The YARA result contains a duplicate match identity.");
            }

            canonicalMatches.Add(accepted);
        }

        var acceptedResult = result with
        {
            Target = result.Target with
            {
                EvidenceIdentity = result.Target.EvidenceIdentity with { },
                EvidenceReference = result.Target.EvidenceReference with { }
            },
            Ruleset = result.Ruleset with { },
            Matches = new ReadOnlyCollection<YaraRuleMatch>(canonicalMatches
                .OrderBy(item => item.RuleNamespace, StringComparer.Ordinal)
                .ThenBy(item => item.RuleId, StringComparer.Ordinal)
                .ThenBy(item => item.MatchId, StringComparer.Ordinal)
                .ToArray())
        };

        return new YaraScanValidationDecision
        {
            Accepted = true,
            Failure = YaraAnalysisFailure.None,
            Result = acceptedResult
        };
    }

    private static YaraAnalysisFailure ValidateTarget(YaraScanTarget? target)
    {
        if (target == null || !Enum.IsDefined(target.Kind) || target.Kind == YaraScanTargetKind.Unknown)
        {
            return YaraAnalysisFailure.UnknownTargetKind;
        }

        if (!IsValidScope(target.EvidenceIdentity))
        {
            return YaraAnalysisFailure.InvalidScope;
        }

        if (!IsRequiredIdentity(target.SourceRunId))
        {
            return YaraAnalysisFailure.InvalidSourceRun;
        }

        var expectedKind = target.Kind switch
        {
            YaraScanTargetKind.FileArtifact => EvidenceReferenceKind.FileArtifact,
            YaraScanTargetKind.MemoryDump => EvidenceReferenceKind.MemoryDump,
            YaraScanTargetKind.MemoryImageRegion => EvidenceReferenceKind.MemoryImage,
            _ => EvidenceReferenceKind.GenericArtifact
        };
        if (target.EvidenceReference == null || target.EvidenceReference.IsEmpty ||
            target.EvidenceReference.Kind != expectedKind ||
            !IsRequiredIdentity(target.EvidenceReference.Id))
        {
            return YaraAnalysisFailure.InvalidTargetReference;
        }

        if (!IsSha256(target.ContentHashSha256))
        {
            return YaraAnalysisFailure.InvalidTargetHash;
        }

        if (target.OffsetBytes < 0 || target.LengthBytes <= 0 ||
            target.LengthBytes > MaximumTargetBytes ||
            target.OffsetBytes > long.MaxValue - target.LengthBytes ||
            target.Kind != YaraScanTargetKind.MemoryImageRegion && target.OffsetBytes != 0)
        {
            return YaraAnalysisFailure.InvalidTargetRange;
        }

        return YaraAnalysisFailure.None;
    }

    private static YaraAnalysisFailure ValidateRuleset(YaraRulesetIdentity? ruleset)
    {
        if (ruleset == null || !IsRequiredIdentity(ruleset.ScannerId) ||
            !IsBoundedRequired(ruleset.ScannerVersion, MaximumVersionLength))
        {
            return YaraAnalysisFailure.InvalidScannerIdentity;
        }

        if (!IsRequiredIdentity(ruleset.RulesetId) ||
            !IsBoundedRequired(ruleset.RulesetVersion, MaximumVersionLength) ||
            !IsSha256(ruleset.RulesetHashSha256))
        {
            return YaraAnalysisFailure.InvalidRulesetIdentity;
        }

        return YaraAnalysisFailure.None;
    }

    private static YaraAnalysisFailure ValidateMatch(
        YaraRuleMatch? match,
        YaraScanTarget target,
        out YaraRuleMatch? accepted)
    {
        accepted = null;
        if (match == null || !IsRequiredIdentity(match.MatchId) ||
            !IsRequiredIdentity(match.RuleNamespace) || !IsRequiredIdentity(match.RuleId))
        {
            return YaraAnalysisFailure.InvalidMatch;
        }

        var tags = match.Tags;
        if (tags == null)
        {
            return YaraAnalysisFailure.InvalidTag;
        }

        if (tags.Count > MaximumTagsPerMatch)
        {
            return YaraAnalysisFailure.TagLimitExceeded;
        }

        if (tags.Any(tag => !IsBoundedRequired(tag, MaximumTagLength)))
        {
            return YaraAnalysisFailure.InvalidTag;
        }

        if (tags.Distinct(StringComparer.Ordinal).Count() != tags.Count)
        {
            return YaraAnalysisFailure.InvalidTag;
        }

        var metadata = match.Metadata;
        if (metadata == null)
        {
            return YaraAnalysisFailure.InvalidMetadata;
        }

        if (metadata.Count > MaximumMetadataPerMatch)
        {
            return YaraAnalysisFailure.MetadataLimitExceeded;
        }

        if (metadata.Any(item => item == null ||
                !IsBoundedRequired(item.Key, MaximumMetadataKeyLength) ||
                !IsBoundedOptional(item.Value, MaximumMetadataValueLength)) ||
            metadata.Select(item => item.Key).Distinct(StringComparer.Ordinal).Count() != metadata.Count)
        {
            return YaraAnalysisFailure.InvalidMetadata;
        }

        var stringMatches = match.StringMatches;
        if (stringMatches == null)
        {
            return YaraAnalysisFailure.InvalidStringMatch;
        }

        if (stringMatches.Count > MaximumStringMatchesPerMatch)
        {
            return YaraAnalysisFailure.StringMatchLimitExceeded;
        }

        var acceptedStrings = new List<YaraStringMatch>(stringMatches.Count);
        var stringKeys = new HashSet<(string Identifier, long OffsetBytes, int LengthBytes)>();
        foreach (var stringMatch in stringMatches)
        {
            var stringFailure = ValidateStringMatch(stringMatch, target);
            if (stringFailure != YaraAnalysisFailure.None)
            {
                return stringFailure;
            }

            var key = (stringMatch!.Identifier, stringMatch.OffsetBytes, stringMatch.LengthBytes);
            if (!stringKeys.Add(key))
            {
                return YaraAnalysisFailure.DuplicateStringMatch;
            }

            acceptedStrings.Add(stringMatch with { });
        }

        accepted = match with
        {
            Tags = new ReadOnlyCollection<string>(tags.Order(StringComparer.Ordinal).ToArray()),
            Metadata = new ReadOnlyCollection<YaraMatchMetadata>(metadata
                .OrderBy(item => item.Key, StringComparer.Ordinal)
                .Select(item => item with { })
                .ToArray()),
            StringMatches = new ReadOnlyCollection<YaraStringMatch>(acceptedStrings
                .OrderBy(item => item.OffsetBytes)
                .ThenBy(item => item.Identifier, StringComparer.Ordinal)
                .ThenBy(item => item.LengthBytes)
                .ToArray())
        };
        return YaraAnalysisFailure.None;
    }

    private static YaraAnalysisFailure ValidateStringMatch(
        YaraStringMatch? match,
        YaraScanTarget target)
    {
        if (match == null || !IsRequiredIdentity(match.Identifier) || match.OffsetBytes < 0 ||
            match.LengthBytes <= 0 || match.OffsetBytes > long.MaxValue - match.LengthBytes ||
            match.OffsetBytes + match.LengthBytes > target.LengthBytes)
        {
            return YaraAnalysisFailure.InvalidStringMatch;
        }

        if (!Enum.IsDefined(match.ExcerptEncoding))
        {
            return YaraAnalysisFailure.UnknownExcerptEncoding;
        }

        if (match.ExcerptEncoding == YaraExcerptEncoding.None)
        {
            return string.IsNullOrEmpty(match.Excerpt)
                ? YaraAnalysisFailure.None
                : YaraAnalysisFailure.InvalidExcerpt;
        }

        if (string.IsNullOrWhiteSpace(match.Excerpt))
        {
            return YaraAnalysisFailure.InvalidExcerpt;
        }

        try
        {
            byte[] decoded;
            if (match.ExcerptEncoding == YaraExcerptEncoding.Hex)
            {
                if (match.Excerpt.Length > MaximumExcerptBytes * 2 ||
                    match.Excerpt.Length % 2 != 0 ||
                    match.Excerpt.Any(character => !Uri.IsHexDigit(character)))
                {
                    return YaraAnalysisFailure.InvalidExcerpt;
                }

                decoded = Convert.FromHexString(match.Excerpt);
            }
            else if (match.ExcerptEncoding == YaraExcerptEncoding.Base64)
            {
                var maximumBase64Length = ((MaximumExcerptBytes + 2) / 3) * 4;
                if (match.Excerpt.Length > maximumBase64Length)
                {
                    return YaraAnalysisFailure.InvalidExcerpt;
                }

                decoded = Convert.FromBase64String(match.Excerpt);
            }
            else
            {
                return YaraAnalysisFailure.UnknownExcerptEncoding;
            }

            return decoded.Length <= MaximumExcerptBytes && decoded.Length <= match.LengthBytes
                ? YaraAnalysisFailure.None
                : YaraAnalysisFailure.InvalidExcerpt;
        }
        catch (FormatException)
        {
            return YaraAnalysisFailure.InvalidExcerpt;
        }
    }

    private static bool IsKnownAvailability(AnalysisSourceAvailability availability) =>
        availability is AnalysisSourceAvailability.Available or
            AnalysisSourceAvailability.NotCollected or
            AnalysisSourceAvailability.Unavailable or
            AnalysisSourceAvailability.Failed or
            AnalysisSourceAvailability.Stale;

    private static bool IsValidScope(EvidenceIdentity? identity) =>
        identity != null && IsBoundedOptional(identity.CaseId, MaximumIdentityLength) &&
        IsRequiredIdentity(identity.EvidenceSessionId) &&
        IsBoundedOptional(identity.CaptureId, MaximumIdentityLength) &&
        IsRequiredIdentity(identity.SourceIdentityId) && IsRequiredIdentity(identity.HostId) &&
        IsRequiredIdentity(identity.ExecutionRootId);

    private static bool IsRequiredIdentity(string? value) =>
        IsBoundedRequired(value, MaximumIdentityLength);

    private static bool IsBoundedRequired(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;

    private static bool IsBoundedOptional(string? value, int maximumLength) =>
        value != null && value.Length <= maximumLength;

    private static bool IsSha256(string? value) => value is { Length: 64 } &&
        value.All(character => Uri.IsHexDigit(character));

    private static bool IsUtc(DateTime value) => value.Kind == DateTimeKind.Utc;

    private static YaraScanValidationDecision Reject(
        YaraAnalysisFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = diagnostic
        };

    private static string Diagnostic(YaraAnalysisFailure failure) => failure switch
    {
        YaraAnalysisFailure.UnknownTargetKind => "The YARA target kind is unknown or unsupported.",
        YaraAnalysisFailure.InvalidScope => "The YARA target evidence scope is incomplete or invalid.",
        YaraAnalysisFailure.InvalidSourceRun => "The YARA target source-run identity is invalid.",
        YaraAnalysisFailure.InvalidTargetReference => "The YARA target reference does not match its target kind.",
        YaraAnalysisFailure.InvalidTargetHash => "The YARA target requires an exact SHA-256 content hash.",
        YaraAnalysisFailure.InvalidTargetRange => "The YARA target byte range is invalid or exceeds the bound.",
        YaraAnalysisFailure.InvalidScannerIdentity => "The YARA scanner identity is incomplete or invalid.",
        YaraAnalysisFailure.InvalidRulesetIdentity => "The YARA ruleset identity is incomplete or invalid.",
        YaraAnalysisFailure.InvalidMatch => "A YARA rule match is incomplete or invalid.",
        YaraAnalysisFailure.TagLimitExceeded => "A YARA rule match exceeds the bounded tag limit.",
        YaraAnalysisFailure.InvalidTag => "A YARA rule match contains an invalid or duplicate tag.",
        YaraAnalysisFailure.MetadataLimitExceeded => "A YARA rule match exceeds the bounded metadata limit.",
        YaraAnalysisFailure.InvalidMetadata => "A YARA rule match contains invalid or duplicate metadata.",
        YaraAnalysisFailure.StringMatchLimitExceeded => "A YARA rule exceeds the bounded string-match limit.",
        YaraAnalysisFailure.InvalidStringMatch => "A YARA string match has an invalid identity or target-relative range.",
        YaraAnalysisFailure.DuplicateStringMatch => "A YARA rule contains a duplicate string match.",
        YaraAnalysisFailure.UnknownExcerptEncoding => "A YARA excerpt encoding is unknown or unsupported.",
        YaraAnalysisFailure.InvalidExcerpt => "A YARA excerpt is malformed, plaintext, or exceeds the decoded bound.",
        _ => "The YARA result violates the portable contract."
    };
}
