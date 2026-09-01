using System.Collections.ObjectModel;

namespace ProcInsider.Models.Analysis;

public enum YaraScannerDeploymentSource
{
    Unknown = 0,
    BundledRelease = 1,
    AdministratorProvisioned = 2
}

public enum YaraRulesetOrigin
{
    Unknown = 0,
    BundledRelease = 1,
    AnalystImport = 2
}

public enum YaraRulesetReviewState
{
    Unknown = 0,
    MaintainerReviewed = 1,
    AnalystApproved = 2
}

public enum YaraTrustAdmissionFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    UnknownScannerDeploymentSource = 2,
    UnknownRulesetOrigin = 3,
    UnknownRulesetReviewState = 4,
    InvalidIdentity = 5,
    InvalidHash = 6,
    InvalidAdapterProtocol = 7,
    UnknownTargetKind = 8,
    InvalidTargetSet = 9,
    DuplicateTargetKind = 10,
    InvalidProvenance = 11,
    DuplicateProvenance = 12,
    InvalidReview = 13,
    ContradictoryTrust = 14,
    UnsupportedTargetKind = 15,
    InvalidLimit = 16
}

public sealed record YaraScannerTrustDescriptor
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string ScannerId { get; init; } = string.Empty;

    public string ScannerVersion { get; init; } = string.Empty;

    public string ArtifactHashSha256 { get; init; } = string.Empty;

    public int AdapterProtocolVersion { get; init; }

    public YaraScannerDeploymentSource DeploymentSource { get; init; }

    public IReadOnlyList<YaraScanTargetKind> SupportedTargetKinds { get; init; } =
        Array.Empty<YaraScanTargetKind>();
}

public sealed record YaraRulesetProvenance
{
    public string ProvenanceId { get; init; } = string.Empty;

    public string SourceName { get; init; } = string.Empty;

    public string SourceVersion { get; init; } = string.Empty;

    public string SourceUri { get; init; } = string.Empty;

    public string SourceHashSha256 { get; init; } = string.Empty;

    public string LicenseId { get; init; } = string.Empty;

    public string Attribution { get; init; } = string.Empty;

    public DateTime RetrievedUtc { get; init; }
}

public sealed record YaraRulesetTrustDescriptor
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string RulesetId { get; init; } = string.Empty;

    public string RulesetVersion { get; init; } = string.Empty;

    public string RulesetHashSha256 { get; init; } = string.Empty;

    public string ManifestHashSha256 { get; init; } = string.Empty;

    public YaraRulesetOrigin Origin { get; init; }

    public YaraRulesetReviewState ReviewState { get; init; }

    public string ReviewerId { get; init; } = string.Empty;

    public string ReviewPolicyId { get; init; } = string.Empty;

    public string ReviewPolicyVersion { get; init; } = string.Empty;

    public DateTime ReviewedUtc { get; init; }

    public IReadOnlyList<YaraRulesetProvenance> Provenance { get; init; } =
        Array.Empty<YaraRulesetProvenance>();
}

/// <summary>
/// Package-free admission metadata for one future YARA execution profile. The
/// contract grants no authority to acquire or load the scanner or rules, read a
/// target, schedule an Agent job, persist output, or create a risk signal.
/// </summary>
public sealed record YaraScanAdmissionProfile
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string ProfileId { get; init; } = string.Empty;

    public string ProfileVersion { get; init; } = string.Empty;

    public YaraScannerTrustDescriptor Scanner { get; init; } = new();

    public YaraRulesetTrustDescriptor Ruleset { get; init; } = new();

    public IReadOnlyList<YaraScanTargetKind> AllowedTargetKinds { get; init; } =
        Array.Empty<YaraScanTargetKind>();

    public long MaximumTargetBytes { get; init; }

    public int MaximumMatches { get; init; }

    public int MaximumTagsPerMatch { get; init; }

    public int MaximumMetadataPerMatch { get; init; }

    public int MaximumStringMatchesPerMatch { get; init; }

    public int MaximumExcerptBytes { get; init; }
}

public sealed record YaraScanAdmissionDecision
{
    public bool Accepted { get; init; }

    public YaraTrustAdmissionFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public YaraScanAdmissionProfile? Profile { get; init; }

    public YaraRulesetIdentity? RulesetIdentity { get; init; }
}

/// <summary>
/// Pure fail-closed validation of scanner and ruleset trust metadata. Accepted
/// collections are copied into canonical order for deterministic handoff to a
/// future Agent-owned authorization and execution boundary.
/// </summary>
public static class YaraTrustAdmissionPolicy
{
    public const int CurrentAdapterProtocolVersion = 1;
    public const int MaximumProvenanceEntries = 64;

    private const int MaximumIdentityLength = 512;
    private const int MaximumVersionLength = 256;
    private const int MaximumUriLength = 2048;
    private const int MaximumAttributionLength = 2048;

    public static YaraScanAdmissionDecision Validate(YaraScanAdmissionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        if (profile.SchemaVersion != YaraScanAdmissionProfile.CurrentSchemaVersion ||
            profile.Scanner?.SchemaVersion != YaraScannerTrustDescriptor.CurrentSchemaVersion ||
            profile.Ruleset?.SchemaVersion != YaraRulesetTrustDescriptor.CurrentSchemaVersion)
        {
            return Reject(YaraTrustAdmissionFailure.InvalidSchemaVersion,
                "The YARA trust schema version is unsupported.");
        }

        if (!IsRequiredIdentity(profile.ProfileId) ||
            !IsBoundedRequired(profile.ProfileVersion, MaximumVersionLength))
        {
            return Reject(YaraTrustAdmissionFailure.InvalidIdentity,
                "The YARA admission profile identity is incomplete or exceeds the contract bound.");
        }

        var scannerFailure = ValidateScanner(profile.Scanner, out var scanner, out var supportedTargets);
        if (scannerFailure != YaraTrustAdmissionFailure.None)
        {
            return Reject(scannerFailure, Diagnostic(scannerFailure));
        }

        var rulesetFailure = ValidateRuleset(profile.Ruleset, out var ruleset);
        if (rulesetFailure != YaraTrustAdmissionFailure.None)
        {
            return Reject(rulesetFailure, Diagnostic(rulesetFailure));
        }

        var targetFailure = ValidateTargets(profile.AllowedTargetKinds, out var allowedTargets);
        if (targetFailure != YaraTrustAdmissionFailure.None)
        {
            return Reject(targetFailure, Diagnostic(targetFailure));
        }

        if (allowedTargets!.Any(kind => !supportedTargets!.Contains(kind)))
        {
            return Reject(YaraTrustAdmissionFailure.UnsupportedTargetKind,
                "The YARA profile allows a target kind unsupported by the pinned scanner.");
        }

        if (!AreLimitsValid(profile))
        {
            return Reject(YaraTrustAdmissionFailure.InvalidLimit,
                "The YARA profile limits must be positive and cannot exceed the portable result bounds.");
        }

        var acceptedProfile = profile with
        {
            Scanner = scanner!,
            Ruleset = ruleset!,
            AllowedTargetKinds = allowedTargets!
        };
        return new YaraScanAdmissionDecision
        {
            Accepted = true,
            Failure = YaraTrustAdmissionFailure.None,
            Profile = acceptedProfile,
            RulesetIdentity = new YaraRulesetIdentity
            {
                ScannerId = scanner!.ScannerId,
                ScannerVersion = scanner.ScannerVersion,
                RulesetId = ruleset!.RulesetId,
                RulesetVersion = ruleset.RulesetVersion,
                RulesetHashSha256 = ruleset.RulesetHashSha256
            }
        };
    }

    private static YaraTrustAdmissionFailure ValidateScanner(
        YaraScannerTrustDescriptor? scanner,
        out YaraScannerTrustDescriptor? accepted,
        out HashSet<YaraScanTargetKind>? supportedTargets)
    {
        accepted = null;
        supportedTargets = null;
        if (scanner == null || !Enum.IsDefined(scanner.DeploymentSource) ||
            scanner.DeploymentSource == YaraScannerDeploymentSource.Unknown)
        {
            return YaraTrustAdmissionFailure.UnknownScannerDeploymentSource;
        }

        if (!IsRequiredIdentity(scanner.ScannerId) ||
            !IsBoundedRequired(scanner.ScannerVersion, MaximumVersionLength))
        {
            return YaraTrustAdmissionFailure.InvalidIdentity;
        }

        if (!IsSha256(scanner.ArtifactHashSha256))
        {
            return YaraTrustAdmissionFailure.InvalidHash;
        }

        if (scanner.AdapterProtocolVersion != CurrentAdapterProtocolVersion)
        {
            return YaraTrustAdmissionFailure.InvalidAdapterProtocol;
        }

        var targetFailure = ValidateTargets(scanner.SupportedTargetKinds, out var canonicalTargets);
        if (targetFailure != YaraTrustAdmissionFailure.None)
        {
            return targetFailure;
        }

        supportedTargets = canonicalTargets!.ToHashSet();
        accepted = scanner with { SupportedTargetKinds = canonicalTargets! };
        return YaraTrustAdmissionFailure.None;
    }

    private static YaraTrustAdmissionFailure ValidateRuleset(
        YaraRulesetTrustDescriptor? ruleset,
        out YaraRulesetTrustDescriptor? accepted)
    {
        accepted = null;
        if (ruleset == null || !Enum.IsDefined(ruleset.Origin) ||
            ruleset.Origin == YaraRulesetOrigin.Unknown)
        {
            return YaraTrustAdmissionFailure.UnknownRulesetOrigin;
        }

        if (!Enum.IsDefined(ruleset.ReviewState) ||
            ruleset.ReviewState == YaraRulesetReviewState.Unknown)
        {
            return YaraTrustAdmissionFailure.UnknownRulesetReviewState;
        }

        if (!IsRequiredIdentity(ruleset.RulesetId) ||
            !IsBoundedRequired(ruleset.RulesetVersion, MaximumVersionLength))
        {
            return YaraTrustAdmissionFailure.InvalidIdentity;
        }

        if (!IsSha256(ruleset.RulesetHashSha256) || !IsSha256(ruleset.ManifestHashSha256))
        {
            return YaraTrustAdmissionFailure.InvalidHash;
        }

        if (!IsRequiredIdentity(ruleset.ReviewerId) ||
            !IsRequiredIdentity(ruleset.ReviewPolicyId) ||
            !IsBoundedRequired(ruleset.ReviewPolicyVersion, MaximumVersionLength) ||
            !IsUtc(ruleset.ReviewedUtc))
        {
            return YaraTrustAdmissionFailure.InvalidReview;
        }

        if (ruleset.Origin == YaraRulesetOrigin.BundledRelease &&
                ruleset.ReviewState != YaraRulesetReviewState.MaintainerReviewed ||
            ruleset.Origin == YaraRulesetOrigin.AnalystImport &&
                ruleset.ReviewState != YaraRulesetReviewState.AnalystApproved)
        {
            return YaraTrustAdmissionFailure.ContradictoryTrust;
        }

        var provenance = ruleset.Provenance;
        if (provenance == null || provenance.Count == 0 ||
            provenance.Count > MaximumProvenanceEntries)
        {
            return YaraTrustAdmissionFailure.InvalidProvenance;
        }

        var provenanceIds = new HashSet<string>(StringComparer.Ordinal);
        var acceptedProvenance = new List<YaraRulesetProvenance>(provenance.Count);
        foreach (var item in provenance)
        {
            if (!IsValidProvenance(item, ruleset.ReviewedUtc))
            {
                return YaraTrustAdmissionFailure.InvalidProvenance;
            }

            if (!provenanceIds.Add(item!.ProvenanceId))
            {
                return YaraTrustAdmissionFailure.DuplicateProvenance;
            }

            acceptedProvenance.Add(item with { });
        }

        accepted = ruleset with
        {
            Provenance = new ReadOnlyCollection<YaraRulesetProvenance>(acceptedProvenance
                .OrderBy(item => item.ProvenanceId, StringComparer.Ordinal)
                .ToArray())
        };
        return YaraTrustAdmissionFailure.None;
    }

    private static YaraTrustAdmissionFailure ValidateTargets(
        IReadOnlyList<YaraScanTargetKind>? targets,
        out IReadOnlyList<YaraScanTargetKind>? accepted)
    {
        accepted = null;
        if (targets == null || targets.Count == 0)
        {
            return YaraTrustAdmissionFailure.InvalidTargetSet;
        }

        if (targets.Any(kind => !Enum.IsDefined(kind) || kind == YaraScanTargetKind.Unknown))
        {
            return YaraTrustAdmissionFailure.UnknownTargetKind;
        }

        if (targets.Distinct().Count() != targets.Count)
        {
            return YaraTrustAdmissionFailure.DuplicateTargetKind;
        }

        accepted = new ReadOnlyCollection<YaraScanTargetKind>(targets.Order().ToArray());
        return YaraTrustAdmissionFailure.None;
    }

    private static bool IsValidProvenance(YaraRulesetProvenance? item, DateTime reviewedUtc)
    {
        if (item == null || !IsRequiredIdentity(item.ProvenanceId) ||
            !IsRequiredIdentity(item.SourceName) ||
            !IsBoundedRequired(item.SourceVersion, MaximumVersionLength) ||
            !IsSha256(item.SourceHashSha256) || !IsRequiredIdentity(item.LicenseId) ||
            !IsBoundedRequired(item.Attribution, MaximumAttributionLength) ||
            !IsUtc(item.RetrievedUtc) || item.RetrievedUtc > reviewedUtc ||
            string.IsNullOrWhiteSpace(item.SourceUri) || item.SourceUri.Length > MaximumUriLength)
        {
            return false;
        }

        return Uri.TryCreate(item.SourceUri, UriKind.Absolute, out var uri) &&
               string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
    }

    private static bool AreLimitsValid(YaraScanAdmissionProfile profile) =>
        profile.MaximumTargetBytes is > 0 and <= YaraAnalysisContractPolicy.MaximumTargetBytes &&
        profile.MaximumMatches is > 0 and <= YaraAnalysisContractPolicy.MaximumMatches &&
        profile.MaximumTagsPerMatch is > 0 and <= YaraAnalysisContractPolicy.MaximumTagsPerMatch &&
        profile.MaximumMetadataPerMatch is > 0 and <= YaraAnalysisContractPolicy.MaximumMetadataPerMatch &&
        profile.MaximumStringMatchesPerMatch is > 0 and <= YaraAnalysisContractPolicy.MaximumStringMatchesPerMatch &&
        profile.MaximumExcerptBytes is > 0 and <= YaraAnalysisContractPolicy.MaximumExcerptBytes;

    private static bool IsRequiredIdentity(string? value) =>
        IsBoundedRequired(value, MaximumIdentityLength);

    private static bool IsBoundedRequired(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;

    private static bool IsSha256(string? value) => value is { Length: 64 } &&
        value.All(character => Uri.IsHexDigit(character));

    private static bool IsUtc(DateTime value) => value.Kind == DateTimeKind.Utc;

    private static YaraScanAdmissionDecision Reject(
        YaraTrustAdmissionFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = diagnostic
        };

    private static string Diagnostic(YaraTrustAdmissionFailure failure) => failure switch
    {
        YaraTrustAdmissionFailure.UnknownScannerDeploymentSource =>
            "The YARA scanner deployment source is unknown or unsupported.",
        YaraTrustAdmissionFailure.UnknownRulesetOrigin =>
            "The YARA ruleset origin is unknown or unsupported.",
        YaraTrustAdmissionFailure.UnknownRulesetReviewState =>
            "The YARA ruleset review state is unknown or unsupported.",
        YaraTrustAdmissionFailure.InvalidIdentity =>
            "A required YARA trust identity is missing or exceeds the contract bound.",
        YaraTrustAdmissionFailure.InvalidHash =>
            "A required YARA scanner, ruleset, manifest, or source SHA-256 is malformed.",
        YaraTrustAdmissionFailure.InvalidAdapterProtocol =>
            "The YARA scanner adapter protocol version is unsupported.",
        YaraTrustAdmissionFailure.UnknownTargetKind =>
            "The YARA target kind is unknown or unsupported.",
        YaraTrustAdmissionFailure.InvalidTargetSet =>
            "The YARA target-kind set must be nonempty.",
        YaraTrustAdmissionFailure.DuplicateTargetKind =>
            "The YARA target-kind set contains a duplicate.",
        YaraTrustAdmissionFailure.InvalidProvenance =>
            "The YARA ruleset provenance is incomplete, unsafe, incoherent, or exceeds the contract bound.",
        YaraTrustAdmissionFailure.DuplicateProvenance =>
            "The YARA ruleset provenance contains a duplicate identity.",
        YaraTrustAdmissionFailure.InvalidReview =>
            "The YARA ruleset requires complete bounded review identity, policy, and UTC time.",
        YaraTrustAdmissionFailure.ContradictoryTrust =>
            "The YARA ruleset origin and review state contradict the admission policy.",
        YaraTrustAdmissionFailure.UnsupportedTargetKind =>
            "The YARA profile allows a target kind unsupported by the pinned scanner.",
        YaraTrustAdmissionFailure.InvalidLimit =>
            "The YARA profile limits exceed the portable contract or are not positive.",
        _ => "The YARA trust profile is invalid."
    };
}
