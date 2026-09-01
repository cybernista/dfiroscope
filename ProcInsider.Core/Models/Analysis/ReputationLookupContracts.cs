using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace ProcInsider.Models.Analysis;

public enum ReputationIndicatorKind
{
    Unknown = 0,
    Sha256 = 1,
    Domain = 2,
    IPv4 = 3,
    IPv6 = 4,
    Url = 5
}

public enum ReputationLookupInitiation
{
    Unknown = 0,
    Analyst = 1
}

/// <summary>
/// Describes where a future lookup owner obtained a result. A query mode is
/// provenance only; it does not authorize network access or provider use.
/// </summary>
public enum ReputationQueryMode
{
    Unknown = 0,
    LocalCache = 1,
    LocalReference = 2,
    AnalystList = 3,
    ExternalService = 4
}

public enum ReputationLookupFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    UnknownIndicatorKind = 2,
    InvalidIndicator = 3,
    UnknownInitiation = 4,
    InvalidRequestIdentity = 5,
    InvalidScope = 6,
    InvalidSourceRun = 7,
    EvidenceReferenceLimitExceeded = 8,
    InvalidEvidenceReference = 9,
    DuplicateEvidenceReference = 10,
    InvalidRequestTimestamp = 11,
    UnknownQueryMode = 12,
    InvalidProviderIdentity = 13,
    UnknownAvailability = 14,
    ContradictoryState = 15,
    InvalidDetectionCount = 16,
    CategoryLimitExceeded = 17,
    InvalidCategory = 18,
    DuplicateCategory = 19,
    InvalidProviderRecord = 20,
    InvalidResultTimestamp = 21,
    InvalidDiagnostic = 22,
    InvalidContentHash = 23
}

/// <summary>
/// One exact canonical indicator. Files and other evidence content are represented
/// only by their exact SHA-256; this contract never carries a path or bytes.
/// </summary>
public sealed record ReputationIndicator
{
    public ReputationIndicatorKind Kind { get; init; }

    public string Value { get; init; } = string.Empty;
}

/// <summary>
/// Analyst-initiated, evidence-scoped request identity. A future workflow must
/// authorize and execute the lookup separately.
/// </summary>
public sealed record ReputationLookupRequest
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string RequestId { get; init; } = string.Empty;

    public ReputationLookupInitiation Initiation { get; init; }

    public ReputationIndicator Indicator { get; init; } = new();

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string SourceRunId { get; init; } = string.Empty;

    public DateTime RequestedUtc { get; init; }

    public IReadOnlyList<EvidenceReference> EvidenceReferences { get; init; } =
        Array.Empty<EvidenceReference>();
}

/// <summary>
/// Versioned provenance for one result. It identifies a source and dataset but
/// does not establish provider trust or grant access to either source.
/// </summary>
public sealed record ReputationProviderIdentity
{
    public string ProviderId { get; init; } = string.Empty;

    public string ProviderVersion { get; init; } = string.Empty;

    public string DatasetId { get; init; } = string.Empty;

    public string DatasetVersion { get; init; } = string.Empty;

    public ReputationQueryMode QueryMode { get; init; }
}

/// <summary>
/// Provider-neutral aggregate reputation result. Found and not-found are lookup
/// outcomes, never benignness or malware verdicts.
/// </summary>
public sealed record ReputationLookupResult
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ReputationLookupRequest Request { get; init; } = new();

    public ReputationProviderIdentity Provider { get; init; } = new();

    public AnalysisSourceAvailability Availability { get; init; }

    public bool RecordFound { get; init; }

    public int AnalyzedCount { get; init; }

    public int PositiveCount { get; init; }

    public int SuspiciousCount { get; init; }

    public int UndetectedCount { get; init; }

    public IReadOnlyList<string> Categories { get; init; } = Array.Empty<string>();

    public string ProviderRecordId { get; init; } = string.Empty;

    public DateTime? ProviderObservedUtc { get; init; }

    public DateTime RetrievedUtc { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public string ContentHashSha256 { get; init; } = string.Empty;
}

public sealed record ReputationLookupValidationDecision
{
    public bool Accepted { get; init; }

    public ReputationLookupFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationLookupResult? Result { get; init; }
}

/// <summary>
/// Pure fail-closed validation and canonicalization for the portable reputation
/// handoff. This type performs no provider, network, storage, evidence, or UI work.
/// </summary>
public static class ReputationLookupContractPolicy
{
    public const int MaximumEvidenceReferences = 32;
    public const int MaximumCategories = 32;
    public const int MaximumDetectionCount = 10_000;
    public const int MaximumIndicatorLength = 2_048;

    private const int MaximumIdentityLength = 256;
    private const int MaximumProviderIdentityLength = 128;
    private const int MaximumCategoryLength = 64;
    private const int MaximumDiagnosticLength = 512;

    public static ReputationLookupValidationDecision Validate(ReputationLookupResult candidate) =>
        ValidateInternal(candidate, requireContentHash: true);

    public static string ComputeContentHash(ReputationLookupResult candidate)
    {
        var decision = ValidateInternal(candidate, requireContentHash: false);
        if (!decision.Accepted || decision.Result == null)
        {
            throw new ArgumentException(decision.Diagnostic, nameof(candidate));
        }

        return decision.Result.ContentHashSha256;
    }

    private static ReputationLookupValidationDecision ValidateInternal(
        ReputationLookupResult? candidate,
        bool requireContentHash)
    {
        if (candidate == null || candidate.SchemaVersion != ReputationLookupResult.CurrentSchemaVersion)
        {
            return Reject(ReputationLookupFailure.InvalidSchemaVersion);
        }

        if (!TryCanonicalizeRequest(
                candidate.Request,
                out var request,
                out var requestFailure))
        {
            return Reject(requestFailure);
        }

        if (!TryCanonicalizeProvider(
                candidate.Provider,
                out var provider,
                out var providerFailure))
        {
            return Reject(providerFailure);
        }

        if (!IsKnownAvailability(candidate.Availability))
        {
            return Reject(ReputationLookupFailure.UnknownAvailability);
        }

        if (!IsUtc(candidate.RetrievedUtc) || candidate.RetrievedUtc < request.RequestedUtc ||
            candidate.ProviderObservedUtc is { } observedUtc &&
            (!IsUtc(observedUtc) || observedUtc > candidate.RetrievedUtc))
        {
            return Reject(ReputationLookupFailure.InvalidResultTimestamp);
        }

        if (!AreDetectionCountsValid(candidate))
        {
            return Reject(ReputationLookupFailure.InvalidDetectionCount);
        }

        if (!TryCanonicalizeCategories(
                candidate.Categories,
                out var categories,
                out var categoryFailure))
        {
            return Reject(categoryFailure);
        }

        if (!IsBoundedOptionalText(candidate.ProviderRecordId, MaximumIdentityLength))
        {
            return Reject(ReputationLookupFailure.InvalidProviderRecord);
        }

        if (!IsBoundedOptionalText(candidate.Diagnostic, MaximumDiagnosticLength))
        {
            return Reject(ReputationLookupFailure.InvalidDiagnostic);
        }

        if (!ValidateState(candidate, categories.Count, out var stateFailure))
        {
            return Reject(stateFailure);
        }

        var canonical = candidate with
        {
            Request = request,
            Provider = provider,
            Categories = new ReadOnlyCollection<string>(categories.ToArray()),
            ContentHashSha256 = string.Empty
        };
        var expectedHash = ComputeCanonicalHash(canonical);
        if (requireContentHash &&
            (!IsLowerSha256(candidate.ContentHashSha256) ||
             !string.Equals(candidate.ContentHashSha256, expectedHash, StringComparison.Ordinal)))
        {
            return Reject(ReputationLookupFailure.InvalidContentHash);
        }

        return new ReputationLookupValidationDecision
        {
            Accepted = true,
            Failure = ReputationLookupFailure.None,
            Result = canonical with { ContentHashSha256 = expectedHash }
        };
    }

    internal static bool TryCanonicalizeRequest(
        ReputationLookupRequest? candidate,
        out ReputationLookupRequest request,
        out ReputationLookupFailure failure)
    {
        request = new ReputationLookupRequest();
        if (candidate == null || candidate.SchemaVersion != ReputationLookupRequest.CurrentSchemaVersion)
        {
            failure = ReputationLookupFailure.InvalidSchemaVersion;
            return false;
        }

        if (candidate.Initiation != ReputationLookupInitiation.Analyst)
        {
            failure = ReputationLookupFailure.UnknownInitiation;
            return false;
        }

        if (!IsBoundedRequired(candidate.RequestId, MaximumIdentityLength))
        {
            failure = ReputationLookupFailure.InvalidRequestIdentity;
            return false;
        }

        if (!TryCanonicalizeIndicator(candidate.Indicator, out var indicator, out failure))
        {
            return false;
        }

        if (!IsValidScope(candidate.EvidenceIdentity))
        {
            failure = ReputationLookupFailure.InvalidScope;
            return false;
        }

        if (!IsBoundedRequired(candidate.SourceRunId, MaximumIdentityLength))
        {
            failure = ReputationLookupFailure.InvalidSourceRun;
            return false;
        }

        if (!IsUtc(candidate.RequestedUtc))
        {
            failure = ReputationLookupFailure.InvalidRequestTimestamp;
            return false;
        }

        var references = candidate.EvidenceReferences ?? Array.Empty<EvidenceReference>();
        if (references.Count is 0 or > MaximumEvidenceReferences)
        {
            failure = ReputationLookupFailure.EvidenceReferenceLimitExceeded;
            return false;
        }

        var keys = new HashSet<string>(StringComparer.Ordinal);
        var hasMatchingSourceRun = false;
        var hasSourceEvidence = false;
        foreach (var reference in references)
        {
            if (!Enum.IsDefined(typeof(EvidenceReferenceKind), reference.Kind) ||
                !IsBoundedRequired(reference.Id, MaximumIdentityLength))
            {
                failure = ReputationLookupFailure.InvalidEvidenceReference;
                return false;
            }

            if (!keys.Add($"{(int)reference.Kind}:{reference.Id}"))
            {
                failure = ReputationLookupFailure.DuplicateEvidenceReference;
                return false;
            }

            hasMatchingSourceRun |= reference.Kind == EvidenceReferenceKind.SourceRun &&
                                    string.Equals(reference.Id, candidate.SourceRunId,
                                        StringComparison.Ordinal);
            hasSourceEvidence |= reference.Kind != EvidenceReferenceKind.SourceRun;
        }

        if (!hasMatchingSourceRun || !hasSourceEvidence)
        {
            failure = ReputationLookupFailure.InvalidSourceRun;
            return false;
        }

        var canonicalReferences = references
            .OrderBy(reference => (int)reference.Kind)
            .ThenBy(reference => reference.Id, StringComparer.Ordinal)
            .Select(reference => new EvidenceReference(reference.Kind, reference.Id))
            .ToArray();
        request = candidate with
        {
            Indicator = indicator,
            EvidenceIdentity = candidate.EvidenceIdentity with { },
            EvidenceReferences = new ReadOnlyCollection<EvidenceReference>(canonicalReferences)
        };
        failure = ReputationLookupFailure.None;
        return true;
    }

    private static bool TryCanonicalizeIndicator(
        ReputationIndicator? candidate,
        out ReputationIndicator indicator,
        out ReputationLookupFailure failure)
    {
        indicator = new ReputationIndicator();
        if (candidate == null ||
            !Enum.IsDefined(typeof(ReputationIndicatorKind), candidate.Kind) ||
            candidate.Kind == ReputationIndicatorKind.Unknown)
        {
            failure = ReputationLookupFailure.UnknownIndicatorKind;
            return false;
        }

        if (candidate.Value == null || candidate.Value.Length == 0 ||
            candidate.Value.Length > MaximumIndicatorLength ||
            candidate.Value.Any(char.IsControl))
        {
            failure = ReputationLookupFailure.InvalidIndicator;
            return false;
        }

        var valid = candidate.Kind switch
        {
            ReputationIndicatorKind.Sha256 => IsLowerSha256(candidate.Value),
            ReputationIndicatorKind.Domain => IsCanonicalDomain(candidate.Value),
            ReputationIndicatorKind.IPv4 => IsCanonicalIp(candidate.Value, AddressFamilyKind.IPv4),
            ReputationIndicatorKind.IPv6 => IsCanonicalIp(candidate.Value, AddressFamilyKind.IPv6),
            ReputationIndicatorKind.Url => IsCanonicalUrl(candidate.Value),
            _ => false
        };
        if (!valid)
        {
            failure = ReputationLookupFailure.InvalidIndicator;
            return false;
        }

        indicator = candidate with { };
        failure = ReputationLookupFailure.None;
        return true;
    }

    internal static bool TryCanonicalizeProvider(
        ReputationProviderIdentity? candidate,
        out ReputationProviderIdentity provider,
        out ReputationLookupFailure failure)
    {
        provider = new ReputationProviderIdentity();
        if (candidate == null ||
            !Enum.IsDefined(typeof(ReputationQueryMode), candidate.QueryMode) ||
            candidate.QueryMode == ReputationQueryMode.Unknown)
        {
            failure = ReputationLookupFailure.UnknownQueryMode;
            return false;
        }

        if (!IsCanonicalToken(candidate.ProviderId, MaximumProviderIdentityLength) ||
            !IsBoundedRequiredText(candidate.ProviderVersion, MaximumProviderIdentityLength) ||
            !IsCanonicalToken(candidate.DatasetId, MaximumProviderIdentityLength) ||
            !IsBoundedRequiredText(candidate.DatasetVersion, MaximumProviderIdentityLength))
        {
            failure = ReputationLookupFailure.InvalidProviderIdentity;
            return false;
        }

        provider = candidate with { };
        failure = ReputationLookupFailure.None;
        return true;
    }

    private static bool TryCanonicalizeCategories(
        IReadOnlyList<string>? candidate,
        out IReadOnlyList<string> categories,
        out ReputationLookupFailure failure)
    {
        var values = candidate ?? Array.Empty<string>();
        categories = Array.Empty<string>();
        if (values.Count > MaximumCategories)
        {
            failure = ReputationLookupFailure.CategoryLimitExceeded;
            return false;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (!IsCanonicalToken(value, MaximumCategoryLength))
            {
                failure = ReputationLookupFailure.InvalidCategory;
                return false;
            }

            if (!unique.Add(value))
            {
                failure = ReputationLookupFailure.DuplicateCategory;
                return false;
            }
        }

        categories = unique.OrderBy(value => value, StringComparer.Ordinal).ToArray();
        failure = ReputationLookupFailure.None;
        return true;
    }

    private static bool ValidateState(
        ReputationLookupResult candidate,
        int categoryCount,
        out ReputationLookupFailure failure)
    {
        if (candidate.Availability == AnalysisSourceAvailability.Available)
        {
            if (!string.IsNullOrEmpty(candidate.Diagnostic))
            {
                failure = ReputationLookupFailure.ContradictoryState;
                return false;
            }

            if (!candidate.RecordFound &&
                (candidate.AnalyzedCount != 0 || candidate.PositiveCount != 0 ||
                 candidate.SuspiciousCount != 0 || candidate.UndetectedCount != 0 ||
                 categoryCount != 0 || !string.IsNullOrEmpty(candidate.ProviderRecordId)))
            {
                failure = ReputationLookupFailure.ContradictoryState;
                return false;
            }

            if (candidate.RecordFound &&
                !IsBoundedRequiredText(candidate.ProviderRecordId, MaximumIdentityLength))
            {
                failure = ReputationLookupFailure.InvalidProviderRecord;
                return false;
            }

            failure = ReputationLookupFailure.None;
            return true;
        }

        if (string.IsNullOrWhiteSpace(candidate.Diagnostic))
        {
            failure = ReputationLookupFailure.InvalidDiagnostic;
            return false;
        }

        if (candidate.RecordFound || candidate.AnalyzedCount != 0 || candidate.PositiveCount != 0 ||
            candidate.SuspiciousCount != 0 || candidate.UndetectedCount != 0 || categoryCount != 0 ||
            !string.IsNullOrEmpty(candidate.ProviderRecordId) || candidate.ProviderObservedUtc != null)
        {
            failure = ReputationLookupFailure.ContradictoryState;
            return false;
        }

        failure = ReputationLookupFailure.None;
        return true;
    }

    private static bool AreDetectionCountsValid(ReputationLookupResult candidate) =>
        candidate.AnalyzedCount is >= 0 and <= MaximumDetectionCount &&
        candidate.PositiveCount is >= 0 and <= MaximumDetectionCount &&
        candidate.SuspiciousCount is >= 0 and <= MaximumDetectionCount &&
        candidate.UndetectedCount is >= 0 and <= MaximumDetectionCount &&
        (long)candidate.PositiveCount + candidate.SuspiciousCount + candidate.UndetectedCount <=
        candidate.AnalyzedCount;

    private static bool IsKnownAvailability(AnalysisSourceAvailability availability) =>
        availability is AnalysisSourceAvailability.Available or
            AnalysisSourceAvailability.NotCollected or
            AnalysisSourceAvailability.Unavailable or
            AnalysisSourceAvailability.Failed or
            AnalysisSourceAvailability.Stale;

    private static bool IsCanonicalDomain(string value)
    {
        if (value.Length is 0 or > 253 || value[0] == '.' || value[^1] == '.' ||
            !string.Equals(value, value.ToLowerInvariant(), StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var label in value.Split('.'))
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-' ||
                label.Any(character =>
                    character is not (>= 'a' and <= 'z') and not (>= '0' and <= '9') and not '-'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsCanonicalIp(string value, AddressFamilyKind expected)
    {
        if (value.Contains('%', StringComparison.Ordinal) ||
            !IPAddress.TryParse(value, out var address))
        {
            return false;
        }

        var family = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? AddressFamilyKind.IPv4
            : address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? AddressFamilyKind.IPv6
                : AddressFamilyKind.Unknown;
        return family == expected && string.Equals(address.ToString(), value, StringComparison.Ordinal);
    }

    private static bool IsCanonicalUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
            uri.HostNameType is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6))
        {
            return false;
        }

        if (uri.HostNameType == UriHostNameType.Dns &&
            (!IsCanonicalDomain(uri.IdnHost) ||
             !string.Equals(uri.Host, uri.IdnHost, StringComparison.Ordinal)))
        {
            return false;
        }

        return string.Equals(uri.AbsoluteUri, value, StringComparison.Ordinal);
    }

    private static bool IsValidScope(EvidenceIdentity? identity) =>
        identity != null && IsBoundedOptional(identity.CaseId, MaximumIdentityLength) &&
        IsBoundedRequired(identity.EvidenceSessionId, MaximumIdentityLength) &&
        IsBoundedOptional(identity.CaptureId, MaximumIdentityLength) &&
        IsBoundedRequired(identity.SourceIdentityId, MaximumIdentityLength) &&
        IsBoundedRequired(identity.HostId, MaximumIdentityLength) &&
        IsBoundedRequired(identity.ExecutionRootId, MaximumIdentityLength);

    private static bool IsCanonicalToken(string? value, int maximumLength) =>
        value is { Length: > 0 } && value.Length <= maximumLength &&
        value[0] is (>= 'a' and <= 'z') or (>= '0' and <= '9') &&
        value.All(character =>
            character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '_' or ':' or '-');

    private static bool IsBoundedRequired(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;

    private static bool IsBoundedOptional(string? value, int maximumLength) =>
        value != null && value.Length <= maximumLength;

    private static bool IsBoundedRequiredText(string? value, int maximumLength) =>
        IsBoundedOptionalText(value, maximumLength) && !string.IsNullOrWhiteSpace(value);

    private static bool IsBoundedOptionalText(string? value, int maximumLength) =>
        value != null && value.Length <= maximumLength &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal) &&
        !value.Any(char.IsControl);

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static bool IsUtc(DateTime value) =>
        value != default && value.Kind == DateTimeKind.Utc;

    private static string ComputeCanonicalHash(ReputationLookupResult result)
    {
        var builder = new StringBuilder();
        Append(builder, result.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(builder, result.Request.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(builder, result.Request.RequestId);
        Append(builder, ((int)result.Request.Initiation).ToString(CultureInfo.InvariantCulture));
        Append(builder, ((int)result.Request.Indicator.Kind).ToString(CultureInfo.InvariantCulture));
        Append(builder, result.Request.Indicator.Value);
        Append(builder, result.Request.EvidenceIdentity.CaseId);
        Append(builder, result.Request.EvidenceIdentity.EvidenceSessionId);
        Append(builder, result.Request.EvidenceIdentity.CaptureId);
        Append(builder, result.Request.EvidenceIdentity.SourceIdentityId);
        Append(builder, result.Request.EvidenceIdentity.HostId);
        Append(builder, result.Request.EvidenceIdentity.ExecutionRootId);
        Append(builder, result.Request.SourceRunId);
        Append(builder, result.Request.RequestedUtc.ToString("O", CultureInfo.InvariantCulture));
        foreach (var reference in result.Request.EvidenceReferences)
        {
            Append(builder, ((int)reference.Kind).ToString(CultureInfo.InvariantCulture));
            Append(builder, reference.Id);
        }

        Append(builder, result.Provider.ProviderId);
        Append(builder, result.Provider.ProviderVersion);
        Append(builder, result.Provider.DatasetId);
        Append(builder, result.Provider.DatasetVersion);
        Append(builder, ((int)result.Provider.QueryMode).ToString(CultureInfo.InvariantCulture));
        Append(builder, ((int)result.Availability).ToString(CultureInfo.InvariantCulture));
        Append(builder, result.RecordFound ? "1" : "0");
        Append(builder, result.AnalyzedCount.ToString(CultureInfo.InvariantCulture));
        Append(builder, result.PositiveCount.ToString(CultureInfo.InvariantCulture));
        Append(builder, result.SuspiciousCount.ToString(CultureInfo.InvariantCulture));
        Append(builder, result.UndetectedCount.ToString(CultureInfo.InvariantCulture));
        foreach (var category in result.Categories)
        {
            Append(builder, category);
        }

        Append(builder, result.ProviderRecordId);
        Append(builder, result.ProviderObservedUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty);
        Append(builder, result.RetrievedUtc.ToString("O", CultureInfo.InvariantCulture));
        Append(builder, result.Diagnostic);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())))
            .ToLowerInvariant();
    }

    private static void Append(StringBuilder builder, string value) =>
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture))
            .Append(':')
            .Append(value)
            .Append('\n');

    private static ReputationLookupValidationDecision Reject(ReputationLookupFailure failure) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = failure switch
            {
                ReputationLookupFailure.InvalidSchemaVersion => "The reputation schema version is unsupported.",
                ReputationLookupFailure.UnknownIndicatorKind => "The reputation indicator kind is unknown or unsupported.",
                ReputationLookupFailure.InvalidIndicator => "The reputation indicator is malformed or noncanonical.",
                ReputationLookupFailure.UnknownInitiation => "The reputation request is not explicitly analyst initiated.",
                ReputationLookupFailure.InvalidRequestIdentity => "The reputation request identity is incomplete or invalid.",
                ReputationLookupFailure.InvalidScope => "The reputation evidence scope is incomplete or invalid.",
                ReputationLookupFailure.InvalidSourceRun => "The reputation source-run reference is incomplete or mismatched.",
                ReputationLookupFailure.EvidenceReferenceLimitExceeded => "The reputation evidence-reference set is empty or exceeds its bound.",
                ReputationLookupFailure.InvalidEvidenceReference => "A reputation evidence reference is invalid.",
                ReputationLookupFailure.DuplicateEvidenceReference => "The reputation evidence-reference set contains a duplicate.",
                ReputationLookupFailure.InvalidRequestTimestamp => "The reputation request timestamp must be UTC.",
                ReputationLookupFailure.UnknownQueryMode => "The reputation query mode is unknown or unsupported.",
                ReputationLookupFailure.InvalidProviderIdentity => "The reputation provider or dataset identity is incomplete or invalid.",
                ReputationLookupFailure.UnknownAvailability => "The reputation availability state is unknown or unsupported.",
                ReputationLookupFailure.ContradictoryState => "The reputation availability, found state, or aggregate metadata is contradictory.",
                ReputationLookupFailure.InvalidDetectionCount => "The reputation aggregate detection counts are invalid or exceed their bound.",
                ReputationLookupFailure.CategoryLimitExceeded => "The reputation category set exceeds its bound.",
                ReputationLookupFailure.InvalidCategory => "A reputation category is malformed or noncanonical.",
                ReputationLookupFailure.DuplicateCategory => "The reputation category set contains a duplicate.",
                ReputationLookupFailure.InvalidProviderRecord => "The reputation provider-record identity is invalid.",
                ReputationLookupFailure.InvalidResultTimestamp => "The reputation result timestamps are invalid or inconsistent.",
                ReputationLookupFailure.InvalidDiagnostic => "The reputation diagnostic is invalid or missing for a gap state.",
                ReputationLookupFailure.InvalidContentHash => "The reputation deterministic content identity is missing or mismatched.",
                _ => "The reputation result violates the portable contract."
            }
        };

    private enum AddressFamilyKind
    {
        Unknown = 0,
        IPv4 = 1,
        IPv6 = 2
    }
}
