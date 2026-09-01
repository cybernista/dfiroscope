using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace ProcInsider.Models.Analysis;

public enum ReputationProviderPrivacyKind
{
    Unknown = 0,
    LocalOnly = 1,
    ExternalIndicatorDisclosure = 2
}

public enum ReputationCredentialRequirement
{
    Unknown = 0,
    None = 1,
    Required = 2
}

public enum ReputationProviderAuthorizationFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    InvalidLookupRequest = 2,
    InvalidProviderIdentity = 3,
    UnknownPrivacyKind = 4,
    PrivacyQueryModeMismatch = 5,
    InvalidDestinationOrigin = 6,
    UnknownCredentialRequirement = 7,
    InvalidCredentialSlot = 8,
    InvalidPrivacyNoticeVersion = 9,
    IndicatorKindLimitExceeded = 10,
    UnknownIndicatorKind = 11,
    DuplicateIndicatorKind = 12,
    NoncanonicalIndicatorOrder = 13,
    InvalidResourceLimits = 14,
    InvalidAdmissionHash = 15,
    UnsupportedIndicatorKind = 16,
    MissingApproval = 17,
    UnexpectedApproval = 18,
    InvalidApproval = 19,
    ApprovalMismatch = 20,
    ExternalDisclosureNotApproved = 21,
    ApprovalAfterRequest = 22,
    CredentialSlotMismatch = 23,
    InvalidAuthorizationTimestamp = 24,
    InvalidAuthorizationHash = 25
}

/// <summary>
/// Hard ceilings for one future provider execution. The response length is a
/// byte ceiling, but this policy never reads or carries response content.
/// </summary>
public sealed record ReputationProviderResourceLimits
{
    public int RequestTimeoutSeconds { get; init; }

    public int MaximumResponseLength { get; init; }

    public int MaximumConcurrency { get; init; }

    public int MaximumRequestsPerMinute { get; init; }

    public int MaximumRequestsPerDay { get; init; }
}

/// <summary>
/// Provider-neutral admission metadata. An accepted admission describes an
/// eligible provider configuration; it grants no permission to contact it.
/// </summary>
public sealed record ReputationProviderAdmission
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ReputationProviderIdentity Provider { get; init; } = new();

    public ReputationProviderPrivacyKind PrivacyKind { get; init; }

    public string DestinationOrigin { get; init; } = string.Empty;

    public ReputationCredentialRequirement CredentialRequirement { get; init; }

    public string CredentialSlotId { get; init; } = string.Empty;

    public string PrivacyNoticeVersion { get; init; } = string.Empty;

    public IReadOnlyList<ReputationIndicatorKind> SupportedIndicatorKinds { get; init; } =
        Array.Empty<ReputationIndicatorKind>();

    public ReputationProviderResourceLimits Limits { get; init; } = new();

    public string AdmissionHashSha256 { get; init; } = string.Empty;
}

/// <summary>
/// Explicit analyst approval for one exact external-provider admission and
/// privacy-notice version. The approval contains no credential or secret.
/// </summary>
public sealed record ReputationProviderApproval
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ReputationProviderIdentity Provider { get; init; } = new();

    public string AdmissionHashSha256 { get; init; } = string.Empty;

    public string PrivacyNoticeVersion { get; init; } = string.Empty;

    public string AnalystId { get; init; } = string.Empty;

    public DateTime ApprovedUtc { get; init; }

    public bool ExternalIndicatorDisclosureAccepted { get; init; }

    public string ApprovalHashSha256 { get; init; } = string.Empty;
}

/// <summary>
/// Canonical per-request authorization. It binds an accepted #399 request to
/// one admitted provider without performing provider, evidence, or secret I/O.
/// </summary>
public sealed record ReputationProviderAuthorization
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ReputationLookupRequest LookupRequest { get; init; } = new();

    public ReputationProviderAdmission Admission { get; init; } = new();

    public ReputationProviderApproval? Approval { get; init; }

    public string CredentialSlotId { get; init; } = string.Empty;

    public DateTime AuthorizedUtc { get; init; }

    public string AuthorizationHashSha256 { get; init; } = string.Empty;
}

public sealed record ReputationProviderAdmissionDecision
{
    public bool Accepted { get; init; }

    public ReputationProviderAuthorizationFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationProviderAdmission? Admission { get; init; }
}

public sealed record ReputationProviderApprovalDecision
{
    public bool Accepted { get; init; }

    public ReputationProviderAuthorizationFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationProviderApproval? Approval { get; init; }
}

public sealed record ReputationProviderAuthorizationDecision
{
    public bool Accepted { get; init; }

    public ReputationProviderAuthorizationFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationProviderAuthorization? Authorization { get; init; }
}

/// <summary>
/// Pure admission, approval, and per-request authorization policy. Acceptance
/// is a data handoff only and performs no network, secret, evidence, storage,
/// scoring, annotation, Agent, or UI work.
/// </summary>
public static class ReputationProviderAuthorizationPolicy
{
    public const int MaximumSupportedIndicatorKinds = 5;
    public const int MaximumRequestTimeoutSeconds = 120;
    public const int MaximumResponseLength = 1_048_576;
    public const int MaximumConcurrency = 8;
    public const int MaximumRequestsPerMinute = 120;
    public const int MaximumRequestsPerDay = 10_000;

    private const int MaximumIdentityLength = 128;
    private const int MaximumOriginLength = 512;

    public static ReputationProviderAdmissionDecision ValidateAdmission(
        ReputationProviderAdmission candidate)
    {
        if (!TryCanonicalizeAdmission(candidate, requireHash: true, out var admission, out var failure))
        {
            return RejectAdmission(failure);
        }

        return new ReputationProviderAdmissionDecision
        {
            Accepted = true,
            Failure = ReputationProviderAuthorizationFailure.None,
            Admission = admission
        };
    }

    public static string ComputeAdmissionHash(ReputationProviderAdmission candidate)
    {
        if (!TryCanonicalizeAdmission(candidate, requireHash: false, out var admission, out _))
        {
            return string.Empty;
        }

        return ComputeAdmissionHashCanonical(admission);
    }

    public static ReputationProviderApprovalDecision ValidateApproval(
        ReputationProviderApproval candidate,
        ReputationProviderAdmission admission)
    {
        if (!TryCanonicalizeAdmission(admission, requireHash: true, out var canonicalAdmission,
                out var failure))
        {
            return RejectApproval(failure);
        }

        if (!TryCanonicalizeApproval(candidate, canonicalAdmission, requireHash: true,
                out var approval, out failure))
        {
            return RejectApproval(failure);
        }

        return new ReputationProviderApprovalDecision
        {
            Accepted = true,
            Failure = ReputationProviderAuthorizationFailure.None,
            Approval = approval
        };
    }

    public static string ComputeApprovalHash(
        ReputationProviderApproval candidate,
        ReputationProviderAdmission admission)
    {
        if (!TryCanonicalizeAdmission(admission, requireHash: true, out var canonicalAdmission,
                out _) ||
            !TryCanonicalizeApproval(candidate, canonicalAdmission, requireHash: false,
                out var approval, out _))
        {
            return string.Empty;
        }

        return ComputeApprovalHashCanonical(approval);
    }

    public static ReputationProviderAuthorizationDecision Authorize(
        ReputationLookupRequest lookupRequest,
        ReputationProviderAdmission admission,
        ReputationProviderApproval? approval,
        string credentialSlotId)
    {
        if (!ReputationLookupContractPolicy.TryCanonicalizeRequest(
                lookupRequest, out var canonicalRequest, out _))
        {
            return RejectAuthorization(ReputationProviderAuthorizationFailure.InvalidLookupRequest);
        }

        if (!TryCanonicalizeAdmission(admission, requireHash: true, out var canonicalAdmission,
                out var failure))
        {
            return RejectAuthorization(failure);
        }

        if (!canonicalAdmission.SupportedIndicatorKinds.Contains(canonicalRequest.Indicator.Kind))
        {
            return RejectAuthorization(ReputationProviderAuthorizationFailure.UnsupportedIndicatorKind);
        }

        if (!TryValidateCredentialSlot(canonicalAdmission, credentialSlotId, out failure))
        {
            return RejectAuthorization(failure);
        }

        ReputationProviderApproval? canonicalApproval = null;
        if (canonicalAdmission.PrivacyKind == ReputationProviderPrivacyKind.ExternalIndicatorDisclosure)
        {
            if (approval == null)
            {
                return RejectAuthorization(ReputationProviderAuthorizationFailure.MissingApproval);
            }

            if (!TryCanonicalizeApproval(approval, canonicalAdmission, requireHash: true,
                    out canonicalApproval, out failure))
            {
                return RejectAuthorization(failure);
            }

            if (canonicalApproval.ApprovedUtc > canonicalRequest.RequestedUtc)
            {
                return RejectAuthorization(ReputationProviderAuthorizationFailure.ApprovalAfterRequest);
            }
        }
        else if (approval != null)
        {
            return RejectAuthorization(ReputationProviderAuthorizationFailure.UnexpectedApproval);
        }

        var authorization = new ReputationProviderAuthorization
        {
            LookupRequest = canonicalRequest,
            Admission = canonicalAdmission,
            Approval = canonicalApproval,
            CredentialSlotId = credentialSlotId,
            AuthorizedUtc = canonicalRequest.RequestedUtc
        };
        authorization = authorization with
        {
            AuthorizationHashSha256 = ComputeAuthorizationHashCanonical(authorization)
        };
        return new ReputationProviderAuthorizationDecision
        {
            Accepted = true,
            Failure = ReputationProviderAuthorizationFailure.None,
            Authorization = authorization
        };
    }

    public static ReputationProviderAuthorizationDecision ValidateAuthorization(
        ReputationProviderAuthorization candidate)
    {
        if (candidate == null ||
            candidate.SchemaVersion != ReputationProviderAuthorization.CurrentSchemaVersion)
        {
            return RejectAuthorization(ReputationProviderAuthorizationFailure.InvalidSchemaVersion);
        }

        var decision = Authorize(
            candidate.LookupRequest,
            candidate.Admission,
            candidate.Approval,
            candidate.CredentialSlotId);
        if (!decision.Accepted || decision.Authorization == null)
        {
            return decision;
        }

        if (!IsUtc(candidate.AuthorizedUtc) ||
            candidate.AuthorizedUtc != decision.Authorization.AuthorizedUtc)
        {
            return RejectAuthorization(
                ReputationProviderAuthorizationFailure.InvalidAuthorizationTimestamp);
        }

        var expectedHash = decision.Authorization.AuthorizationHashSha256;
        if (!IsLowerSha256(candidate.AuthorizationHashSha256) ||
            !string.Equals(candidate.AuthorizationHashSha256, expectedHash, StringComparison.Ordinal))
        {
            return RejectAuthorization(ReputationProviderAuthorizationFailure.InvalidAuthorizationHash);
        }

        return decision;
    }

    private static bool TryCanonicalizeAdmission(
        ReputationProviderAdmission? candidate,
        bool requireHash,
        out ReputationProviderAdmission admission,
        out ReputationProviderAuthorizationFailure failure)
    {
        admission = new ReputationProviderAdmission();
        if (candidate == null || candidate.SchemaVersion != ReputationProviderAdmission.CurrentSchemaVersion)
        {
            failure = ReputationProviderAuthorizationFailure.InvalidSchemaVersion;
            return false;
        }

        if (!ReputationLookupContractPolicy.TryCanonicalizeProvider(
                candidate.Provider, out var provider, out _))
        {
            failure = ReputationProviderAuthorizationFailure.InvalidProviderIdentity;
            return false;
        }

        if (!Enum.IsDefined(typeof(ReputationProviderPrivacyKind), candidate.PrivacyKind) ||
            candidate.PrivacyKind == ReputationProviderPrivacyKind.Unknown)
        {
            failure = ReputationProviderAuthorizationFailure.UnknownPrivacyKind;
            return false;
        }

        if (!IsQueryModeCompatible(candidate.PrivacyKind, provider.QueryMode))
        {
            failure = ReputationProviderAuthorizationFailure.PrivacyQueryModeMismatch;
            return false;
        }

        if (!TryCanonicalizeOrigin(candidate.DestinationOrigin, candidate.PrivacyKind,
                out var destinationOrigin))
        {
            failure = ReputationProviderAuthorizationFailure.InvalidDestinationOrigin;
            return false;
        }

        if (!Enum.IsDefined(typeof(ReputationCredentialRequirement), candidate.CredentialRequirement) ||
            candidate.CredentialRequirement == ReputationCredentialRequirement.Unknown)
        {
            failure = ReputationProviderAuthorizationFailure.UnknownCredentialRequirement;
            return false;
        }

        if ((candidate.CredentialRequirement == ReputationCredentialRequirement.Required &&
             !IsCanonicalToken(candidate.CredentialSlotId, MaximumIdentityLength)) ||
            (candidate.CredentialRequirement == ReputationCredentialRequirement.None &&
             candidate.CredentialSlotId is not { Length: 0 }))
        {
            failure = ReputationProviderAuthorizationFailure.InvalidCredentialSlot;
            return false;
        }

        if (!IsCanonicalToken(candidate.PrivacyNoticeVersion, MaximumIdentityLength))
        {
            failure = ReputationProviderAuthorizationFailure.InvalidPrivacyNoticeVersion;
            return false;
        }

        var indicatorKinds = candidate.SupportedIndicatorKinds ?? Array.Empty<ReputationIndicatorKind>();
        if (indicatorKinds.Count is 0 or > MaximumSupportedIndicatorKinds)
        {
            failure = ReputationProviderAuthorizationFailure.IndicatorKindLimitExceeded;
            return false;
        }

        var seen = new HashSet<ReputationIndicatorKind>();
        foreach (var indicatorKind in indicatorKinds)
        {
            if (!Enum.IsDefined(typeof(ReputationIndicatorKind), indicatorKind) ||
                indicatorKind == ReputationIndicatorKind.Unknown)
            {
                failure = ReputationProviderAuthorizationFailure.UnknownIndicatorKind;
                return false;
            }

            if (!seen.Add(indicatorKind))
            {
                failure = ReputationProviderAuthorizationFailure.DuplicateIndicatorKind;
                return false;
            }
        }

        var orderedKinds = indicatorKinds.OrderBy(kind => (int)kind).ToArray();
        if (!indicatorKinds.SequenceEqual(orderedKinds))
        {
            failure = ReputationProviderAuthorizationFailure.NoncanonicalIndicatorOrder;
            return false;
        }

        if (!AreLimitsValid(candidate.Limits))
        {
            failure = ReputationProviderAuthorizationFailure.InvalidResourceLimits;
            return false;
        }

        admission = candidate with
        {
            Provider = provider,
            DestinationOrigin = destinationOrigin,
            SupportedIndicatorKinds = new ReadOnlyCollection<ReputationIndicatorKind>(orderedKinds),
            Limits = candidate.Limits with { }
        };
        var expectedHash = ComputeAdmissionHashCanonical(admission);
        if (requireHash &&
            (!IsLowerSha256(candidate.AdmissionHashSha256) ||
             !string.Equals(candidate.AdmissionHashSha256, expectedHash, StringComparison.Ordinal)))
        {
            failure = ReputationProviderAuthorizationFailure.InvalidAdmissionHash;
            return false;
        }

        admission = admission with { AdmissionHashSha256 = expectedHash };
        failure = ReputationProviderAuthorizationFailure.None;
        return true;
    }

    private static bool TryCanonicalizeApproval(
        ReputationProviderApproval? candidate,
        ReputationProviderAdmission admission,
        bool requireHash,
        out ReputationProviderApproval approval,
        out ReputationProviderAuthorizationFailure failure)
    {
        approval = new ReputationProviderApproval();
        if (candidate == null || candidate.SchemaVersion != ReputationProviderApproval.CurrentSchemaVersion)
        {
            failure = ReputationProviderAuthorizationFailure.InvalidApproval;
            return false;
        }

        if (admission.PrivacyKind != ReputationProviderPrivacyKind.ExternalIndicatorDisclosure)
        {
            failure = ReputationProviderAuthorizationFailure.UnexpectedApproval;
            return false;
        }

        if (!ReputationLookupContractPolicy.TryCanonicalizeProvider(
                candidate.Provider, out var provider, out _) ||
            !ProviderEquals(provider, admission.Provider) ||
            !string.Equals(candidate.AdmissionHashSha256, admission.AdmissionHashSha256,
                StringComparison.Ordinal) ||
            !string.Equals(candidate.PrivacyNoticeVersion, admission.PrivacyNoticeVersion,
                StringComparison.Ordinal))
        {
            failure = ReputationProviderAuthorizationFailure.ApprovalMismatch;
            return false;
        }

        if (!IsCanonicalToken(candidate.AnalystId, MaximumIdentityLength) ||
            !IsUtc(candidate.ApprovedUtc))
        {
            failure = ReputationProviderAuthorizationFailure.InvalidApproval;
            return false;
        }

        if (!candidate.ExternalIndicatorDisclosureAccepted)
        {
            failure = ReputationProviderAuthorizationFailure.ExternalDisclosureNotApproved;
            return false;
        }

        approval = candidate with { Provider = provider };
        var expectedHash = ComputeApprovalHashCanonical(approval);
        if (requireHash &&
            (!IsLowerSha256(candidate.ApprovalHashSha256) ||
             !string.Equals(candidate.ApprovalHashSha256, expectedHash, StringComparison.Ordinal)))
        {
            failure = ReputationProviderAuthorizationFailure.InvalidApproval;
            return false;
        }

        approval = approval with { ApprovalHashSha256 = expectedHash };
        failure = ReputationProviderAuthorizationFailure.None;
        return true;
    }

    private static bool TryValidateCredentialSlot(
        ReputationProviderAdmission admission,
        string? credentialSlotId,
        out ReputationProviderAuthorizationFailure failure)
    {
        if (credentialSlotId == null ||
            (admission.CredentialRequirement == ReputationCredentialRequirement.Required &&
             (!IsCanonicalToken(credentialSlotId, MaximumIdentityLength) ||
              !string.Equals(credentialSlotId, admission.CredentialSlotId, StringComparison.Ordinal))) ||
            (admission.CredentialRequirement == ReputationCredentialRequirement.None &&
             credentialSlotId.Length != 0))
        {
            failure = ReputationProviderAuthorizationFailure.CredentialSlotMismatch;
            return false;
        }

        failure = ReputationProviderAuthorizationFailure.None;
        return true;
    }

    private static bool IsQueryModeCompatible(
        ReputationProviderPrivacyKind privacyKind,
        ReputationQueryMode queryMode) =>
        privacyKind switch
        {
            ReputationProviderPrivacyKind.LocalOnly => queryMode is
                ReputationQueryMode.LocalCache or
                ReputationQueryMode.LocalReference or
                ReputationQueryMode.AnalystList,
            ReputationProviderPrivacyKind.ExternalIndicatorDisclosure =>
                queryMode == ReputationQueryMode.ExternalService,
            _ => false
        };

    private static bool TryCanonicalizeOrigin(
        string? candidate,
        ReputationProviderPrivacyKind privacyKind,
        out string origin)
    {
        origin = string.Empty;
        if (candidate is not { Length: > 0 } || candidate.Length > MaximumOriginLength ||
            !Uri.TryCreate(candidate, UriKind.Absolute, out var uri) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            uri.AbsolutePath != "/" ||
            uri.HostNameType is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6))
        {
            return false;
        }

        var canonicalOrigin = uri.GetLeftPart(UriPartial.Authority);
        if (!string.Equals(candidate, canonicalOrigin, StringComparison.Ordinal))
        {
            return false;
        }

        if (uri.HostNameType == UriHostNameType.Dns &&
            (!IsCanonicalDomain(uri.IdnHost) ||
             !string.Equals(uri.Host, uri.IdnHost, StringComparison.Ordinal)))
        {
            return false;
        }

        var numericHost = IPAddress.TryParse(uri.IdnHost, out var address);
        if (privacyKind == ReputationProviderPrivacyKind.LocalOnly)
        {
            if (uri.Scheme is not ("http" or "https") || !numericHost ||
                address == null || !IPAddress.IsLoopback(address))
            {
                return false;
            }
        }
        else if (privacyKind == ReputationProviderPrivacyKind.ExternalIndicatorDisclosure)
        {
            if (uri.Scheme != "https" ||
                (numericHost && address != null && IPAddress.IsLoopback(address)) ||
                (!numericHost &&
                 (string.Equals(uri.IdnHost, "localhost", StringComparison.Ordinal) ||
                  uri.IdnHost.EndsWith(".localhost", StringComparison.Ordinal))))
            {
                return false;
            }
        }
        else
        {
            return false;
        }

        origin = canonicalOrigin;
        return true;
    }

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
                    character is not (>= 'a' and <= 'z') and
                    not (>= '0' and <= '9') and not '-'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool AreLimitsValid(ReputationProviderResourceLimits? limits) =>
        limits != null &&
        limits.RequestTimeoutSeconds is >= 1 and <= MaximumRequestTimeoutSeconds &&
        limits.MaximumResponseLength is >= 1 and <= MaximumResponseLength &&
        limits.MaximumConcurrency is >= 1 and <= MaximumConcurrency &&
        limits.MaximumRequestsPerMinute is >= 1 and <= MaximumRequestsPerMinute &&
        limits.MaximumRequestsPerDay is >= 1 and <= MaximumRequestsPerDay &&
        limits.MaximumRequestsPerDay >= limits.MaximumRequestsPerMinute;

    private static bool ProviderEquals(
        ReputationProviderIdentity left,
        ReputationProviderIdentity right) =>
        string.Equals(left.ProviderId, right.ProviderId, StringComparison.Ordinal) &&
        string.Equals(left.ProviderVersion, right.ProviderVersion, StringComparison.Ordinal) &&
        string.Equals(left.DatasetId, right.DatasetId, StringComparison.Ordinal) &&
        string.Equals(left.DatasetVersion, right.DatasetVersion, StringComparison.Ordinal) &&
        left.QueryMode == right.QueryMode;

    private static string ComputeAdmissionHashCanonical(ReputationProviderAdmission admission)
    {
        var builder = new StringBuilder();
        Append(builder, admission.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        AppendProvider(builder, admission.Provider);
        Append(builder, ((int)admission.PrivacyKind).ToString(CultureInfo.InvariantCulture));
        Append(builder, admission.DestinationOrigin);
        Append(builder, ((int)admission.CredentialRequirement).ToString(CultureInfo.InvariantCulture));
        Append(builder, admission.CredentialSlotId);
        Append(builder, admission.PrivacyNoticeVersion);
        foreach (var kind in admission.SupportedIndicatorKinds)
        {
            Append(builder, ((int)kind).ToString(CultureInfo.InvariantCulture));
        }

        Append(builder, admission.Limits.RequestTimeoutSeconds.ToString(CultureInfo.InvariantCulture));
        Append(builder, admission.Limits.MaximumResponseLength.ToString(CultureInfo.InvariantCulture));
        Append(builder, admission.Limits.MaximumConcurrency.ToString(CultureInfo.InvariantCulture));
        Append(builder, admission.Limits.MaximumRequestsPerMinute.ToString(CultureInfo.InvariantCulture));
        Append(builder, admission.Limits.MaximumRequestsPerDay.ToString(CultureInfo.InvariantCulture));
        return Hash(builder);
    }

    private static string ComputeApprovalHashCanonical(ReputationProviderApproval approval)
    {
        var builder = new StringBuilder();
        Append(builder, approval.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        AppendProvider(builder, approval.Provider);
        Append(builder, approval.AdmissionHashSha256);
        Append(builder, approval.PrivacyNoticeVersion);
        Append(builder, approval.AnalystId);
        Append(builder, approval.ApprovedUtc.ToString("O", CultureInfo.InvariantCulture));
        Append(builder, approval.ExternalIndicatorDisclosureAccepted ? "1" : "0");
        return Hash(builder);
    }

    private static string ComputeAuthorizationHashCanonical(ReputationProviderAuthorization authorization)
    {
        var builder = new StringBuilder();
        Append(builder, authorization.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        AppendRequest(builder, authorization.LookupRequest);
        Append(builder, authorization.Admission.AdmissionHashSha256);
        Append(builder, authorization.Approval?.ApprovalHashSha256 ?? string.Empty);
        Append(builder, authorization.CredentialSlotId);
        Append(builder, authorization.AuthorizedUtc.ToString("O", CultureInfo.InvariantCulture));
        return Hash(builder);
    }

    private static void AppendRequest(StringBuilder builder, ReputationLookupRequest request)
    {
        Append(builder, request.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(builder, request.RequestId);
        Append(builder, ((int)request.Initiation).ToString(CultureInfo.InvariantCulture));
        Append(builder, ((int)request.Indicator.Kind).ToString(CultureInfo.InvariantCulture));
        Append(builder, request.Indicator.Value);
        Append(builder, request.EvidenceIdentity.CaseId);
        Append(builder, request.EvidenceIdentity.EvidenceSessionId);
        Append(builder, request.EvidenceIdentity.CaptureId);
        Append(builder, request.EvidenceIdentity.SourceIdentityId);
        Append(builder, request.EvidenceIdentity.HostId);
        Append(builder, request.EvidenceIdentity.ExecutionRootId);
        Append(builder, request.SourceRunId);
        Append(builder, request.RequestedUtc.ToString("O", CultureInfo.InvariantCulture));
        foreach (var reference in request.EvidenceReferences)
        {
            Append(builder, ((int)reference.Kind).ToString(CultureInfo.InvariantCulture));
            Append(builder, reference.Id);
        }
    }

    private static void AppendProvider(StringBuilder builder, ReputationProviderIdentity provider)
    {
        Append(builder, provider.ProviderId);
        Append(builder, provider.ProviderVersion);
        Append(builder, provider.DatasetId);
        Append(builder, provider.DatasetVersion);
        Append(builder, ((int)provider.QueryMode).ToString(CultureInfo.InvariantCulture));
    }

    private static string Hash(StringBuilder builder) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())))
            .ToLowerInvariant();

    private static void Append(StringBuilder builder, string value) =>
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture))
            .Append(':')
            .Append(value)
            .Append('\n');

    private static bool IsCanonicalToken(string? value, int maximumLength) =>
        value is { Length: > 0 } && value.Length <= maximumLength &&
        value[0] is (>= 'a' and <= 'z') or (>= '0' and <= '9') &&
        value.All(character =>
            character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '_' or ':' or '-');

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static bool IsUtc(DateTime value) =>
        value != default && value.Kind == DateTimeKind.Utc;

    private static ReputationProviderAdmissionDecision RejectAdmission(
        ReputationProviderAuthorizationFailure failure) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = Diagnostic(failure)
        };

    private static ReputationProviderApprovalDecision RejectApproval(
        ReputationProviderAuthorizationFailure failure) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = Diagnostic(failure)
        };

    private static ReputationProviderAuthorizationDecision RejectAuthorization(
        ReputationProviderAuthorizationFailure failure) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = Diagnostic(failure)
        };

    private static string Diagnostic(ReputationProviderAuthorizationFailure failure) =>
        failure switch
        {
            ReputationProviderAuthorizationFailure.InvalidSchemaVersion =>
                "The reputation provider authorization schema version is unsupported.",
            ReputationProviderAuthorizationFailure.InvalidLookupRequest =>
                "The reputation provider authorization does not contain a valid #399 request.",
            ReputationProviderAuthorizationFailure.InvalidProviderIdentity =>
                "The reputation provider or dataset identity is invalid.",
            ReputationProviderAuthorizationFailure.UnknownPrivacyKind =>
                "The reputation provider privacy classification is unknown.",
            ReputationProviderAuthorizationFailure.PrivacyQueryModeMismatch =>
                "The reputation provider privacy classification and query mode disagree.",
            ReputationProviderAuthorizationFailure.InvalidDestinationOrigin =>
                "The reputation provider destination origin is invalid for its privacy classification.",
            ReputationProviderAuthorizationFailure.UnknownCredentialRequirement =>
                "The reputation provider credential requirement is unknown.",
            ReputationProviderAuthorizationFailure.InvalidCredentialSlot =>
                "The reputation provider credential-slot reference is invalid.",
            ReputationProviderAuthorizationFailure.InvalidPrivacyNoticeVersion =>
                "The reputation provider privacy-notice version is invalid.",
            ReputationProviderAuthorizationFailure.IndicatorKindLimitExceeded =>
                "The reputation provider supported-indicator set is empty or exceeds its bound.",
            ReputationProviderAuthorizationFailure.UnknownIndicatorKind =>
                "The reputation provider admits an unknown indicator kind.",
            ReputationProviderAuthorizationFailure.DuplicateIndicatorKind =>
                "The reputation provider supported-indicator set contains a duplicate.",
            ReputationProviderAuthorizationFailure.NoncanonicalIndicatorOrder =>
                "The reputation provider supported-indicator set is not canonically ordered.",
            ReputationProviderAuthorizationFailure.InvalidResourceLimits =>
                "The reputation provider resource limits are invalid or exceed policy ceilings.",
            ReputationProviderAuthorizationFailure.InvalidAdmissionHash =>
                "The reputation provider admission identity is missing or mismatched.",
            ReputationProviderAuthorizationFailure.UnsupportedIndicatorKind =>
                "The selected reputation provider does not admit this indicator kind.",
            ReputationProviderAuthorizationFailure.MissingApproval =>
                "External reputation indicator disclosure requires exact analyst approval.",
            ReputationProviderAuthorizationFailure.UnexpectedApproval =>
                "A local-only reputation provider cannot consume external-disclosure approval.",
            ReputationProviderAuthorizationFailure.InvalidApproval =>
                "The reputation provider approval is invalid or has identity drift.",
            ReputationProviderAuthorizationFailure.ApprovalMismatch =>
                "The reputation provider approval does not match the exact admission and notice.",
            ReputationProviderAuthorizationFailure.ExternalDisclosureNotApproved =>
                "External reputation indicator disclosure was not explicitly approved.",
            ReputationProviderAuthorizationFailure.ApprovalAfterRequest =>
                "The reputation provider approval postdates the lookup request.",
            ReputationProviderAuthorizationFailure.CredentialSlotMismatch =>
                "The reputation provider credential-slot assertion does not match the admission.",
            ReputationProviderAuthorizationFailure.InvalidAuthorizationTimestamp =>
                "The reputation provider authorization timestamp is invalid or mismatched.",
            ReputationProviderAuthorizationFailure.InvalidAuthorizationHash =>
                "The reputation provider authorization identity is missing or mismatched.",
            _ => "The reputation provider authorization violates the portable policy."
        };
}
