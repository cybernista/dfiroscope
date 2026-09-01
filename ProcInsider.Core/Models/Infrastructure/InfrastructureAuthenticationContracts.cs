using System.Security.Cryptography;
using ProcInsider.Models.Agent;

namespace ProcInsider.Models.Infrastructure;

public enum InfrastructureIdentityKind
{
    Unknown = 0,
    AgentService = 1,
    ViewerUser = 2
}

public enum InfrastructureCredentialLifecycleState
{
    Unknown = 0,
    Active = 1,
    Rotated = 2,
    Expired = 3,
    Revoked = 4,
    Compromised = 5
}

public enum InfrastructureViewerRole
{
    Unknown = 0,
    Administrator = 1,
    Operator = 2,
    Analyst = 3,
    Reader = 4
}

public enum InfrastructureAuthenticationFailure
{
    None = 0,
    InvalidRequest = 1,
    IdentityUnknown = 2,
    IdentityDisabled = 3,
    IdentityMismatch = 4,
    HostBindingMismatch = 5,
    EndpointMismatch = 6,
    ProtocolIncompatible = 7,
    ReleaseIncompatible = 8,
    CredentialEpochMismatch = 9,
    CredentialRotated = 10,
    CredentialExpired = 11,
    CredentialRevoked = 12,
    CredentialCompromised = 13,
    CertificateMismatch = 14,
    CertificateProfileMismatch = 15,
    CertificateChainRejected = 16,
    CertificateOutsideValidity = 17,
    MutualTlsProofMissing = 18,
    FreshProofInvalid = 19,
    ClockSkewRejected = 20,
    ConnectionGenerationInvalid = 21,
    ConnectionDuplicate = 22,
    ConnectionReplayed = 23,
    ViewerRoleUnavailable = 24,
    AuditUnavailable = 25
}

public enum InfrastructureAuditAction
{
    Unknown = 0,
    EnrollmentTokenCreated = 1,
    EnrollmentAttempted = 2,
    EnrollmentCompleted = 3,
    CredentialAuthenticated = 4,
    AuthenticationDenied = 5,
    CredentialRotated = 6,
    CredentialRevoked = 7,
    CredentialCompromised = 8,
    ViewerIdentityEnabled = 9,
    SessionReplaced = 10,
    HealthDisclosed = 11,
    HealthDisclosureDenied = 12,
    CommandAuthorized = 13,
    CommandAuthorizationDenied = 14,
    CommandDispatched = 15,
    CommandResultReceived = 16,
    EvidencePrepared = 17,
    EvidenceAdmissionDenied = 18,
    EvidenceCommitted = 19,
    EvidenceConflict = 20,
    EvidenceAcknowledged = 21,
    CaseRevisionDisclosed = 22,
    CaseQueryDisclosed = 23,
    CaseQueryDenied = 24,
    CaseAnnotationAuthorized = 25,
    CaseAnnotationDenied = 26,
    CaseGrantUpdated = 27,
    CaseGrantRevoked = 28
}

public enum InfrastructureAuditOutcome
{
    Unknown = 0,
    Allowed = 1,
    Denied = 2,
    Failed = 3
}

public enum InfrastructureEnrollmentRedemptionOutcome
{
    Unknown = 0,
    Redeemed = 1,
    TokenUnknown = 2,
    TokenInvalid = 3,
    TokenExpired = 4,
    TokenLocked = 5,
    TokenAlreadyUsed = 6
}

/// <summary>
/// Stable application certificate profiles. The private 2.25 OIDs are UUID-derived,
/// globally unique values; each profile also requires the applicable standard TLS EKU.
/// </summary>
public static class InfrastructureCertificateProfiles
{
    public const string ServerTlsOid = "2.25.68206011533713495728376599780635181057";
    public const string AgentClientOid = "2.25.68206011533713495728376599780635181058";
    public const string ViewerClientOid = "2.25.68206011533713495728376599780635181059";
    public const string TlsServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
    public const string TlsClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

    public static string ForIdentity(InfrastructureIdentityKind kind) => kind switch
    {
        InfrastructureIdentityKind.AgentService => AgentClientOid,
        InfrastructureIdentityKind.ViewerUser => ViewerClientOid,
        _ => string.Empty
    };
}

/// <summary>
/// In-memory holder for a single-use 256-bit enrollment token. It never exposes the
/// token through ToString and zeroes the owned buffer on disposal.
/// </summary>
public sealed class InfrastructureEnrollmentToken : IDisposable
{
    public const int ByteLength = 32;
    private byte[]? _bytes;

    public InfrastructureEnrollmentToken(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
        {
            throw new ArgumentException("An enrollment token must contain exactly 256 bits.", nameof(bytes));
        }

        _bytes = bytes.ToArray();
    }

    public static InfrastructureEnrollmentToken Create()
    {
        var bytes = RandomNumberGenerator.GetBytes(ByteLength);
        try
        {
            return new InfrastructureEnrollmentToken(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public byte[] CopyBytes() =>
        _bytes?.ToArray() ?? throw new ObjectDisposedException(nameof(InfrastructureEnrollmentToken));

    public override string ToString() => "<redacted-enrollment-token>";

    public void Dispose()
    {
        var bytes = Interlocked.Exchange(ref _bytes, null);
        if (bytes != null)
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}

public sealed record InfrastructureEnrollmentTarget
{
    public InfrastructureIdentityKind IdentityKind { get; init; }

    public string IdentityId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string ViewerUserId { get; init; } = string.Empty;

    public string ServerUri { get; init; } = string.Empty;

    public string AuthorityChainSha256 { get; init; } = string.Empty;
}

public sealed record InfrastructureEnrollmentTokenRecord
{
    public string TokenId { get; init; } = string.Empty;

    public InfrastructureEnrollmentTarget Target { get; init; } = new();

    public byte[] Salt { get; init; } = Array.Empty<byte>();

    public byte[] TokenHash { get; init; } = Array.Empty<byte>();

    public DateTime CreatedAtUtc { get; init; }

    public DateTime ExpiresAtUtc { get; init; }

    public int FailedAttempts { get; init; }

    public DateTime? UsedAtUtc { get; init; }

    public DateTime? LockedAtUtc { get; init; }
}

public sealed record InfrastructureEnrollmentRedemption(
    InfrastructureEnrollmentRedemptionOutcome Outcome,
    InfrastructureEnrollmentTarget? Target,
    int FailedAttempts);

public sealed record InfrastructureEnrollmentBundle : IDisposable
{
    public string TokenId { get; init; } = string.Empty;

    public InfrastructureEnrollmentTarget Target { get; init; } = new();

    public InfrastructureEnrollmentToken Token { get; init; } =
        new(new byte[InfrastructureEnrollmentToken.ByteLength]);

    public DateTime ExpiresAtUtc { get; init; }

    public void Dispose() => Token.Dispose();
}

public sealed record InfrastructureCredentialRecord
{
    public InfrastructureIdentityKind IdentityKind { get; init; }

    public string IdentityId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string ViewerUserId { get; init; } = string.Empty;

    public bool ViewerEnabled { get; init; }

    public InfrastructureViewerRole ViewerRole { get; init; }

    public InfrastructureCredentialLifecycleState State { get; init; }

    public long CredentialEpoch { get; init; }

    public string CertificateSha256 { get; init; } = string.Empty;

    public string CertificateProfileOid { get; init; } = string.Empty;

    public string IssuerId { get; init; } = string.Empty;

    public DateTime NotBeforeUtc { get; init; }

    public DateTime NotAfterUtc { get; init; }

    public string ServerUri { get; init; } = string.Empty;

    public int ProtocolGeneration { get; init; }

    public string ReleaseId { get; init; } = string.Empty;

    public DateTime UpdatedAtUtc { get; init; }
}

public sealed record InfrastructureMutualAuthenticationRequest
{
    public InfrastructureIdentityKind IdentityKind { get; init; }

    public string IdentityId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string ViewerUserId { get; init; } = string.Empty;

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public string CertificateSha256 { get; init; } = string.Empty;

    public string CertificateProfileOid { get; init; } = string.Empty;

    public string ServerUri { get; init; } = string.Empty;

    public int ProtocolGeneration { get; init; }

    public string ReleaseId { get; init; } = string.Empty;

    public byte[] SessionChallenge { get; init; } = Array.Empty<byte>();

    public DateTime ProofCreatedAtUtc { get; init; }

    public bool ServerCertificateVerified { get; init; }

    public bool ClientCertificateChainVerified { get; init; }

    public bool MutualTlsProofVerified { get; init; }

    public bool FreshCredentialProofVerified { get; init; }

    public AgentAuthorizationScope AgentScope { get; init; } = new();

    public IReadOnlyList<AgentCommandKind> AgentCommandCapabilities { get; init; } =
        Array.Empty<AgentCommandKind>();
}

/// <summary>
/// One bounded Server-issued nonce for an exact identity and proposed connection
/// generation. The nonce is ephemeral, single-use, and never persisted or audited.
/// </summary>
public sealed record InfrastructureAuthenticationChallenge
{
    public string IdentityId { get; init; } = string.Empty;

    public Guid ConnectionGeneration { get; init; }

    public byte[] SessionChallenge { get; init; } = Array.Empty<byte>();

    public DateTime IssuedAtUtc { get; init; }

    public DateTime ExpiresAtUtc { get; init; }

    public override string ToString() =>
        $"InfrastructureAuthenticationChallenge {{ IdentityId = {IdentityId}, " +
        $"ConnectionGeneration = {ConnectionGeneration}, SessionChallenge = <redacted>, " +
        $"IssuedAtUtc = {IssuedAtUtc:O}, ExpiresAtUtc = {ExpiresAtUtc:O} }}";
}

public sealed record AuthenticatedInfrastructureViewerContext
{
    public string ViewerUserId { get; init; } = string.Empty;

    public InfrastructureViewerRole Role { get; init; }

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public int ProtocolGeneration { get; init; }

    public string ReleaseId { get; init; } = string.Empty;

    public DateTime AuthenticatedAtUtc { get; init; }

    public DateTime FreshUntilUtc { get; init; }
}

public sealed record InfrastructureAuthenticationDecision
{
    public bool Allowed { get; init; }

    public InfrastructureAuthenticationFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public AuthenticatedAgentContext? Agent { get; init; }

    public AuthenticatedInfrastructureViewerContext? Viewer { get; init; }
}

public sealed record InfrastructureAuthenticationAuditEvent
{
    public string EventId { get; init; } = string.Empty;

    public InfrastructureAuditAction Action { get; init; }

    public InfrastructureAuditOutcome Outcome { get; init; }

    public string ActorIdentityId { get; init; } = string.Empty;

    public InfrastructureIdentityKind IdentityKind { get; init; }

    public string IdentityId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string ViewerUserId { get; init; } = string.Empty;

    public string CaseId { get; init; } = string.Empty;

    public string CaptureId { get; init; } = string.Empty;

    public string TargetSessionId { get; init; } = string.Empty;

    public string DatabaseIdentity { get; init; } = string.Empty;

    public AgentCommandKind CommandKind { get; init; }

    public long AuthorizationRevision { get; init; }

    public long ServerSessionGeneration { get; init; }

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public string CorrelationId { get; init; } = string.Empty;

    public string ReasonCode { get; init; } = string.Empty;

    public DateTime EmittedAtUtc { get; init; }
}

public static class InfrastructureEnrollmentTokenHash
{
    public const int SaltLength = 32;
    public const int HashLength = 32;

    public static byte[] CreateSalt() => RandomNumberGenerator.GetBytes(SaltLength);

    public static byte[] Compute(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> token)
    {
        if (salt.Length != SaltLength || token.Length != InfrastructureEnrollmentToken.ByteLength)
        {
            throw new ArgumentException("Enrollment token hashing requires a 256-bit salt and token.");
        }

        Span<byte> input = stackalloc byte[SaltLength + InfrastructureEnrollmentToken.ByteLength];
        try
        {
            salt.CopyTo(input);
            token.CopyTo(input[SaltLength..]);
            return SHA256.HashData(input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    public static bool Verify(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> expectedHash)
    {
        if (expectedHash.Length != HashLength)
        {
            return false;
        }

        var actual = Compute(salt, token);
        try
        {
            return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }
}

public static class InfrastructureCredentialLifecyclePolicy
{
    public static readonly TimeSpan MaximumIssuerOverlap = TimeSpan.FromDays(30);
    public static readonly TimeSpan MaximumAgentCredentialLifetime = TimeSpan.FromDays(30);
    public static readonly TimeSpan MaximumViewerCredentialLifetime = TimeSpan.FromHours(8);
    public static readonly TimeSpan MaximumServerCertificateLifetime = TimeSpan.FromDays(397);
    public static readonly TimeSpan MaximumEnrollmentIssuerLifetime = TimeSpan.FromDays(731);

    public static bool IsRenewalDue(InfrastructureCredentialRecord credential, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (nowUtc.Kind != DateTimeKind.Utc || credential.NotBeforeUtc.Kind != DateTimeKind.Utc ||
            credential.NotAfterUtc.Kind != DateTimeKind.Utc || credential.NotAfterUtc <= credential.NotBeforeUtc)
        {
            return false;
        }

        var lifetime = credential.NotAfterUtc - credential.NotBeforeUtc;
        return nowUtc >= credential.NotAfterUtc - TimeSpan.FromTicks(lifetime.Ticks / 3);
    }

    public static bool IsIssuerOverlapAllowed(DateTime overlapStartsUtc, DateTime overlapEndsUtc) =>
        overlapStartsUtc.Kind == DateTimeKind.Utc &&
        overlapEndsUtc.Kind == DateTimeKind.Utc &&
        overlapEndsUtc >= overlapStartsUtc &&
        overlapEndsUtc - overlapStartsUtc <= MaximumIssuerOverlap;

    public static bool IsCredentialLifetimeAllowed(
        InfrastructureIdentityKind identityKind,
        DateTime notBeforeUtc,
        DateTime notAfterUtc)
    {
        if (notBeforeUtc.Kind != DateTimeKind.Utc || notAfterUtc.Kind != DateTimeKind.Utc ||
            notAfterUtc <= notBeforeUtc)
        {
            return false;
        }

        var maximum = identityKind switch
        {
            InfrastructureIdentityKind.AgentService => MaximumAgentCredentialLifetime,
            InfrastructureIdentityKind.ViewerUser => MaximumViewerCredentialLifetime,
            _ => TimeSpan.Zero
        };
        return maximum > TimeSpan.Zero && notAfterUtc - notBeforeUtc <= maximum;
    }
}

/// <summary>
/// Pure post-cryptography policy. Chain, TLS and signature adapters report verified
/// facts; this policy binds them to enrollment state before producing an identity.
/// </summary>
public static class InfrastructureAuthenticationPolicy
{
    public const int MaximumClockSkewMinutes = 5;
    public static readonly TimeSpan MaximumAuthenticationFreshness = TimeSpan.FromSeconds(30);

    public static InfrastructureAuthenticationDecision Evaluate(
        InfrastructureMutualAuthenticationRequest request,
        InfrastructureCredentialRecord? credential,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!IsWellFormedRequest(request) || nowUtc.Kind != DateTimeKind.Utc)
        {
            return Deny(InfrastructureAuthenticationFailure.InvalidRequest,
                "The mutual-authentication request is incomplete or malformed.");
        }

        if (credential == null)
        {
            return Deny(InfrastructureAuthenticationFailure.IdentityUnknown,
                "The presented identity is not enrolled.");
        }

        var bindingFailure = ValidateBinding(request, credential);
        if (bindingFailure != InfrastructureAuthenticationFailure.None)
        {
            return Deny(bindingFailure, "The credential is not bound to the exact requested identity and endpoint.");
        }

        var lifecycleFailure = credential.State switch
        {
            InfrastructureCredentialLifecycleState.Active => InfrastructureAuthenticationFailure.None,
            InfrastructureCredentialLifecycleState.Rotated => InfrastructureAuthenticationFailure.CredentialRotated,
            InfrastructureCredentialLifecycleState.Expired => InfrastructureAuthenticationFailure.CredentialExpired,
            InfrastructureCredentialLifecycleState.Revoked => InfrastructureAuthenticationFailure.CredentialRevoked,
            InfrastructureCredentialLifecycleState.Compromised => InfrastructureAuthenticationFailure.CredentialCompromised,
            _ => InfrastructureAuthenticationFailure.IdentityDisabled
        };
        if (lifecycleFailure != InfrastructureAuthenticationFailure.None)
        {
            return Deny(lifecycleFailure, "The credential lifecycle state is not eligible.");
        }

        if (nowUtc < credential.NotBeforeUtc || nowUtc > credential.NotAfterUtc)
        {
            return Deny(InfrastructureAuthenticationFailure.CertificateOutsideValidity,
                "Expired or not-yet-valid credentials receive no authorization grace.");
        }

        if (!request.ServerCertificateVerified || !request.ClientCertificateChainVerified)
        {
            return Deny(InfrastructureAuthenticationFailure.CertificateChainRejected,
                "Both endpoint certificate chains and the configured Server pin must validate.");
        }

        if (!request.MutualTlsProofVerified)
        {
            return Deny(InfrastructureAuthenticationFailure.MutualTlsProofMissing,
                "TLS key possession alone did not establish the required mutual session proof.");
        }

        if (!request.FreshCredentialProofVerified)
        {
            return Deny(InfrastructureAuthenticationFailure.FreshProofInvalid,
                "The credential did not prove the fresh session challenge.");
        }

        var skew = (nowUtc - request.ProofCreatedAtUtc).Duration();
        if (skew > TimeSpan.FromMinutes(MaximumClockSkewMinutes))
        {
            return Deny(InfrastructureAuthenticationFailure.ClockSkewRejected,
                "The authentication proof exceeds the five-minute clock-skew limit.");
        }

        return request.IdentityKind switch
        {
            InfrastructureIdentityKind.AgentService => AllowAgent(request, credential, nowUtc),
            InfrastructureIdentityKind.ViewerUser => AllowViewer(request, credential, nowUtc),
            _ => Deny(InfrastructureAuthenticationFailure.InvalidRequest,
                "The identity profile is unknown.")
        };
    }

    private static InfrastructureAuthenticationDecision AllowAgent(
        InfrastructureMutualAuthenticationRequest request,
        InfrastructureCredentialRecord credential,
        DateTime nowUtc)
    {
        var freshUntil = Min(nowUtc + MaximumAuthenticationFreshness, credential.NotAfterUtc);
        var candidate = new AgentAuthenticationCandidate
        {
            Context = new AuthenticatedAgentContext
            {
                AgentId = credential.AgentId,
                HostId = credential.HostId,
                AuthenticationKind = AgentAuthenticationKind.EnrolledWindowsService,
                EnrollmentState = AgentEnrollmentState.Active,
                CredentialEpoch = credential.CredentialEpoch,
                ConnectionGeneration = request.ConnectionGeneration,
                ProtocolContractVersion = request.ProtocolGeneration,
                ReleaseId = request.ReleaseId,
                ReleaseMatch = AgentReleaseProfileMatch.Match,
                AuthenticatedAtUtc = nowUtc,
                FreshUntilUtc = freshUntil,
                CommandCapabilities = Array.AsReadOnly(request.AgentCommandCapabilities.ToArray()),
                Scope = request.AgentScope with { },
                IsAuthoritativeEvidenceWriter = true
            },
            CredentialStatus = AgentCredentialStatus.Active,
            ConnectionStatus = AgentConnectionStatus.Current,
            CredentialProofVerified = true,
            HostBindingVerified = true,
            ProtocolCompatible = true
        };
        var decision = AgentAuthenticationPolicy.Evaluate(candidate, nowUtc);
        return decision.Allowed
            ? new InfrastructureAuthenticationDecision
            {
                Allowed = true,
                Diagnostic = "The enrolled Agent proved the current credential and connection generation.",
                Agent = decision.Context
            }
            : Deny(InfrastructureAuthenticationFailure.InvalidRequest, decision.Diagnostic);
    }

    private static InfrastructureAuthenticationDecision AllowViewer(
        InfrastructureMutualAuthenticationRequest request,
        InfrastructureCredentialRecord credential,
        DateTime nowUtc)
    {
        if (!credential.ViewerEnabled)
        {
            return Deny(InfrastructureAuthenticationFailure.IdentityDisabled,
                "The separately enrolled Viewer identity is disabled by default.");
        }

        if (credential.ViewerRole == InfrastructureViewerRole.Unknown)
        {
            return Deny(InfrastructureAuthenticationFailure.ViewerRoleUnavailable,
                "The Viewer identity has no bounded role mapping.");
        }

        return new InfrastructureAuthenticationDecision
        {
            Allowed = true,
            Diagnostic = "The separately enrolled Viewer identity authenticated; exact grants remain required.",
            Viewer = new AuthenticatedInfrastructureViewerContext
            {
                ViewerUserId = credential.ViewerUserId,
                Role = credential.ViewerRole,
                CredentialEpoch = credential.CredentialEpoch,
                ConnectionGeneration = request.ConnectionGeneration,
                ProtocolGeneration = request.ProtocolGeneration,
                ReleaseId = request.ReleaseId,
                AuthenticatedAtUtc = nowUtc,
                FreshUntilUtc = Min(nowUtc + MaximumAuthenticationFreshness, credential.NotAfterUtc)
            }
        };
    }

    private static InfrastructureAuthenticationFailure ValidateBinding(
        InfrastructureMutualAuthenticationRequest request,
        InfrastructureCredentialRecord credential)
    {
        if (request.IdentityKind != credential.IdentityKind ||
            !Equal(request.IdentityId, credential.IdentityId))
        {
            return InfrastructureAuthenticationFailure.IdentityMismatch;
        }

        if (request.IdentityKind == InfrastructureIdentityKind.AgentService &&
            (!Equal(request.AgentId, credential.AgentId) || !Equal(request.HostId, credential.HostId)))
        {
            return InfrastructureAuthenticationFailure.HostBindingMismatch;
        }

        if (request.IdentityKind == InfrastructureIdentityKind.ViewerUser &&
            !Equal(request.ViewerUserId, credential.ViewerUserId))
        {
            return InfrastructureAuthenticationFailure.IdentityMismatch;
        }

        if (!UriEquals(request.ServerUri, credential.ServerUri))
        {
            return InfrastructureAuthenticationFailure.EndpointMismatch;
        }

        if (request.ProtocolGeneration != credential.ProtocolGeneration)
        {
            return InfrastructureAuthenticationFailure.ProtocolIncompatible;
        }

        if (!Equal(request.ReleaseId, credential.ReleaseId))
        {
            return InfrastructureAuthenticationFailure.ReleaseIncompatible;
        }

        if (request.CredentialEpoch != credential.CredentialEpoch)
        {
            return InfrastructureAuthenticationFailure.CredentialEpochMismatch;
        }

        if (!Equal(request.CertificateSha256, credential.CertificateSha256))
        {
            return InfrastructureAuthenticationFailure.CertificateMismatch;
        }

        var expectedProfile = InfrastructureCertificateProfiles.ForIdentity(request.IdentityKind);
        if (!Equal(request.CertificateProfileOid, expectedProfile) ||
            !Equal(credential.CertificateProfileOid, expectedProfile))
        {
            return InfrastructureAuthenticationFailure.CertificateProfileMismatch;
        }

        return InfrastructureAuthenticationFailure.None;
    }

    public static bool IsWellFormedRequest(InfrastructureMutualAuthenticationRequest request) =>
        request.IdentityKind is InfrastructureIdentityKind.AgentService or InfrastructureIdentityKind.ViewerUser &&
        IsIdentity(request.IdentityId) &&
        request.CredentialEpoch > 0 &&
        request.ConnectionGeneration != Guid.Empty &&
        IsSha256(request.CertificateSha256) &&
        IsIdentity(request.CertificateProfileOid) &&
        Uri.TryCreate(request.ServerUri, UriKind.Absolute, out var uri) &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
        request.ProtocolGeneration > 0 &&
        IsIdentity(request.ReleaseId) &&
        request.SessionChallenge?.Length is >= 32 and <= 128 &&
        request.ProofCreatedAtUtc.Kind == DateTimeKind.Utc &&
        request.AgentCommandCapabilities != null &&
        request.AgentCommandCapabilities.Count <= 256 &&
        request.AgentCommandCapabilities.Distinct().Count() == request.AgentCommandCapabilities.Count &&
        request.AgentCommandCapabilities.All(kind => Enum.IsDefined(kind) && kind != AgentCommandKind.Unknown) &&
        (request.IdentityKind == InfrastructureIdentityKind.AgentService
            ? IsIdentity(request.AgentId) && IsIdentity(request.HostId) &&
              AgentAuthenticationPolicy.IsValidContext(new AuthenticatedAgentContext
              {
                  AgentId = request.AgentId,
                  HostId = request.HostId,
                  AuthenticationKind = AgentAuthenticationKind.EnrolledWindowsService,
                  EnrollmentState = AgentEnrollmentState.Active,
                  CredentialEpoch = request.CredentialEpoch,
                  ConnectionGeneration = request.ConnectionGeneration,
                  ProtocolContractVersion = request.ProtocolGeneration,
                  ReleaseId = request.ReleaseId,
                  ReleaseMatch = AgentReleaseProfileMatch.Match,
                  AuthenticatedAtUtc = request.ProofCreatedAtUtc,
                  FreshUntilUtc = request.ProofCreatedAtUtc,
                  CommandCapabilities = request.AgentCommandCapabilities,
                  Scope = request.AgentScope
              })
            : IsIdentity(request.ViewerUserId) &&
              string.IsNullOrEmpty(request.AgentId) && string.IsNullOrEmpty(request.HostId));

    public static bool IsValidTarget(InfrastructureEnrollmentTarget? target) =>
        target != null &&
        target.IdentityKind is InfrastructureIdentityKind.AgentService or InfrastructureIdentityKind.ViewerUser &&
        IsIdentity(target.IdentityId) &&
        Uri.TryCreate(target.ServerUri, UriKind.Absolute, out var uri) &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
        IsSha256(target.AuthorityChainSha256) &&
        (target.IdentityKind == InfrastructureIdentityKind.AgentService
            ? IsIdentity(target.AgentId) && IsIdentity(target.HostId) && string.IsNullOrEmpty(target.ViewerUserId)
            : IsIdentity(target.ViewerUserId) && string.IsNullOrEmpty(target.AgentId) && string.IsNullOrEmpty(target.HostId));

    private static bool IsIdentity(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512;

    private static bool IsSha256(string? value) =>
        value?.Length == 64 && value.All(Uri.IsHexDigit);

    private static bool Equal(string left, string right) =>
        string.Equals(left, right, StringComparison.Ordinal);

    private static bool UriEquals(string left, string right) =>
        Uri.TryCreate(left, UriKind.Absolute, out var leftUri) &&
        Uri.TryCreate(right, UriKind.Absolute, out var rightUri) &&
        Uri.Compare(leftUri, rightUri, UriComponents.AbsoluteUri, UriFormat.SafeUnescaped,
            StringComparison.OrdinalIgnoreCase) == 0;

    private static DateTime Min(DateTime left, DateTime right) => left <= right ? left : right;

    private static InfrastructureAuthenticationDecision Deny(
        InfrastructureAuthenticationFailure failure,
        string diagnostic) =>
        new()
        {
            Failure = failure,
            Diagnostic = diagnostic
        };
}
