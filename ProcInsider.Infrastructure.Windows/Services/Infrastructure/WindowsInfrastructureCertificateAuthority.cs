using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ProcInsider.Models.Infrastructure;

namespace ProcInsider.Services.Infrastructure;

/// <summary>
/// Secret-free trust snapshot loaded from protected Server configuration/control state.
/// Certificate bytes and private keys remain in the Windows LocalMachine certificate store.
/// </summary>
public sealed record InfrastructureCertificateAuthoritySnapshot
{
    public string ServerUri { get; init; } = string.Empty;

    public string ServerCertificateSha256 { get; init; } = string.Empty;

    public string ServerTrustAnchorSha256 { get; init; } = string.Empty;

    public string CurrentEnrollmentIssuerSha256 { get; init; } = string.Empty;

    public string PreviousEnrollmentIssuerSha256 { get; init; } = string.Empty;

    public DateTime? PreviousIssuerTrustStartsAtUtc { get; init; }

    public DateTime? PreviousIssuerTrustEndsAtUtc { get; init; }

    public bool IsWellFormed()
    {
        if (!Uri.TryCreate(ServerUri, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !IsSha256(ServerCertificateSha256) || !IsSha256(ServerTrustAnchorSha256) ||
            !IsSha256(CurrentEnrollmentIssuerSha256))
        {
            return false;
        }

        var hasPrevious = !string.IsNullOrEmpty(PreviousEnrollmentIssuerSha256);
        if (hasPrevious != PreviousIssuerTrustStartsAtUtc.HasValue ||
            hasPrevious != PreviousIssuerTrustEndsAtUtc.HasValue)
        {
            return false;
        }

        return !hasPrevious ||
               (IsSha256(PreviousEnrollmentIssuerSha256) &&
                !string.Equals(
                    PreviousEnrollmentIssuerSha256,
                    CurrentEnrollmentIssuerSha256,
                    StringComparison.OrdinalIgnoreCase) &&
                InfrastructureCredentialLifecyclePolicy.IsIssuerOverlapAllowed(
                    PreviousIssuerTrustStartsAtUtc!.Value,
                    PreviousIssuerTrustEndsAtUtc!.Value));
    }

    public bool IsPreviousIssuerTrusted(DateTime nowUtc) =>
        nowUtc.Kind == DateTimeKind.Utc && IsWellFormed() &&
        PreviousIssuerTrustStartsAtUtc <= nowUtc && nowUtc <= PreviousIssuerTrustEndsAtUtc;

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);
}

/// <summary>
/// Server-owned certificate-derived authentication authority. It resolves only exact
/// LocalMachine/My SHA-256 identities, builds the client chain to the configured enrollment
/// issuer itself, and never accepts caller-provided chain, issuer, or Server-trust booleans.
/// </summary>
public sealed class WindowsInfrastructureCertificateAuthority
{
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);
    private readonly InfrastructureCertificateAuthoritySnapshot _snapshot;
    private readonly Func<string, bool, X509Certificate2> _resolver;

    public WindowsInfrastructureCertificateAuthority(
        InfrastructureCertificateAuthoritySnapshot snapshot,
        WindowsInfrastructureCertificateStore certificateStore)
        : this(
            snapshot,
            (sha256, requirePrivateKey) =>
                certificateStore.ResolveLocalMachineBySha256(sha256, requirePrivateKey))
    {
    }

    public WindowsInfrastructureCertificateAuthority(
        InfrastructureCertificateAuthoritySnapshot snapshot,
        Func<string, bool, X509Certificate2> resolver)
    {
        _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        if (!_snapshot.IsWellFormed())
        {
            throw new ArgumentException(
                "The Server certificate-authority trust snapshot is malformed or has an invalid issuer overlap.",
                nameof(snapshot));
        }
    }

    public InfrastructureCertificateAuthoritySnapshot Snapshot => _snapshot with { };

    public InfrastructureCertificateValidation ValidateConfiguredServerCertificate(DateTime nowUtc)
    {
        if (nowUtc.Kind != DateTimeKind.Utc)
        {
            return Invalid("ServerCertificateTimeInvalid", "Server certificate validation requires a UTC clock.");
        }

        try
        {
            using var certificate = _resolver(_snapshot.ServerCertificateSha256, true);
            if (!WindowsInfrastructureCertificatePolicy.IsNonExportablePrivateCredential(certificate))
            {
                return Invalid(
                    "ServerPrivateKeyProtectionInvalid",
                    "The configured Server private key is missing or exportable.");
            }

            using var trustAnchor = _resolver(_snapshot.ServerTrustAnchorSha256, false);
            var trustAnchorValidation = ValidateServerTrustAnchor(
                trustAnchor,
                _snapshot.ServerTrustAnchorSha256,
                nowUtc);
            if (!trustAnchorValidation.IsValid)
            {
                return trustAnchorValidation;
            }

            var chainVerified = BuildExactServerChain(certificate, trustAnchor, nowUtc);
            var expectedHost = new Uri(_snapshot.ServerUri).DnsSafeHost;
            return WindowsInfrastructureCertificatePolicy.ValidateServerCertificate(
                certificate,
                _snapshot.ServerCertificateSha256,
                expectedHost,
                nowUtc,
                chainVerified);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException)
        {
            return Invalid(
                "ServerCertificateReferenceRejected",
                "The exact configured Server certificate reference is absent, ambiguous, or unusable.");
        }
    }

    public InfrastructureCertificateValidation ValidateClientCertificate(
        X509Certificate2 certificate,
        InfrastructureCredentialRecord expected,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(expected);
        if (nowUtc.Kind != DateTimeKind.Utc)
        {
            return Invalid("CertificateTimeInvalid", "Client certificate validation requires a UTC clock.");
        }

        if (!TrySelectIssuer(expected.IssuerId, nowUtc, out var issuerSha256, out var requirePrivateKey))
        {
            return Invalid(
                "CertificateIssuerTrustRejected",
                "The credential issuer is neither the current authority nor the bounded previous overlap authority.");
        }

        try
        {
            using var issuer = _resolver(issuerSha256, requirePrivateKey);
            var issuerValidation = ValidateEnrollmentIssuer(
                issuer,
                issuerSha256,
                nowUtc,
                requirePrivateKey);
            if (!issuerValidation.IsValid)
            {
                return issuerValidation;
            }

            var leafValidation = WindowsInfrastructureCertificatePolicy.ValidateClientCertificate(
                certificate,
                expected,
                nowUtc,
                chainVerified: true,
                issuerSha256);
            if (!leafValidation.IsValid)
            {
                return leafValidation;
            }

            if (!BuildExactClientChain(certificate, issuer, nowUtc))
            {
                return Invalid(
                    "CertificateChainRejected",
                    "The client certificate did not build an exact signature chain to the selected enrollment issuer.");
            }

            return leafValidation;
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException)
        {
            return Invalid(
                "CertificateIssuerReferenceRejected",
                "The exact enrollment-issuer certificate reference is absent, ambiguous, or unusable.");
        }
    }

    public X509Certificate2 ResolveCurrentEnrollmentIssuerForIssuance(DateTime nowUtc)
    {
        if (nowUtc.Kind != DateTimeKind.Utc)
        {
            throw new ArgumentException("Enrollment issuance requires a UTC clock.", nameof(nowUtc));
        }

        var issuer = _resolver(_snapshot.CurrentEnrollmentIssuerSha256, true);
        var validation = ValidateEnrollmentIssuer(
            issuer,
            _snapshot.CurrentEnrollmentIssuerSha256,
            nowUtc,
            requirePrivateKey: true);
        if (validation.IsValid)
        {
            return issuer;
        }

        issuer.Dispose();
        throw new InvalidOperationException(validation.Diagnostic);
    }

    public InfrastructureAuthenticationFailure RevalidateCredentialAuthority(
        InfrastructureCredentialRecord credential,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (nowUtc.Kind != DateTimeKind.Utc)
        {
            return InfrastructureAuthenticationFailure.ClockSkewRejected;
        }

        if (credential.State != InfrastructureCredentialLifecycleState.Active)
        {
            return credential.State switch
            {
                InfrastructureCredentialLifecycleState.Rotated =>
                    InfrastructureAuthenticationFailure.CredentialRotated,
                InfrastructureCredentialLifecycleState.Expired =>
                    InfrastructureAuthenticationFailure.CredentialExpired,
                InfrastructureCredentialLifecycleState.Revoked =>
                    InfrastructureAuthenticationFailure.CredentialRevoked,
                InfrastructureCredentialLifecycleState.Compromised =>
                    InfrastructureAuthenticationFailure.CredentialCompromised,
                _ => InfrastructureAuthenticationFailure.IdentityDisabled
            };
        }

        if (nowUtc < credential.NotBeforeUtc || nowUtc > credential.NotAfterUtc)
        {
            return InfrastructureAuthenticationFailure.CertificateOutsideValidity;
        }

        return TrySelectIssuer(credential.IssuerId, nowUtc, out _, out _)
            ? InfrastructureAuthenticationFailure.None
            : InfrastructureAuthenticationFailure.CertificateChainRejected;
    }

    private bool TrySelectIssuer(
        string credentialIssuerId,
        DateTime nowUtc,
        out string issuerSha256,
        out bool requirePrivateKey)
    {
        issuerSha256 = string.Empty;
        requirePrivateKey = false;
        if (string.Equals(
                credentialIssuerId,
                _snapshot.CurrentEnrollmentIssuerSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            issuerSha256 = _snapshot.CurrentEnrollmentIssuerSha256;
            requirePrivateKey = true;
            return true;
        }

        if (_snapshot.IsPreviousIssuerTrusted(nowUtc) &&
            string.Equals(
                credentialIssuerId,
                _snapshot.PreviousEnrollmentIssuerSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            issuerSha256 = _snapshot.PreviousEnrollmentIssuerSha256;
            return true;
        }

        return false;
    }

    private static InfrastructureCertificateValidation ValidateEnrollmentIssuer(
        X509Certificate2 issuer,
        string expectedSha256,
        DateTime nowUtc,
        bool requirePrivateKey)
    {
        var actualSha256 = issuer.GetCertHashString(HashAlgorithmName.SHA256);
        if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            return Invalid("EnrollmentIssuerHashMismatch", "The enrollment issuer hash changed after exact resolution.");
        }

        var notBeforeUtc = issuer.NotBefore.ToUniversalTime();
        var notAfterUtc = issuer.NotAfter.ToUniversalTime();
        if (nowUtc + MaximumClockSkew < notBeforeUtc || nowUtc - MaximumClockSkew > notAfterUtc ||
            notAfterUtc <= notBeforeUtc ||
            notAfterUtc - notBeforeUtc > InfrastructureCredentialLifecyclePolicy.MaximumEnrollmentIssuerLifetime)
        {
            return Invalid("EnrollmentIssuerValidityRejected", "The enrollment issuer validity/lifetime is outside policy.");
        }

        var constraints = issuer.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        var usages = issuer.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        const X509KeyUsageFlags permitted = X509KeyUsageFlags.DigitalSignature |
                                              X509KeyUsageFlags.KeyCertSign |
                                              X509KeyUsageFlags.CrlSign;
        if (constraints.Length != 1 || !constraints[0].CertificateAuthority ||
            usages.Length != 1 || !usages[0].KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign) ||
            !usages[0].KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign) ||
            (usages[0].KeyUsages & ~permitted) != 0 ||
            issuer.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any())
        {
            return Invalid(
                "EnrollmentIssuerPurposeRejected",
                "The enrollment issuer is not one exact CA/key-cert-sign/CRL-sign authority profile.");
        }

        if (requirePrivateKey &&
            !WindowsInfrastructureCertificatePolicy.IsNonExportablePrivateCredential(issuer))
        {
            return Invalid(
                "EnrollmentIssuerPrivateKeyProtectionInvalid",
                "The current enrollment issuer private key is missing or exportable.");
        }

        return new InfrastructureCertificateValidation(
            true,
            string.Empty,
            "The exact enrollment issuer identity, purpose, validity, lifetime and key protection are valid.",
            actualSha256,
            ValidatedIssuerId: actualSha256);
    }

    private static bool BuildExactClientChain(
        X509Certificate2 certificate,
        X509Certificate2 issuer,
        DateTime nowUtc)
    {
        using var publicIssuer = X509CertificateLoader.LoadCertificate(issuer.RawData);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(publicIssuer);
        chain.ChainPolicy.ExtraStore.Add(publicIssuer);
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        var certificateNotBeforeUtc = certificate.NotBefore.ToUniversalTime();
        var certificateNotAfterUtc = certificate.NotAfter.ToUniversalTime();
        chain.ChainPolicy.VerificationTime = nowUtc < certificateNotBeforeUtc &&
                                             certificateNotBeforeUtc - nowUtc <= MaximumClockSkew
            ? certificateNotBeforeUtc
            : nowUtc > certificateNotAfterUtc && nowUtc - certificateNotAfterUtc <= MaximumClockSkew
                ? certificateNotAfterUtc
                : nowUtc;
        if (!chain.Build(certificate) || chain.ChainElements.Count != 2)
        {
            return false;
        }

        var leafHash = chain.ChainElements[0].Certificate.GetCertHashString(HashAlgorithmName.SHA256);
        var issuerHash = chain.ChainElements[1].Certificate.GetCertHashString(HashAlgorithmName.SHA256);
        return string.Equals(
                   leafHash,
                   certificate.GetCertHashString(HashAlgorithmName.SHA256),
                   StringComparison.OrdinalIgnoreCase) &&
               string.Equals(
                   issuerHash,
                   issuer.GetCertHashString(HashAlgorithmName.SHA256),
                   StringComparison.OrdinalIgnoreCase) &&
               chain.ChainStatus.All(status => status.Status == X509ChainStatusFlags.NoError);
    }

    private static InfrastructureCertificateValidation ValidateServerTrustAnchor(
        X509Certificate2 trustAnchor,
        string expectedSha256,
        DateTime nowUtc)
    {
        var actualSha256 = trustAnchor.GetCertHashString(HashAlgorithmName.SHA256);
        var constraints = trustAnchor.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        var usages = trustAnchor.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            return Invalid("ServerTrustAnchorHashMismatch", "The Server trust-anchor hash changed after exact resolution.");
        }

        if (nowUtc + MaximumClockSkew < trustAnchor.NotBefore.ToUniversalTime() ||
            nowUtc - MaximumClockSkew > trustAnchor.NotAfter.ToUniversalTime())
        {
            return Invalid("ServerTrustAnchorValidityRejected", "The Server trust anchor is outside its validity window.");
        }

        const X509KeyUsageFlags permittedUsage = X509KeyUsageFlags.DigitalSignature |
                                                  X509KeyUsageFlags.KeyCertSign |
                                                  X509KeyUsageFlags.CrlSign;
        if (constraints.Length != 1 || !constraints[0].CertificateAuthority ||
            usages.Length != 1 || !usages[0].KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign) ||
            !usages[0].KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign) ||
            (usages[0].KeyUsages & ~permittedUsage) != 0 ||
            trustAnchor.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any())
        {
            return Invalid("ServerTrustAnchorPurposeRejected", "The Server trust anchor is not an exact CA signing authority.");
        }

        return new InfrastructureCertificateValidation(
            true,
            string.Empty,
            "The exact Server trust-anchor identity, purpose and validity are valid.",
            actualSha256);
    }

    private static bool BuildExactServerChain(
        X509Certificate2 certificate,
        X509Certificate2 trustAnchor,
        DateTime nowUtc)
    {
        using var publicAnchor = X509CertificateLoader.LoadCertificate(trustAnchor.RawData);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(publicAnchor);
        chain.ChainPolicy.ExtraStore.Add(publicAnchor);
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        var certificateNotBeforeUtc = certificate.NotBefore.ToUniversalTime();
        var certificateNotAfterUtc = certificate.NotAfter.ToUniversalTime();
        chain.ChainPolicy.VerificationTime = nowUtc < certificateNotBeforeUtc &&
                                             certificateNotBeforeUtc - nowUtc <= MaximumClockSkew
            ? certificateNotBeforeUtc
            : nowUtc > certificateNotAfterUtc && nowUtc - certificateNotAfterUtc <= MaximumClockSkew
                ? certificateNotAfterUtc
                : nowUtc;
        if (!chain.Build(certificate) || chain.ChainElements.Count < 2)
        {
            return false;
        }

        return string.Equals(
                   chain.ChainElements[0].Certificate.GetCertHashString(HashAlgorithmName.SHA256),
                   certificate.GetCertHashString(HashAlgorithmName.SHA256),
                   StringComparison.OrdinalIgnoreCase) &&
               string.Equals(
                   chain.ChainElements[^1].Certificate.GetCertHashString(HashAlgorithmName.SHA256),
                   trustAnchor.GetCertHashString(HashAlgorithmName.SHA256),
                   StringComparison.OrdinalIgnoreCase) &&
               chain.ChainStatus.All(status => status.Status == X509ChainStatusFlags.NoError);
    }

    private static InfrastructureCertificateValidation Invalid(string code, string diagnostic) =>
        new(false, code, diagnostic);
}
