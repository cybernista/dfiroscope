using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ProcInsider.Models.Infrastructure;
using Contracts = ProcInsider.Models.Infrastructure.InfrastructureConfigurationContracts;

namespace ProcInsider.Services.Infrastructure;

public interface IInfrastructureViewerCredentialSource
{
    X509Certificate2 ResolveClientCertificate(
        InfrastructureViewerServerProfile profile,
        InfrastructureCredentialRecord credential,
        DateTime nowUtc);
}

public interface IInfrastructureViewerServerCertificateAuthority
{
    InfrastructureCertificateValidation Validate(
        X509Certificate2 serverCertificate,
        Uri requestedEndpoint,
        DateTime nowUtc);
}

/// <summary>
/// Resolves one exact CurrentUser/My Viewer credential. There is no subject-name search,
/// certificate picker, machine-store fallback, or exportable-key compatibility path.
/// </summary>
public sealed class WindowsInfrastructureViewerCredentialSource : IInfrastructureViewerCredentialSource
{
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);
    private readonly Func<Contracts.ProtectedStoreReference, X509Certificate2> _certificateResolver;

    public WindowsInfrastructureViewerCredentialSource(WindowsInfrastructureCertificateStore certificateStore)
        : this(reference => certificateStore.Resolve(
            reference,
            InfrastructureIdentityKind.ViewerUser,
            requirePrivateKey: true))
    {
        ArgumentNullException.ThrowIfNull(certificateStore);
    }

    public WindowsInfrastructureViewerCredentialSource(
        Func<Contracts.ProtectedStoreReference, X509Certificate2> certificateResolver)
    {
        _certificateResolver = certificateResolver ?? throw new ArgumentNullException(nameof(certificateResolver));
    }

    public X509Certificate2 ResolveClientCertificate(
        InfrastructureViewerServerProfile profile,
        InfrastructureCredentialRecord credential,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(credential);
        if (nowUtc.Kind != DateTimeKind.Utc ||
            !InfrastructureViewerRuntimeContract.IsWellFormed(profile) ||
            credential.IdentityKind != InfrastructureIdentityKind.ViewerUser ||
            !string.Equals(credential.IdentityId, profile.ViewerUserId, StringComparison.Ordinal) ||
            !string.Equals(credential.ViewerUserId, profile.ViewerUserId, StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(credential.AgentId) ||
            !string.IsNullOrEmpty(credential.HostId) ||
            !credential.ViewerEnabled ||
            credential.ViewerRole == InfrastructureViewerRole.Unknown ||
            credential.State != InfrastructureCredentialLifecycleState.Active ||
            credential.CredentialEpoch != profile.CredentialEpoch ||
            !string.Equals(
                credential.CertificateProfileOid,
                InfrastructureCertificateProfiles.ViewerClientOid,
                StringComparison.Ordinal) ||
            !string.Equals(credential.ServerUri, profile.ServerUri, StringComparison.OrdinalIgnoreCase) ||
            credential.ProtocolGeneration != profile.ProtocolGeneration ||
            !string.Equals(credential.ReleaseId, profile.ReleaseId, StringComparison.Ordinal) ||
            credential.NotBeforeUtc.Kind != DateTimeKind.Utc ||
            credential.NotAfterUtc.Kind != DateTimeKind.Utc ||
            nowUtc + MaximumClockSkew < credential.NotBeforeUtc ||
            nowUtc > credential.NotAfterUtc ||
            !profile.CredentialReference.Identifier.EndsWith(
                "/" + credential.CertificateSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "InfrastructureViewerCredentialBindingRejected");
        }

        var certificate = _certificateResolver(profile.CredentialReference);
        var validation = WindowsInfrastructureCertificatePolicy.ValidateClientCertificate(
            certificate,
            credential,
            nowUtc,
            chainVerified: true,
            credential.IssuerId);
        if (!validation.IsValid ||
            !WindowsInfrastructureCertificatePolicy.IsNonExportablePrivateCredential(certificate))
        {
            certificate.Dispose();
            throw new InvalidOperationException(
                "InfrastructureViewerCredentialReferenceRejected");
        }

        return certificate;
    }
}

/// <summary>
/// Viewer-side Server authority. It builds one custom-root chain and then binds the exact
/// configured leaf hash, DNS name, Server EKU/profile, lifetime, and endpoint.
/// </summary>
public sealed class WindowsInfrastructureViewerServerCertificateAuthority :
    IInfrastructureViewerServerCertificateAuthority
{
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);
    private readonly InfrastructureViewerServerProfile _profile;
    private readonly Func<Contracts.ProtectedStoreReference, X509Certificate2> _trustAnchorResolver;

    public WindowsInfrastructureViewerServerCertificateAuthority(
        InfrastructureViewerServerProfile profile,
        WindowsInfrastructureCertificateStore certificateStore)
        : this(
            profile,
            reference => certificateStore.Resolve(
                reference,
                InfrastructureIdentityKind.ViewerUser,
                requirePrivateKey: false))
    {
        ArgumentNullException.ThrowIfNull(certificateStore);
    }

    public WindowsInfrastructureViewerServerCertificateAuthority(
        InfrastructureViewerServerProfile profile,
        Func<Contracts.ProtectedStoreReference, X509Certificate2> trustAnchorResolver)
    {
        _profile = profile ?? throw new ArgumentNullException(nameof(profile));
        _trustAnchorResolver = trustAnchorResolver ??
                               throw new ArgumentNullException(nameof(trustAnchorResolver));
        if (!InfrastructureViewerRuntimeContract.IsWellFormed(_profile))
        {
            throw new ArgumentException("InfrastructureViewerServerProfileMalformed", nameof(profile));
        }
    }

    public InfrastructureCertificateValidation Validate(
        X509Certificate2 serverCertificate,
        Uri requestedEndpoint,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(serverCertificate);
        ArgumentNullException.ThrowIfNull(requestedEndpoint);
        if (nowUtc.Kind != DateTimeKind.Utc ||
            !Uri.TryCreate(_profile.ServerUri, UriKind.Absolute, out var configured) ||
            !UriEquals(configured, requestedEndpoint))
        {
            return Invalid(
                "InfrastructureViewerServerEndpointMismatch",
                "The TLS endpoint is not the exact configured Viewer Server URI.");
        }

        try
        {
            using var anchor = _trustAnchorResolver(_profile.TrustAnchorReference);
            if (!IsValidTrustAnchor(anchor, nowUtc) || !BuildExactChain(serverCertificate, anchor, nowUtc))
            {
                return Invalid(
                    "InfrastructureViewerServerChainRejected",
                    "The Server leaf did not chain to the exact Viewer trust anchor.");
            }

            var validation = WindowsInfrastructureCertificatePolicy.ValidateServerCertificate(
                serverCertificate,
                _profile.ServerCertificateSha256,
                configured.DnsSafeHost,
                nowUtc,
                chainVerified: true);
            if (!validation.IsValid)
            {
                return validation;
            }

            var serverIdentity = serverCertificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            return string.Equals(
                serverIdentity,
                _profile.ExpectedServerIdentity,
                StringComparison.Ordinal)
                ? validation
                : Invalid(
                    "InfrastructureViewerServerIdentityMismatch",
                    "The Server certificate subject identity is not the exact configured Server identity.");
        }
        catch (Exception exception) when (exception is CryptographicException or InvalidOperationException)
        {
            return Invalid(
                "InfrastructureViewerServerTrustReferenceRejected",
                "The exact Viewer trust anchor is absent, ambiguous, or unusable.");
        }
    }

    private static bool BuildExactChain(X509Certificate2 leaf, X509Certificate2 anchor, DateTime nowUtc)
    {
        using var publicAnchor = X509CertificateLoader.LoadCertificate(anchor.RawData);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(publicAnchor);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationTime = nowUtc;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        return chain.Build(leaf) && chain.ChainElements.Count >= 2 &&
               string.Equals(
                   chain.ChainElements[^1].Certificate.GetCertHashString(HashAlgorithmName.SHA256),
                   anchor.GetCertHashString(HashAlgorithmName.SHA256),
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsValidTrustAnchor(X509Certificate2 anchor, DateTime nowUtc)
    {
        var constraints = anchor.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        var usages = anchor.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        return constraints.Length == 1 && constraints[0].CertificateAuthority &&
               usages.Length == 1 && usages[0].KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign) &&
               nowUtc + MaximumClockSkew >= anchor.NotBefore.ToUniversalTime() &&
               nowUtc - MaximumClockSkew <= anchor.NotAfter.ToUniversalTime();
    }

    private static bool UriEquals(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.DnsSafeHost, right.DnsSafeHost, StringComparison.OrdinalIgnoreCase) &&
        left.Port == right.Port &&
        string.Equals(left.AbsolutePath, right.AbsolutePath, StringComparison.Ordinal);

    private static InfrastructureCertificateValidation Invalid(string code, string diagnostic) =>
        new(false, code, diagnostic);
}
