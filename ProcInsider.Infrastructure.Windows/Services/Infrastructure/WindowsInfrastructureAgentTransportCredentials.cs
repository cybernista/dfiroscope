using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Infrastructure;
using Contracts = ProcInsider.Models.Infrastructure.InfrastructureConfigurationContracts;

namespace ProcInsider.Services.Infrastructure;

/// <summary>
/// Non-secret metadata retained beside the protected Agent certificate reference after
/// enrollment. The private key remains in the LocalMachine certificate store.
/// </summary>
public sealed record InfrastructureAgentCredentialBinding
{
    public InfrastructureCredentialRecord Credential { get; init; } = new();

    public AgentAuthorizationScope Scope { get; init; } = new();

    public IReadOnlyList<AgentCommandKind> CommandCapabilities { get; init; } =
        Array.Empty<AgentCommandKind>();
}

public sealed record InfrastructureAgentServerTrustSnapshot
{
    public string ServerUri { get; init; } = string.Empty;

    public string ServerCertificateSha256 { get; init; } = string.Empty;

    public Contracts.ProtectedStoreReference TrustAnchorReference { get; init; } = new();

    public bool IsWellFormed() =>
        Uri.TryCreate(ServerUri, UriKind.Absolute, out var uri) &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
        ServerCertificateSha256.Length == 64 && ServerCertificateSha256.All(Uri.IsHexDigit) &&
        TrustAnchorReference.Store == Contracts.ProtectedStoreKind.WindowsCertificateStore &&
        !string.IsNullOrWhiteSpace(TrustAnchorReference.Identifier);
}

public interface IInfrastructureAgentCredentialSource
{
    X509Certificate2 ResolveClientCertificate(
        Contracts.InfrastructureAgentConfiguration configuration,
        InfrastructureAgentCredentialBinding binding);
}

public interface IInfrastructureAgentServerCertificateAuthority
{
    InfrastructureCertificateValidation Validate(
        X509Certificate2 serverCertificate,
        Uri requestedEndpoint,
        DateTime nowUtc);
}

/// <summary>
/// Resolves the exact post-enrollment LocalMachine/My certificate reference. A pending CNG
/// key name is not a usable transport credential and never falls back to subject lookup.
/// </summary>
public sealed class WindowsInfrastructureAgentCredentialSource : IInfrastructureAgentCredentialSource
{
    private readonly Func<Contracts.ProtectedStoreReference, X509Certificate2> _certificateResolver;

    public WindowsInfrastructureAgentCredentialSource(WindowsInfrastructureCertificateStore certificateStore)
        : this(reference => certificateStore.Resolve(
            reference,
            InfrastructureIdentityKind.AgentService,
            requirePrivateKey: true))
    {
        ArgumentNullException.ThrowIfNull(certificateStore);
    }

    public WindowsInfrastructureAgentCredentialSource(
        Func<Contracts.ProtectedStoreReference, X509Certificate2> certificateResolver)
    {
        _certificateResolver = certificateResolver ??
                               throw new ArgumentNullException(nameof(certificateResolver));
    }

    public X509Certificate2 ResolveClientCertificate(
        Contracts.InfrastructureAgentConfiguration configuration,
        InfrastructureAgentCredentialBinding binding)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(binding);
        var credential = binding.Credential;
        if (credential.IdentityKind != InfrastructureIdentityKind.AgentService ||
            !string.Equals(credential.AgentId, configuration.AgentId, StringComparison.Ordinal) ||
            !string.Equals(credential.HostId, configuration.HostId, StringComparison.Ordinal) ||
            configuration.ServerEndpoints.Count == 0 ||
            !string.Equals(credential.ServerUri, configuration.ServerEndpoints[0].Uri,
                StringComparison.OrdinalIgnoreCase) ||
            credential.ProtocolGeneration != configuration.ProtocolGeneration ||
            !string.Equals(credential.ReleaseId, configuration.ReleaseId, StringComparison.Ordinal) ||
            credential.State != InfrastructureCredentialLifecycleState.Active ||
            credential.CredentialEpoch <= 0 ||
            !string.Equals(
                credential.CertificateProfileOid,
                InfrastructureCertificateProfiles.AgentClientOid,
                StringComparison.Ordinal) ||
            configuration.CredentialReference.Store !=
            Contracts.ProtectedStoreKind.WindowsCertificateStore)
        {
            throw new InvalidOperationException("The local credential metadata is not the exact active Agent binding.");
        }

        var certificate = _certificateResolver(configuration.CredentialReference);
        if (!string.Equals(
                certificate.GetCertHashString(HashAlgorithmName.SHA256),
                credential.CertificateSha256,
                StringComparison.OrdinalIgnoreCase) ||
            !WindowsInfrastructureCertificatePolicy.IsNonExportablePrivateCredential(certificate))
        {
            certificate.Dispose();
            throw new InvalidOperationException("The protected Agent certificate does not match its active credential epoch.");
        }

        return certificate;
    }
}

/// <summary>
/// Agent-side Server authority. It builds one custom-root chain itself and binds the exact
/// configured leaf pin and endpoint; the TLS callback cannot assert trust with a boolean.
/// </summary>
public sealed class WindowsInfrastructureAgentServerCertificateAuthority :
    IInfrastructureAgentServerCertificateAuthority
{
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);
    private readonly InfrastructureAgentServerTrustSnapshot _snapshot;
    private readonly Func<Contracts.ProtectedStoreReference, X509Certificate2> _trustAnchorResolver;

    public WindowsInfrastructureAgentServerCertificateAuthority(
        InfrastructureAgentServerTrustSnapshot snapshot,
        WindowsInfrastructureCertificateStore certificateStore)
        : this(
            snapshot,
            reference => certificateStore.Resolve(
                reference,
                InfrastructureIdentityKind.AgentService,
                requirePrivateKey: false))
    {
        ArgumentNullException.ThrowIfNull(certificateStore);
    }

    public WindowsInfrastructureAgentServerCertificateAuthority(
        InfrastructureAgentServerTrustSnapshot snapshot,
        Func<Contracts.ProtectedStoreReference, X509Certificate2> trustAnchorResolver)
    {
        _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
        _trustAnchorResolver = trustAnchorResolver ??
                               throw new ArgumentNullException(nameof(trustAnchorResolver));
        if (!_snapshot.IsWellFormed())
        {
            throw new ArgumentException("The Agent Server-trust snapshot is malformed.", nameof(snapshot));
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
            !Uri.TryCreate(_snapshot.ServerUri, UriKind.Absolute, out var configured) ||
            !UriEquals(configured, requestedEndpoint))
        {
            return Invalid("ServerEndpointMismatch", "The TLS endpoint is not the exact configured Server URI.");
        }

        try
        {
            using var anchor = _trustAnchorResolver(_snapshot.TrustAnchorReference);
            if (!IsValidTrustAnchor(anchor, nowUtc) || !BuildExactChain(serverCertificate, anchor, nowUtc))
            {
                return Invalid("ServerCertificateChainRejected", "The Server leaf did not chain to the exact Agent trust anchor.");
            }

            return WindowsInfrastructureCertificatePolicy.ValidateServerCertificate(
                serverCertificate,
                _snapshot.ServerCertificateSha256,
                configured.DnsSafeHost,
                nowUtc,
                chainVerified: true);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException)
        {
            return Invalid("ServerTrustReferenceRejected", "The exact Agent trust anchor is absent, ambiguous, or unusable.");
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
        string.Equals(left.AbsolutePath.TrimEnd('/'), right.AbsolutePath.TrimEnd('/'), StringComparison.Ordinal);

    private static InfrastructureCertificateValidation Invalid(string code, string diagnostic) =>
        new(false, code, diagnostic);
}
