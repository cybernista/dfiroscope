using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ProcInsider.Models.Infrastructure;
using Contracts = ProcInsider.Models.Infrastructure.InfrastructureConfigurationContracts;

namespace ProcInsider.Services.Infrastructure;

public sealed record InfrastructureIssuedCertificate(
    byte[] CertificateDer,
    string CertificateSha256,
    string CertificateProfileOid,
    string IssuerId,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc);

public sealed record InfrastructureCertificateValidation(
    bool IsValid,
    string ErrorCode,
    string Diagnostic,
    string CertificateSha256 = "",
    string CertificateProfileOid = "",
    string SubjectPublicKeyInfoSha256 = "",
    string ValidatedIssuerId = "");

/// <summary>
/// Exact Windows certificate profiles for Server, Agent Service, and Viewer identities.
/// Certificate possession remains only one input to the separate enrollment policy.
/// </summary>
public static class WindowsInfrastructureCertificatePolicy
{
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);

    public static InfrastructureCertificateValidation ValidateClientCertificate(
        X509Certificate2 certificate,
        InfrastructureCredentialRecord expected,
        DateTime nowUtc,
        bool chainVerified,
        string validatedIssuerId)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(expected);
        if (nowUtc.Kind != DateTimeKind.Utc)
        {
            return Invalid("CertificateTimeInvalid", "Certificate validation requires a UTC clock.");
        }

        if (!chainVerified)
        {
            return Invalid("CertificateChainRejected", "The enrollment issuer chain was not trusted.");
        }

        if (!string.Equals(validatedIssuerId, expected.IssuerId, StringComparison.OrdinalIgnoreCase))
        {
            return Invalid("CertificateIssuerMismatch",
                "The validated enrollment issuer does not match the credential epoch.");
        }

        var notBefore = certificate.NotBefore.ToUniversalTime();
        var notAfter = certificate.NotAfter.ToUniversalTime();
        if (nowUtc + MaximumClockSkew < notBefore || nowUtc - MaximumClockSkew > notAfter)
        {
            return Invalid("CertificateOutsideValidity", "The certificate is outside its bounded validity window.");
        }

        var sha256 = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        if (!string.Equals(sha256, expected.CertificateSha256, StringComparison.OrdinalIgnoreCase))
        {
            return Invalid("CertificateHashMismatch", "The certificate does not match the enrolled SHA-256 identity.");
        }

        var expectedProfile = InfrastructureCertificateProfiles.ForIdentity(expected.IdentityKind);
        if (!HasExactClientProfile(certificate, expectedProfile))
        {
            return Invalid("CertificateProfileMismatch", "The certificate EKUs do not match the exact Agent or Viewer profile.");
        }

        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        var usages = certificate.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        if (constraints.Length != 1 || constraints[0].CertificateAuthority ||
            usages.Length != 1 || usages[0].KeyUsages != X509KeyUsageFlags.DigitalSignature)
        {
            return Invalid(
                "CertificatePurposeMismatch",
                "The client certificate must be a non-CA signing identity with one exact digital-signature usage.");
        }

        if (!string.Equals(
                certificate.GetNameInfo(X509NameType.SimpleName, false),
                expected.IdentityId,
                StringComparison.Ordinal))
        {
            return Invalid("CertificateIdentityBindingMismatch",
                "The issuer-signed exact identity subject does not match the enrollment record.");
        }

        return new InfrastructureCertificateValidation(
            true,
            string.Empty,
            "The client certificate chain, profile, hash, validity and identity binding are exact.",
            sha256,
            expectedProfile,
            ComputeSubjectPublicKeyInfoSha256(certificate),
            validatedIssuerId);
    }

    public static InfrastructureCertificateValidation ValidateServerCertificate(
        X509Certificate2 certificate,
        string expectedCertificateSha256,
        string expectedDnsName,
        DateTime nowUtc,
        bool chainVerified)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (nowUtc.Kind != DateTimeKind.Utc ||
            string.IsNullOrWhiteSpace(expectedDnsName) ||
            expectedCertificateSha256.Length != 64)
        {
            return Invalid("ServerCertificateExpectationInvalid", "The configured Server certificate expectation is invalid.");
        }

        if (!chainVerified)
        {
            return Invalid("ServerCertificateChainRejected", "The configured Server chain was not trusted.");
        }

        var notBefore = certificate.NotBefore.ToUniversalTime();
        var notAfter = certificate.NotAfter.ToUniversalTime();
        if (nowUtc + MaximumClockSkew < notBefore || nowUtc - MaximumClockSkew > notAfter)
        {
            return Invalid("ServerCertificateOutsideValidity", "The Server certificate is outside its validity window.");
        }

        if (notAfter - notBefore > InfrastructureCredentialLifecyclePolicy.MaximumServerCertificateLifetime)
        {
            return Invalid("ServerCertificateLifetimeExceeded",
                "The Server certificate exceeds the fixed 397-day lifetime.");
        }

        var sha256 = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        if (!string.Equals(sha256, expectedCertificateSha256, StringComparison.OrdinalIgnoreCase))
        {
            return Invalid("ServerCertificatePinMismatch", "The Server certificate does not match the configured SHA-256 pin.");
        }

        if (!HasExactServerProfile(certificate))
        {
            return Invalid("ServerCertificateProfileMismatch", "The Server certificate lacks the exact Server TLS profile.");
        }

        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        var usages = certificate.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        if (constraints.Length != 1 || constraints[0].CertificateAuthority ||
            usages.Length != 1 || usages[0].KeyUsages != X509KeyUsageFlags.DigitalSignature)
        {
            return Invalid(
                "ServerCertificatePurposeMismatch",
                "The Server certificate must be a non-CA signing identity with one exact digital-signature usage.");
        }

        var dnsName = certificate.GetNameInfo(X509NameType.DnsName, false);
        if (!string.Equals(dnsName, expectedDnsName, StringComparison.OrdinalIgnoreCase))
        {
            return Invalid("ServerCertificateNameMismatch", "The Server certificate name does not match the configured endpoint.");
        }

        return new InfrastructureCertificateValidation(
            true,
            string.Empty,
            "The Server chain, endpoint name, application profile, validity and SHA-256 pin are exact.",
            sha256,
            InfrastructureCertificateProfiles.ServerTlsOid,
            ComputeSubjectPublicKeyInfoSha256(certificate));
    }

    public static string ComputeSubjectPublicKeyInfoSha256(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var spki = certificate.PublicKey.ExportSubjectPublicKeyInfo();
        try
        {
            return Convert.ToHexString(SHA256.HashData(spki));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(spki);
        }
    }

    public static bool IsNonExportablePrivateCredential(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (!certificate.HasPrivateKey)
        {
            return false;
        }

        using var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa is ECDsaCng ecdsaCng)
        {
            return IsNonExportablePrivateKey(ecdsaCng.Key);
        }

        using var rsa = certificate.GetRSAPrivateKey();
        return rsa is RSACng rsaCng && IsNonExportablePrivateKey(rsaCng.Key);
    }

    public static bool IsNonExportablePrivateKey(CngKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return
        (key.ExportPolicy &
         (CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport |
          CngExportPolicies.AllowArchiving | CngExportPolicies.AllowPlaintextArchiving)) == 0;
    }

    private static bool HasExactClientProfile(X509Certificate2 certificate, string profileOid)
    {
        if (string.IsNullOrEmpty(profileOid))
        {
            return false;
        }

        var extensions = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        if (extensions.Length != 1)
        {
            return false;
        }

        var values = extensions[0].EnhancedKeyUsages.Cast<Oid>()
            .Select(oid => oid.Value)
            .Where(value => value != null)
            .ToHashSet(StringComparer.Ordinal);
        return values.SetEquals(
            [InfrastructureCertificateProfiles.TlsClientAuthenticationOid, profileOid]);
    }

    private static bool HasExactServerProfile(X509Certificate2 certificate)
    {
        var extensions = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        if (extensions.Length != 1)
        {
            return false;
        }

        var values = extensions[0].EnhancedKeyUsages.Cast<Oid>()
            .Select(oid => oid.Value)
            .Where(value => value != null)
            .ToHashSet(StringComparer.Ordinal);
        return values.SetEquals(
            [InfrastructureCertificateProfiles.TlsServerAuthenticationOid,
                InfrastructureCertificateProfiles.ServerTlsOid]);
    }

    private static InfrastructureCertificateValidation Invalid(string code, string diagnostic) =>
        new(false, code, diagnostic);
}

/// <summary>
/// Server-side issuer for a proof-of-possession PKCS#10 request. The returned certificate
/// contains no private key; the non-exportable key remains on the enrolling endpoint.
/// </summary>
public sealed class WindowsInfrastructureEnrollmentIssuer
{
    public InfrastructureIssuedCertificate IssueClientCertificate(
        ReadOnlySpan<byte> pkcs10,
        X509Certificate2 issuerCertificate,
        InfrastructureCredentialRecord requestedCredential,
        DateTime nowUtc,
        TimeSpan validity)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(requestedCredential);
        if (!issuerCertificate.HasPrivateKey || nowUtc.Kind != DateTimeKind.Utc ||
            validity <= TimeSpan.Zero || !IsValidEnrollmentIssuer(issuerCertificate, nowUtc))
        {
            throw new InvalidOperationException("The enrollment issuer or requested validity is unavailable.");
        }

        var profileOid = InfrastructureCertificateProfiles.ForIdentity(requestedCredential.IdentityKind);
        if (string.IsNullOrEmpty(profileOid))
        {
            throw new InvalidOperationException("The requested certificate profile is unknown.");
        }

        var loaded = CertificateRequest.LoadSigningRequest(
            pkcs10.ToArray(),
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.Default,
            RSASignaturePadding.Pkcs1);
        var subject = new X500DistinguishedName($"CN={EscapeDistinguishedName(requestedCredential.IdentityId)}");
        var request = new CertificateRequest(subject, loaded.PublicKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection
            {
                new Oid(InfrastructureCertificateProfiles.TlsClientAuthenticationOid, "TLS Web Client Authentication"),
                new Oid(profileOid, requestedCredential.IdentityKind == InfrastructureIdentityKind.AgentService
                    ? "DFIRoscope Agent Service"
                    : "DFIRoscope Viewer User")
            },
            true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var notBefore = nowUtc.AddMinutes(-1);
        var notAfter = Min(notBefore + validity, issuerCertificate.NotAfter.ToUniversalTime());
        if (notAfter <= notBefore)
        {
            throw new InvalidOperationException("The issuer lifetime cannot cover the requested client credential.");
        }

        if (!InfrastructureCredentialLifecyclePolicy.IsCredentialLifetimeAllowed(
                requestedCredential.IdentityKind,
                notBefore,
                notAfter))
        {
            throw new InvalidOperationException("The requested client credential exceeds its fixed lifetime.");
        }

        Span<byte> serial = stackalloc byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        using var issuerRsa = issuerCertificate.GetRSAPrivateKey();
        using var issuerEcdsa = issuerCertificate.GetECDsaPrivateKey();
        var generator = issuerRsa != null
            ? X509SignatureGenerator.CreateForRSA(issuerRsa, RSASignaturePadding.Pkcs1)
            : issuerEcdsa != null
                ? X509SignatureGenerator.CreateForECDsa(issuerEcdsa)
                : throw new InvalidOperationException("The enrollment issuer uses an unsupported private-key algorithm.");
        using var issued = request.Create(
            issuerCertificate.SubjectName,
            generator,
            new DateTimeOffset(notBefore),
            new DateTimeOffset(notAfter),
            serial);
        return new InfrastructureIssuedCertificate(
            issued.Export(X509ContentType.Cert),
            issued.GetCertHashString(HashAlgorithmName.SHA256),
            profileOid,
            issuerCertificate.GetCertHashString(HashAlgorithmName.SHA256),
            notBefore,
            notAfter);
    }

    private static string EscapeDistinguishedName(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace(",", "\\,", StringComparison.Ordinal)
            .Replace("+", "\\+", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);

    private static bool IsValidEnrollmentIssuer(X509Certificate2 issuer, DateTime nowUtc)
    {
        var notBefore = issuer.NotBefore.ToUniversalTime();
        var notAfter = issuer.NotAfter.ToUniversalTime();
        if (nowUtc + TimeSpan.FromMinutes(5) < notBefore || nowUtc > notAfter ||
            notAfter - notBefore > InfrastructureCredentialLifecyclePolicy.MaximumEnrollmentIssuerLifetime)
        {
            return false;
        }

        var constraints = issuer.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        var usages = issuer.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        return constraints.Length == 1 && constraints[0].CertificateAuthority &&
               usages.Length == 1 && usages[0].KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign);
    }

    private static DateTime Min(DateTime left, DateTime right) => left <= right ? left : right;
}

/// <summary>Canonical application proof bound to one credential and connection generation.</summary>
public static class WindowsInfrastructureCredentialProof
{
    public static byte[] CreateTranscript(InfrastructureMutualAuthenticationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write(1);
        Write(writer, request.IdentityKind.ToString());
        Write(writer, request.IdentityId);
        Write(writer, request.AgentId);
        Write(writer, request.HostId);
        Write(writer, request.ViewerUserId);
        writer.Write(request.CredentialEpoch);
        writer.Write(request.ConnectionGeneration.ToByteArray());
        Write(writer, request.CertificateSha256);
        Write(writer, request.ServerUri);
        writer.Write(request.ProtocolGeneration);
        Write(writer, request.ReleaseId);
        writer.Write(request.ProofCreatedAtUtc.Ticks);
        writer.Write(request.SessionChallenge.Length);
        writer.Write(request.SessionChallenge);
        writer.Flush();
        return stream.ToArray();
    }

    public static byte[] Sign(
        InfrastructureMutualAuthenticationRequest request,
        X509Certificate2 credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        var transcript = CreateTranscript(request);
        using var ecdsa = credential.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            return ecdsa.SignData(transcript, HashAlgorithmName.SHA256);
        }

        using var rsa = credential.GetRSAPrivateKey();
        return rsa?.SignData(transcript, HashAlgorithmName.SHA256, RSASignaturePadding.Pss) ??
               throw new InvalidOperationException("The credential has no supported signing key.");
    }

    public static bool Verify(
        InfrastructureMutualAuthenticationRequest request,
        ReadOnlySpan<byte> signature,
        X509Certificate2 credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        var transcript = CreateTranscript(request);
        using var ecdsa = credential.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            return ecdsa.VerifyData(transcript, signature, HashAlgorithmName.SHA256);
        }

        using var rsa = credential.GetRSAPublicKey();
        return rsa != null && rsa.VerifyData(
            transcript,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
    }

    private static void Write(BinaryWriter writer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }
}

/// <summary>
/// Resolves only exact SHA-256 references from the approved Windows certificate stores.
/// It never falls back to another location, subject name, or current-user pairing state.
/// </summary>
public sealed class WindowsInfrastructureCertificateStore
{
    public X509Certificate2 Resolve(
        Contracts.ProtectedStoreReference reference,
        InfrastructureIdentityKind identityKind,
        bool requirePrivateKey)
    {
        ArgumentNullException.ThrowIfNull(reference);
        if (reference.Store != Contracts.ProtectedStoreKind.WindowsCertificateStore)
        {
            throw new InvalidOperationException("The protected reference is not a Windows certificate-store identity.");
        }

        var parts = reference.Identifier.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3 || !Enum.TryParse<StoreLocation>(parts[0], out var location) ||
            !Enum.TryParse<StoreName>(parts[1], out var name) || parts[2].Length != 64)
        {
            throw new InvalidOperationException("Certificate references must use Location/Store/SHA256.");
        }

        var expectedLocation = identityKind == InfrastructureIdentityKind.ViewerUser
            ? StoreLocation.CurrentUser
            : StoreLocation.LocalMachine;
        if (location != expectedLocation || name != StoreName.My)
        {
            throw new InvalidOperationException("The certificate reference is outside the approved identity store.");
        }

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var matches = store.Certificates
            .Where(certificate => string.Equals(
                certificate.GetCertHashString(HashAlgorithmName.SHA256),
                parts[2],
                StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (matches.Length != 1)
        {
            foreach (var certificate in matches)
            {
                certificate.Dispose();
            }

            throw new InvalidOperationException("The exact protected certificate reference is absent or ambiguous.");
        }

        var result = matches[0];
        if (requirePrivateKey &&
            !WindowsInfrastructureCertificatePolicy.IsNonExportablePrivateCredential(result))
        {
            result.Dispose();
            throw new InvalidOperationException("The private credential is missing or exportable.");
        }

        return result;
    }

    public X509Certificate2 ResolveLocalMachineBySha256(
        string certificateSha256,
        bool requirePrivateKey)
    {
        if (string.IsNullOrWhiteSpace(certificateSha256) || certificateSha256.Length != 64 ||
            !certificateSha256.All(Uri.IsHexDigit))
        {
            throw new InvalidOperationException("The LocalMachine certificate identity must be one SHA-256 value.");
        }

        return Resolve(
            new Contracts.ProtectedStoreReference
            {
                Store = Contracts.ProtectedStoreKind.WindowsCertificateStore,
                Identifier = $"{StoreLocation.LocalMachine}/{StoreName.My}/{certificateSha256.ToUpperInvariant()}"
            },
            InfrastructureIdentityKind.AgentService,
            requirePrivateKey);
    }
}

public sealed record WindowsInfrastructureCredentialRequest(
    string KeyName,
    Contracts.ProtectedStoreReference Reference,
    byte[] Pkcs10);

/// <summary>
/// Endpoint-side credential owner. It creates one named non-exportable machine key for
/// an Agent Service or current-user key for a Viewer, then installs only the returned
/// issuer certificate that matches that key. Cleanup deletes only the exact certificate/key.
/// </summary>
public sealed class WindowsInfrastructureCredentialProvisioner
{
    public WindowsInfrastructureCredentialRequest CreateRequest(
        InfrastructureIdentityKind identityKind,
        string identityId,
        string keyName)
    {
        if (identityKind is not (InfrastructureIdentityKind.AgentService or InfrastructureIdentityKind.ViewerUser) ||
            string.IsNullOrWhiteSpace(identityId) || identityId.Length > 512 ||
            string.IsNullOrWhiteSpace(keyName) || keyName.Length > 256)
        {
            throw new ArgumentException("The protected credential request identity is invalid.");
        }

        var creation = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing,
            KeyCreationOptions = identityKind == InfrastructureIdentityKind.AgentService
                ? CngKeyCreationOptions.MachineKey
                : CngKeyCreationOptions.None
        };
        using var key = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creation);
        using var ecdsa = new ECDsaCng(key);
        var request = new CertificateRequest(
            $"CN={EscapeDistinguishedName(identityId)}",
            ecdsa,
            HashAlgorithmName.SHA256);
        var pkcs10 = request.CreateSigningRequest();
        var location = identityKind == InfrastructureIdentityKind.AgentService
            ? StoreLocation.LocalMachine
            : StoreLocation.CurrentUser;
        return new WindowsInfrastructureCredentialRequest(
            keyName,
            new Contracts.ProtectedStoreReference
            {
                Store = Contracts.ProtectedStoreKind.WindowsCertificateStore,
                Identifier = $"{location}/{StoreName.My}/pending"
            },
            pkcs10);
    }

    public Contracts.ProtectedStoreReference InstallIssuedCertificate(
        InfrastructureIdentityKind identityKind,
        string keyName,
        ReadOnlySpan<byte> certificateDer,
        InfrastructureCredentialRecord expected,
        DateTime nowUtc)
    {
        var expectedLocation = identityKind == InfrastructureIdentityKind.AgentService
            ? StoreLocation.LocalMachine
            : StoreLocation.CurrentUser;
        using var publicCertificate = X509CertificateLoader.LoadCertificate(certificateDer);
        using var key = CngKey.Open(
            keyName,
            CngProvider.MicrosoftSoftwareKeyStorageProvider,
            identityKind == InfrastructureIdentityKind.AgentService
                ? CngKeyOpenOptions.MachineKey
                : CngKeyOpenOptions.None);
        if (!WindowsInfrastructureCertificatePolicy.IsNonExportablePrivateKey(key))
        {
            throw new InvalidOperationException("The protected endpoint credential became exportable.");
        }

        using var ecdsa = new ECDsaCng(key);
        using var certificate = publicCertificate.CopyWithPrivateKey(ecdsa);
        var validation = WindowsInfrastructureCertificatePolicy.ValidateClientCertificate(
            certificate,
            expected,
            nowUtc,
            chainVerified: true,
            expected.IssuerId);
        if (!validation.IsValid)
        {
            throw new InvalidOperationException(validation.Diagnostic);
        }

        using (var store = new X509Store(StoreName.My, expectedLocation))
        {
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            store.Add(certificate);
        }

        return new Contracts.ProtectedStoreReference
        {
            Store = Contracts.ProtectedStoreKind.WindowsCertificateStore,
            Identifier = $"{expectedLocation}/{StoreName.My}/{validation.CertificateSha256}"
        };
    }

    public void RemoveExact(
        InfrastructureIdentityKind identityKind,
        string keyName,
        string certificateSha256)
    {
        var location = identityKind == InfrastructureIdentityKind.AgentService
            ? StoreLocation.LocalMachine
            : StoreLocation.CurrentUser;
        using (var store = new X509Store(StoreName.My, location))
        {
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            var matches = store.Certificates
                .Where(certificate => string.Equals(
                    certificate.GetCertHashString(HashAlgorithmName.SHA256),
                    certificateSha256,
                    StringComparison.OrdinalIgnoreCase))
                .ToArray();
            foreach (var certificate in matches)
            {
                store.Remove(certificate);
                certificate.Dispose();
            }
        }

        try
        {
            using var key = CngKey.Open(
                keyName,
                CngProvider.MicrosoftSoftwareKeyStorageProvider,
                identityKind == InfrastructureIdentityKind.AgentService
                    ? CngKeyOpenOptions.MachineKey
                    : CngKeyOpenOptions.None);
            key.Delete();
        }
        catch (CryptographicException)
        {
        }
    }

    private static string EscapeDistinguishedName(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace(",", "\\,", StringComparison.Ordinal)
            .Replace("+", "\\+", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
}
