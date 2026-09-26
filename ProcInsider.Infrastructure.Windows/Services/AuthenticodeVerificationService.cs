using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class AuthenticodeTrustResult
{
    public AuthenticodeSignatureKind SignatureKind { get; init; } = AuthenticodeSignatureKind.Unknown;
    public AuthenticodeVerificationStatus VerificationStatus { get; init; } = AuthenticodeVerificationStatus.Unknown;
    public string SignerSubject { get; init; } = string.Empty;
    public string Publisher { get; init; } = string.Empty;
    public string CertificateThumbprint { get; init; } = string.Empty;
    public string Issuer { get; init; } = string.Empty;
    public bool HasTimestamp { get; init; }
    public string TimestampSubject { get; init; } = string.Empty;
    public DateTime? TimestampUtc { get; init; }
    public AuthenticodeRevocationMode RevocationMode { get; init; } = AuthenticodeRevocationMode.Unknown;
    public AuthenticodeRevocationStatus RevocationStatus { get; init; } = AuthenticodeRevocationStatus.Unknown;
    public string NativeStatusCode { get; init; } = string.Empty;
    public string DiagnosticCode { get; init; } = string.Empty;
    public string DiagnosticText { get; init; } = string.Empty;
}

public interface IAuthenticodeTrustProvider
{
    AuthenticodeTrustResult Verify(string filePath);
}

public interface IAuthenticodeVerificationService
{
    AuthenticodeVerificationRecord Verify(PeAnalysisRecord analysis);
}

public sealed class AuthenticodeVerificationService : IAuthenticodeVerificationService
{
    public const string PolicyName = "AuthenticodeGenericVerifyV2/OfflineCacheOnly/v1";
    private const int MaxDiagnosticLength = 1024;
    private readonly IAuthenticodeTrustProvider _trustProvider;

    public AuthenticodeVerificationService(IAuthenticodeTrustProvider? trustProvider = null)
    {
        _trustProvider = trustProvider ?? new WindowsAuthenticodeTrustProvider();
    }

    public AuthenticodeVerificationRecord Verify(PeAnalysisRecord analysis)
    {
        ArgumentNullException.ThrowIfNull(analysis);
        var verificationTimeUtc = DateTime.UtcNow;
        AuthenticodeTrustResult result;
        try
        {
            result = _trustProvider.Verify(analysis.FilePath);
            if (!IsClassified(result))
            {
                result = Failure(
                    AuthenticodeVerificationStatus.Error,
                    "authenticode.unclassified-provider-result",
                    "The trust provider returned an unknown enum value or an inconsistent signature/status combination.");
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            result = Failure(
                AuthenticodeVerificationStatus.AccessDenied,
                "authenticode.access-denied",
                ex.Message);
        }
        catch (FileNotFoundException ex)
        {
            result = Failure(
                AuthenticodeVerificationStatus.FileMissing,
                "authenticode.file-missing",
                ex.Message);
        }
        catch (PlatformNotSupportedException ex)
        {
            result = Failure(
                AuthenticodeVerificationStatus.Unsupported,
                "authenticode.unsupported-platform",
                ex.Message);
        }
        catch (Exception ex)
        {
            result = Failure(
                AuthenticodeVerificationStatus.Error,
                "authenticode.verification-error",
                ex.Message);
        }

        var record = new AuthenticodeVerificationRecord
        {
            CaseId = analysis.CaseId,
            EvidenceSessionId = analysis.EvidenceSessionId,
            CaptureId = analysis.CaptureId,
            SourceIdentityId = analysis.SourceIdentityId,
            HostId = analysis.HostId,
            ExecutionRootId = analysis.ExecutionRootId,
            AnalysisId = analysis.AnalysisId,
            ProcessEntityId = analysis.ProcessEntityId,
            ProcessKey = analysis.ProcessKey,
            ProcessId = analysis.ProcessId,
            ProcessGuid = analysis.ProcessGuid,
            ProcessName = analysis.ProcessName,
            FilePath = analysis.FilePath,
            Sha256Hash = analysis.Sha256Hash,
            SignatureKind = result.SignatureKind,
            VerificationStatus = result.VerificationStatus,
            SignerSubject = Bound(result.SignerSubject),
            Publisher = Bound(result.Publisher),
            CertificateThumbprint = Bound(result.CertificateThumbprint),
            Issuer = Bound(result.Issuer),
            HasTimestamp = result.HasTimestamp,
            TimestampSubject = Bound(result.TimestampSubject),
            TimestampUtc = result.TimestampUtc,
            VerificationPolicy = PolicyName,
            VerificationTimeUtc = verificationTimeUtc,
            RevocationMode = result.RevocationMode,
            RevocationStatus = result.RevocationStatus,
            NativeStatusCode = Bound(result.NativeStatusCode),
            DiagnosticCode = Bound(result.DiagnosticCode),
            DiagnosticText = Bound(result.DiagnosticText),
            Source = "AgentAuthenticodeVerification",
            SourceRunId = analysis.SourceRunId,
            IngestionJobId = analysis.IngestionJobId
        };
        record.VerificationId = BuildVerificationId(record);
        return record;
    }

    public static AuthenticodeVerificationRecord CloneForAnalysis(
        AuthenticodeVerificationRecord template,
        PeAnalysisRecord analysis)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(analysis);
        var clone = new AuthenticodeVerificationRecord
        {
            CaseId = analysis.CaseId,
            EvidenceSessionId = analysis.EvidenceSessionId,
            CaptureId = analysis.CaptureId,
            SourceIdentityId = analysis.SourceIdentityId,
            HostId = analysis.HostId,
            ExecutionRootId = analysis.ExecutionRootId,
            AnalysisId = analysis.AnalysisId,
            ProcessEntityId = analysis.ProcessEntityId,
            ProcessKey = analysis.ProcessKey,
            ProcessId = analysis.ProcessId,
            ProcessGuid = analysis.ProcessGuid,
            ProcessName = analysis.ProcessName,
            FilePath = template.FilePath,
            Sha256Hash = template.Sha256Hash,
            SignatureKind = template.SignatureKind,
            VerificationStatus = template.VerificationStatus,
            SignerSubject = template.SignerSubject,
            Publisher = template.Publisher,
            CertificateThumbprint = template.CertificateThumbprint,
            Issuer = template.Issuer,
            HasTimestamp = template.HasTimestamp,
            TimestampSubject = template.TimestampSubject,
            TimestampUtc = template.TimestampUtc,
            VerificationPolicy = template.VerificationPolicy,
            VerificationTimeUtc = template.VerificationTimeUtc,
            RevocationMode = template.RevocationMode,
            RevocationStatus = template.RevocationStatus,
            NativeStatusCode = template.NativeStatusCode,
            DiagnosticCode = template.DiagnosticCode,
            DiagnosticText = template.DiagnosticText,
            Source = template.Source,
            SourceRunId = analysis.SourceRunId,
            IngestionJobId = analysis.IngestionJobId
        };
        clone.VerificationId = BuildVerificationId(clone);
        return clone;
    }

    private static AuthenticodeTrustResult Failure(
        AuthenticodeVerificationStatus status,
        string code,
        string text) => new()
    {
        VerificationStatus = status,
        RevocationMode = AuthenticodeRevocationMode.OfflineCacheOnly,
        RevocationStatus = AuthenticodeRevocationStatus.Unknown,
        DiagnosticCode = code,
        DiagnosticText = Bound(text)
    };

    private static bool IsClassified(AuthenticodeTrustResult result)
    {
        if (result == null ||
            !Enum.IsDefined(result.SignatureKind) ||
            !Enum.IsDefined(result.VerificationStatus) ||
            !Enum.IsDefined(result.RevocationMode) ||
            !Enum.IsDefined(result.RevocationStatus))
        {
            return false;
        }

        return result.VerificationStatus switch
        {
            AuthenticodeVerificationStatus.Valid => result.SignatureKind is
                AuthenticodeSignatureKind.Embedded or AuthenticodeSignatureKind.Catalog,
            AuthenticodeVerificationStatus.Unsigned => result.SignatureKind == AuthenticodeSignatureKind.None,
            AuthenticodeVerificationStatus.Unknown or
                AuthenticodeVerificationStatus.Invalid or
                AuthenticodeVerificationStatus.Untrusted or
                AuthenticodeVerificationStatus.Expired or
                AuthenticodeVerificationStatus.Revoked or
                AuthenticodeVerificationStatus.RevocationUnavailable or
                AuthenticodeVerificationStatus.AccessDenied or
                AuthenticodeVerificationStatus.FileMissing or
                AuthenticodeVerificationStatus.Unsupported or
                AuthenticodeVerificationStatus.Error => true,
            _ => false
        };
    }

    private static string BuildVerificationId(AuthenticodeVerificationRecord record)
    {
        var identity = string.Join(
            '\n',
            record.AnalysisId,
            record.ProcessEntityId,
            record.ProcessKey,
            record.FilePath,
            record.Sha256Hash,
            record.VerificationPolicy,
            record.VerificationTimeUtc.ToUniversalTime().ToString("O"));
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(identity))).ToLowerInvariant();
    }

    private static string Bound(string value)
    {
        value ??= string.Empty;
        return value.Length <= MaxDiagnosticLength ? value : value[..MaxDiagnosticLength];
    }
}

/// <summary>
/// Uses WinVerifyTrust with cache-only revocation checks. It never downloads trust
/// material and reports catalog signatures separately from embedded signatures.
/// </summary>
public sealed class WindowsAuthenticodeTrustProvider : IAuthenticodeTrustProvider
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public AuthenticodeTrustResult Verify(string filePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Authenticode verification requires Windows.");
        }

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            throw new FileNotFoundException("The process image is unavailable for Authenticode verification.", filePath);
        }

        if (HasEmbeddedSignature(filePath))
        {
            return VerifyTrust(filePath, AuthenticodeSignatureKind.Embedded, catalog: null);
        }

        using var catalog = CatalogContext.TryOpen(filePath);
        if (catalog != null)
        {
            return VerifyTrust(filePath, AuthenticodeSignatureKind.Catalog, catalog);
        }

        return new AuthenticodeTrustResult
        {
            SignatureKind = AuthenticodeSignatureKind.None,
            VerificationStatus = AuthenticodeVerificationStatus.Unsigned,
            RevocationMode = AuthenticodeRevocationMode.OfflineCacheOnly,
            RevocationStatus = AuthenticodeRevocationStatus.NotChecked,
            NativeStatusCode = Hex(TrustENoSignature),
            DiagnosticCode = "authenticode.unsigned",
            DiagnosticText = "No embedded or Windows catalog Authenticode signature was found."
        };
    }

    private static AuthenticodeTrustResult VerifyTrust(
        string filePath,
        AuthenticodeSignatureKind signatureKind,
        CatalogContext? catalog)
    {
        var info = catalog == null
            ? MarshalFileInfo(filePath)
            : MarshalCatalogInfo(filePath, catalog);
        try
        {
            var data = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2,
                RevocationChecks = 1,
                UnionChoice = catalog == null ? 1u : 2u,
                InfoStruct = info,
                StateAction = 1,
                ProviderFlags = 0x00000080u | 0x00001000u,
                UiContext = 0
            };
            var action = GenericVerifyV2;
            var nativeStatus = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            X509Certificate2? providerCertificate = null;
            string timestampSubject = string.Empty;
            DateTime? timestampUtc = null;
            try
            {
                ReadProviderMetadata(data.StateData, out providerCertificate, out timestampSubject, out timestampUtc);
                var certificate = providerCertificate;
                var status = MapStatus(nativeStatus, signatureKind);
                return new AuthenticodeTrustResult
                {
                    SignatureKind = signatureKind,
                    VerificationStatus = status,
                    SignerSubject = certificate?.Subject ?? string.Empty,
                    Publisher = certificate?.GetNameInfo(X509NameType.SimpleName, forIssuer: false) ?? string.Empty,
                    CertificateThumbprint = certificate?.Thumbprint ?? string.Empty,
                    Issuer = certificate?.Issuer ?? string.Empty,
                    HasTimestamp = timestampUtc.HasValue || !string.IsNullOrWhiteSpace(timestampSubject),
                    TimestampSubject = timestampSubject,
                    TimestampUtc = timestampUtc,
                    RevocationMode = AuthenticodeRevocationMode.OfflineCacheOnly,
                    RevocationStatus = MapRevocationStatus(status),
                    NativeStatusCode = Hex(nativeStatus),
                    DiagnosticCode = DiagnosticCode(status),
                    DiagnosticText = DiagnosticText(status, signatureKind)
                };
            }
            finally
            {
                providerCertificate?.Dispose();
                data.StateAction = 2;
                _ = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            }
        }
        finally
        {
            if (catalog == null)
            {
                Marshal.DestroyStructure<WinTrustFileInfo>(info);
            }
            else
            {
                Marshal.DestroyStructure<WinTrustCatalogInfo>(info);
            }
            Marshal.FreeHGlobal(info);
        }
    }

    private static IntPtr MarshalFileInfo(string filePath)
    {
        var value = new WinTrustFileInfo
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            FilePath = filePath
        };
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        Marshal.StructureToPtr(value, pointer, false);
        return pointer;
    }

    private static IntPtr MarshalCatalogInfo(string filePath, CatalogContext catalog)
    {
        var value = new WinTrustCatalogInfo
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
            CatalogFilePath = catalog.CatalogPath,
            MemberTag = Convert.ToHexString(catalog.FileHash),
            MemberFilePath = filePath,
            MemberFile = catalog.FileHandle.DangerousGetHandle(),
            CalculatedFileHash = catalog.HashPointer,
            CalculatedFileHashSize = (uint)catalog.FileHash.Length,
            CatalogContext = catalog.CatalogHandle,
            CatalogAdmin = catalog.AdminHandle
        };
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
        Marshal.StructureToPtr(value, pointer, false);
        return pointer;
    }

    private static bool HasEmbeddedSignature(string path)
    {
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new BinaryReader(stream);
            if (stream.Length < 256 || reader.ReadUInt16() != 0x5A4D)
            {
                return false;
            }

            stream.Position = 0x3C;
            var peOffset = reader.ReadInt32();
            if (peOffset <= 0 || peOffset > stream.Length - 256)
            {
                return false;
            }

            stream.Position = peOffset;
            if (reader.ReadUInt32() != 0x00004550)
            {
                return false;
            }

            stream.Position += 20;
            var optionalMagic = reader.ReadUInt16();
            var dataDirectoryOffset = optionalMagic switch
            {
                0x10B => peOffset + 24 + 96,
                0x20B => peOffset + 24 + 112,
                _ => -1
            };
            if (dataDirectoryOffset < 0 || dataDirectoryOffset + 40 > stream.Length)
            {
                return false;
            }

            stream.Position = dataDirectoryOffset + (8 * 4);
            var certificateOffset = reader.ReadUInt32();
            var certificateSize = reader.ReadUInt32();
            return certificateOffset > 0 && certificateSize >= 8 &&
                   certificateOffset <= stream.Length - certificateSize;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static void ReadProviderMetadata(
        IntPtr stateData,
        out X509Certificate2? signerCertificate,
        out string timestampSubject,
        out DateTime? timestampUtc)
    {
        signerCertificate = null;
        timestampSubject = string.Empty;
        timestampUtc = null;
        if (stateData == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var providerData = WTHelperProvDataFromStateData(stateData);
            if (providerData == IntPtr.Zero)
            {
                return;
            }

            var signerPointer = WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
            if (signerPointer == IntPtr.Zero)
            {
                return;
            }

            var signer = Marshal.PtrToStructure<CryptProviderSigner>(signerPointer);
            signerCertificate = ReadFirstCertificate(signer.CertificateChain);
            if (signer.CounterSignerCount == 0 || signer.CounterSigners == IntPtr.Zero)
            {
                return;
            }

            var counterSigner = Marshal.PtrToStructure<CryptProviderSigner>(signer.CounterSigners);
            using var timestampCertificate = ReadFirstCertificate(counterSigner.CertificateChain);
            timestampSubject = timestampCertificate?.Subject ?? string.Empty;
            timestampUtc = FileTimeToUtc(counterSigner.VerifyAsOf);
        }
        catch (Exception)
        {
            signerCertificate?.Dispose();
            signerCertificate = null;
            timestampSubject = string.Empty;
            timestampUtc = null;
        }
    }

    private static X509Certificate2? ReadFirstCertificate(IntPtr chain)
    {
        if (chain == IntPtr.Zero)
        {
            return null;
        }

        var providerCertificate = Marshal.PtrToStructure<CryptProviderCertificate>(chain);
        if (providerCertificate.Certificate == IntPtr.Zero)
        {
            return null;
        }

        var context = Marshal.PtrToStructure<CertificateContext>(providerCertificate.Certificate);
        if (context.EncodedCertificate == IntPtr.Zero || context.EncodedCertificateSize == 0)
        {
            return null;
        }

        var bytes = new byte[context.EncodedCertificateSize];
        Marshal.Copy(context.EncodedCertificate, bytes, 0, bytes.Length);
        return X509CertificateLoader.LoadCertificate(bytes);
    }

    private static DateTime? FileTimeToUtc(System.Runtime.InteropServices.ComTypes.FILETIME fileTime)
    {
        var value = ((long)fileTime.dwHighDateTime << 32) | (uint)fileTime.dwLowDateTime;
        if (value <= 0)
        {
            return null;
        }

        try
        {
            return DateTime.FromFileTimeUtc(value);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static AuthenticodeVerificationStatus MapStatus(int status, AuthenticodeSignatureKind kind) => status switch
    {
        0 => AuthenticodeVerificationStatus.Valid,
        TrustENoSignature => kind == AuthenticodeSignatureKind.None
            ? AuthenticodeVerificationStatus.Unsigned
            : AuthenticodeVerificationStatus.Invalid,
        TrustEExplicitDistrust or TrustESubjectNotTrusted or CertEUntrustedRoot => AuthenticodeVerificationStatus.Untrusted,
        CertEExpired => AuthenticodeVerificationStatus.Expired,
        CertERevoked => AuthenticodeVerificationStatus.Revoked,
        CryptERevocationOffline or CertERevocationFailure => AuthenticodeVerificationStatus.RevocationUnavailable,
        EAccessDenied => AuthenticodeVerificationStatus.AccessDenied,
        TrustEBadDigest or TrustEBadMessage => AuthenticodeVerificationStatus.Invalid,
        _ => AuthenticodeVerificationStatus.Invalid
    };

    private static AuthenticodeRevocationStatus MapRevocationStatus(AuthenticodeVerificationStatus status) => status switch
    {
        AuthenticodeVerificationStatus.Valid => AuthenticodeRevocationStatus.Good,
        AuthenticodeVerificationStatus.Revoked => AuthenticodeRevocationStatus.Revoked,
        AuthenticodeVerificationStatus.RevocationUnavailable => AuthenticodeRevocationStatus.Unavailable,
        AuthenticodeVerificationStatus.Unsigned or AuthenticodeVerificationStatus.FileMissing or
            AuthenticodeVerificationStatus.Unsupported => AuthenticodeRevocationStatus.NotChecked,
        _ => AuthenticodeRevocationStatus.Unknown
    };

    private static string DiagnosticCode(AuthenticodeVerificationStatus status) => status switch
    {
        AuthenticodeVerificationStatus.Valid => "authenticode.valid",
        AuthenticodeVerificationStatus.Unsigned => "authenticode.unsigned",
        AuthenticodeVerificationStatus.Invalid => "authenticode.invalid",
        AuthenticodeVerificationStatus.Untrusted => "authenticode.untrusted",
        AuthenticodeVerificationStatus.Expired => "authenticode.expired",
        AuthenticodeVerificationStatus.Revoked => "authenticode.revoked",
        AuthenticodeVerificationStatus.RevocationUnavailable => "authenticode.revocation-unavailable",
        AuthenticodeVerificationStatus.AccessDenied => "authenticode.access-denied",
        AuthenticodeVerificationStatus.FileMissing => "authenticode.file-missing",
        AuthenticodeVerificationStatus.Unsupported => "authenticode.unsupported",
        AuthenticodeVerificationStatus.Error => "authenticode.error",
        AuthenticodeVerificationStatus.Unknown => "authenticode.unknown",
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unknown Authenticode verification status.")
    };

    private static string DiagnosticText(
        AuthenticodeVerificationStatus status,
        AuthenticodeSignatureKind kind) => status switch
    {
        AuthenticodeVerificationStatus.Valid => $"The {kind.ToString().ToLowerInvariant()} signature is valid under the cache-only verification policy; validity identifies a publisher but does not establish benignness.",
        AuthenticodeVerificationStatus.Unsigned => "No Authenticode signature is present.",
        AuthenticodeVerificationStatus.Invalid => $"The {kind.ToString().ToLowerInvariant()} signature failed integrity or policy verification.",
        AuthenticodeVerificationStatus.Untrusted => "The signature chain is not trusted under the verification policy.",
        AuthenticodeVerificationStatus.Expired => "The signing certificate is outside its validity period under the verification policy.",
        AuthenticodeVerificationStatus.Revoked => "A certificate in the signature chain is revoked.",
        AuthenticodeVerificationStatus.RevocationUnavailable => "Revocation status could not be established from the local cache.",
        AuthenticodeVerificationStatus.AccessDenied => "Access was denied while verifying the process image.",
        AuthenticodeVerificationStatus.FileMissing => "The process image was unavailable when verification ran.",
        AuthenticodeVerificationStatus.Unsupported => "Authenticode verification is unsupported on this platform.",
        AuthenticodeVerificationStatus.Error => "Authenticode verification failed unexpectedly.",
        AuthenticodeVerificationStatus.Unknown => "Authenticode verification did not produce a classified result.",
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unknown Authenticode verification status.")
    };

    private static string Hex(int status) => $"0x{unchecked((uint)status):X8}";

    private sealed class CatalogContext : IDisposable
    {
        private CatalogContext(
            IntPtr adminHandle,
            IntPtr catalogHandle,
            SafeFileHandle fileHandle,
            byte[] fileHash,
            string catalogPath)
        {
            AdminHandle = adminHandle;
            CatalogHandle = catalogHandle;
            FileHandle = fileHandle;
            FileHash = fileHash;
            CatalogPath = catalogPath;
            HashPointer = Marshal.AllocHGlobal(fileHash.Length);
            Marshal.Copy(fileHash, 0, HashPointer, fileHash.Length);
        }

        public IntPtr AdminHandle { get; }
        public IntPtr CatalogHandle { get; }
        public SafeFileHandle FileHandle { get; }
        public byte[] FileHash { get; }
        public string CatalogPath { get; }
        public IntPtr HashPointer { get; }

        public static CatalogContext? TryOpen(string filePath)
        {
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
            {
                return null;
            }

            SafeFileHandle? file = null;
            IntPtr catalog = IntPtr.Zero;
            try
            {
                file = File.OpenHandle(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                uint hashSize = 0;
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, ref hashSize, null, 0) || hashSize == 0)
                {
                    return null;
                }

                var hash = new byte[hashSize];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, ref hashSize, hash, 0))
                {
                    return null;
                }

                var previous = IntPtr.Zero;
                catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, hashSize, 0, ref previous);
                if (catalog == IntPtr.Zero)
                {
                    return null;
                }

                var info = new CatalogInfo { StructSize = (uint)Marshal.SizeOf<CatalogInfo>() };
                if (!CryptCATCatalogInfoFromContext(catalog, ref info, 0) || string.IsNullOrWhiteSpace(info.CatalogFilePath))
                {
                    return null;
                }

                var result = new CatalogContext(admin, catalog, file, hash, info.CatalogFilePath);
                admin = IntPtr.Zero;
                catalog = IntPtr.Zero;
                file = null;
                return result;
            }
            finally
            {
                file?.Dispose();
                if (catalog != IntPtr.Zero)
                {
                    CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                }
                if (admin != IntPtr.Zero)
                {
                    CryptCATAdminReleaseContext(admin, 0);
                }
            }
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(HashPointer);
            FileHandle.Dispose();
            CryptCATAdminReleaseCatalogContext(AdminHandle, CatalogHandle, 0);
            CryptCATAdminReleaseContext(AdminHandle, 0);
        }
    }

    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustEExplicitDistrust = unchecked((int)0x800B0111);
    private const int TrustESubjectNotTrusted = unchecked((int)0x800B0004);
    private const int TrustEBadDigest = unchecked((int)0x80096010);
    private const int TrustEBadMessage = unchecked((int)0x80096005);
    private const int CertEExpired = unchecked((int)0x800B0101);
    private const int CertEUntrustedRoot = unchecked((int)0x800B0109);
    private const int CertERevoked = unchecked((int)0x800B010C);
    private const int CertERevocationFailure = unchecked((int)0x800B010E);
    private const int CryptERevocationOffline = unchecked((int)0x80092013);
    private const int EAccessDenied = unchecked((int)0x80070005);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        [MarshalAs(UnmanagedType.LPWStr)] public string FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustCatalogInfo
    {
        public uint StructSize;
        public uint CatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string CatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberFilePath;
        public IntPtr MemberFile;
        public IntPtr CalculatedFileHash;
        public uint CalculatedFileHashSize;
        public IntPtr CatalogContext;
        public IntPtr CatalogAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr InfoStruct;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderSigner
    {
        public uint StructSize;
        public System.Runtime.InteropServices.ComTypes.FILETIME VerifyAsOf;
        public uint CertificateChainCount;
        public IntPtr CertificateChain;
        public uint SignerType;
        public IntPtr Signer;
        public uint Error;
        public uint CounterSignerCount;
        public IntPtr CounterSigners;
        public IntPtr ChainContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderCertificate
    {
        public uint StructSize;
        public IntPtr Certificate;
        public int Commercial;
        public int TrustedRoot;
        public int SelfSigned;
        public int TestCertificate;
        public uint RevokedReason;
        public uint Confidence;
        public uint Error;
        public IntPtr TrustListContext;
        public int TrustListSignerCertificate;
        public IntPtr CtlContext;
        public uint CtlError;
        public int IsCyclic;
        public IntPtr ChainElement;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertificateContext
    {
        public uint EncodingType;
        public IntPtr EncodedCertificate;
        public uint EncodedCertificateSize;
        public IntPtr CertificateInfo;
        public IntPtr CertificateStore;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint StructSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string CatalogFilePath;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref WinTrustData data);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr providerData,
        uint signerIndex,
        [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
        uint counterSignerIndex);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr catalogAdmin,
        IntPtr subsystem,
        string hashAlgorithm,
        IntPtr strongHashPolicy,
        uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr catalogAdmin,
        SafeFileHandle file,
        ref uint hashSize,
        [Out] byte[]? hash,
        uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr catalogAdmin,
        byte[] hash,
        uint hashSize,
        uint flags,
        ref IntPtr previousCatalog);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr catalogContext,
        ref CatalogInfo catalogInfo,
        uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr catalogAdmin,
        IntPtr catalogContext,
        uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catalogAdmin, uint flags);
}
