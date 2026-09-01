using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public interface IAgentPairingSecretProtector
{
    byte[] Protect(byte[] plaintext, byte[] entropy);

    byte[] Unprotect(byte[] protectedBytes, byte[] entropy);
}

public sealed class CurrentUserDpapiAgentPairingSecretProtector : IAgentPairingSecretProtector
{
    private const int CryptProtectUiForbidden = 0x1;

    public byte[] Protect(byte[] plaintext, byte[] entropy) =>
        RunDpapi(plaintext, entropy, protect: true);

    public byte[] Unprotect(byte[] protectedBytes, byte[] entropy) =>
        RunDpapi(protectedBytes, entropy, protect: false);

    private static byte[] RunDpapi(byte[] bytes, byte[] entropy, bool protect)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(entropy);
        var input = CreateBlob(bytes);
        var optionalEntropy = CreateBlob(entropy);
        var output = default(DataBlob);
        try
        {
            var succeeded = protect
                ? CryptProtectData(
                    ref input,
                    "DFIRoscope Live local-agent pairing",
                    ref optionalEntropy,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    ref output)
                : CryptUnprotectData(
                    ref input,
                    IntPtr.Zero,
                    ref optionalEntropy,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    ref output);
            if (!succeeded)
            {
                throw new CryptographicException(
                    $"Windows DPAPI failed with error {Marshal.GetLastWin32Error()}.");
            }

            var result = new byte[output.cbData];
            Marshal.Copy(output.pbData, result, 0, output.cbData);
            return result;
        }
        finally
        {
            FreeBlob(input, zeroMemory: true);
            FreeBlob(optionalEntropy, zeroMemory: true);
            if (output.pbData != IntPtr.Zero)
            {
                if (output.cbData > 0)
                {
                    Marshal.Copy(new byte[output.cbData], 0, output.pbData, output.cbData);
                }

                LocalFree(output.pbData);
            }
        }
    }

    private static DataBlob CreateBlob(byte[] bytes)
    {
        var blob = new DataBlob
        {
            cbData = bytes.Length,
            pbData = bytes.Length == 0 ? IntPtr.Zero : Marshal.AllocHGlobal(bytes.Length)
        };
        if (bytes.Length > 0)
        {
            Marshal.Copy(bytes, 0, blob.pbData, bytes.Length);
        }

        return blob;
    }

    private static void FreeBlob(DataBlob blob, bool zeroMemory)
    {
        if (blob.pbData == IntPtr.Zero)
        {
            return;
        }

        if (zeroMemory && blob.cbData > 0)
        {
            var zeros = new byte[blob.cbData];
            Marshal.Copy(zeros, 0, blob.pbData, zeros.Length);
        }

        Marshal.FreeHGlobal(blob.pbData);
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DataBlob pDataIn,
        string? szDataDescr,
        ref DataBlob pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DataBlob pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(
        ref DataBlob pDataIn,
        IntPtr ppszDataDescr,
        ref DataBlob pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DataBlob pDataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }
}

public sealed record AgentPairingStoreResult(
    AgentPairingState State,
    long PairingGeneration,
    DateTime? ExpiresAtUtc,
    string Status,
    AgentPairingLeaseMetadata? Lease = null);

public sealed record AgentPairingDiscoveryRecord(
    string DirectoryPath,
    string LeasePath,
    string SecretPath,
    AgentPairingLeaseMetadata Lease);

internal sealed class AgentPairingSecretLease : IDisposable
{
    public AgentPairingSecretLease(
        AgentPairingContext context,
        byte[] secret,
        DateTime expiresAtUtc)
    {
        Context = context;
        Secret = secret;
        ExpiresAtUtc = expiresAtUtc;
    }

    public AgentPairingContext Context { get; }

    public byte[] Secret { get; }

    public DateTime ExpiresAtUtc { get; }

    public void Dispose() => CryptographicOperations.ZeroMemory(Secret);
}

/// <summary>
/// Stores the non-secret discovery lease and the independently DPAPI-protected
/// high-entropy pairing secret in an account-local directory outside the capture.
/// </summary>
public sealed class AgentPairingStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private readonly object _gate = new();
    private readonly IAgentPairingSecretProtector _protector;

    public AgentPairingStore(
        InvestigationSessionPaths sessionPaths,
        IAgentPairingSecretProtector? protector = null)
        : this(
            sessionPaths?.AgentPairingDirectory ?? string.Empty,
            sessionPaths?.AgentPairingLeasePath ?? string.Empty,
            sessionPaths?.AgentPairingSecretPath ?? string.Empty,
            protector)
    {
    }

    public AgentPairingStore(
        string directory,
        string leasePath,
        string secretPath,
        IAgentPairingSecretProtector? protector = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(leasePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretPath);
        DirectoryPath = Path.GetFullPath(directory);
        LeasePath = EnsureContainedPath(DirectoryPath, leasePath, nameof(leasePath));
        SecretPath = EnsureContainedPath(DirectoryPath, secretPath, nameof(secretPath));
        _protector = protector ?? new CurrentUserDpapiAgentPairingSecretProtector();
    }

    public string DirectoryPath { get; }

    public string LeasePath { get; }

    public string SecretPath { get; }

    public static IReadOnlyList<AgentPairingDiscoveryRecord> Discover(
        string? localAppDataDirectory = null)
    {
        var root = SessionPathService.GetAgentPairingRootDirectory(localAppDataDirectory);
        if (!Directory.Exists(root))
        {
            return Array.Empty<AgentPairingDiscoveryRecord>();
        }

        var discoveries = new List<AgentPairingDiscoveryRecord>();
        foreach (var directory in Directory.GetDirectories(root))
        {
            var leasePath = Path.Combine(directory, "agent-lease.json");
            if (!File.Exists(leasePath))
            {
                continue;
            }

            try
            {
                var lease = JsonSerializer.Deserialize<AgentPairingLeaseMetadata>(
                    File.ReadAllText(leasePath),
                    JsonOptions);
                if (lease != null)
                {
                    discoveries.Add(new AgentPairingDiscoveryRecord(
                        directory,
                        leasePath,
                        Path.Combine(directory, "agent-pairing.dpapi.json"),
                        lease));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                discoveries.Add(new AgentPairingDiscoveryRecord(
                    directory,
                    leasePath,
                    Path.Combine(directory, "agent-pairing.dpapi.json"),
                    new AgentPairingLeaseMetadata { State = AgentPairingState.Corrupt }));
            }
        }

        return discoveries
            .OrderByDescending(item => item.Lease.LastHeartbeatUtc)
            .ToArray();
    }

    internal AgentPairingSecretLease CreateOrRotate(
        string sessionId,
        string databaseIdentity,
        string releaseId,
        DateTime nowUtc,
        TimeSpan lifetime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        ArgumentException.ThrowIfNullOrWhiteSpace(databaseIdentity);
        ArgumentException.ThrowIfNullOrWhiteSpace(releaseId);
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        }

        lock (_gate)
        {
            Directory.CreateDirectory(DirectoryPath);
            var generation = ReadEnvelopeGenerationNoThrow() + 1;
            var context = CreateContext(sessionId, databaseIdentity, releaseId, generation);
            var secret = RandomNumberGenerator.GetBytes(32);
            try
            {
                var entropy = BuildEntropy(context);
                var protectedSecret = _protector.Protect(secret, entropy);
                var expiresAtUtc = nowUtc.Add(lifetime);
                var envelope = new ProtectedAgentPairingSecret
                {
                    PairingContractVersion = context.PairingContractVersion,
                    IpcContractVersion = context.IpcContractVersion,
                    SessionId = context.SessionId,
                    DatabaseIdentity = context.DatabaseIdentity,
                    ReleaseId = context.ReleaseId,
                    PairingGeneration = generation,
                    CreatedAtUtc = nowUtc,
                    ExpiresAtUtc = expiresAtUtc,
                    ProtectedSecret = Convert.ToBase64String(protectedSecret)
                };
                AtomicWrite(SecretPath, JsonSerializer.Serialize(envelope, JsonOptions));
                return new AgentPairingSecretLease(context, secret, expiresAtUtc);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(secret);
                throw;
            }
        }
    }

    internal AgentPairingSecretLease? LoadSecret(
        string expectedSessionId,
        string expectedDatabaseIdentity,
        string expectedReleaseId,
        DateTime nowUtc,
        out AgentPairingStoreResult result,
        bool allowReleaseMismatch = false)
    {
        lock (_gate)
        {
            if (!File.Exists(SecretPath))
            {
                result = WithLease(
                    AgentPairingState.RePairRequired,
                    0,
                    null,
                    "No protected local-agent pairing secret exists for this session.",
                    nowUtc);
                return null;
            }

            ProtectedAgentPairingSecret envelope;
            try
            {
                envelope = JsonSerializer.Deserialize<ProtectedAgentPairingSecret>(
                    File.ReadAllText(SecretPath),
                    JsonOptions) ?? throw new JsonException("The protected pairing file is empty.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                result = WithLease(
                    AgentPairingState.Corrupt,
                    0,
                    null,
                    $"The protected local-agent pairing state is unreadable ({ex.GetType().Name}).",
                    nowUtc);
                return null;
            }

            var context = CreateContext(
                envelope.SessionId,
                envelope.DatabaseIdentity,
                envelope.ReleaseId,
                envelope.PairingGeneration);
            var mismatch = ValidateEnvelope(
                envelope,
                expectedSessionId,
                expectedDatabaseIdentity,
                expectedReleaseId,
                nowUtc,
                allowReleaseMismatch);
            if (mismatch != null)
            {
                result = WithLease(
                    mismatch.Value.State,
                    envelope.PairingGeneration,
                    envelope.ExpiresAtUtc,
                    mismatch.Value.Status,
                    nowUtc);
                return null;
            }

            try
            {
                var protectedBytes = Convert.FromBase64String(envelope.ProtectedSecret);
                var secret = _protector.Unprotect(protectedBytes, BuildEntropy(context));
                if (secret.Length < 32)
                {
                    CryptographicOperations.ZeroMemory(secret);
                    result = WithLease(
                        AgentPairingState.Corrupt,
                        envelope.PairingGeneration,
                        envelope.ExpiresAtUtc,
                        "The protected local-agent pairing secret has an invalid length.",
                        nowUtc);
                    return null;
                }

                result = WithLease(
                    AgentPairingState.Ready,
                    envelope.PairingGeneration,
                    envelope.ExpiresAtUtc,
                    "The protected local-agent pairing is ready.",
                    nowUtc);
                if (result.State != AgentPairingState.Ready)
                {
                    CryptographicOperations.ZeroMemory(secret);
                    return null;
                }

                return new AgentPairingSecretLease(context, secret, envelope.ExpiresAtUtc);
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException or PlatformNotSupportedException)
            {
                result = WithLease(
                    ex is CryptographicException ? AgentPairingState.WrongUser : AgentPairingState.Corrupt,
                    envelope.PairingGeneration,
                    envelope.ExpiresAtUtc,
                    ex is CryptographicException
                        ? "The pairing secret is not decryptable by the current Windows account."
                        : "The protected local-agent pairing secret is corrupt.",
                    nowUtc);
                return null;
            }
        }
    }

    internal AgentPairingSecretLease? AdoptPreparedSecret(
        string expectedSessionId,
        string expectedDatabaseIdentity,
        string expectedReleaseId,
        long expectedGeneration,
        DateTime nowUtc,
        out AgentPairingStoreResult result)
    {
        if (expectedGeneration <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedGeneration));
        }

        lock (_gate)
        {
            if (!File.Exists(SecretPath))
            {
                result = new AgentPairingStoreResult(
                    AgentPairingState.RePairRequired,
                    0,
                    null,
                    $"Prepared pairing generation {expectedGeneration} cannot be adopted because the protected secret is missing.",
                    ReadLease());
                return null;
            }

            ProtectedAgentPairingSecret envelope;
            try
            {
                envelope = JsonSerializer.Deserialize<ProtectedAgentPairingSecret>(
                    File.ReadAllText(SecretPath),
                    JsonOptions) ?? throw new JsonException("The protected pairing file is empty.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                result = new AgentPairingStoreResult(
                    AgentPairingState.Corrupt,
                    0,
                    null,
                    $"Prepared pairing generation {expectedGeneration} cannot be adopted because the protected state is unreadable ({ex.GetType().Name}).",
                    ReadLease());
                return null;
            }

            var context = CreateContext(
                envelope.SessionId,
                envelope.DatabaseIdentity,
                envelope.ReleaseId,
                envelope.PairingGeneration);
            var mismatch = ValidateEnvelope(
                envelope,
                expectedSessionId,
                expectedDatabaseIdentity,
                expectedReleaseId,
                nowUtc);
            if (mismatch != null)
            {
                result = new AgentPairingStoreResult(
                    mismatch.Value.State,
                    envelope.PairingGeneration,
                    envelope.ExpiresAtUtc,
                    $"Prepared pairing generation {expectedGeneration} cannot be adopted. {mismatch.Value.Status}",
                    ReadLease());
                return null;
            }

            if (envelope.PairingGeneration != expectedGeneration)
            {
                result = new AgentPairingStoreResult(
                    AgentPairingState.RePairRequired,
                    envelope.PairingGeneration,
                    envelope.ExpiresAtUtc,
                    $"Prepared pairing generation mismatch: startup expected {expectedGeneration}, but the protected state contains {envelope.PairingGeneration}.",
                    ReadLease());
                return null;
            }

            try
            {
                var protectedBytes = Convert.FromBase64String(envelope.ProtectedSecret);
                var secret = _protector.Unprotect(protectedBytes, BuildEntropy(context));
                if (secret.Length < 32)
                {
                    CryptographicOperations.ZeroMemory(secret);
                    result = new AgentPairingStoreResult(
                        AgentPairingState.Corrupt,
                        envelope.PairingGeneration,
                        envelope.ExpiresAtUtc,
                        $"Prepared pairing generation {expectedGeneration} contains an invalid protected secret.",
                        ReadLease());
                    return null;
                }

                result = new AgentPairingStoreResult(
                    AgentPairingState.Ready,
                    envelope.PairingGeneration,
                    envelope.ExpiresAtUtc,
                    $"Prepared pairing generation {expectedGeneration} is ready for exact agent adoption.",
                    ReadLease());
                return new AgentPairingSecretLease(context, secret, envelope.ExpiresAtUtc);
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException or PlatformNotSupportedException)
            {
                result = new AgentPairingStoreResult(
                    ex is CryptographicException ? AgentPairingState.WrongUser : AgentPairingState.Corrupt,
                    envelope.PairingGeneration,
                    envelope.ExpiresAtUtc,
                    ex is CryptographicException
                        ? $"Prepared pairing generation {expectedGeneration} is not decryptable by the current Windows account."
                        : $"Prepared pairing generation {expectedGeneration} contains corrupt protected state.",
                    ReadLease());
                return null;
            }
        }
    }

    public AgentPairingStoreResult Inspect(
        string expectedSessionId,
        string expectedDatabaseIdentity,
        string expectedReleaseId,
        DateTime? nowUtc = null)
    {
        using var secret = LoadSecret(
            expectedSessionId,
            expectedDatabaseIdentity,
            expectedReleaseId,
            nowUtc ?? DateTime.UtcNow,
            out var result);
        return result;
    }

    public AgentPairingLeaseMetadata? ReadLease()
    {
        lock (_gate)
        {
            if (!File.Exists(LeasePath))
            {
                return null;
            }

            try
            {
                return JsonSerializer.Deserialize<AgentPairingLeaseMetadata>(
                    File.ReadAllText(LeasePath),
                    JsonOptions);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                return new AgentPairingLeaseMetadata { State = AgentPairingState.Corrupt };
            }
        }
    }

    public void WriteLease(AgentPairingLeaseMetadata lease)
    {
        ArgumentNullException.ThrowIfNull(lease);
        lock (_gate)
        {
            Directory.CreateDirectory(DirectoryPath);
            AtomicWrite(
                LeasePath,
                JsonSerializer.Serialize(lease, JsonOptions),
                moveAttemptCount: 4);
        }
    }

    public void DeleteSecret()
    {
        lock (_gate)
        {
            if (File.Exists(SecretPath))
            {
                File.Delete(SecretPath);
            }
        }
    }

    private AgentPairingStoreResult WithLease(
        AgentPairingState secretState,
        long generation,
        DateTime? secretExpiry,
        string status,
        DateTime nowUtc)
    {
        var lease = ReadLease();
        if (lease == null)
        {
            return new AgentPairingStoreResult(secretState, generation, secretExpiry, status);
        }

        if (lease.State == AgentPairingState.Corrupt)
        {
            return new AgentPairingStoreResult(
                AgentPairingState.Corrupt,
                generation,
                secretExpiry,
                "The local-agent discovery lease is corrupt.",
                lease);
        }

        if (lease.State is AgentPairingState.Revoked or AgentPairingState.AgentExited)
        {
            return new AgentPairingStoreResult(
                lease.State,
                lease.PairingGeneration,
                lease.ExpiresAtUtc,
                lease.State == AgentPairingState.Revoked
                    ? "The local-agent pairing was explicitly revoked."
                    : "The paired local-agent process has exited.",
                lease);
        }

        if (lease.ExpiresAtUtc <= nowUtc || lease.State == AgentPairingState.Expired)
        {
            return new AgentPairingStoreResult(
                AgentPairingState.Expired,
                lease.PairingGeneration,
                lease.ExpiresAtUtc,
                "The local-agent discovery lease heartbeat expired.",
                lease);
        }

        return new AgentPairingStoreResult(secretState, generation, secretExpiry, status, lease);
    }

    private static (AgentPairingState State, string Status)? ValidateEnvelope(
        ProtectedAgentPairingSecret envelope,
        string expectedSessionId,
        string expectedDatabaseIdentity,
        string expectedReleaseId,
        DateTime nowUtc,
        bool allowReleaseMismatch = false)
    {
        if (envelope.PairingContractVersion != AgentContracts.PairingContractVersion ||
            envelope.IpcContractVersion != AgentContracts.ContractVersion ||
            envelope.PairingGeneration <= 0)
        {
            return (AgentPairingState.RePairRequired, "The local-agent pairing protocol is incompatible and must be replaced.");
        }

        if (!string.Equals(envelope.SessionId, expectedSessionId, StringComparison.Ordinal) ||
            !PathEquals(envelope.DatabaseIdentity, expectedDatabaseIdentity))
        {
            return (AgentPairingState.WrongSession, "The protected pairing belongs to another session or live database.");
        }

        if (!allowReleaseMismatch &&
            !string.Equals(envelope.ReleaseId, expectedReleaseId, StringComparison.Ordinal))
        {
            return (AgentPairingState.WrongRelease, "The protected pairing belongs to another application release.");
        }

        if (envelope.ExpiresAtUtc <= nowUtc)
        {
            return (AgentPairingState.Expired, "The protected local-agent pairing expired.");
        }

        if (string.IsNullOrWhiteSpace(envelope.ProtectedSecret))
        {
            return (AgentPairingState.Corrupt, "The protected local-agent pairing secret is missing.");
        }

        return null;
    }

    private long ReadEnvelopeGenerationNoThrow()
    {
        var envelopeGeneration = 0L;
        try
        {
            if (File.Exists(SecretPath))
            {
                envelopeGeneration = Math.Max(0, JsonSerializer.Deserialize<ProtectedAgentPairingSecret>(
                    File.ReadAllText(SecretPath),
                    JsonOptions)?.PairingGeneration ?? 0);
            }
        }
        catch
        {
        }

        var leaseGeneration = 0L;
        try
        {
            leaseGeneration = Math.Max(0, ReadLease()?.PairingGeneration ?? 0);
        }
        catch
        {
        }

        return Math.Max(envelopeGeneration, leaseGeneration);
    }

    private static AgentPairingContext CreateContext(
        string sessionId,
        string databaseIdentity,
        string releaseId,
        long generation) => new()
    {
        SessionId = sessionId?.Trim() ?? string.Empty,
        DatabaseIdentity = SessionPathService.NormalizeLiveDatabaseIdentity(databaseIdentity),
        ReleaseId = releaseId?.Trim() ?? string.Empty,
        PairingGeneration = generation
    };

    private static byte[] BuildEntropy(AgentPairingContext context) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(AgentPairingProofCrypto.BuildContextIdentity(context)));

    private static bool PathEquals(string left, string right)
    {
        try
        {
            return string.Equals(
                SessionPathService.NormalizeLiveDatabaseIdentity(left),
                SessionPathService.NormalizeLiveDatabaseIdentity(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string EnsureContainedPath(string directory, string path, string parameterName)
    {
        var fullPath = Path.GetFullPath(path);
        var relative = Path.GetRelativePath(directory, fullPath);
        if (Path.IsPathRooted(relative) ||
            string.Equals(relative, "..", StringComparison.Ordinal) ||
            relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
        {
            throw new ArgumentException("The pairing file must be inside its owned directory.", parameterName);
        }

        return fullPath;
    }

    private static void AtomicWrite(
        string path,
        string contents,
        int moveAttemptCount = 1)
    {
        if (moveAttemptCount < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(moveAttemptCount));
        }

        var temporaryPath = $"{path}.tmp-{Guid.NewGuid():N}";
        try
        {
            File.WriteAllText(temporaryPath, contents, new UTF8Encoding(false));
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    File.Move(temporaryPath, path, overwrite: true);
                    break;
                }
                catch (Exception ex) when (
                    attempt < moveAttemptCount &&
                    ex is IOException or UnauthorizedAccessException)
                {
                    Thread.Sleep(TimeSpan.FromMilliseconds(25));
                }
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private sealed record ProtectedAgentPairingSecret
    {
        public int PairingContractVersion { get; init; }
        public int IpcContractVersion { get; init; }
        public string SessionId { get; init; } = string.Empty;
        public string DatabaseIdentity { get; init; } = string.Empty;
        public string ReleaseId { get; init; } = string.Empty;
        public long PairingGeneration { get; init; }
        public DateTime CreatedAtUtc { get; init; }
        public DateTime ExpiresAtUtc { get; init; }
        public string ProtectedSecret { get; init; } = string.Empty;
    }
}

internal static class AgentPairingProofCrypto
{
    public static string ComputeResponseMac(
        byte[] secret,
        AgentPairingContext context,
        AgentPairingChallenge challenge,
        AgentIpcRequest protectedRequest)
    {
        using var hmac = new HMACSHA256(secret);
        var bytes = Encoding.UTF8.GetBytes(BuildProofMessage(context, challenge, protectedRequest));
        return Convert.ToBase64String(hmac.ComputeHash(bytes));
    }

    public static bool VerifyResponseMac(
        byte[] secret,
        AgentPairingContext context,
        AgentPairingChallenge challenge,
        AgentIpcRequest protectedRequest,
        string responseMac)
    {
        try
        {
            var expected = Convert.FromBase64String(ComputeResponseMac(secret, context, challenge, protectedRequest));
            var supplied = Convert.FromBase64String(responseMac);
            return CryptographicOperations.FixedTimeEquals(expected, supplied);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static string BuildContextIdentity(AgentPairingContext context) => BuildFields(
        context.PairingContractVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
        context.IpcContractVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
        context.SessionId,
        NormalizeForProof(context.DatabaseIdentity),
        context.ReleaseId,
        context.Endpoint,
        context.PairingGeneration.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private static string BuildProofMessage(
        AgentPairingContext context,
        AgentPairingChallenge challenge,
        AgentIpcRequest request) => BuildFields(
        BuildContextIdentity(context),
        challenge.ChallengeId.ToString("N"),
        challenge.Nonce,
        challenge.ExpiresAtUtc.ToUniversalTime().Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture),
        request.RequestId.ToString("N"),
        ((int)request.Kind).ToString(System.Globalization.CultureInfo.InvariantCulture),
        ((int)request.CommandKind).ToString(System.Globalization.CultureInfo.InvariantCulture),
        request.JobId?.ToString("N") ?? string.Empty,
        request.ViewerReleaseId,
        request.Payload?.GetRawText() ?? string.Empty);

    private static string BuildFields(params string?[] fields) => string.Concat(fields.Select(field =>
    {
        var value = field ?? string.Empty;
        return $"{value.Length}:{value}";
    }));

    private static string NormalizeForProof(string path)
    {
        try
        {
            return SessionPathService.NormalizeLiveDatabaseIdentity(path).ToUpperInvariant();
        }
        catch
        {
            return path ?? string.Empty;
        }
    }
}

public sealed class AgentPairingClientSession
{
    private readonly object _gate = new();
    private readonly Func<InvestigationSessionPaths, AgentPairingStore> _storeFactory;
    private InvestigationSessionPaths? _sessionPaths;
    private AgentPairingStore? _store;
    private string _releaseId = string.Empty;

    public AgentPairingClientSession()
        : this(static sessionPaths => new AgentPairingStore(sessionPaths))
    {
    }

    internal AgentPairingClientSession(
        Func<InvestigationSessionPaths, AgentPairingStore> storeFactory)
    {
        ArgumentNullException.ThrowIfNull(storeFactory);
        _storeFactory = storeFactory;
    }

    public void Bind(InvestigationSessionPaths sessionPaths, string releaseId)
    {
        ArgumentNullException.ThrowIfNull(sessionPaths);
        ArgumentException.ThrowIfNullOrWhiteSpace(releaseId);
        lock (_gate)
        {
            _sessionPaths = sessionPaths;
            _store = _storeFactory(sessionPaths);
            _releaseId = releaseId;
        }
    }

    public void Unbind()
    {
        lock (_gate)
        {
            _sessionPaths = null;
            _store = null;
            _releaseId = string.Empty;
        }
    }

    public AgentPairingStoreResult PrepareNewPairing(DateTime? nowUtc = null)
    {
        lock (_gate)
        {
            var (paths, store, releaseId) = RequireBinding();
            using var secret = store.CreateOrRotate(
                paths.SessionId,
                paths.LiveDatabasePath,
                releaseId,
                nowUtc ?? DateTime.UtcNow,
                TimeSpan.FromDays(7));
            return new AgentPairingStoreResult(
                AgentPairingState.Ready,
                secret.Context.PairingGeneration,
                secret.ExpiresAtUtc,
                "A new DPAPI-protected local-agent pairing was prepared.",
                store.ReadLease());
        }
    }

    public AgentPairingStoreResult Inspect(DateTime? nowUtc = null)
    {
        lock (_gate)
        {
            if (_sessionPaths == null || _store == null || string.IsNullOrWhiteSpace(_releaseId))
            {
                return new AgentPairingStoreResult(
                    AgentPairingState.RePairRequired,
                    0,
                    null,
                    "No active live session is bound for local-agent pairing.");
            }

            return _store.Inspect(
                _sessionPaths.SessionId,
                _sessionPaths.LiveDatabasePath,
                _releaseId,
                nowUtc);
        }
    }

    internal AgentPairingSecretLease? LoadForEndpoint(
        string endpoint,
        DateTime nowUtc,
        out AgentPairingStoreResult result,
        bool allowReleaseMismatch = false)
    {
        lock (_gate)
        {
            if (_sessionPaths == null || _store == null || string.IsNullOrWhiteSpace(_releaseId))
            {
                result = new AgentPairingStoreResult(
                    AgentPairingState.RePairRequired,
                    0,
                    null,
                    "No active live session is bound for local-agent pairing.");
                return null;
            }

            var secret = _store.LoadSecret(
                _sessionPaths.SessionId,
                _sessionPaths.LiveDatabasePath,
                _releaseId,
                nowUtc,
                out result,
                allowReleaseMismatch);
            if (secret == null)
            {
                return null;
            }

            var copy = secret.Secret.ToArray();
            secret.Dispose();
            return new AgentPairingSecretLease(
                secret.Context with { Endpoint = endpoint },
                copy,
                secret.ExpiresAtUtc);
        }
    }

    public void RevokeLocal()
    {
        lock (_gate)
        {
            _store?.DeleteSecret();
        }
    }

    private (InvestigationSessionPaths Paths, AgentPairingStore Store, string ReleaseId) RequireBinding()
    {
        if (_sessionPaths == null || _store == null || string.IsNullOrWhiteSpace(_releaseId))
        {
            throw new InvalidOperationException("No active live session is bound for local-agent pairing.");
        }

        return (_sessionPaths, _store, _releaseId);
    }
}

public sealed record AgentPairingAuthenticationResult(
    bool Allowed,
    string ErrorCode,
    string ErrorMessage)
{
    public static AgentPairingAuthenticationResult Permit() => new(true, string.Empty, string.Empty);

    public static AgentPairingAuthenticationResult Deny(string code, string message) => new(false, code, message);
}

/// <summary>
/// Agent-owned in-memory pairing authority and heartbeat lease. A single instance
/// is shared by current/former command and shutdown pipe aliases.
/// </summary>
public sealed class AgentPairingRuntime : IDisposable
{
    private static readonly TimeSpan SecretLifetime = TimeSpan.FromDays(7);
    private static readonly TimeSpan LeaseHeartbeatInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan LeaseExpiryInterval = TimeSpan.FromSeconds(20);
    private const int MaximumChallenges = 256;

    private readonly object _gate = new();
    private readonly AgentPairingStore _store;
    private readonly string _sessionId;
    private readonly string _databaseIdentity;
    private readonly string _releaseId;
    private readonly int _processId;
    private readonly ProcInsider.Models.CaptureWorkspaceMode _workspaceMode;
    private readonly bool _captureSealed;
    private readonly DateTime _processStartedAtUtc;
    private readonly string _executableName;
    private readonly string _executablePath;
    private readonly IReadOnlyList<string> _endpoints;
    private readonly TimeSpan _challengeLifetime;
    private readonly TimeSpan _leaseHeartbeatInterval;
    private readonly TimeSpan _leaseExpiryInterval;
    private readonly ConcurrentDictionary<Guid, PendingChallenge> _challenges = new();
    private readonly Timer _heartbeatTimer;
    private AgentPairingSecretLease? _secret;
    private AgentPairingState _state;
    private bool _disposed;

    private AgentPairingRuntime(
        AgentPairingStore store,
        string sessionId,
        string databaseIdentity,
        string releaseId,
        ProcInsider.Models.CaptureWorkspaceMode workspaceMode,
        bool captureSealed,
        int processId,
        DateTime processStartedAtUtc,
        string executableName,
        string executablePath,
        IReadOnlyList<string> endpoints,
        long? preparedPairingGeneration = null,
        TimeSpan? challengeLifetime = null,
        TimeSpan? leaseHeartbeatInterval = null,
        TimeSpan? leaseExpiryInterval = null)
    {
        _store = store;
        _sessionId = sessionId;
        _databaseIdentity = SessionPathService.NormalizeLiveDatabaseIdentity(databaseIdentity);
        _releaseId = releaseId;
        _workspaceMode = workspaceMode;
        _captureSealed = captureSealed;
        _processId = processId;
        _processStartedAtUtc = processStartedAtUtc;
        _executableName = executableName;
        _executablePath = executablePath;
        _endpoints = endpoints;
        _challengeLifetime = challengeLifetime ?? TimeSpan.FromSeconds(15);
        _leaseHeartbeatInterval = leaseHeartbeatInterval ?? LeaseHeartbeatInterval;
        _leaseExpiryInterval = leaseExpiryInterval ?? LeaseExpiryInterval;
        if (_challengeLifetime <= TimeSpan.Zero ||
            _leaseHeartbeatInterval <= TimeSpan.Zero ||
            _leaseExpiryInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(challengeLifetime), "Pairing lifetimes must be positive.");
        }
        if (preparedPairingGeneration.HasValue)
        {
            _secret = _store.AdoptPreparedSecret(
                sessionId,
                _databaseIdentity,
                releaseId,
                preparedPairingGeneration.Value,
                DateTime.UtcNow,
                out var adoption);
            if (_secret == null)
            {
                throw new InvalidOperationException(
                    $"PreparedPairingRejected ({adoption.State}): {adoption.Status}");
            }
        }
        else
        {
            _secret = _store.CreateOrRotate(
                sessionId,
                _databaseIdentity,
                releaseId,
                DateTime.UtcNow,
                SecretLifetime);
        }
        try
        {
            _state = AgentPairingState.Ready;
            WriteLease(DateTime.UtcNow, AgentPairingState.Ready);
            _heartbeatTimer = new Timer(
                _ => Heartbeat(),
                null,
                _leaseHeartbeatInterval,
                _leaseHeartbeatInterval);
        }
        catch
        {
            _secret?.Dispose();
            _secret = null;
            throw;
        }
    }

    public static AgentPairingRuntime Start(
        InvestigationSessionPaths sessionPaths,
        string releaseId,
        ProcInsider.Models.CaptureWorkspaceMode workspaceMode,
        bool captureSealed,
        long? preparedPairingGeneration = null)
    {
        ArgumentNullException.ThrowIfNull(sessionPaths);
        ArgumentException.ThrowIfNullOrWhiteSpace(releaseId);
        using var process = Process.GetCurrentProcess();
        var executablePath = Path.GetFullPath(
            Environment.ProcessPath ?? process.MainModule?.FileName ?? throw new InvalidOperationException(
                "The local-agent executable path is unavailable for pairing identity."));
        return new AgentPairingRuntime(
            new AgentPairingStore(sessionPaths),
            sessionPaths.SessionId,
            sessionPaths.LiveDatabasePath,
            releaseId,
            workspaceMode,
            captureSealed,
            Environment.ProcessId,
            process.StartTime.ToUniversalTime(),
            Path.GetFileName(executablePath),
            executablePath,
            AgentContracts.CompatiblePipeNames
                .Concat(AgentContracts.CompatibleShutdownControlPipeNames)
                .Distinct(StringComparer.Ordinal)
                .ToArray(),
            preparedPairingGeneration);
    }

    internal static AgentPairingRuntime StartForTest(
        AgentPairingStore store,
        string sessionId,
        string databaseIdentity,
        string releaseId,
        ProcInsider.Models.CaptureWorkspaceMode workspaceMode,
        bool captureSealed,
        int processId,
        DateTime processStartedAtUtc,
        string executableName,
        string executablePath,
        IReadOnlyList<string> endpoints,
        long? preparedPairingGeneration = null,
        TimeSpan? challengeLifetime = null,
        TimeSpan? leaseHeartbeatInterval = null,
        TimeSpan? leaseExpiryInterval = null) =>
        new(
            store,
            sessionId,
            databaseIdentity,
            releaseId,
            workspaceMode,
            captureSealed,
            processId,
            processStartedAtUtc,
            executableName,
            executablePath,
            endpoints,
            preparedPairingGeneration,
            challengeLifetime,
            leaseHeartbeatInterval,
            leaseExpiryInterval);

    public AgentPairingStatusSnapshot Status
    {
        get
        {
            lock (_gate)
            {
                return Snapshot(_state, DateTime.UtcNow);
            }
        }
    }

    public AgentIpcResponse CreateChallenge(
        string endpoint,
        AgentIpcRequest request)
    {
        lock (_gate)
        {
            if (_disposed || _state != AgentPairingState.Ready || _secret == null)
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "PairingUnavailable",
                    "The local-agent pairing is not available; explicitly re-pair or replace the agent.");
            }

            var challengeRequest = request.PairingChallenge;
            if (challengeRequest == null || challengeRequest.ProtectedRequestId == Guid.Empty)
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "PairingChallengeInvalid",
                    "The pairing challenge request is incomplete.");
            }

            var contextFailure = ValidateContext(endpoint, challengeRequest.Context);
            if (contextFailure != null)
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    contextFailure.ErrorCode,
                    contextFailure.ErrorMessage);
            }

            PurgeChallenges(DateTime.UtcNow);
            if (_challenges.Count >= MaximumChallenges)
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "PairingChallengeCapacity",
                    "The local-agent pairing challenge capacity is temporarily exhausted.",
                    isRetryable: true);
            }

            var challenge = new AgentPairingChallenge
            {
                ChallengeId = Guid.NewGuid(),
                Nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ExpiresAtUtc = DateTime.UtcNow.Add(_challengeLifetime),
                PairingGeneration = _secret.Context.PairingGeneration
            };
            _challenges[challenge.ChallengeId] = new PendingChallenge(
                challengeRequest.Context,
                challengeRequest.ProtectedRequestId,
                challenge);
            return AgentIpcResponse.Ok(request.RequestId) with
            {
                PairingChallenge = challenge,
                PairingStatus = Snapshot(AgentPairingState.Ready, DateTime.UtcNow)
            };
        }
    }

    public AgentPairingAuthenticationResult Authenticate(
        string endpoint,
        AgentIpcRequest request)
    {
        lock (_gate)
        {
            if (_disposed || _state != AgentPairingState.Ready || _secret == null)
            {
                return AgentPairingAuthenticationResult.Deny(
                    "PairingUnavailable",
                    "The local-agent pairing is not available; explicitly re-pair or replace the agent.");
            }

            var proof = request.PairingProof;
            if (proof == null || proof.ChallengeId == Guid.Empty || string.IsNullOrWhiteSpace(proof.ResponseMac))
            {
                return AgentPairingAuthenticationResult.Deny(
                    "PairingRequired",
                    "A valid protected pairing and fresh challenge response are required before agent health or commands are disclosed.");
            }

            if (!_challenges.TryRemove(proof.ChallengeId, out var pending))
            {
                return AgentPairingAuthenticationResult.Deny(
                    "PairingChallengeUnknown",
                    "The pairing challenge is unknown, expired, or already used.");
            }

            var nowUtc = DateTime.UtcNow;
            if (pending.Challenge.ExpiresAtUtc <= nowUtc ||
                pending.ProtectedRequestId != request.RequestId)
            {
                return AgentPairingAuthenticationResult.Deny(
                    "PairingChallengeExpired",
                    "The pairing challenge expired or does not authorize this request.");
            }

            var contextFailure = ValidateContext(endpoint, pending.Context);
            if (contextFailure != null)
            {
                return contextFailure;
            }

            if (!AgentPairingProofCrypto.VerifyResponseMac(
                    _secret.Secret,
                    pending.Context,
                    pending.Challenge,
                    request with { PairingProof = null },
                    proof.ResponseMac))
            {
                return AgentPairingAuthenticationResult.Deny(
                    "PairingProofInvalid",
                    "The local-agent pairing challenge response is invalid.");
            }

            return AgentPairingAuthenticationResult.Permit();
        }
    }

    public AgentPairingStatusSnapshot Rotate()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var replacement = _store.CreateOrRotate(
                _sessionId,
                _databaseIdentity,
                _releaseId,
                DateTime.UtcNow,
                SecretLifetime);
            var previous = _secret;
            _secret = replacement;
            previous?.Dispose();
            _challenges.Clear();
            _state = AgentPairingState.Ready;
            WriteLease(DateTime.UtcNow, _state);
            return Snapshot(_state, DateTime.UtcNow);
        }
    }

    public AgentPairingStatusSnapshot Revoke()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _state = AgentPairingState.Revoked;
            _challenges.Clear();
            _secret?.Dispose();
            _secret = null;
            _store.DeleteSecret();
            WriteLease(DateTime.UtcNow, _state);
            return Snapshot(_state, DateTime.UtcNow);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _heartbeatTimer.Dispose();
            _challenges.Clear();
            _secret?.Dispose();
            _secret = null;
            if (_state != AgentPairingState.Revoked)
            {
                _state = AgentPairingState.AgentExited;
                WriteLease(DateTime.UtcNow, _state);
            }
        }
    }

    private AgentPairingAuthenticationResult? ValidateContext(
        string endpoint,
        AgentPairingContext context)
    {
        if (_secret == null ||
            context.PairingContractVersion != AgentContracts.PairingContractVersion ||
            context.IpcContractVersion != AgentContracts.ContractVersion)
        {
            return AgentPairingAuthenticationResult.Deny(
                "PairingProtocolMismatch",
                "The local-agent pairing protocol is incompatible.");
        }

        if (!string.Equals(context.SessionId, _sessionId, StringComparison.Ordinal) ||
            !PathEquals(context.DatabaseIdentity, _databaseIdentity))
        {
            return AgentPairingAuthenticationResult.Deny(
                "PairingSessionMismatch",
                "The local-agent pairing does not match this session and live database.");
        }

        if (!string.Equals(context.ReleaseId, _releaseId, StringComparison.Ordinal))
        {
            return AgentPairingAuthenticationResult.Deny(
                "PairingReleaseMismatch",
                "The local-agent pairing does not match this release.");
        }

        if (context.PairingGeneration != _secret.Context.PairingGeneration)
        {
            return AgentPairingAuthenticationResult.Deny(
                "PairingGenerationMismatch",
                $"The local-agent pairing generation is stale and must be replaced: agent expects {_secret.Context.PairingGeneration}, request supplied {context.PairingGeneration}.");
        }

        if (!string.Equals(context.Endpoint, endpoint, StringComparison.Ordinal) ||
            !_endpoints.Contains(endpoint, StringComparer.Ordinal))
        {
            return AgentPairingAuthenticationResult.Deny(
                "PairingEndpointMismatch",
                "The local-agent pairing challenge is bound to another endpoint.");
        }

        return null;
    }

    private void Heartbeat()
    {
        lock (_gate)
        {
            if (_disposed ||
                _secret == null ||
                _state is not (AgentPairingState.Ready or AgentPairingState.Corrupt))
            {
                return;
            }

            try
            {
                WriteLease(DateTime.UtcNow, AgentPairingState.Ready);
                _state = AgentPairingState.Ready;
            }
            catch
            {
                _state = AgentPairingState.Corrupt;
                _challenges.Clear();
            }
        }
    }

    private void WriteLease(DateTime nowUtc, AgentPairingState state)
    {
        _store.WriteLease(new AgentPairingLeaseMetadata
        {
            SessionId = _sessionId,
            DatabaseIdentity = _databaseIdentity,
            ReleaseId = _releaseId,
            WorkspaceMode = _workspaceMode,
            CaptureSealed = _captureSealed,
            AgentProcessId = _processId,
            AgentStartedAtUtc = _processStartedAtUtc,
            ExecutableName = _executableName,
            ExecutablePath = _executablePath,
            Endpoints = _endpoints,
            PairingGeneration = _secret?.Context.PairingGeneration ??
                                _store.ReadLease()?.PairingGeneration ?? 0,
            LastHeartbeatUtc = nowUtc,
            ExpiresAtUtc = state == AgentPairingState.Ready
                ? nowUtc.Add(_leaseExpiryInterval)
                : nowUtc,
            State = state
        });
    }

    private AgentPairingStatusSnapshot Snapshot(AgentPairingState state, DateTime nowUtc)
    {
        var lease = _store.ReadLease();
        return new AgentPairingStatusSnapshot
        {
            State = state,
            PairingGeneration = _secret?.Context.PairingGeneration ?? lease?.PairingGeneration ?? 0,
            ExpiresAtUtc = state == AgentPairingState.Ready
                ? _secret?.ExpiresAtUtc
                : lease?.ExpiresAtUtc,
            LastHeartbeatUtc = lease?.LastHeartbeatUtc ?? nowUtc,
            Status = state switch
            {
                AgentPairingState.Ready => "Local-agent pairing authenticated and ready.",
                AgentPairingState.Revoked => "Local-agent pairing was explicitly revoked.",
                AgentPairingState.AgentExited => "The paired local-agent process exited.",
                _ => "Local-agent pairing is unavailable."
            }
        };
    }

    private void PurgeChallenges(DateTime nowUtc)
    {
        foreach (var pair in _challenges)
        {
            if (pair.Value.Challenge.ExpiresAtUtc <= nowUtc)
            {
                _challenges.TryRemove(pair.Key, out _);
            }
        }
    }

    private static bool PathEquals(string left, string right)
    {
        try
        {
            return string.Equals(
                SessionPathService.NormalizeLiveDatabaseIdentity(left),
                SessionPathService.NormalizeLiveDatabaseIdentity(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private sealed record PendingChallenge(
        AgentPairingContext Context,
        Guid ProtectedRequestId,
        AgentPairingChallenge Challenge);
}
