using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed record AgentInfrastructureEvidenceSpoolPolicy
{
    public long MaximumBytes { get; init; } = InfrastructureEvidenceInterchange.DefaultMaximumSpoolBytes;

    public int MaximumVolumePercent { get; init; } = InfrastructureEvidenceInterchange.DefaultVolumeQuotaPercent;

    public long FreeSpaceReserveBytes { get; init; } = InfrastructureEvidenceInterchange.DefaultFreeSpaceReserveBytes;

    public bool IsValid =>
        MaximumBytes > 0 && MaximumBytes <= InfrastructureEvidenceInterchange.DefaultMaximumSpoolBytes &&
        MaximumVolumePercent is > 0 and <= InfrastructureEvidenceInterchange.DefaultVolumeQuotaPercent &&
        FreeSpaceReserveBytes >= 0;

    public long EffectiveQuota(long volumeCapacityBytes)
    {
        if (!IsValid || volumeCapacityBytes <= 0)
        {
            return 0;
        }

        return Math.Min(MaximumBytes, checked(volumeCapacityBytes / 100 * MaximumVolumePercent));
    }
}

internal sealed record AgentInfrastructureSpoolDiskSnapshot(
    long VolumeCapacityBytes,
    long AvailableFreeBytes);

internal sealed record AgentInfrastructureEvidenceSpoolEntry(
    InfrastructureEvidenceBatchManifest Manifest,
    string PackagePath,
    long PackageBytes,
    string PackageSha256,
    DateTime PublishedAtUtc);

internal sealed record AgentInfrastructureEvidenceSpoolHealth
{
    public InfrastructureEvidenceSpoolState State { get; init; }

    public long EffectiveQuotaBytes { get; init; }

    public long PendingBytes { get; init; }

    public int PendingPackages { get; init; }

    public int QuarantinedPackages { get; init; }

    public string LastErrorCode { get; init; } = string.Empty;

    public DateTime ObservedAtUtc { get; init; }
}

internal sealed record AgentInfrastructureEvidenceSpoolResult(
    bool Accepted,
    InfrastructureEvidenceFailure Failure,
    string ErrorCode,
    AgentInfrastructureEvidenceSpoolEntry? Entry = null);

/// <summary>
/// Machine-owned outbound transfer spool. It is separate from AgentStagingWriter and the
/// live-event spill buffer: callers may publish only already-committed immutable packages.
/// No directory is created until Initialize/Enqueue is explicitly invoked behind publication.
/// </summary>
internal sealed class AgentInfrastructureEvidenceSpool
{
    private const string PackageExtension = ".dfev";
    private static readonly JsonSerializerOptions ReceiptJsonOptions = CreateReceiptJsonOptions();
    private readonly object _gate = new();
    private readonly AgentInfrastructureEvidenceSpoolPolicy _policy;
    private readonly Func<AgentInfrastructureSpoolDiskSnapshot> _diskSnapshot;
    private readonly string _root;
    private readonly string _pending;
    private readonly string _acknowledged;
    private readonly string _quarantine;
    private InfrastructureEvidenceSpoolState _state = InfrastructureEvidenceSpoolState.Healthy;
    private string _lastErrorCode = string.Empty;

    public AgentInfrastructureEvidenceSpool(
        InfrastructureAgentMachinePaths machinePaths,
        string captureId,
        AgentInfrastructureEvidenceSpoolPolicy? policy = null,
        Func<AgentInfrastructureSpoolDiskSnapshot>? diskSnapshot = null)
    {
        ArgumentNullException.ThrowIfNull(machinePaths);
        if (!Path.IsPathFullyQualified(machinePaths.SpoolDirectory) ||
            !InfrastructureEvidenceBatchCodec.IsIdentifier(captureId))
        {
            throw new ArgumentException("A contained machine spool and exact capture identity are required.");
        }

        _policy = policy ?? new AgentInfrastructureEvidenceSpoolPolicy();
        if (!_policy.IsValid)
        {
            throw new ArgumentException("The outbound spool policy exceeds the compiled Gate 0 ceiling.", nameof(policy));
        }

        var machineRoot = Path.GetFullPath(machinePaths.SpoolDirectory);
        var captureDirectory = "capture-" + InfrastructureEvidenceBatchCodec.Hash(
            System.Text.Encoding.UTF8.GetBytes(captureId));
        _root = Path.GetFullPath(Path.Combine(machineRoot, captureDirectory));
        if (!IsWithin(machineRoot, _root))
        {
            throw new InvalidDataException("The capture spool escaped the machine-owned spool root.");
        }

        _pending = Path.Combine(_root, "pending");
        _acknowledged = Path.Combine(_root, "acknowledged");
        _quarantine = Path.Combine(_root, "quarantine");
        _diskSnapshot = diskSnapshot ?? ReadDiskSnapshot;
    }

    public string RootDirectory => _root;

    public void Initialize()
    {
        lock (_gate)
        {
            Directory.CreateDirectory(_pending);
            Directory.CreateDirectory(_acknowledged);
            Directory.CreateDirectory(_quarantine);
            RecoverUnderLock();
        }
    }

    public AgentInfrastructureEvidenceSpoolResult Enqueue(InfrastructureEvidenceBatchPackage package)
    {
        ArgumentNullException.ThrowIfNull(package);
        var bytes = InfrastructureEvidenceBatchCodec.EncodePackage(package);
        lock (_gate)
        {
            EnsureInitialized();
            var finalPath = PackagePath(package.Manifest.BatchId);
            if (File.Exists(finalPath))
            {
                try
                {
                    var existing = InfrastructureEvidenceBatchCodec.DecodePackage(File.ReadAllBytes(finalPath));
                    return string.Equals(existing.Manifest.ManifestSha256, package.Manifest.ManifestSha256, StringComparison.Ordinal)
                        ? new(true, InfrastructureEvidenceFailure.None, "EvidencePackageAlreadySpooled", Entry(finalPath, existing))
                        : new(false, InfrastructureEvidenceFailure.DuplicateConflict, "EvidenceSpoolIdentityConflict");
                }
                catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
                {
                    QuarantineUnderLock(finalPath, "ExistingEvidencePackageCorrupt");
                    return new(false, InfrastructureEvidenceFailure.HashMismatch, "ExistingEvidencePackageCorrupt");
                }
            }

            var disk = _diskSnapshot();
            var quota = _policy.EffectiveQuota(disk.VolumeCapacityBytes);
            var pendingBytes = PendingBytesUnderLock();
            if (quota <= 0 || bytes.LongLength > quota - pendingBytes ||
                disk.AvailableFreeBytes - bytes.LongLength < _policy.FreeSpaceReserveBytes)
            {
                _state = InfrastructureEvidenceSpoolState.QuotaBlocked;
                _lastErrorCode = "EvidenceSpoolQuotaBlocked";
                return new(false, InfrastructureEvidenceFailure.BoundsExceeded, _lastErrorCode);
            }

            var temporaryPath = Path.Combine(_pending, ".tmp-" + Guid.NewGuid().ToString("N"));
            try
            {
                using (var stream = new FileStream(
                           temporaryPath,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           128 * 1024,
                           FileOptions.WriteThrough))
                {
                    stream.Write(bytes);
                    stream.Flush(flushToDisk: true);
                }

                File.Move(temporaryPath, finalPath);
                _state = InfrastructureEvidenceSpoolState.Healthy;
                _lastErrorCode = string.Empty;
                return new(true, InfrastructureEvidenceFailure.None, string.Empty, Entry(finalPath, package));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                TryDeleteTemporary(temporaryPath);
                _state = InfrastructureEvidenceSpoolState.Backpressured;
                _lastErrorCode = "EvidenceSpoolAtomicPublishFailed";
                return new(false, InfrastructureEvidenceFailure.StoreUnavailable, _lastErrorCode);
            }
        }
    }

    public IReadOnlyList<AgentInfrastructureEvidenceSpoolEntry> ListPending()
    {
        lock (_gate)
        {
            EnsureInitialized();
            return RecoverUnderLock();
        }
    }

    public InfrastructureEvidenceBatchPackage Load(AgentInfrastructureEvidenceSpoolEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        lock (_gate)
        {
            EnsureContained(entry.PackagePath, _pending);
            var package = InfrastructureEvidenceBatchCodec.DecodePackage(File.ReadAllBytes(entry.PackagePath));
            if (!string.Equals(package.Manifest.BatchId, entry.Manifest.BatchId, StringComparison.Ordinal) ||
                !string.Equals(package.Manifest.ManifestSha256, entry.Manifest.ManifestSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("EvidenceSpoolEntryChanged");
            }
            return package;
        }
    }

    public bool Acknowledge(
        AgentInfrastructureEvidenceSpoolEntry entry,
        InfrastructureEvidenceAcknowledgementPayload acknowledgement)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return FinalizeAcknowledgement(
            entry.Manifest.BatchId,
            entry.Manifest.ManifestSha256,
            entry.PackageSha256,
            acknowledgement);
    }

    public bool FinalizeAcknowledgement(
        string batchId,
        string manifestSha256,
        string packageSha256,
        InfrastructureEvidenceAcknowledgementPayload acknowledgement)
    {
        ArgumentNullException.ThrowIfNull(acknowledgement);
        lock (_gate)
        {
            EnsureInitialized();
            if (acknowledgement.Outcome is not (InfrastructureEvidenceTransferOutcome.Committed or
                InfrastructureEvidenceTransferOutcome.DuplicateCommitted) ||
                acknowledgement.Failure != InfrastructureEvidenceFailure.None ||
                !InfrastructureEvidenceBatchCodec.IsIdentifier(acknowledgement.CommitId) ||
                acknowledgement.ServerReceiptTimeUtc.Kind != DateTimeKind.Utc ||
                !InfrastructureEvidenceBatchCodec.IsIdentifier(batchId) ||
                !InfrastructureEvidenceBatchCodec.IsSha256(manifestSha256) ||
                !InfrastructureEvidenceBatchCodec.IsSha256(packageSha256) ||
                !string.Equals(acknowledgement.BatchId, batchId, StringComparison.Ordinal) ||
                !string.Equals(acknowledgement.ManifestSha256, manifestSha256, StringComparison.Ordinal))
            {
                return false;
            }

            var pendingPath = PackagePath(batchId);
            var receiptPath = Path.Combine(_acknowledged, batchId + ".receipt.json");
            var receiptTemporary = receiptPath + ".tmp-" + Guid.NewGuid().ToString("N");
            var packageArchive = Path.Combine(_acknowledged, batchId + PackageExtension);
            try
            {
                if (!File.Exists(pendingPath) && !File.Exists(packageArchive))
                {
                    return false;
                }
                if (File.Exists(pendingPath) && !VerifyPackageFile(
                        pendingPath,
                        batchId,
                        manifestSha256,
                        packageSha256))
                {
                    return false;
                }
                if (File.Exists(packageArchive) && !VerifyPackageFile(
                        packageArchive,
                        batchId,
                        manifestSha256,
                        packageSha256))
                {
                    return false;
                }

                var expectedReceipt = new EvidenceSpoolReceipt
                {
                    BatchId = acknowledgement.BatchId,
                    ManifestSha256 = acknowledgement.ManifestSha256,
                    PackageSha256 = packageSha256,
                    Outcome = acknowledgement.Outcome,
                    CommitId = acknowledgement.CommitId,
                    AcknowledgedAtUtc = acknowledgement.ServerReceiptTimeUtc
                };
                if (File.Exists(receiptPath))
                {
                    var existing = JsonSerializer.Deserialize<EvidenceSpoolReceipt>(
                        File.ReadAllBytes(receiptPath),
                        ReceiptJsonOptions);
                    if (existing == null || !Equals(existing, expectedReceipt))
                    {
                        return false;
                    }
                }
                else
                {
                    var receipt = JsonSerializer.SerializeToUtf8Bytes(expectedReceipt, ReceiptJsonOptions);
                    using (var stream = new FileStream(
                               receiptTemporary,
                               FileMode.CreateNew,
                               FileAccess.Write,
                               FileShare.None,
                               16 * 1024,
                               FileOptions.WriteThrough))
                    {
                        stream.Write(receipt);
                        stream.Flush(flushToDisk: true);
                    }
                    File.Move(receiptTemporary, receiptPath, overwrite: false);
                }

                if (!File.Exists(packageArchive))
                {
                    File.Move(pendingPath, packageArchive, overwrite: false);
                }
                else if (File.Exists(pendingPath))
                {
                    File.Delete(pendingPath);
                }
                _state = InfrastructureEvidenceSpoolState.Healthy;
                _lastErrorCode = string.Empty;
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                TryDeleteTemporary(receiptTemporary);
                _state = InfrastructureEvidenceSpoolState.Backpressured;
                _lastErrorCode = "EvidenceAcknowledgementPersistenceFailed";
                return false;
            }
        }
    }

    public bool Quarantine(AgentInfrastructureEvidenceSpoolEntry entry, string errorCode)
    {
        ArgumentNullException.ThrowIfNull(entry);
        lock (_gate)
        {
            EnsureContained(entry.PackagePath, _pending);
            return QuarantineUnderLock(entry.PackagePath, errorCode);
        }
    }

    public AgentInfrastructureEvidenceSpoolHealth GetHealth(DateTime nowUtc)
    {
        lock (_gate)
        {
            var disk = _diskSnapshot();
            var pending = Directory.Exists(_pending)
                ? Directory.EnumerateFiles(_pending, "*" + PackageExtension, SearchOption.TopDirectoryOnly).ToArray()
                : Array.Empty<string>();
            return new AgentInfrastructureEvidenceSpoolHealth
            {
                State = _state,
                EffectiveQuotaBytes = _policy.EffectiveQuota(disk.VolumeCapacityBytes),
                PendingBytes = pending.Sum(path => new FileInfo(path).Length),
                PendingPackages = pending.Length,
                QuarantinedPackages = Directory.Exists(_quarantine)
                    ? Directory.EnumerateFiles(_quarantine, "*" + PackageExtension, SearchOption.TopDirectoryOnly).Count()
                    : 0,
                LastErrorCode = _lastErrorCode,
                ObservedAtUtc = nowUtc
            };
        }
    }

    private IReadOnlyList<AgentInfrastructureEvidenceSpoolEntry> RecoverUnderLock()
    {
        var valid = new List<AgentInfrastructureEvidenceSpoolEntry>();
        var corrupt = false;
        foreach (var path in Directory.EnumerateFiles(_pending, "*" + PackageExtension, SearchOption.TopDirectoryOnly)
                     .Order(StringComparer.Ordinal))
        {
            try
            {
                var package = InfrastructureEvidenceBatchCodec.DecodePackage(File.ReadAllBytes(path));
                if (!string.Equals(Path.GetFileNameWithoutExtension(path), package.Manifest.BatchId, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("EvidenceSpoolFileIdentityMismatch");
                }
                valid.Add(Entry(path, package));
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
            {
                corrupt = QuarantineUnderLock(path, "EvidenceSpoolRecoveryCorrupt") || corrupt;
            }
        }

        if (corrupt)
        {
            _state = InfrastructureEvidenceSpoolState.Corrupt;
            _lastErrorCode = "EvidenceSpoolRecoveryCorrupt";
        }
        return valid.OrderBy(entry => entry.Manifest.SequenceStart).ThenBy(entry => entry.Manifest.BatchId, StringComparer.Ordinal).ToArray();
    }

    private bool QuarantineUnderLock(string path, string errorCode)
    {
        try
        {
            EnsureContained(path, _pending);
            if (!File.Exists(path))
            {
                return false;
            }
            var destination = Path.Combine(
                _quarantine,
                Path.GetFileNameWithoutExtension(path) + "-" + DateTime.UtcNow.ToString("yyyyMMddHHmmssfff") + PackageExtension);
            File.Move(path, destination);
            _state = InfrastructureEvidenceSpoolState.Corrupt;
            _lastErrorCode = errorCode;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            _state = InfrastructureEvidenceSpoolState.Corrupt;
            _lastErrorCode = "EvidenceSpoolQuarantineFailed";
            return false;
        }
    }

    private AgentInfrastructureEvidenceSpoolEntry Entry(string path, InfrastructureEvidenceBatchPackage package)
    {
        using var stream = File.OpenRead(path);
        var packageSha256 = Convert.ToHexStringLower(SHA256.HashData(stream));
        return new(
            package.Manifest,
            path,
            new FileInfo(path).Length,
            packageSha256,
            File.GetLastWriteTimeUtc(path));
    }

    private static bool VerifyPackageFile(
        string path,
        string batchId,
        string manifestSha256,
        string packageSha256)
    {
        using var stream = File.OpenRead(path);
        var actualPackageSha256 = Convert.ToHexStringLower(SHA256.HashData(stream));
        if (!string.Equals(actualPackageSha256, packageSha256, StringComparison.Ordinal))
        {
            return false;
        }
        var package = InfrastructureEvidenceBatchCodec.DecodePackage(File.ReadAllBytes(path));
        return string.Equals(package.Manifest.BatchId, batchId, StringComparison.Ordinal) &&
               string.Equals(package.Manifest.ManifestSha256, manifestSha256, StringComparison.Ordinal);
    }

    private string PackagePath(string batchId) => Path.Combine(_pending, batchId + PackageExtension);

    private long PendingBytesUnderLock() =>
        Directory.EnumerateFiles(_pending, "*" + PackageExtension, SearchOption.TopDirectoryOnly)
            .Sum(path => new FileInfo(path).Length);

    private AgentInfrastructureSpoolDiskSnapshot ReadDiskSnapshot()
    {
        var root = Path.GetPathRoot(_root) ?? throw new DirectoryNotFoundException("EvidenceSpoolVolumeUnavailable");
        var drive = new DriveInfo(root);
        return new AgentInfrastructureSpoolDiskSnapshot(drive.TotalSize, drive.AvailableFreeSpace);
    }

    private void EnsureInitialized()
    {
        if (!Directory.Exists(_pending) || !Directory.Exists(_acknowledged) || !Directory.Exists(_quarantine))
        {
            throw new InvalidOperationException("The outbound evidence spool has not been initialized.");
        }
    }

    private static void EnsureContained(string path, string root)
    {
        if (!IsWithin(Path.GetFullPath(root), Path.GetFullPath(path)))
        {
            throw new InvalidDataException("The outbound evidence spool path escaped its owner root.");
        }
    }

    private static bool IsWithin(string root, string candidate)
    {
        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var normalizedCandidate = Path.GetFullPath(candidate);
        return string.Equals(normalizedRoot, normalizedCandidate, StringComparison.OrdinalIgnoreCase) ||
               normalizedCandidate.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void TryDeleteTemporary(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static JsonSerializerOptions CreateReceiptJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false));
        return options;
    }

    private sealed record EvidenceSpoolReceipt
    {
        public string BatchId { get; init; } = string.Empty;
        public string ManifestSha256 { get; init; } = string.Empty;
        public string PackageSha256 { get; init; } = string.Empty;
        public InfrastructureEvidenceTransferOutcome Outcome { get; init; }
        public string CommitId { get; init; } = string.Empty;
        public DateTime AcknowledgedAtUtc { get; init; }
    }
}
