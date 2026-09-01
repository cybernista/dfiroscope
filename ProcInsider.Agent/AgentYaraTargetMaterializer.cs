using System.Security.Cryptography;
using ProcInsider.Models.Analysis;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal enum YaraPreparationFailure
{
    UnsafePath = 0,
    MissingAsset = 1,
    ScannerHashMismatch = 2,
    RulesetHashMismatch = 3,
    ManifestHashMismatch = 4,
    TargetHashMismatch = 5,
    TargetSizeMismatch = 6,
    IoFailure = 7
}

internal sealed class YaraPreparationException : Exception
{
    public YaraPreparationException(YaraPreparationFailure failure)
        : base($"YARA preparation failed ({failure}).")
    {
        Failure = failure;
    }

    public YaraPreparationFailure Failure { get; }
}

internal sealed class AgentYaraTargetMaterializer
{
    internal const string MarkerFileName = "dfiroscope-yara-working-v1.marker";
    internal const string ScannerFileName = "scanner.exe";
    internal const string RulesetFileName = "rules.yar";
    internal const string ManifestFileName = "rules.manifest.json";
    internal const string TargetFileName = "target.bin";

    private const long MaximumScannerBytes = 128L * 1024 * 1024;
    private const long MaximumRulesetBytes = 64L * 1024 * 1024;
    private const long MaximumManifestBytes = 4L * 1024 * 1024;
    private const int MaximumAbandonedDirectoriesPerPass = 256;

    public async Task<YaraPreparedExecution> PrepareAsync(
        YaraEvidenceTargetRecord resolved,
        YaraAgentExecutionRequest request,
        YaraExecutionAssetPaths assets,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolved);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(assets);

        var safeAssets = ValidateCompositionPaths(assets);
        var targetPath = ValidateTargetPath(resolved.FilePath);
        var workingRoot = ValidateWorkingRoot(assets.SessionRoot, assets.WorkingRoot);
        try
        {
            Directory.CreateDirectory(workingRoot);
            RejectReparsePoint(workingRoot);
        }
        catch (Exception ex) when (IsFileSystemFailure(ex))
        {
            throw new YaraPreparationException(YaraPreparationFailure.IoFailure);
        }

        CleanupAbandoned(workingRoot);
        var ownedDirectory = Path.Combine(workingRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(ownedDirectory);
        var prepared = new YaraPreparedExecution(workingRoot, ownedDirectory);

        try
        {
            await File.WriteAllTextAsync(
                prepared.MarkerPath,
                "DFIRoscope Agent YARA working directory schema 1",
                cancellationToken).ConfigureAwait(false);

            var scannerHash = await CopyAndHashAsync(
                safeAssets.ScannerPath,
                prepared.ScannerPath,
                0,
                null,
                MaximumScannerBytes,
                cancellationToken).ConfigureAwait(false);
            RequireHash(
                scannerHash,
                request.AdmissionProfile.Scanner.ArtifactHashSha256,
                YaraPreparationFailure.ScannerHashMismatch);

            var rulesetHash = await CopyAndHashAsync(
                safeAssets.RulesetPath,
                prepared.RulesetPath,
                0,
                null,
                MaximumRulesetBytes,
                cancellationToken).ConfigureAwait(false);
            RequireHash(
                rulesetHash,
                request.AdmissionProfile.Ruleset.RulesetHashSha256,
                YaraPreparationFailure.RulesetHashMismatch);

            var manifestHash = await CopyAndHashAsync(
                safeAssets.ManifestPath,
                prepared.ManifestPath,
                0,
                null,
                MaximumManifestBytes,
                cancellationToken).ConfigureAwait(false);
            RequireHash(
                manifestHash,
                request.AdmissionProfile.Ruleset.ManifestHashSha256,
                YaraPreparationFailure.ManifestHashMismatch);

            var targetHash = await CopyAndHashAsync(
                targetPath,
                prepared.TargetPath,
                request.Target.OffsetBytes,
                request.Target.LengthBytes,
                request.Limits.MaximumTargetBytes,
                cancellationToken).ConfigureAwait(false);
            RequireHash(
                targetHash,
                request.Target.ContentHashSha256,
                YaraPreparationFailure.TargetHashMismatch);

            return prepared;
        }
        catch
        {
            await prepared.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public static int CleanupAbandoned(string workingRoot)
    {
        if (string.IsNullOrWhiteSpace(workingRoot) || !Directory.Exists(workingRoot))
        {
            return 0;
        }

        var removed = 0;
        foreach (var directory in Directory.EnumerateDirectories(workingRoot)
                     .Take(MaximumAbandonedDirectoriesPerPass))
        {
            if (!Guid.TryParseExact(Path.GetFileName(directory), "N", out _))
            {
                continue;
            }

            try
            {
                RejectReparsePoint(directory);
                if (!File.Exists(Path.Combine(directory, MarkerFileName)))
                {
                    continue;
                }

                if (YaraPreparedExecution.TryDeleteOwnedDirectory(workingRoot, directory))
                {
                    removed++;
                }
            }
            catch (Exception ex) when (IsFileSystemFailure(ex) || ex is YaraPreparationException)
            {
                // A bounded restart cleanup failure leaves the directory for
                // later inspection rather than widening deletion authority.
            }
        }

        return removed;
    }

    private static SafeCompositionPaths ValidateCompositionPaths(YaraExecutionAssetPaths assets)
    {
        var scannerRoot = ValidateAbsoluteDirectory(assets.ScannerRoot);
        var rulesetRoot = ValidateAbsoluteDirectory(assets.RulesetRoot);
        var scanner = ValidateContainedFile(assets.ScannerPath, scannerRoot, "yr.exe");
        var ruleset = ValidateContainedFile(assets.RulesetPath, rulesetRoot);
        var manifest = ValidateContainedFile(assets.RulesetManifestPath, rulesetRoot);
        return new SafeCompositionPaths(scanner, ruleset, manifest);
    }

    private static string ValidateWorkingRoot(string sessionRoot, string workingRoot)
    {
        if (string.IsNullOrWhiteSpace(sessionRoot) || string.IsNullOrWhiteSpace(workingRoot))
        {
            throw new YaraPreparationException(YaraPreparationFailure.UnsafePath);
        }

        var session = Path.GetFullPath(sessionRoot);
        var expected = Path.GetFullPath(Path.Combine(session, "YaraWorking"));
        var actual = Path.GetFullPath(workingRoot);
        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
        {
            throw new YaraPreparationException(YaraPreparationFailure.UnsafePath);
        }

        RejectAlternateDataStream(session);
        if (!Directory.Exists(session))
        {
            throw new YaraPreparationException(YaraPreparationFailure.MissingAsset);
        }

        RejectReparseAncestors(session, Path.GetPathRoot(session)!);

        return actual;
    }

    private static string ValidateTargetPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new YaraPreparationException(YaraPreparationFailure.UnsafePath);
        }

        var fullPath = Path.GetFullPath(path);
        RejectAlternateDataStream(fullPath);
        RejectReparseAncestors(fullPath, Path.GetPathRoot(fullPath)!);
        if (!File.Exists(fullPath))
        {
            throw new YaraPreparationException(YaraPreparationFailure.MissingAsset);
        }

        RejectReparsePoint(fullPath);
        return fullPath;
    }

    private static string ValidateAbsoluteDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new YaraPreparationException(YaraPreparationFailure.UnsafePath);
        }

        var fullPath = Path.GetFullPath(path);
        RejectAlternateDataStream(fullPath);
        if (!Directory.Exists(fullPath))
        {
            throw new YaraPreparationException(YaraPreparationFailure.MissingAsset);
        }

        RejectReparseAncestors(fullPath, Path.GetPathRoot(fullPath)!);
        return fullPath;
    }

    private static string ValidateContainedFile(
        string path,
        string root,
        string? requiredLeaf = null)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new YaraPreparationException(YaraPreparationFailure.UnsafePath);
        }

        var fullPath = Path.GetFullPath(path);
        RejectAlternateDataStream(fullPath);
        var relative = Path.GetRelativePath(root, fullPath);
        if (Path.IsPathRooted(relative) || relative == ".." ||
            relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ||
            requiredLeaf != null && !string.Equals(
                Path.GetFileName(fullPath),
                requiredLeaf,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new YaraPreparationException(YaraPreparationFailure.UnsafePath);
        }

        RejectReparseAncestors(fullPath, root);
        if (!File.Exists(fullPath))
        {
            throw new YaraPreparationException(YaraPreparationFailure.MissingAsset);
        }

        RejectReparsePoint(fullPath);
        return fullPath;
    }

    private static void RejectReparseAncestors(string path, string root)
    {
        var current = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
        var normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
        while (!string.IsNullOrWhiteSpace(current))
        {
            RejectReparsePoint(current);
            var normalized = Path.GetFullPath(current).TrimEnd(Path.DirectorySeparatorChar);
            if (string.Equals(normalized, normalizedRoot, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            current = Path.GetDirectoryName(current);
        }

        throw new YaraPreparationException(YaraPreparationFailure.UnsafePath);
    }

    private static void RejectReparsePoint(string path)
    {
        if (IsReparsePoint(File.GetAttributes(path)))
        {
            throw new YaraPreparationException(YaraPreparationFailure.UnsafePath);
        }
    }

    internal static bool IsReparsePoint(FileAttributes attributes) =>
        (attributes & FileAttributes.ReparsePoint) != 0;

    private static void RejectAlternateDataStream(string fullPath)
    {
        var rootLength = Path.GetPathRoot(fullPath)?.Length ?? 0;
        if (fullPath.AsSpan(rootLength).Contains(':'))
        {
            throw new YaraPreparationException(YaraPreparationFailure.UnsafePath);
        }
    }

    private static async Task<string> CopyAndHashAsync(
        string sourcePath,
        string destinationPath,
        long offset,
        long? length,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var source = new FileStream(
                sourcePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var bytesToCopy = length ?? source.Length;
            if (offset < 0 || bytesToCopy <= 0 || bytesToCopy > maximumBytes ||
                offset > source.Length - bytesToCopy)
            {
                throw new YaraPreparationException(YaraPreparationFailure.TargetSizeMismatch);
            }

            source.Position = offset;
            await using var destination = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[128 * 1024];
            var remaining = bytesToCopy;
            while (remaining > 0)
            {
                var read = await source.ReadAsync(
                    buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new YaraPreparationException(YaraPreparationFailure.TargetSizeMismatch);
                }

                hash.AppendData(buffer, 0, read);
                await destination.WriteAsync(
                    buffer.AsMemory(0, read),
                    cancellationToken).ConfigureAwait(false);
                remaining -= read;
            }

            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            return Convert.ToHexString(hash.GetHashAndReset());
        }
        catch (YaraPreparationException)
        {
            throw;
        }
        catch (Exception ex) when (IsFileSystemFailure(ex))
        {
            throw new YaraPreparationException(YaraPreparationFailure.IoFailure);
        }
    }

    private static void RequireHash(string actual, string expected, YaraPreparationFailure failure)
    {
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new YaraPreparationException(failure);
        }
    }

    internal static bool IsFileSystemFailure(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or ArgumentException or
            NotSupportedException or System.Security.SecurityException;

    private sealed record SafeCompositionPaths(
        string ScannerPath,
        string RulesetPath,
        string ManifestPath);
}

internal sealed class YaraPreparedExecution : IAsyncDisposable
{
    private static readonly string[] OwnedLeafNames =
    [
        AgentYaraTargetMaterializer.ScannerFileName,
        AgentYaraTargetMaterializer.RulesetFileName,
        AgentYaraTargetMaterializer.ManifestFileName,
        AgentYaraTargetMaterializer.TargetFileName,
        AgentYaraTargetMaterializer.MarkerFileName
    ];

    private readonly string _workingRoot;
    private readonly string _ownedDirectory;
    private List<FileStream>? _readLocks;

    public YaraPreparedExecution(string workingRoot, string ownedDirectory)
    {
        _workingRoot = Path.GetFullPath(workingRoot);
        _ownedDirectory = Path.GetFullPath(ownedDirectory);
    }

    public string ScannerPath => Path.Combine(_ownedDirectory, AgentYaraTargetMaterializer.ScannerFileName);
    public string RulesetPath => Path.Combine(_ownedDirectory, AgentYaraTargetMaterializer.RulesetFileName);
    public string ManifestPath => Path.Combine(_ownedDirectory, AgentYaraTargetMaterializer.ManifestFileName);
    public string TargetPath => Path.Combine(_ownedDirectory, AgentYaraTargetMaterializer.TargetFileName);
    public string MarkerPath => Path.Combine(_ownedDirectory, AgentYaraTargetMaterializer.MarkerFileName);
    public string WorkingDirectory => _ownedDirectory;

    public async Task VerifyAndLockAsync(
        YaraAgentExecutionRequest request,
        CancellationToken cancellationToken)
    {
        _readLocks = new List<FileStream>(4);
        try
        {
            await AddVerifiedLockAsync(
                ScannerPath,
                request.AdmissionProfile.Scanner.ArtifactHashSha256,
                YaraPreparationFailure.ScannerHashMismatch,
                cancellationToken).ConfigureAwait(false);
            await AddVerifiedLockAsync(
                RulesetPath,
                request.AdmissionProfile.Ruleset.RulesetHashSha256,
                YaraPreparationFailure.RulesetHashMismatch,
                cancellationToken).ConfigureAwait(false);
            await AddVerifiedLockAsync(
                ManifestPath,
                request.AdmissionProfile.Ruleset.ManifestHashSha256,
                YaraPreparationFailure.ManifestHashMismatch,
                cancellationToken).ConfigureAwait(false);
            await AddVerifiedLockAsync(
                TargetPath,
                request.Target.ContentHashSha256,
                YaraPreparationFailure.TargetHashMismatch,
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            ReleaseLocks();
            throw;
        }
    }

    public ValueTask DisposeAsync()
    {
        ReleaseLocks();
        TryDeleteOwnedDirectory(_workingRoot, _ownedDirectory);
        return ValueTask.CompletedTask;
    }

    internal static bool TryDeleteOwnedDirectory(string workingRoot, string ownedDirectory)
    {
        var root = Path.GetFullPath(workingRoot).TrimEnd(Path.DirectorySeparatorChar);
        var directory = Path.GetFullPath(ownedDirectory).TrimEnd(Path.DirectorySeparatorChar);
        var expectedParent = Path.GetDirectoryName(directory)?.TrimEnd(Path.DirectorySeparatorChar);
        if (!string.Equals(root, expectedParent, StringComparison.OrdinalIgnoreCase) ||
            !Guid.TryParseExact(Path.GetFileName(directory), "N", out _) ||
            !Directory.Exists(directory))
        {
            return false;
        }

        foreach (var leaf in OwnedLeafNames)
        {
            var path = Path.Combine(directory, leaf);
            if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0)
            {
                File.Delete(path);
            }
        }

        if (!Directory.EnumerateFileSystemEntries(directory).Any())
        {
            Directory.Delete(directory, recursive: false);
            return true;
        }

        return false;
    }

    private async Task AddVerifiedLockAsync(
        string path,
        string expectedHash,
        YaraPreparationFailure failure,
        CancellationToken cancellationToken)
    {
        var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        try
        {
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)
                .ConfigureAwait(false));
            if (!string.Equals(hash, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                throw new YaraPreparationException(failure);
            }

            stream.Position = 0;
            _readLocks!.Add(stream);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private void ReleaseLocks()
    {
        if (_readLocks == null)
        {
            return;
        }

        foreach (var stream in _readLocks)
        {
            stream.Dispose();
        }

        _readLocks = null;
    }
}
