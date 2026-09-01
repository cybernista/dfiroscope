using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProcInsider.Compatibility;

public enum DirectoryMigrationOutcome
{
    NoSource,
    NoOp,
    Succeeded,
    Conflict,
    PartialFailure,
    Failed
}

public sealed record DirectoryMigrationRequest
{
    public string SourceRoot { get; init; } = string.Empty;

    public string TargetRoot { get; init; } = string.Empty;

    public string ObservationLogPath { get; init; } = string.Empty;

    public Func<string, IDisposable?>? AcquireSourceDirectoryLease { get; init; }
}

public sealed record DirectoryMigrationResult
{
    public DirectoryMigrationOutcome Outcome { get; init; }

    public int CopiedFileCount { get; init; }

    public int IdenticalFileCount { get; init; }

    public int ConflictCount { get; init; }

    public int FailureCount { get; init; }

    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();

    public bool ObservationRecorded { get; init; }
}

/// <summary>
/// Copies a legacy directory tree into a preferred directory without deleting
/// source data or replacing any target file. The implementation intentionally
/// treats file contents as opaque bytes so protected secrets remain protected.
/// </summary>
public static class DirectoryCompatibilityMigration
{
    private const int MaxDiagnostics = 64;

    private static readonly JsonSerializerOptions ObservationJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static DirectoryMigrationResult Migrate(DirectoryMigrationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        string sourceRoot;
        string targetRoot;
        string observationLogPath;
        try
        {
            sourceRoot = Path.GetFullPath(request.SourceRoot);
            targetRoot = Path.GetFullPath(request.TargetRoot);
            observationLogPath = Path.GetFullPath(request.ObservationLogPath);
            ValidateRoots(sourceRoot, targetRoot);
        }
        catch (Exception ex) when (IsPathFailure(ex))
        {
            return new DirectoryMigrationResult
            {
                Outcome = DirectoryMigrationOutcome.Failed,
                FailureCount = 1,
                Diagnostics = [$"request: {ex.GetType().Name}: {ex.Message}"]
            };
        }

        var state = new MigrationState(sourceRoot);
        if (!Directory.Exists(sourceRoot))
        {
            return RecordObservation(
                new DirectoryMigrationResult { Outcome = DirectoryMigrationOutcome.NoSource },
                sourceRoot,
                targetRoot,
                observationLogPath);
        }

        try
        {
            Directory.CreateDirectory(targetRoot);
            CopyDirectory(sourceRoot, targetRoot, request.AcquireSourceDirectoryLease, state);
        }
        catch (Exception ex) when (IsPathFailure(ex))
        {
            state.AddFailure("root", ex);
        }

        var result = new DirectoryMigrationResult
        {
            Outcome = GetOutcome(state),
            CopiedFileCount = state.CopiedFileCount,
            IdenticalFileCount = state.IdenticalFileCount,
            ConflictCount = state.ConflictCount,
            FailureCount = state.FailureCount,
            Diagnostics = state.Diagnostics.ToArray()
        };
        return RecordObservation(result, sourceRoot, targetRoot, observationLogPath);
    }

    private static void CopyDirectory(
        string sourceDirectory,
        string targetDirectory,
        Func<string, IDisposable?>? acquireSourceDirectoryLease,
        MigrationState state)
    {
        IDisposable? lease = null;
        try
        {
            lease = acquireSourceDirectoryLease?.Invoke(sourceDirectory);
        }
        catch (Exception ex) when (IsPathFailure(ex))
        {
            state.AddFailure(state.Relative(sourceDirectory), ex);
            return;
        }

        using (lease)
        {
            FileSystemInfo sourceInfo;
            try
            {
                sourceInfo = new DirectoryInfo(sourceDirectory);
                if ((sourceInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    state.AddFailure(state.Relative(sourceDirectory), new IOException("Reparse-point directories are not migrated."));
                    return;
                }

                if (File.Exists(targetDirectory))
                {
                    state.AddConflict(state.Relative(sourceDirectory), "The target path is a file.");
                    return;
                }

                Directory.CreateDirectory(targetDirectory);
            }
            catch (Exception ex) when (IsPathFailure(ex))
            {
                state.AddFailure(state.Relative(sourceDirectory), ex);
                return;
            }

            string[] files;
            string[] directories;
            try
            {
                files = Directory.GetFiles(sourceDirectory);
                directories = Directory.GetDirectories(sourceDirectory);
                Array.Sort(files, StringComparer.OrdinalIgnoreCase);
                Array.Sort(directories, StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex) when (IsPathFailure(ex))
            {
                state.AddFailure(state.Relative(sourceDirectory), ex);
                return;
            }

            foreach (var sourceFile in files)
            {
                CopyFile(sourceFile, Path.Combine(targetDirectory, Path.GetFileName(sourceFile)), state);
            }

            foreach (var childSource in directories)
            {
                CopyDirectory(
                    childSource,
                    Path.Combine(targetDirectory, Path.GetFileName(childSource)),
                    acquireSourceDirectoryLease,
                    state);
            }
        }
    }

    private static void CopyFile(string sourceFile, string targetFile, MigrationState state)
    {
        var relativePath = state.Relative(sourceFile);
        string? temporaryPath = null;
        try
        {
            var sourceInfo = new FileInfo(sourceFile);
            if ((sourceInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                state.AddFailure(relativePath, new IOException("Reparse-point files are not migrated."));
                return;
            }

            if (Directory.Exists(targetFile))
            {
                state.AddConflict(relativePath, "The target path is a directory.");
                return;
            }

            if (File.Exists(targetFile))
            {
                if (FilesEqual(sourceFile, targetFile))
                {
                    state.IdenticalFileCount++;
                }
                else
                {
                    state.AddConflict(relativePath, "Target data already exists and was preserved.");
                }

                return;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(targetFile)!);
            temporaryPath = targetFile + $".migration-{Environment.ProcessId}-{Guid.NewGuid():N}.tmp";
            using (var source = new FileStream(sourceFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var target = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 1024 * 128,
                       FileOptions.WriteThrough))
            {
                source.CopyTo(target);
                target.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, targetFile, overwrite: false);
            temporaryPath = null;
            File.SetLastWriteTimeUtc(targetFile, sourceInfo.LastWriteTimeUtc);
            state.CopiedFileCount++;
        }
        catch (Exception ex) when (IsPathFailure(ex))
        {
            if (File.Exists(targetFile))
            {
                state.AddConflict(relativePath, "Target data appeared during migration and was preserved.");
            }
            else
            {
                state.AddFailure(relativePath, ex);
            }
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(temporaryPath))
            {
                try
                {
                    File.Delete(temporaryPath);
                }
                catch (Exception ex) when (IsPathFailure(ex))
                {
                    Trace.TraceWarning($"Unable to remove incomplete migration file: {ex.GetType().Name}: {ex.Message}");
                }
            }
        }
    }

    private static bool FilesEqual(string firstPath, string secondPath)
    {
        var first = new FileInfo(firstPath);
        var second = new FileInfo(secondPath);
        if (first.Length != second.Length)
        {
            return false;
        }

        using var firstStream = new FileStream(firstPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var secondStream = new FileStream(secondPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var firstHash = SHA256.HashData(firstStream);
        var secondHash = SHA256.HashData(secondStream);
        return CryptographicOperations.FixedTimeEquals(firstHash, secondHash);
    }

    private static DirectoryMigrationOutcome GetOutcome(MigrationState state)
    {
        if (state.FailureCount > 0)
        {
            return state.CopiedFileCount > 0 || state.IdenticalFileCount > 0 || state.ConflictCount > 0
                ? DirectoryMigrationOutcome.PartialFailure
                : DirectoryMigrationOutcome.Failed;
        }

        if (state.ConflictCount > 0)
        {
            return DirectoryMigrationOutcome.Conflict;
        }

        return state.CopiedFileCount > 0
            ? DirectoryMigrationOutcome.Succeeded
            : DirectoryMigrationOutcome.NoOp;
    }

    private static DirectoryMigrationResult RecordObservation(
        DirectoryMigrationResult result,
        string sourceRoot,
        string targetRoot,
        string observationLogPath)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(observationLogPath)!);
            var observation = new
            {
                timestampUtc = DateTimeOffset.UtcNow,
                outcome = result.Outcome.ToString(),
                sourceRootName = Path.GetFileName(sourceRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)),
                targetRootName = Path.GetFileName(targetRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)),
                result.CopiedFileCount,
                result.IdenticalFileCount,
                result.ConflictCount,
                result.FailureCount,
                result.Diagnostics
            };
            var line = JsonSerializer.Serialize(observation, ObservationJsonOptions) + Environment.NewLine;
            using var stream = new FileStream(observationLogPath, FileMode.Append, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            writer.Write(line);
            return result with { ObservationRecorded = true };
        }
        catch (Exception ex) when (IsPathFailure(ex))
        {
            Trace.TraceWarning($"Local-data migration observation could not be recorded: {ex.GetType().Name}: {ex.Message}");
            return result;
        }
    }

    private static void ValidateRoots(string sourceRoot, string targetRoot)
    {
        if (string.Equals(sourceRoot, targetRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Source and target migration roots must be different.");
        }

        var sourcePrefix = EnsureTrailingSeparator(sourceRoot);
        var targetPrefix = EnsureTrailingSeparator(targetRoot);
        if (targetPrefix.StartsWith(sourcePrefix, StringComparison.OrdinalIgnoreCase) ||
            sourcePrefix.StartsWith(targetPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Migration roots must not contain one another.");
        }
    }

    private static string EnsureTrailingSeparator(string path) =>
        path.EndsWith(Path.DirectorySeparatorChar) ? path : path + Path.DirectorySeparatorChar;

    private static bool IsPathFailure(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or
        System.Security.SecurityException;

    private sealed class MigrationState
    {
        private readonly string _sourceRoot;

        public MigrationState(string sourceRoot)
        {
            _sourceRoot = sourceRoot;
        }

        public int CopiedFileCount { get; set; }

        public int IdenticalFileCount { get; set; }

        public int ConflictCount { get; private set; }

        public int FailureCount { get; private set; }

        public List<string> Diagnostics { get; } = [];

        public string Relative(string path)
        {
            var relative = Path.GetRelativePath(_sourceRoot, path);
            return relative == "." ? "root" : relative;
        }

        public void AddConflict(string relativePath, string detail)
        {
            ConflictCount++;
            AddDiagnostic($"conflict:{relativePath}: {detail}");
        }

        public void AddFailure(string relativePath, Exception ex)
        {
            FailureCount++;
            AddDiagnostic($"failure:{relativePath}: {ex.GetType().Name}: {ex.Message}");
        }

        private void AddDiagnostic(string diagnostic)
        {
            if (Diagnostics.Count < MaxDiagnostics)
            {
                Diagnostics.Add(diagnostic);
            }
        }
    }
}
