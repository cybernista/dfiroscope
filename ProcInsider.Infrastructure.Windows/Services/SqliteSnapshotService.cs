using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

public enum SqliteSnapshotSourceOpenMode
{
    Unknown = 0,
    ReadOnly = 1
}

public sealed record SqliteSnapshotSourceDiagnostics(
    SqliteSnapshotSourceOpenMode OpenMode,
    bool ViewerCheckpointAttempted,
    string Summary);

public sealed record SqliteSnapshotResult(
    string SnapshotPath,
    DateTime SnapshotUtc,
    double TotalDurationMilliseconds = 0,
    double BackupDurationMilliseconds = 0,
    double ReplaceDurationMilliseconds = 0,
    SqliteSnapshotSourceDiagnostics? SourceAccess = null,
    string DiagnosticsLogPath = "");

public enum LiveSnapshotSourcePendingReason
{
    DatabaseNotCreated,
    CompatibilityMetadataNotCommitted,
    BusyOrLocked
}

public sealed class LiveSnapshotSourcePendingException : IOException
{
    public LiveSnapshotSourcePendingException(
        string databasePath,
        LiveSnapshotSourcePendingReason reason,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        DatabasePath = Path.GetFullPath(databasePath);
        Reason = reason;
    }

    public string DatabasePath { get; }

    public LiveSnapshotSourcePendingReason Reason { get; }
}

public sealed class SqliteSnapshotService
{
    public Task<SqliteSnapshotResult> CreateSnapshotAsync(
        string liveDatabasePath,
        string snapshotDatabasePath,
        string expectedEvidenceSessionId = "",
        CaptureManifestCompatibilityMetadata? manifest = null,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(
            () => CreateSnapshot(
                liveDatabasePath,
                snapshotDatabasePath,
                expectedEvidenceSessionId,
                manifest,
                cancellationToken),
            cancellationToken);
    }

    public SqliteSnapshotResult CreateSnapshot(
        string liveDatabasePath,
        string snapshotDatabasePath,
        string expectedEvidenceSessionId = "",
        CaptureManifestCompatibilityMetadata? manifest = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(liveDatabasePath))
        {
            throw new ArgumentException("Live database path is required.", nameof(liveDatabasePath));
        }

        if (string.IsNullOrWhiteSpace(snapshotDatabasePath))
        {
            throw new ArgumentException("Snapshot database path is required.", nameof(snapshotDatabasePath));
        }

        liveDatabasePath = Path.GetFullPath(liveDatabasePath);
        snapshotDatabasePath = Path.GetFullPath(snapshotDatabasePath);
        if (!File.Exists(liveDatabasePath))
        {
            if (IsCurrentLiveInitializationTarget(manifest, expectedEvidenceSessionId))
            {
                throw new LiveSnapshotSourcePendingException(
                    liveDatabasePath,
                    LiveSnapshotSourcePendingReason.DatabaseNotCreated,
                    "The active Agent has not created the live SQLite database yet.");
            }

            throw new FileNotFoundException("The live SQLite database does not exist.", liveDatabasePath);
        }

        CaptureCompatibilityAssessment sourceAssessment;
        try
        {
            sourceAssessment = SqliteStagingStore.AssessExistingDatabaseForLiveSnapshot(
                liveDatabasePath,
                manifest,
                expectedEvidenceSessionId);
        }
        catch (SqliteException ex) when (
            ex.SqliteErrorCode is 5 or 6 &&
            IsCurrentLiveInitializationTarget(manifest, expectedEvidenceSessionId))
        {
            throw new LiveSnapshotSourcePendingException(
                liveDatabasePath,
                LiveSnapshotSourcePendingReason.BusyOrLocked,
                "The active live SQLite database is temporarily busy while the Agent commits evidence.",
                ex);
        }

        if (sourceAssessment.State == CaptureCompatibilityState.MissingVersionMetadata &&
            IsCurrentLiveInitializationTarget(manifest, expectedEvidenceSessionId))
        {
            throw new LiveSnapshotSourcePendingException(
                liveDatabasePath,
                LiveSnapshotSourcePendingReason.CompatibilityMetadataNotCommitted,
                "The active Agent has created the live SQLite database but has not committed its compatibility metadata yet.");
        }

        CaptureCompatibilityPolicy.EnsureAllowed(
            sourceAssessment,
            CaptureOpenCapability.ReadEvidence);

        Directory.CreateDirectory(Path.GetDirectoryName(snapshotDatabasePath) ?? AppContext.BaseDirectory);

        var snapshotUtc = DateTime.UtcNow;
        var tempPath = CreateShortSiblingPath(snapshotDatabasePath);
        var backupPath = CreateShortSiblingPath(snapshotDatabasePath);

        DeleteIfExists(tempPath);
        DeleteSqliteSidecars(tempPath);

        var totalStopwatch = Stopwatch.StartNew();
        TimeSpan backupDuration = TimeSpan.Zero;
        TimeSpan replaceDuration = TimeSpan.Zero;
        var sourceAccess = new SqliteSnapshotSourceDiagnostics(
            SqliteSnapshotSourceOpenMode.ReadOnly,
            ViewerCheckpointAttempted: false,
            "Source opened read-only; no viewer checkpoint was attempted.");

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var backupStopwatch = Stopwatch.StartNew();
            try
            {
                using var source = OpenSnapshotSource(liveDatabasePath);
                using var destination = OpenConnection(
                    tempPath,
                    SqliteOpenMode.ReadWriteCreate,
                    SqlitePerformanceProfileName.Conservative);
                source.BackupDatabase(destination);
            }
            catch (SqliteException ex) when (
                ex.SqliteErrorCode is 5 or 6 &&
                IsCurrentLiveInitializationTarget(manifest, expectedEvidenceSessionId))
            {
                throw new LiveSnapshotSourcePendingException(
                    liveDatabasePath,
                    LiveSnapshotSourcePendingReason.BusyOrLocked,
                    "The active live SQLite database is temporarily busy while the Agent commits evidence.",
                    ex);
            }
            backupStopwatch.Stop();
            backupDuration = backupStopwatch.Elapsed;
            cancellationToken.ThrowIfCancellationRequested();
            SqliteDiagnosticsLogger.LogOperation(
                liveDatabasePath,
                "Snapshot",
                "BackupDatabase",
                backupDuration,
                $"snapshot={snapshotDatabasePath}; sourceMode=ReadOnly; viewerCheckpoint=not attempted",
                force: true);

            DeleteSqliteSidecars(tempPath);

            var snapshotAssessment = SqliteStagingStore.AssessExistingDatabase(
                tempPath,
                CaptureOpenContext.ViewerLiveSnapshot,
                manifest,
                expectedEvidenceSessionId);
            if (!snapshotAssessment.Allows(CaptureOpenCapability.ReadEvidence))
            {
                throw new InvalidDataException(CaptureCompatibilityPolicy.FormatDiagnostic(
                    snapshotAssessment,
                    tempPath,
                    packageLeftUntouched: true));
            }

            cancellationToken.ThrowIfCancellationRequested();
            var replaceStopwatch = Stopwatch.StartNew();
            if (File.Exists(snapshotDatabasePath))
            {
                DeleteIfExists(backupPath);
                File.Replace(tempPath, snapshotDatabasePath, backupPath, ignoreMetadataErrors: true);
                DeleteIfExists(backupPath);
            }
            else
            {
                File.Move(tempPath, snapshotDatabasePath);
            }
            ExplorerCorrelationCountCache.Remove(snapshotDatabasePath);
            replaceStopwatch.Stop();
            replaceDuration = replaceStopwatch.Elapsed;
            SqliteDiagnosticsLogger.LogOperation(
                snapshotDatabasePath,
                "Snapshot",
                "ReplaceSnapshotFile",
                replaceDuration,
                $"live={liveDatabasePath}",
                force: true);

            DeleteSqliteSidecars(snapshotDatabasePath);
            totalStopwatch.Stop();
            SqliteDiagnosticsLogger.LogOperation(
                snapshotDatabasePath,
                "Snapshot",
                "CreateSnapshotTotal",
                totalStopwatch.Elapsed,
                $"live={liveDatabasePath}",
                force: true);
            return new SqliteSnapshotResult(
                snapshotDatabasePath,
                snapshotUtc,
                totalStopwatch.Elapsed.TotalMilliseconds,
                backupDuration.TotalMilliseconds,
                replaceDuration.TotalMilliseconds,
                sourceAccess,
                SqliteDiagnosticsLogger.GetLogPath(snapshotDatabasePath));
        }
        finally
        {
            DeleteIfExists(tempPath);
            DeleteIfExists(backupPath);
            DeleteSqliteSidecars(tempPath);
        }
    }

    private static SqliteConnection OpenConnection(
        string databasePath,
        SqliteOpenMode mode,
        SqlitePerformanceProfileName profile)
        => SqlitePerformanceProfile.OpenConnection(databasePath, mode, profile);

    private static SqliteConnection OpenSnapshotSource(string liveDatabasePath)
        => OpenConnection(
            liveDatabasePath,
            SqliteOpenMode.ReadOnly,
            SqlitePerformanceProfileName.HighMemoryRead);

    private static bool IsCurrentLiveInitializationTarget(
        CaptureManifestCompatibilityMetadata? manifest,
        string expectedEvidenceSessionId)
        => manifest is
           {
               SchemaVersion: CaptureCompatibilityPolicy.CurrentManifestSchemaVersion
           } &&
           manifest.DeclaredEvidenceFormatVersion is
               null or CaptureCompatibilityPolicy.CurrentEvidenceFormatVersion &&
           !string.IsNullOrWhiteSpace(expectedEvidenceSessionId) &&
           string.Equals(
               manifest.SessionId,
               expectedEvidenceSessionId.Trim(),
               StringComparison.Ordinal);

    private static void DeleteSqliteSidecars(string databasePath)
    {
        DeleteIfExists($"{databasePath}-wal");
        DeleteIfExists($"{databasePath}-shm");
    }

    private static string CreateShortSiblingPath(string anchorPath)
    {
        var directory = Path.GetDirectoryName(anchorPath) ?? AppContext.BaseDirectory;
        for (var attempt = 0; attempt < 16; attempt++)
        {
            // SQLite's Windows VFS can reject paths that exceed the legacy MAX_PATH
            // boundary even when managed file APIs accept them. Keep staging names
            // independent of the (potentially long) configured snapshot filename.
            var candidate = Path.Combine(directory, Path.GetRandomFileName());
            if (!File.Exists(candidate) &&
                !File.Exists($"{candidate}-wal") &&
                !File.Exists($"{candidate}-shm"))
            {
                return candidate;
            }
        }

        throw new IOException(
            $"Could not allocate a short SQLite staging filename beside '{anchorPath}'.");
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
