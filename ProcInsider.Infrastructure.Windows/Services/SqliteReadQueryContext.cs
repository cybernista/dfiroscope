using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Data.Sqlite;

namespace ProcInsider.Services;

/// <summary>
/// Facade-selected read context shared by focused SQLite query components.
/// Construction does not assess or migrate a database; the validated
/// <see cref="SqliteStagingQueryService"/> remains the open authority.
/// </summary>
internal sealed class SqliteReadQueryContext
{
    internal const string AnnotationSchemaName = "AnnotationDb";

    internal SqliteReadQueryContext(
        string databasePath,
        string? annotationDatabasePath,
        SqlitePerformanceProfileName performanceProfile)
    {
        DatabasePath = Path.GetFullPath(databasePath);
        AnnotationDatabasePath = string.IsNullOrWhiteSpace(annotationDatabasePath)
            ? null
            : Path.GetFullPath(annotationDatabasePath);
        PerformanceProfile = performanceProfile;
    }

    internal string DatabasePath { get; }

    internal string? AnnotationDatabasePath { get; }

    internal SqlitePerformanceProfileName PerformanceProfile { get; }

    internal bool UsesAnnotationDatabase =>
        !string.IsNullOrWhiteSpace(AnnotationDatabasePath) &&
        File.Exists(AnnotationDatabasePath);

    internal string BookmarkTableName => UsesAnnotationDatabase
        ? $"{AnnotationSchemaName}.Bookmarks"
        : "Bookmarks";

    internal string? NoteTableName => UsesAnnotationDatabase
        ? $"{AnnotationSchemaName}.Notes"
        : null;

    internal SqliteConnection OpenReadOnlyConnection()
    {
        var connection = SqlitePerformanceProfile.OpenConnection(
            DatabasePath,
            SqliteOpenMode.ReadOnly,
            PerformanceProfile);
        AttachAnnotationDatabase(connection);
        return connection;
    }

    internal T MeasureRead<T>(
        string operation,
        Func<T> action,
        string detail = "",
        Func<T, long>? rowCountSelector = null)
    {
        var stopwatch = Stopwatch.StartNew();
        using var stage = SqliteWorkScope.Current == null ? null : SqliteWorkScope.Begin(operation);
        if (stage?.HasProgressObserver == true)
            SqliteDiagnosticsLogger.LogOperation(DatabasePath, "SnapshotRead", operation + ".Started",
                TimeSpan.Zero, detail, force: true);
        try
        {
            var result = action();
            stopwatch.Stop();
            SqliteDiagnosticsLogger.LogOperation(
                DatabasePath,
                "SnapshotRead",
                operation,
                stopwatch.Elapsed,
                detail,
                rowCountSelector?.Invoke(result), force: stage?.HasProgressObserver == true);
            if (rowCountSelector != null) stage?.Advance(rowCountSelector(result), rowCountSelector(result), "rows");
            return result;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 9 &&
            SqliteWorkScope.Current?.CancellationToken.IsCancellationRequested == true)
        {
            SqliteDiagnosticsLogger.LogOperation(DatabasePath, "SnapshotRead", operation + ".Canceled",
                stopwatch.Elapsed, detail, force: true);
            throw new OperationCanceledException("SQLite query canceled.", ex,
                SqliteWorkScope.Current.CancellationToken);
        }
        catch (Exception ex) when (ex is SqliteException or IOException or InvalidOperationException)
        {
            stopwatch.Stop();
            SqliteDiagnosticsLogger.LogOperation(
                DatabasePath,
                "SnapshotRead",
                operation,
                stopwatch.Elapsed,
                $"{detail}; error={ex.Message}",
                force: true);
            throw;
        }
    }

    private void AttachAnnotationDatabase(SqliteConnection connection)
    {
        if (!UsesAnnotationDatabase)
        {
            return;
        }

        using var command = connection.CreateCommand();
        command.CommandText = $"ATTACH DATABASE $AnnotationDatabasePath AS {AnnotationSchemaName};";
        command.Parameters.AddWithValue("$AnnotationDatabasePath", AnnotationDatabasePath);
        command.ExecuteNonQuery();
    }
}
