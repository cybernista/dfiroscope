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
                rowCountSelector?.Invoke(result));
            return result;
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
