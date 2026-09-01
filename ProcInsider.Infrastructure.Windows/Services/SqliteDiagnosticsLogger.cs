using System;
using System.Globalization;
using System.IO;

namespace ProcInsider.Services;

public static class SqliteDiagnosticsLogger
{
    public const double SlowOperationThresholdMilliseconds = 250;

    private static readonly object SyncRoot = new();

    public static string GetLogPath(string databasePath)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            return string.Empty;
        }

        var fullPath = Path.GetFullPath(databasePath);
        return Path.Combine(
            Path.GetDirectoryName(fullPath) ?? AppContext.BaseDirectory,
            "sqlite-diagnostics.log");
    }

    public static void LogOperation(
        string databasePath,
        string role,
        string operation,
        TimeSpan elapsed,
        string detail = "",
        long? rowCount = null,
        bool force = false)
    {
        if (!force && elapsed.TotalMilliseconds < SlowOperationThresholdMilliseconds)
        {
            return;
        }

        var logPath = GetLogPath(databasePath);
        if (string.IsNullOrWhiteSpace(logPath))
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? AppContext.BaseDirectory);
            var rowText = rowCount.HasValue
                ? FormattableString.Invariant($" rows={rowCount.Value}")
                : string.Empty;
            var detailText = string.IsNullOrWhiteSpace(detail)
                ? string.Empty
                : $" detail=\"{detail.Replace("\"", "'", StringComparison.Ordinal)}\"";
            var line = string.Create(CultureInfo.InvariantCulture,
                $"{DateTime.UtcNow:O} role={role} operation={operation} elapsed_ms={elapsed.TotalMilliseconds:F1}{rowText} db=\"{Path.GetFullPath(databasePath)}\"{detailText}");

            lock (SyncRoot)
            {
                File.AppendAllText(logPath, line + Environment.NewLine);
            }
        }
        catch (Exception)
        {
            // Diagnostics must never block evidence reads or writes.
        }
    }
}
