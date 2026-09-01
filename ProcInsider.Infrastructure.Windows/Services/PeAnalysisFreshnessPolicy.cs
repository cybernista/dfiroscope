using System;
using System.IO;
using ProcInsider.Models;

namespace ProcInsider.Services;

public static class PeAnalysisFreshnessPolicy
{
    public static readonly TimeSpan LegacySuccessfulAnalysisWindow = TimeSpan.FromHours(6);
    public static readonly TimeSpan FailureThrottleWindow = TimeSpan.FromMinutes(10);

    public static bool ShouldAnalyzeProcessImage(
        ProcessRecord process,
        PeAnalysisRecord? latest,
        bool force,
        DateTime utcNow,
        PeStringExtractionMode requestedStringMode = PeStringExtractionMode.Deferred)
    {
        ArgumentNullException.ThrowIfNull(process);
        if (force)
        {
            return true;
        }

        if (!TryNormalizePath(process.ProcessPath, out var processPath))
        {
            return false;
        }

        if (latest is null)
        {
            return true;
        }

        var age = utcNow - latest.AnalyzedUtc;
        if (latest.Status != PeAnalysisStatus.Completed)
        {
            return age > FailureThrottleWindow;
        }

        if (requestedStringMode == PeStringExtractionMode.Immediate &&
            latest.StringAnalysisStatus != PeStringAnalysisStatus.Completed)
        {
            return true;
        }

        if (!latest.FileLastWriteUtc.HasValue)
        {
            // Rows created before freshness metadata was introduced retain the
            // previous six-hour policy until one re-analysis establishes it.
            return age > LegacySuccessfulAnalysisWindow;
        }

        if (!TryNormalizePath(latest.FilePath, out var analyzedPath) ||
            !string.Equals(processPath, analyzedPath, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        try
        {
            var info = new FileInfo(processPath);
            return !info.Exists ||
                   info.Length != latest.FileSizeBytes ||
                   info.LastWriteTimeUtc != latest.FileLastWriteUtc.Value;
        }
        catch
        {
            // Let analysis persist a clear access/not-found failure instead of
            // treating an unreadable freshness probe as proof of no change.
            return true;
        }
    }

    private static bool TryNormalizePath(string path, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(path) || path == "<not available>")
        {
            return false;
        }

        try
        {
            normalized = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
