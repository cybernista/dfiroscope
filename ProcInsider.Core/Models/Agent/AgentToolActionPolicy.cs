using System.IO;

namespace ProcInsider.Models.Agent;

public enum AgentZeekToolMode
{
    Unknown = 0,
    NativeDiscovery = 1,
    NativeExecutable = 2,
    Wsl = 3
}

/// <summary>
/// Wire-neutral bounds and token/path-shape validation shared by viewer action
/// builders and the agent command boundary. Filesystem existence and active-session
/// containment are intentionally rechecked by each process at execution time.
/// </summary>
public static class AgentToolActionPolicy
{
    public const int MaximumCaptureIdLength = 128;
    public const int MaximumPathLength = 32_767;
    public const int MaximumWslDistributionLength = 128;
    public const int MaximumWslCommandLength = 260;
    public const int MaximumProcessMonitorRows = 200_000;
    public const int MinimumBenchmarkPhaseDurationSeconds = 1;
    public const int MaximumBenchmarkPhaseDurationSeconds = 60;
    public const int MinimumBenchmarkPhaseCount = 1;
    public const int MaximumBenchmarkPhaseCount = 8;
    public const int MinimumBenchmarkProcessBatchSize = 1;
    public const int MaximumBenchmarkProcessBatchSize = 5_000;
    public const int MinimumBenchmarkEventsPerProcess = 0;
    public const int MaximumBenchmarkEventsPerProcess = 25;
    public const int MinimumBenchmarkInFlightBatches = 1;
    public const int MaximumBenchmarkInFlightBatches = 64;
    public const int MinimumBenchmarkPendingWriterWorkItems = 1;
    public const int MaximumBenchmarkPendingWriterWorkItems = 4_096;

    public static bool TryNormalizeCaptureId(string? value, out string normalized)
    {
        normalized = value?.Trim() ?? string.Empty;
        return normalized.Length is > 0 and <= MaximumCaptureIdLength &&
               normalized.All(character =>
                   char.IsLetterOrDigit(character) || character is '-' or '_' or '.');
    }

    public static bool TryNormalizeAbsolutePath(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > MaximumPathLength ||
            HasCredentialBearingNetworkSyntax(value))
        {
            return false;
        }

        try
        {
            if (!Path.IsPathFullyQualified(value))
            {
                return false;
            }

            normalized = Path.GetFullPath(value);
            return normalized.Length <= MaximumPathLength;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            normalized = string.Empty;
            return false;
        }
    }

    public static bool IsSupportedPcapPath(string path) =>
        string.Equals(Path.GetExtension(path), ".pcap", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Path.GetExtension(path), ".pcapng", StringComparison.OrdinalIgnoreCase);

    public static bool IsSupportedProcessMonitorInputPath(string path) =>
        string.Equals(Path.GetExtension(path), ".csv", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Path.GetExtension(path), ".pml", StringComparison.OrdinalIgnoreCase);

    public static bool IsSupportedProcessMonitorExecutablePath(string path)
    {
        var fileName = Path.GetFileName(path);
        return string.Equals(fileName, "Procmon.exe", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(fileName, "Procmon64.exe", StringComparison.OrdinalIgnoreCase);
    }

    public static bool TryNormalizeOptionalProcessMonitorPath(
        string? value,
        out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        return TryNormalizeAbsolutePath(value, out normalized) &&
               IsSupportedProcessMonitorExecutablePath(normalized);
    }

    public static bool TryNormalizeZeekToolMode(
        string? zeekPath,
        string? wslDistribution,
        string? wslCommand,
        out AgentZeekToolMode mode,
        out string normalizedZeekPath,
        out string normalizedDistribution,
        out string normalizedCommand,
        out string error)
    {
        mode = AgentZeekToolMode.Unknown;
        normalizedZeekPath = string.Empty;
        normalizedDistribution = wslDistribution?.Trim() ?? string.Empty;
        normalizedCommand = wslCommand?.Trim() ?? string.Empty;
        error = string.Empty;

        var hasNativePath = !string.IsNullOrWhiteSpace(zeekPath);
        var hasWsl = normalizedDistribution.Length > 0 || normalizedCommand.Length > 0;
        if (hasNativePath && hasWsl)
        {
            error = "Zeek native and WSL modes are mutually exclusive.";
            return false;
        }

        if (hasNativePath)
        {
            if (!TryNormalizeAbsolutePath(zeekPath, out normalizedZeekPath) ||
                !string.Equals(Path.GetExtension(normalizedZeekPath), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                error = "Native Zeek mode requires one absolute executable path.";
                return false;
            }

            mode = AgentZeekToolMode.NativeExecutable;
            return true;
        }

        if (!hasWsl)
        {
            mode = AgentZeekToolMode.NativeDiscovery;
            return true;
        }

        if (normalizedDistribution.Length is 0 or > MaximumWslDistributionLength ||
            !normalizedDistribution.All(character =>
                char.IsLetterOrDigit(character) || character is '-' or '_' or '.'))
        {
            error = "WSL distribution must be one bounded distribution-name token.";
            return false;
        }

        if (normalizedCommand.Length > MaximumWslCommandLength ||
            normalizedCommand.Any(character =>
                !(char.IsLetterOrDigit(character) || character is '/' or '_' or '-' or '+' or '.')))
        {
            error = "WSL Zeek command must be one bounded executable token or absolute Linux path.";
            return false;
        }

        mode = AgentZeekToolMode.Wsl;
        return true;
    }

    public static bool TryValidateBenchmark(
        QueueSqliteBenchmarkCommand command,
        out string error)
    {
        ArgumentNullException.ThrowIfNull(command);
        error = command.PhaseDurationSeconds is < MinimumBenchmarkPhaseDurationSeconds or > MaximumBenchmarkPhaseDurationSeconds
            ? $"Benchmark phase duration must be from {MinimumBenchmarkPhaseDurationSeconds} through {MaximumBenchmarkPhaseDurationSeconds} seconds."
            : command.MaxPhaseCount is < MinimumBenchmarkPhaseCount or > MaximumBenchmarkPhaseCount
                ? $"Benchmark phase count must be from {MinimumBenchmarkPhaseCount} through {MaximumBenchmarkPhaseCount}."
                : command.InitialProcessBatchSize is < MinimumBenchmarkProcessBatchSize or > MaximumBenchmarkProcessBatchSize
                    ? $"Benchmark initial process batch size must be from {MinimumBenchmarkProcessBatchSize} through {MaximumBenchmarkProcessBatchSize}."
                    : command.InitialEventsPerProcess is < MinimumBenchmarkEventsPerProcess or > MaximumBenchmarkEventsPerProcess
                        ? $"Benchmark initial events per process must be from {MinimumBenchmarkEventsPerProcess} through {MaximumBenchmarkEventsPerProcess}."
                        : command.MaxInFlightBatches is < MinimumBenchmarkInFlightBatches or > MaximumBenchmarkInFlightBatches
                            ? $"Benchmark max in-flight batches must be from {MinimumBenchmarkInFlightBatches} through {MaximumBenchmarkInFlightBatches}."
                            : command.MaxPendingWriterWorkItems is < MinimumBenchmarkPendingWriterWorkItems or > MaximumBenchmarkPendingWriterWorkItems
                                ? $"Benchmark max pending writer work items must be from {MinimumBenchmarkPendingWriterWorkItems} through {MaximumBenchmarkPendingWriterWorkItems}."
                                : string.Empty;
        return error.Length == 0;
    }

    public static bool IsStrictChildPath(string parentPath, string childPath)
    {
        try
        {
            var parent = Path.GetFullPath(parentPath)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var child = Path.GetFullPath(childPath)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return child.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    public static bool PathsEqual(string left, string right)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(left).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                Path.GetFullPath(right).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    public static bool HasCredentialBearingNetworkSyntax(string value)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
            !uri.IsFile &&
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            return true;
        }

        if (!value.StartsWith("\\\\", StringComparison.Ordinal))
        {
            return false;
        }

        var serverEnd = value.IndexOf('\\', 2);
        var server = serverEnd < 0 ? value[2..] : value[2..serverEnd];
        return server.Contains('@') || server.Contains(':');
    }
}
