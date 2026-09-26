using System.Security.Cryptography;
using System.Text;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Wire-neutral bounds and token/path-shape validation shared by viewer memory
/// request builders and the agent command boundary. File existence, read access,
/// staged-image identity, and active-session containment are rechecked by the agent.
/// </summary>
public static class AgentMemoryActionPolicy
{
    public const int MinimumAcquisitionTimeoutSeconds = 1;
    public const int MaximumAcquisitionTimeoutSeconds = 7_200;
    public const int DefaultAcquisitionTimeoutSeconds = 1_800;
    public const int MinimumPluginTimeoutSeconds = 30;
    public const int MaximumPluginTimeoutSeconds = 86_400;
    public const int DefaultPluginTimeoutSeconds = 600;
    public const int MaximumOutputFileNameLength = 260;
    public const int MaximumImageIdLength = 256;
    public const int MaximumMetadataLength = 1_024;
    public const int MaximumCommandLineMetadataLength = 4_096;
    public const int MaximumPluginNameLength = 128;
    public const int MaximumPluginCount = 32;

    private static readonly HashSet<string> SupportedImageExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".raw",
            ".mem",
            ".dmp",
            ".dump",
            ".vmem",
            ".lime",
            ".bin"
        };

    private static readonly HashSet<string> ReservedWindowsDeviceNames =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };

    public static bool IsSupportedImagePath(string path) =>
        !string.IsNullOrWhiteSpace(path) &&
        SupportedImageExtensions.Contains(Path.GetExtension(path));

    public static bool TryNormalizeOptionalOutputFileName(
        string? value,
        out string normalized)
    {
        normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length == 0)
        {
            return true;
        }

        if (normalized.Length > MaximumOutputFileNameLength ||
            Path.IsPathRooted(normalized) ||
            !string.Equals(normalized, Path.GetFileName(normalized), StringComparison.Ordinal) ||
            normalized.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]) >= 0 ||
            normalized.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            string.IsNullOrWhiteSpace(Path.GetFileNameWithoutExtension(normalized)) ||
            ReservedWindowsDeviceNames.Contains(normalized.Split('.', 2)[0].TrimEnd()) ||
            !IsSupportedImagePath(normalized))
        {
            normalized = string.Empty;
            return false;
        }

        return true;
    }

    public static bool TryNormalizeImageId(string? value, out string normalized)
    {
        normalized = value?.Trim() ?? string.Empty;
        return normalized.Length is > 0 and <= MaximumImageIdLength &&
               char.IsLetterOrDigit(normalized[0]) &&
               char.IsLetterOrDigit(normalized[^1]) &&
               normalized.All(character =>
                   char.IsLetterOrDigit(character) || character is '-' or '_' or '.');
    }

    public static bool TryNormalizeOptionalMetadata(
        string? value,
        int maximumLength,
        out string normalized)
    {
        normalized = value?.Trim() ?? string.Empty;
        return maximumLength > 0 &&
               normalized.Length <= maximumLength &&
               !normalized.Any(char.IsControl);
    }

    public static bool TryNormalizePlugins(
        IReadOnlyList<string>? values,
        out string[] normalized,
        out string error)
    {
        normalized = Array.Empty<string>();
        error = string.Empty;
        if (values is not { Count: > 0 })
        {
            return true;
        }

        if (values.Count > MaximumPluginCount)
        {
            error = $"Volatility accepts at most {MaximumPluginCount} plugin names.";
            return false;
        }

        var result = new List<string>(values.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var supplied in values)
        {
            var plugin = supplied?.Trim() ?? string.Empty;
            if (plugin.Length is 0 or > MaximumPluginNameLength ||
                !char.IsLetterOrDigit(plugin[0]) ||
                !char.IsLetterOrDigit(plugin[^1]) ||
                plugin.Any(character =>
                    !(char.IsLetterOrDigit(character) || character is '.' or '_' or '-')))
            {
                error = "Volatility plugin names must be bounded dot-delimited tokens without paths, whitespace, or process arguments.";
                return false;
            }

            if (seen.Add(plugin))
            {
                result.Add(plugin);
            }
        }

        normalized = result.ToArray();
        return true;
    }

    public static bool IsValidAcquisitionTimeout(int seconds) =>
        seconds is >= MinimumAcquisitionTimeoutSeconds and <= MaximumAcquisitionTimeoutSeconds;

    public static bool IsValidPluginTimeout(int seconds) =>
        seconds is >= MinimumPluginTimeoutSeconds and <= MaximumPluginTimeoutSeconds;

    public static string BuildVolatilityOutputDirectory(
        string memoryDirectory,
        string imageId,
        string imagePath)
    {
        var selector = imageId.Length > 0
            ? imageId
            : "external-" + Convert.ToHexString(
                    SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(imagePath))))
                .ToLowerInvariant()[..24];
        return Path.Combine(Path.GetFullPath(memoryDirectory), selector, "Volatility");
    }
}
