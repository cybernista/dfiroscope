using System.Globalization;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Wire-neutral limits and exact-identity validation shared by viewer request builders
/// and the agent command boundary.
/// </summary>
public static class AgentEvidenceActionPolicy
{
    public const int MaximumEnrichmentTargetCount = 128;
    public const int MaximumProcessEntityIdLength = 256;
    public const int MaximumProcessKeyLength = 128;
    public const int MaximumFilesystemImportFiles = 10_000;

    public static bool TryNormalizeExactProcessKey(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var candidate = value.Trim();
        if (candidate.Length > MaximumProcessKeyLength || candidate.Any(char.IsControl))
        {
            return false;
        }

        var separator = candidate.IndexOf('_');
        if (separator <= 0 || separator != candidate.LastIndexOf('_') || separator == candidate.Length - 1 ||
            !int.TryParse(candidate.AsSpan(0, separator), NumberStyles.None, CultureInfo.InvariantCulture, out var processId) ||
            processId <= 0 ||
            !long.TryParse(candidate.AsSpan(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var startTimeTicks) ||
            startTimeTicks <= 0 ||
            startTimeTicks > DateTime.MaxValue.Ticks)
        {
            return false;
        }

        normalized = $"{processId.ToString(CultureInfo.InvariantCulture)}_{startTimeTicks.ToString(CultureInfo.InvariantCulture)}";
        return string.Equals(candidate, normalized, StringComparison.Ordinal);
    }

    public static bool TryNormalizeProcessEntityIds(
        IReadOnlyList<string>? values,
        out string[] normalized,
        out string error)
    {
        normalized = Array.Empty<string>();
        error = string.Empty;
        if (values is not { Count: > 0 } || values.Count > MaximumEnrichmentTargetCount)
        {
            error = $"Process entity scope requires 1 through {MaximumEnrichmentTargetCount.ToString(CultureInfo.InvariantCulture)} targets.";
            return false;
        }

        var candidates = values.Select(value => value?.Trim() ?? string.Empty).ToArray();
        if (candidates.Any(value =>
                string.IsNullOrWhiteSpace(value) ||
                value.Length > MaximumProcessEntityIdLength ||
                value.Any(char.IsControl)))
        {
            error = $"Process entity IDs must be non-empty, control-free, and at most {MaximumProcessEntityIdLength.ToString(CultureInfo.InvariantCulture)} characters.";
            return false;
        }

        if (candidates.Distinct(StringComparer.Ordinal).Count() != candidates.Length)
        {
            error = "Process entity scope contains a duplicate target.";
            return false;
        }

        normalized = candidates;
        return true;
    }

    public static bool TryNormalizeProcessKeys(
        IReadOnlyList<string>? values,
        out string[] normalized,
        out string error)
    {
        normalized = Array.Empty<string>();
        error = string.Empty;
        if (values is not { Count: > 0 } || values.Count > MaximumEnrichmentTargetCount)
        {
            error = $"Process-key scope requires 1 through {MaximumEnrichmentTargetCount.ToString(CultureInfo.InvariantCulture)} targets.";
            return false;
        }

        var candidates = new string[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            if (!TryNormalizeExactProcessKey(values[index], out candidates[index]))
            {
                error = "Every process-key target must use exact PID_StartTimeTicks form; PID-only or malformed targets are not accepted.";
                return false;
            }
        }

        if (candidates.Distinct(StringComparer.Ordinal).Count() != candidates.Length)
        {
            error = "Process-key scope contains a duplicate target.";
            return false;
        }

        normalized = candidates;
        return true;
    }
}
