using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed record AgentSecurityAuditPolicyProfile(
    string ProfileId,
    string Path,
    SecurityAuditPolicyProfileEntry[]? Entries,
    bool IsCsv);

/// <summary>
/// Resolves and validates an Agent-owned Security audit-policy profile before either a read-only
/// comparison or deployment can consume it. The caller-supplied path is only a concordance check;
/// it can never select a file outside the bundled profile manifest.
/// </summary>
internal sealed class AgentSecurityAuditPolicyProfileResolver
{
    private const long MaximumJsonProfileBytes = 256 * 1024;
    private const long MaximumCsvProfileBytes = 2 * 1024 * 1024;
    private const int MaximumSubcategoryCount = 128;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly ConfigProfileService _configProfiles;

    public AgentSecurityAuditPolicyProfileResolver(ConfigProfileService configProfiles)
    {
        _configProfiles = configProfiles ?? throw new ArgumentNullException(nameof(configProfiles));
    }

    public AgentSecurityAuditPolicyProfile Resolve(AgentSecurityAuditMonitoringIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);

        var profiles = _configProfiles.GetProfiles(ConfigProfileKind.WindowsSecurityAuditPolicy);
        var profile = string.IsNullOrWhiteSpace(intent.PolicyProfileId)
            ? profiles.FirstOrDefault(candidate => candidate.IsDefault) ?? profiles.FirstOrDefault()
            : profiles.FirstOrDefault(candidate =>
                string.Equals(candidate.Id, intent.PolicyProfileId, StringComparison.OrdinalIgnoreCase));
        if (profile == null)
        {
            throw new InvalidOperationException(
                $"The selected Windows Security audit-policy profile ID '{Display(intent.PolicyProfileId)}' is unknown.");
        }

        var profilePath = _configProfiles.ResolveProfileFilePath(profile);
        var policyRoot = Path.GetFullPath(Path.Combine(_configProfiles.ConfigRoot, "WindowsSecurity"));
        if (!IsSupportedPath(profilePath, policyRoot))
        {
            throw new InvalidOperationException(
                $"Windows Security audit-policy profile '{profile.Id}' resolves outside the Agent-owned profile root or has an unsupported extension.");
        }

        var normalizedPath = Path.GetFullPath(profilePath!);
        if (!string.IsNullOrWhiteSpace(intent.AuditPolicyPath) &&
            (!IsSupportedPath(intent.AuditPolicyPath, policyRoot) ||
             !string.Equals(Path.GetFullPath(intent.AuditPolicyPath), normalizedPath, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException(
                $"The supplied audit-policy path does not match Agent-owned profile '{profile.Id}'. " +
                "Reopen Apply preconfigured audit settings and save the selected bundled profile again, " +
                "or submit its profile ID with an empty auditPolicyPath. No Windows settings were changed.");
        }

        if (!File.Exists(normalizedPath))
        {
            throw new InvalidOperationException(
                $"Windows Security audit-policy profile '{profile.Id}' is missing at its Agent-owned path.");
        }

        var isCsv = string.Equals(Path.GetExtension(normalizedPath), ".csv", StringComparison.OrdinalIgnoreCase);
        using var profileStream = new FileStream(
            normalizedPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 16 * 1024,
            FileOptions.SequentialScan);
        var length = profileStream.Length;
        if (isCsv)
        {
            if (length <= 0 || length > MaximumCsvProfileBytes)
            {
                throw new InvalidOperationException(
                    "The Security audit policy CSV must be non-empty and no larger than 2 MB.");
            }

            return new AgentSecurityAuditPolicyProfile(profile.Id, normalizedPath, null, IsCsv: true);
        }

        if (length <= 0 || length > MaximumJsonProfileBytes)
        {
            throw new InvalidOperationException(
                "The Security audit policy profile must be non-empty and no larger than 256 KB.");
        }

        var entries = JsonSerializer.Deserialize<SecurityAuditPolicyProfileEntry[]>(profileStream, JsonOptions) ?? [];
        if (entries.Length == 0 || entries.Length > MaximumSubcategoryCount)
        {
            throw new InvalidOperationException(
                "The Security audit policy profile must contain between 1 and 128 subcategories.");
        }

        if (entries.Any(static entry => entry is null))
        {
            throw new InvalidOperationException(
                "The Security audit policy profile cannot contain a null subcategory entry.");
        }

        var subcategories = entries
            .Select(entry => entry.Subcategory?.Trim() ?? string.Empty)
            .ToArray();
        var subcategoryGuidValues = entries
            .Select(entry => entry.SubcategoryGuid?.Trim() ?? string.Empty)
            .Select(value => string.IsNullOrWhiteSpace(value)
                ? (Raw: value, Parsed: (Guid?)null, IsValid: true)
                : Guid.TryParse(value, out var parsed)
                    ? (Raw: value, Parsed: (Guid?)parsed, IsValid: true)
                    : (Raw: value, Parsed: (Guid?)null, IsValid: false))
            .ToArray();
        if (subcategories.Any(subcategory =>
                subcategory.Length == 0 ||
                subcategory.Length > 128 ||
                subcategory.Contains('"')) ||
            subcategories.Distinct(StringComparer.OrdinalIgnoreCase).Count() != subcategories.Length ||
            subcategoryGuidValues.Any(value => !value.IsValid) ||
            subcategoryGuidValues.Where(value => value.Parsed.HasValue)
                .Select(value => value.Parsed!.Value)
                .Distinct()
                .Count() !=
            subcategoryGuidValues.Count(value => value.Parsed.HasValue))
        {
            throw new InvalidOperationException(
                "The Security audit policy profile contains an invalid or duplicate subcategory name or GUID.");
        }

        return new AgentSecurityAuditPolicyProfile(profile.Id, normalizedPath, entries, IsCsv: false);
    }

    internal static string GetAuditPolSubcategoryIdentifier(SecurityAuditPolicyProfileEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return Guid.TryParse(entry.SubcategoryGuid, out var subcategoryGuid)
            ? subcategoryGuid.ToString("B")
            : entry.Subcategory.Trim();
    }

    private static bool IsSupportedPath(string? path, string policyRoot)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var extension = Path.GetExtension(path);
        if (!string.Equals(extension, ".csv", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(extension, ".json", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            var normalizedRoot = policyRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            var normalizedPath = Path.GetFullPath(path);
            return normalizedPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static string Display(string value) => string.IsNullOrWhiteSpace(value) ? "<default>" : value;
}
