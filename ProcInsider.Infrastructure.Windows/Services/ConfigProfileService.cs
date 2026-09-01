using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Discovers bundled profile manifests under the application Config directory.
/// </summary>
public sealed class ConfigProfileService
{
    private const string ConfigDirectoryName = "Config";
    private const string ManifestFileName = "profiles.json";

    private static readonly IReadOnlyDictionary<ConfigProfileKind, string> KindDirectories =
        new Dictionary<ConfigProfileKind, string>
        {
            [ConfigProfileKind.Etw] = "Etw",
            [ConfigProfileKind.Sysmon] = "Sysmon",
            [ConfigProfileKind.SecurityMonitoring] = "SecurityMonitoring",
            [ConfigProfileKind.PowerShellAuditing] = "PowerShellAuditing",
            [ConfigProfileKind.EventLogs] = "EventLogs"
        };

    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public string ConfigRoot { get; }

    public ConfigProfileService()
        : this(Path.Combine(AppContext.BaseDirectory, ConfigDirectoryName))
    {
    }

    public ConfigProfileService(string configRoot)
    {
        ConfigRoot = configRoot;
    }

    public IReadOnlyList<ConfigProfileDefinition> GetProfiles(ConfigProfileKind kind)
    {
        if (!KindDirectories.TryGetValue(kind, out var directoryName))
        {
            return Array.Empty<ConfigProfileDefinition>();
        }

        var manifestPath = Path.Combine(ConfigRoot, directoryName, ManifestFileName);
        return LoadProfiles(manifestPath)
            .Where(profile => profile.Kind == kind)
            .ToList();
    }

    public ConfigProfileDefinition? GetDefaultProfile(ConfigProfileKind kind)
    {
        var profiles = GetProfiles(kind);
        return profiles.FirstOrDefault(profile => profile.IsDefault) ?? profiles.FirstOrDefault();
    }

    public string? ResolveProfileFilePath(ConfigProfileDefinition profile)
    {
        return ResolveProfileRelativePath(profile, profile.FilePath);
    }

    public string? ResolveProfileActionPath(ConfigProfileDefinition profile, string actionName)
    {
        return profile.Actions.TryGetValue(actionName, out var relativePath)
            ? ResolveProfileRelativePath(profile, relativePath)
            : null;
    }

    private IReadOnlyList<ConfigProfileDefinition> LoadProfiles(string manifestPath)
    {
        if (!File.Exists(manifestPath))
        {
            return Array.Empty<ConfigProfileDefinition>();
        }

        try
        {
            var json = File.ReadAllText(manifestPath);
            var manifest = JsonSerializer.Deserialize<ConfigProfileManifest>(json, _jsonOptions);
            if (manifest?.Profiles == null)
            {
                return Array.Empty<ConfigProfileDefinition>();
            }

            var manifestDirectory = Path.GetDirectoryName(manifestPath) ?? ConfigRoot;
            foreach (var profile in manifest.Profiles)
            {
                profile.ManifestDirectory = manifestDirectory;
            }

            return manifest.Profiles;
        }
        catch
        {
            return Array.Empty<ConfigProfileDefinition>();
        }
    }

    private static string? ResolveProfileRelativePath(ConfigProfileDefinition profile, string? relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) || string.IsNullOrWhiteSpace(profile.ManifestDirectory))
        {
            return null;
        }

        var normalized = relativePath.Replace('/', Path.DirectorySeparatorChar);
        return Path.GetFullPath(Path.Combine(profile.ManifestDirectory, normalized));
    }
}
