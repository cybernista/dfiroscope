using System.Text.Json.Serialization;

namespace ProcInsider.Models;

public enum ConfigProfileKind
{
    Unknown = 0,
    Etw,
    Sysmon,
    SecurityMonitoring,
    PowerShellAuditing,
    EventLogs
}

public sealed class ConfigProfileManifest
{
    public int SchemaVersion { get; set; } = 1;

    public List<ConfigProfileDefinition> Profiles { get; set; } = new();
}

public sealed class ConfigProfileDefinition
{
    public string Id { get; set; } = string.Empty;

    public ConfigProfileKind Kind { get; set; }

    public string DisplayName { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string Warning { get; set; } = string.Empty;

    public string FilePath { get; set; } = string.Empty;

    public bool IsDefault { get; set; }

    public Dictionary<string, string> Actions { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    [JsonIgnore]
    public string ManifestDirectory { get; internal set; } = string.Empty;
}
