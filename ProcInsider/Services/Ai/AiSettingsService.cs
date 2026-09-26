using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public sealed class AiSettingsService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private string _settingsPath;

    public AiSettingsService(string settingsPath)
    {
        _settingsPath = settingsPath;
    }

    public string SettingsPath => _settingsPath;

    public void SetPath(string settingsPath)
    {
        _settingsPath = settingsPath;
    }

    public AiProviderSettings Load()
    {
        if (string.IsNullOrWhiteSpace(_settingsPath) || !File.Exists(_settingsPath))
        {
            return AiProviderSettings.CreateDefault();
        }

        try
        {
            var json = File.ReadAllText(_settingsPath);
            var settings = JsonSerializer.Deserialize<AiProviderSettings>(json, JsonOptions)
                ?? AiProviderSettings.CreateDefault();
            return Normalize(settings);
        }
        catch
        {
            return AiProviderSettings.CreateDefault();
        }
    }

    public void Save(AiProviderSettings settings)
    {
        if (string.IsNullOrWhiteSpace(_settingsPath))
        {
            throw new InvalidOperationException("AI settings path is not configured.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(_settingsPath) ?? AppContext.BaseDirectory);
        var normalized = Normalize(settings);
        File.WriteAllText(_settingsPath, JsonSerializer.Serialize(normalized, JsonOptions));
    }

    private static AiProviderSettings Normalize(AiProviderSettings settings)
    {
        var normalized = settings.Clone();
        normalized.SchemaVersion = 1;
        normalized.ProfileName = string.IsNullOrWhiteSpace(normalized.ProfileName)
            ? normalized.ProviderDisplayName
            : normalized.ProfileName.Trim();
        normalized.BaseUrl = normalized.BaseUrl.Trim();
        normalized.ModelName = normalized.ModelName.Trim();
        if (normalized.TimeoutSeconds <= 0)
        {
            normalized.TimeoutSeconds = AiProviderSettings.DefaultTimeoutSeconds;
        }

        normalized.TimeoutSeconds = Math.Clamp(normalized.TimeoutSeconds, 5, 900);
        normalized.MaxContextCharacters = Math.Clamp(normalized.MaxContextCharacters, 1000, 200000);
        normalized.MaxResponseCharacters = Math.Clamp(normalized.MaxResponseCharacters, 500, 50000);

        if (normalized.ProviderKind == AiProviderKind.Disabled)
        {
            normalized.ProfileName = "Disabled";
        }

        return normalized;
    }
}
