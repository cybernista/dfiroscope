using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
    private string? _profilesPath;

    public AiSettingsService(string settingsPath, string? profilesPath = null)
    {
        _settingsPath = settingsPath;
        _profilesPath = profilesPath;
    }

    public string SettingsPath => _settingsPath;
    public string? ProfilesPath => _profilesPath;
    public bool UsesProfileCatalog => !string.IsNullOrWhiteSpace(_profilesPath);

    public void SetPath(string settingsPath) => _settingsPath = settingsPath;

    public void SetPaths(string settingsPath, string profilesPath)
    {
        _settingsPath = settingsPath;
        _profilesPath = profilesPath;
    }

    // The legacy session document remains the owner of the session-only HTTP permission.
    public AiProviderSettings Load()
    {
        if (string.IsNullOrWhiteSpace(_settingsPath) || !File.Exists(_settingsPath))
            return AiProviderSettings.CreateDefault();
        try
        {
            var settings = JsonSerializer.Deserialize<AiProviderSettings>(File.ReadAllText(_settingsPath), JsonOptions);
            return settings is null ? AiProviderSettings.CreateDefault() : Normalize(settings);
        }
        catch (JsonException)
        {
            return AiProviderSettings.CreateDefault();
        }
    }

    public void Save(AiProviderSettings settings)
    {
        if (string.IsNullOrWhiteSpace(_settingsPath))
            throw new InvalidOperationException("AI settings path is not configured.");
        ValidateTokenLimit(settings);
        var document = ReadSessionDocument();
        var updated = JsonSerializer.SerializeToNode(Normalize(settings), JsonOptions)!.AsObject();
        foreach (var pair in updated) document[pair.Key] = pair.Value?.DeepClone();
        AtomicWrite(_settingsPath, document.ToJsonString(JsonOptions));
    }

    public void SaveSessionPermission(bool allowed)
    {
        if (string.IsNullOrWhiteSpace(_settingsPath))
            throw new InvalidOperationException("AI settings path is not configured.");
        var catalogAlreadyExists = UsesProfileCatalog && File.Exists(_profilesPath);
        var preserveExplicitDisabled = false;
        // Retire the legacy provider fields only after their application copy is durable.
        if (UsesProfileCatalog && !catalogAlreadyExists)
        {
            var original = LoadLegacyForCatalog(out var explicitProviderKind);
            var inherited = FromLegacy(original);
            if (inherited.Profiles.Count > 0) SaveCatalog(inherited);
            preserveExplicitDisabled = explicitProviderKind && !original.IsEnabled;
        }
        // An application catalog may belong to a different provider. Keep this session's
        // historical provider fields, including an explicit Disabled choice.
        if ((catalogAlreadyExists || preserveExplicitDisabled) && File.Exists(_settingsPath))
        {
            try
            {
                var json = File.ReadAllText(_settingsPath);
                var original = JsonSerializer.Deserialize<AiProviderSettings>(json, JsonOptions)
                    ?? throw new InvalidDataException("Existing AI session settings are empty.");
                if (original.SchemaVersion is not (1 or 2))
                    throw new InvalidDataException("Existing AI session settings version is unsupported.");
                var document = JsonNode.Parse(json) as JsonObject
                    ?? throw new InvalidDataException("Existing AI session settings must be an object.");
                document[nameof(AiProviderSettings.AllowPrivateNetworkHttp)] = allowed;
                AtomicWrite(_settingsPath, document.ToJsonString(JsonOptions));
                return;
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Existing AI session settings are invalid.", ex);
            }
        }
        var sessionDocument = ReadSessionDocument();
        sessionDocument[nameof(AiProviderSettings.AllowPrivateNetworkHttp)] = allowed;
        AtomicWrite(_settingsPath, sessionDocument.ToJsonString(JsonOptions));
    }

    private const string SessionPromptField = "SystemPromptInstructions";
    private const string ChatPromptsField = "ChatSystemPromptInstructions";

    public string? LoadSystemPrompt(string scopeKey)
    {
        var document = ReadSessionDocument();
        var selected = (document[ChatPromptsField] as JsonObject)?[scopeKey] ?? document[SessionPromptField];
        if (selected is null) return null;
        var text = selected.GetValue<string>();
        return AiPromptCatalog.ResolveSystemInstructions(text, null);
    }

    public bool SystemPromptAppliesToAllChats(string scopeKey)
    {
        var document = ReadSessionDocument();
        return (document[ChatPromptsField] as JsonObject)?[scopeKey] is null && document[SessionPromptField] is not null;
    }

    public void SaveSystemPrompt(string scopeKey, string text, bool allChatsInSession)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scopeKey);
        AiPromptCatalog.ResolveSystemInstructions(text, null);
        var document = ReadSessionDocument();
        if (allChatsInSession)
        {
            document[SessionPromptField] = text;
            document.Remove(ChatPromptsField);
        }
        else
        {
            var chats = document[ChatPromptsField] as JsonObject;
            if (chats is null) document[ChatPromptsField] = chats = new JsonObject();
            chats[scopeKey] = text;
        }
        AtomicWrite(_settingsPath, document.ToJsonString(JsonOptions));
    }

    private JsonObject ReadSessionDocument()
    {
        if (string.IsNullOrWhiteSpace(_settingsPath))
            throw new InvalidOperationException("AI settings path is not configured.");
        if (!File.Exists(_settingsPath)) return new JsonObject { ["SchemaVersion"] = 2 };
        try
        {
            var document = JsonNode.Parse(File.ReadAllText(_settingsPath)) as JsonObject ??
                throw new InvalidDataException("Existing AI session settings must be an object.");
            if (document["SchemaVersion"]?.GetValue<int>() is { } version && version is not (1 or 2))
                throw new InvalidDataException("Existing AI session settings version is unsupported.");
            return document;
        }
        catch (JsonException ex) { throw new InvalidDataException("Existing AI session settings are invalid.", ex); }
    }

    public AiProviderCatalog LoadCatalog()
    {
        if (!UsesProfileCatalog) return FromLegacy(Load());
        if (!File.Exists(_profilesPath))
        {
            var original = LoadLegacyForCatalog(out var explicitProviderKind);
            var legacy = FromLegacy(original);
            if (legacy.Profiles.Count > 0 || explicitProviderKind) return legacy;
            var initial = AiProviderPresets.CreateInitialCatalog();
            if (AtomicWrite(_profilesPath!, SerializeCatalog(initial), createOnly: true))
                return initial;
            // Another Viewer created the catalog first. Read that version, including
            // any choices it saved, without replacing it with the presets.
            return LoadCatalog();
        }

        AiProviderCatalog catalog;
        try
        {
            catalog = JsonSerializer.Deserialize<AiProviderCatalog>(File.ReadAllText(_profilesPath!), JsonOptions)
                ?? throw new InvalidDataException("AI provider catalog is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("AI provider catalog is invalid.", ex);
        }
        if (catalog.SchemaVersion != 1 || catalog.Profiles is null)
            throw new InvalidDataException("AI provider catalog version or profile list is invalid.");

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var profile in catalog.Profiles)
        {
            if (profile is null || !Guid.TryParse(profile.ProfileId, out var id) || !ids.Add(id.ToString("D")) ||
                !profile.IsEnabled)
                throw new InvalidDataException("AI provider catalog contains an invalid or duplicate profile.");
            profile.ProfileId = id.ToString("D");
            ValidateTokenLimit(profile);
        }
        catalog.Profiles = catalog.Profiles.Select(Normalize).ToList();
        if (!catalog.Profiles.Any(profile => profile.ProfileId == catalog.DefaultProfileId))
            catalog.DefaultProfileId = catalog.Profiles.FirstOrDefault()?.ProfileId;
        return catalog;
    }

    internal void PersistLegacyCatalog()
    {
        if (!UsesProfileCatalog || File.Exists(_profilesPath)) return;
        var inherited = FromLegacy(LoadLegacyForCatalog(out _));
        if (inherited.Profiles.Count == 0) return;
        // Preserve the original provider before an explicit writable key migration
        // retires its session secret. A concurrent application catalog wins.
        AtomicWrite(_profilesPath!, SerializeCatalog(inherited), createOnly: true);
    }
    public void SaveCatalog(AiProviderCatalog catalog)
    {
        if (!UsesProfileCatalog)
            throw new InvalidOperationException("AI provider catalog path is not configured.");
        AtomicWrite(_profilesPath!, SerializeCatalog(catalog));
    }

    private static string SerializeCatalog(AiProviderCatalog catalog)
    {
        if (catalog.Profiles is null)
            throw new InvalidOperationException("AI provider catalog has no profile list.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var profile in catalog.Profiles)
        {
            if (!Guid.TryParse(profile.ProfileId, out var id) || !ids.Add(id.ToString("D")) || !profile.IsEnabled)
                throw new InvalidOperationException("AI provider catalog contains an invalid profile.");
            profile.ProfileId = id.ToString("D");
            ValidateTokenLimit(profile);
        }
        if (catalog.DefaultProfileId is not null && !ids.Contains(catalog.DefaultProfileId))
            throw new InvalidOperationException("The default AI profile does not exist.");
        var normalized = new AiProviderCatalog
        {
            SchemaVersion = 1,
            Profiles = catalog.Profiles.Select(Normalize).ToList(),
            DefaultProfileId = catalog.DefaultProfileId ?? catalog.Profiles.FirstOrDefault()?.ProfileId
        };
        return JsonSerializer.Serialize(normalized, JsonOptions);
    }

    private static AiProviderCatalog FromLegacy(AiProviderSettings legacy)
    {
        if (!legacy.IsEnabled) return new AiProviderCatalog();
        var seed = Encoding.UTF8.GetBytes($"{legacy.ProviderKind}\n{legacy.BaseUrl}\n{legacy.ModelName}");
        legacy.ProfileId = new Guid(SHA256.HashData(seed).AsSpan(0, 16)).ToString("D");
        legacy.AllowPrivateNetworkHttp = false;
        return new AiProviderCatalog { Profiles = new List<AiProviderSettings> { legacy }, DefaultProfileId = legacy.ProfileId };
    }

    private AiProviderSettings LoadLegacyForCatalog(out bool explicitProviderKind)
    {
        explicitProviderKind = false;
        if (string.IsNullOrWhiteSpace(_settingsPath) || !File.Exists(_settingsPath))
            return AiProviderSettings.CreateDefault();
        try
        {
            var json = File.ReadAllText(_settingsPath);
            using var document = JsonDocument.Parse(json);
            explicitProviderKind = document.RootElement.ValueKind == JsonValueKind.Object &&
                document.RootElement.TryGetProperty(nameof(AiProviderSettings.ProviderKind), out _);
            var settings = JsonSerializer.Deserialize<AiProviderSettings>(json, JsonOptions)
                ?? throw new InvalidDataException("Legacy AI settings are empty.");
            if (settings.SchemaVersion is not (1 or 2))
                throw new InvalidDataException("Legacy AI settings version is unsupported.");
            return Normalize(settings);
        }
        catch (JsonException ex) { throw new InvalidDataException("Legacy AI settings are invalid.", ex); }
    }

    private static void ValidateTokenLimit(AiProviderSettings settings)
    {
        if (settings.MaximumOutputTokens is < 1 or > 64000)
            throw new InvalidOperationException("AI output token limit must be between 1 and 64000.");
    }

    internal static AiProviderSettings Normalize(AiProviderSettings settings)
    {
        var normalized = settings.Clone();
        normalized.SchemaVersion = 1;
        normalized.ProfileName = string.IsNullOrWhiteSpace(normalized.ProfileName)
            ? normalized.ProviderDisplayName : normalized.ProfileName.Trim();
        normalized.BaseUrl = (normalized.BaseUrl ?? string.Empty).Trim();
        normalized.ModelName = (normalized.ModelName ?? string.Empty).Trim();
        normalized.TimeoutSeconds = Math.Clamp(
            normalized.TimeoutSeconds <= 0 ? AiProviderSettings.DefaultTimeoutSeconds : normalized.TimeoutSeconds, 5, 900);
        normalized.MaxContextCharacters = Math.Clamp(normalized.MaxContextCharacters, 1000, 200000);
        normalized.MaxResponseCharacters = Math.Clamp(normalized.MaxResponseCharacters, 500, 50000);
        normalized.ContextWindowTokens = normalized.ContextWindowTokens is > 0 ? normalized.ContextWindowTokens : null;
        if (!normalized.IsEnabled) normalized.ProfileName = "Disabled";
        return normalized;
    }

    internal static bool AtomicWrite(string path, string content, bool createOnly = false)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096,
                       FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            {
                writer.Write(content);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }
            if (createOnly)
            {
                try { File.Move(temporary, fullPath); }
                catch (IOException) when (File.Exists(fullPath)) { return false; }
            }
            else if (File.Exists(fullPath)) File.Replace(temporary, fullPath, null);
            else File.Move(temporary, fullPath);
            return true;
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

}
