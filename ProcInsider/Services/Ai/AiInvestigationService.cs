using ProcInsider.Models;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public sealed class AiSubmissionChangedException : InvalidOperationException
{
    public AiSubmissionChangedException() : base(
        "AI provider destination or model changed after submission. Review the configured destination and submit again.") { }
}

public sealed record AiProviderReadiness(bool IsAvailable, string Message, string Code);

public sealed class AiInvestigationService : IDisposable
{
    private readonly AiSettingsService _settingsService;
    private readonly ProtectedAiSecretStore _secretStore;
    private readonly Func<AiProviderSettings, string, IModelProvider> _providerFactory;
    private string? _selectedProfileId;
    public event EventHandler? SettingsChanged;
    private void NotifySettingsChanged() => SettingsChanged?.Invoke(this, EventArgs.Empty);

    public AiInvestigationService(string settingsPath, string secretPath)
        : this(settingsPath, secretPath, null, null, (settings, key) => new AiProviderFactory().Create(settings, key), false) { }

    public AiInvestigationService(string settingsPath, string secretPath,
        Func<AiProviderSettings, string, IModelProvider> providerFactory)
        : this(settingsPath, secretPath, null, null, providerFactory, false) { }

    public AiInvestigationService(string settingsPath, string legacySecretPath,
        string profilesPath, string vaultPath)
        : this(settingsPath, legacySecretPath, profilesPath, vaultPath, false) { }

    public AiInvestigationService(string settingsPath, string legacySecretPath,
        string profilesPath, string vaultPath, bool allowLegacySecretMigration)
        : this(settingsPath, legacySecretPath, profilesPath, vaultPath,
            (settings, key) => new AiProviderFactory().Create(settings, key), allowLegacySecretMigration) { }

    public AiInvestigationService(string settingsPath, string legacySecretPath,
        string? profilesPath, string? vaultPath,
        Func<AiProviderSettings, string, IModelProvider> providerFactory,
        bool allowLegacySecretMigration = false)
    {
        _settingsService = new AiSettingsService(settingsPath, profilesPath);
        _secretStore = new ProtectedAiSecretStore(legacySecretPath, vaultPath, allowLegacySecretMigration);
        _providerFactory = providerFactory ?? throw new ArgumentNullException(nameof(providerFactory));
    }

    public string? LoadSystemPrompt(string scopeKey) => _settingsService.LoadSystemPrompt(scopeKey);
    public bool SystemPromptAppliesToAllChats(string scopeKey) => _settingsService.SystemPromptAppliesToAllChats(scopeKey);
    public void SaveSystemPrompt(string scopeKey, string text, bool allChatsInSession) =>
        _settingsService.SaveSystemPrompt(scopeKey, text, allChatsInSession);
    public string SettingsPath => _settingsService.SettingsPath;
    public string SecretPath => _secretStore.SecretPath;
    public string? ProfilesPath => _settingsService.ProfilesPath;
    public string? DefaultProfileId => _settingsService.LoadCatalog().DefaultProfileId;
    public string? SelectedProfileId => ResolveSelectedId(_settingsService.LoadCatalog());
    public bool IsPasswordConfigured => _secretStore.IsPasswordConfigured;
    public bool IsVaultUnlocked => _secretStore.IsUnlocked;
    public bool HasApiKey => HasApiKeyFor(LoadSettings());

    public bool HasApiKeyFor(AiProviderSettings settings)
    {
        _secretStore.BindLegacyScope(LegacyScope());
        return _secretStore.HasSecretFor(settings.SecretScope);
    }

    public const string ProviderUnavailableMessage = "Provider unavailable. Add or unlock a provider in Explorer > AI providers.";

    // Readiness checks only the saved key inventory. It never unwraps a provider key or constructs a provider.
    // Send still reviews the exact destination and loads its key at execution time.
    public AiProviderReadiness GetProviderReadiness(AiProviderSettings? profile = null)
    {
        try
        {
            var settings = profile?.Clone() ?? LoadSettings();
            if (profile is not null)
                settings.AllowPrivateNetworkHttp = _settingsService.Load().AllowPrivateNetworkHttp;
            if (!settings.IsEnabled)
                return new(false, "No AI provider is selected. Select or add one in Explorer > AI providers.", "provider.disabled");
            if (!settings.TryGetEndpoint(out _))
                return new(false, "The selected AI provider has no valid endpoint. Edit it in Explorer > AI providers.", "provider.endpoint-invalid");
            if (string.IsNullOrWhiteSpace(settings.ModelName))
                return new(false, "The selected AI provider has no model. Choose one in Explorer > AI providers.", "provider.model-missing");
            var hasKey = HasApiKeyFor(settings);
            if (settings.RequiresApiKey && !hasKey)
                return new(false, $"No API key is saved for this {settings.ProviderDisplayName} endpoint. Edit the provider in Explorer > AI providers to add a key.", "provider.key-missing");
            if (hasKey && IsPasswordConfigured && !IsVaultUnlocked)
                return new(false, "AI key storage is locked. Unlock it in Explorer > AI providers.", "provider.vault-locked");
            if (!settings.TryValidateTransport(hasKey ? "saved-key-present" : null, out _))
                return new(false, "The selected AI provider's endpoint or transport permission is invalid. Edit it in Explorer > AI providers.", "provider.transport-invalid");
            return new(true, string.Empty, "provider.ready");
        }
        catch (Exception)
        {
            return new(false, "AI provider settings or saved key status could not be read. Check the provider in Explorer > AI providers.", "provider.status-unavailable");
        }
    }

    public bool IsProviderAvailable() => GetProviderReadiness().IsAvailable;
    public void SetStoragePaths(string settingsPath, string secretPath)
    {
        _settingsService.SetPath(settingsPath);
        _secretStore.SetPath(secretPath);
        _selectedProfileId = null;
    }

    public void SetStoragePaths(string settingsPath, string legacySecretPath, string profilesPath, string vaultPath,
        bool allowLegacySecretMigration = false)
    {
        _settingsService.SetPaths(settingsPath, profilesPath);
        _secretStore.SetPaths(legacySecretPath, vaultPath, allowLegacySecretMigration);
        _selectedProfileId = null;
    }

    public AiProviderCatalog LoadProfiles()
    {
        var catalog = _settingsService.LoadCatalog();
        return new AiProviderCatalog
        {
            SchemaVersion = catalog.SchemaVersion,
            DefaultProfileId = catalog.DefaultProfileId,
            Profiles = catalog.Profiles.Select(profile => profile.Clone()).ToList()
        };
    }

    public void SelectProfile(string profileId)
    {
        var catalog = _settingsService.LoadCatalog();
        if (!catalog.Profiles.Any(profile => profile.ProfileId == profileId))
            throw new InvalidOperationException("AI provider profile does not exist.");
        var changed = _selectedProfileId != profileId;
        _selectedProfileId = profileId;
        if (changed) NotifySettingsChanged();
    }

    public void SetDefaultProfile(string profileId)
    {
        var catalog = _settingsService.LoadCatalog();
        if (!catalog.Profiles.Any(profile => profile.ProfileId == profileId))
            throw new InvalidOperationException("AI provider profile does not exist.");
        var currentSelection = ResolveSelectedId(catalog);
        catalog.DefaultProfileId = profileId;
        _settingsService.SaveCatalog(catalog);
        _selectedProfileId = currentSelection;
        NotifySettingsChanged();
    }

    public AiProviderSettings SaveProfile(AiProviderSettings settings, string? apiKey = null)
    {
        if (!_settingsService.UsesProfileCatalog)
            throw new InvalidOperationException("AI provider catalog path is not configured.");
        if (!settings.IsEnabled || string.IsNullOrWhiteSpace(settings.SecretScope))
            throw new InvalidOperationException("Select a provider with a valid endpoint.");
        if (settings.MaximumOutputTokens is < 1 or > 64000)
            throw new InvalidOperationException("AI output token limit must be between 1 and 64000.");
        var normalized = AiSettingsService.Normalize(settings);
        normalized.AllowPrivateNetworkHttp = _settingsService.Load().AllowPrivateNetworkHttp;
        if (!normalized.TryValidateTransport(apiKey, out var transportError))
            throw new InvalidOperationException(transportError);
        _secretStore.BindLegacyScope(LegacyScope());
        if (normalized.IsPrivateNetworkHttp && _secretStore.HasSecretFor(normalized.SecretScope))
            throw new InvalidOperationException("Clear the saved API key before enabling private network HTTP.");

        var catalog = _settingsService.LoadCatalog();
        if (string.IsNullOrWhiteSpace(normalized.ProfileId))
            normalized.ProfileId = Guid.NewGuid().ToString("D");
        else if (!Guid.TryParse(normalized.ProfileId, out var parsed))
            throw new InvalidOperationException("AI provider profile ID is invalid.");
        else normalized.ProfileId = parsed.ToString("D");
        var index = catalog.Profiles.FindIndex(profile => profile.ProfileId == normalized.ProfileId);
        if (index >= 0 && catalog.Profiles[index].SecretScope != normalized.SecretScope &&
            !catalog.Profiles.Where((_, position) => position != index)
                .Any(profile => profile.SecretScope == catalog.Profiles[index].SecretScope))
        {
            RequireNoOrphanedKey(catalog.Profiles[index].SecretScope);
        }
        if (index >= 0) catalog.Profiles[index] = normalized;
        else catalog.Profiles.Add(normalized);
        if (catalog.DefaultProfileId is null) catalog.DefaultProfileId = normalized.ProfileId;

        // Persist the key first, so a failed vault write never makes a profile appear ready.
        if (!string.IsNullOrWhiteSpace(apiKey)) _secretStore.SaveSecret(apiKey, normalized.SecretScope);
        var stored = normalized.Clone();
        stored.AllowPrivateNetworkHttp = false;
        var storedIndex = catalog.Profiles.FindIndex(profile => profile.ProfileId == stored.ProfileId);
        catalog.Profiles[storedIndex] = stored;
        _settingsService.SaveCatalog(catalog);
        _selectedProfileId = normalized.ProfileId;
        NotifySettingsChanged();
        return normalized;
    }

    public AiProviderSettings SetProfileModel(string profileId, string model)
    {
        if (string.IsNullOrWhiteSpace(model)) throw new InvalidOperationException("Select a model.");
        var catalog = _settingsService.LoadCatalog();
        var profile = catalog.Profiles.FirstOrDefault(item => item.ProfileId == profileId)
            ?? throw new InvalidOperationException("AI provider profile does not exist.");
        if (HasApiKeyFor(profile) && IsPasswordConfigured && !IsVaultUnlocked)
            throw new InvalidOperationException("Unlock the saved keys before changing this model.");
        var selection = ResolveSelectedId(catalog);
        if (profile.ModelName != model.Trim()) AiProviderPresets.ApplyModelCapabilities(profile, model);
        _settingsService.SaveCatalog(catalog);
        _selectedProfileId = selection;
        NotifySettingsChanged();
        return profile.Clone();
    }
    public void RemoveProfile(string profileId)
    {
        _secretStore.BindLegacyScope(LegacyScope());
        var catalog = _settingsService.LoadCatalog();
        var removed = catalog.Profiles.FirstOrDefault(profile => profile.ProfileId == profileId);
        if (removed is null)
            throw new InvalidOperationException("AI provider profile does not exist.");
        if (!catalog.Profiles.Any(profile => profile.ProfileId != profileId && profile.SecretScope == removed.SecretScope))
            RequireNoOrphanedKey(removed.SecretScope);
        catalog.Profiles.RemoveAll(profile => profile.ProfileId == profileId);
        if (catalog.DefaultProfileId == profileId)
            catalog.DefaultProfileId = catalog.Profiles.FirstOrDefault()?.ProfileId;
        _settingsService.SaveCatalog(catalog);
        if (_selectedProfileId == profileId) _selectedProfileId = null;
        NotifySettingsChanged();
    }

    public void SetAllowPrivateNetworkHttp(bool allowed)
    {
        if (_settingsService.UsesProfileCatalog && !_secretStore.AllowsLegacyMigration)
            throw new InvalidOperationException("Archived session AI settings are read-only.");
        _secretStore.BindLegacyScope(LegacyScope());
        _secretStore.PersistLegacyScope();
        _settingsService.SaveSessionPermission(allowed);
        NotifySettingsChanged();
    }

    public AiProviderSettings LoadSettings()
    {
        var legacy = _settingsService.Load();
        _secretStore.BindLegacyScope(LegacyScope());
        if (!_settingsService.UsesProfileCatalog) return legacy;
        var catalog = _settingsService.LoadCatalog();
        var selected = catalog.Profiles.FirstOrDefault(profile => profile.ProfileId == ResolveSelectedId(catalog));
        var settings = selected?.Clone() ?? AiProviderSettings.CreateDefault();
        settings.AllowPrivateNetworkHttp = legacy.AllowPrivateNetworkHttp;
        return settings;
    }

    internal (AiProviderSettings Settings, IModelProvider Provider) CaptureRuntimeProvider(
        AiSubmissionConstraint? expectedSubmission = null)
    {
        var settings = LoadSettings();
        if (expectedSubmission is not null && expectedSubmission != AiSubmissionConstraint.Capture(settings))
            throw new AiSubmissionChangedException();
        return (settings, CreateProvider(settings));
    }

    internal (AiProviderSettings Settings, IModelProvider? Provider, Exception? Failure,
        Func<string, string> SanitizeDiagnostic) CaptureRuntimeProviderForExecution(
        AiSubmissionConstraint? expectedSubmission = null)
    {
        var settings = LoadSettings();
        if (expectedSubmission is not null && expectedSubmission != AiSubmissionConstraint.Capture(settings))
            throw new AiSubmissionChangedException();
        var apiKey = string.Empty;
        string Sanitize(string diagnostic) => ModelDiagnosticRedactor.Sanitize(diagnostic, apiKey);
        try
        {
            apiKey = LoadApiKey(settings);
            return (settings, CreateProvider(settings, apiKey), null, Sanitize);
        }
        catch (Exception failure) when (failure is not OutOfMemoryException)
        {
            // Retain the original chain/stack as sanitized text, never as a raw inner
            // exception. Setup failed before any provider request was submitted.
            return (settings, null, new InvalidOperationException(
                "DFIRoscope provider setup failed before request submission.\n" + Sanitize(failure.ToString())), Sanitize);
        }
    }

    public void SaveSettings(AiProviderSettings settings, string? apiKey)
    {
        if (_settingsService.UsesProfileCatalog)
        {
            // The existing caller edits both fields together; new profile UI uses the separate owners.
            var originalAllowed = _settingsService.Load().AllowPrivateNetworkHttp;
            if (settings.AllowPrivateNetworkHttp != originalAllowed)
                SetAllowPrivateNetworkHttp(settings.AllowPrivateNetworkHttp);
            try { SaveProfile(settings, apiKey); }
            catch
            {
                if (settings.AllowPrivateNetworkHttp != originalAllowed)
                    SetAllowPrivateNetworkHttp(originalAllowed);
                throw;
            }
            return;
        }
        if (settings.IsEnabled && string.IsNullOrWhiteSpace(settings.SecretScope))
            throw new InvalidOperationException("AI endpoint is invalid.");
        if (settings.MaximumOutputTokens is < 1 or > 64000)
            throw new InvalidOperationException("AI output token limit must be between 1 and 64000.");
        _secretStore.BindLegacyScope(_settingsService.Load().SecretScope);
        if (settings.IsEnabled && !settings.TryValidateTransport(apiKey, out var transportError))
            throw new InvalidOperationException(transportError);
        if (settings.IsEnabled && settings.IsPrivateNetworkHttp && _secretStore.HasSecretFor(settings.SecretScope))
            throw new InvalidOperationException("Clear the saved API key before enabling private network HTTP.");
        if (!string.IsNullOrWhiteSpace(apiKey)) _secretStore.SaveSecret(apiKey, settings.SecretScope);
        _settingsService.Save(settings);
        NotifySettingsChanged();
    }

    public void InitializePassword(string password)
    {
        _secretStore.BindLegacyScope(LegacyScope());
        if (_secretStore.AllowsLegacyMigration) _settingsService.PersistLegacyCatalog();
        _secretStore.InitializePassword(password);
    }

    public bool Unlock(string password)
    {
        _secretStore.BindLegacyScope(LegacyScope());
        if (_secretStore.AllowsLegacyMigration) _settingsService.PersistLegacyCatalog();
        return _secretStore.Unlock(password);
    }

    public void Lock() => _secretStore.Lock();

    public void Dispose() => Lock();

    public void ChangePassword(string oldPassword, string newPassword) =>
        _secretStore.ChangePassword(oldPassword, newPassword);

    public void ClearApiKey(AiProviderSettings? settings = null)
    {
        _secretStore.BindLegacyScope(LegacyScope());
        _secretStore.ClearSecretFor((settings ?? LoadSettings()).SecretScope);
    }

    public async Task<AiProviderTestResult> TestConnectionAsync(AiProviderSettings settings, CancellationToken cancellationToken,
        string? transientApiKey = null)
    {
        if (settings.ProviderKind == AiProviderKind.Disabled)
            return new AiProviderTestResult { Success = false,
                Message = "AI provider is disabled. Select a local or commercial provider first." };
        // An entered key belongs only to this request. Do not inspect or unlock the saved vault.
        string key;
        if (string.IsNullOrWhiteSpace(transientApiKey))
        {
            _secretStore.BindLegacyScope(LegacyScope());
            key = LoadApiKey(settings);
        }
        else key = transientApiKey;
        var provider = CreateProvider(settings, key);
        var response = await provider.InvokeAsync(new ModelRequest(
            $"You are testing an AI provider connection for {ProductIdentity.DisplayName}.",
            new[] { new ModelMessage(ModelMessageRole.User, "Reply with exactly: OK") }), cancellationToken);
        return new AiProviderTestResult
        {
            Success = response.Success,
            Message = response.Success
                ? $"AI provider test succeeded with {settings.ProviderDisplayName}."
                : ModelDiagnosticRedactor.Sanitize(response.Error?.SafeDiagnostic ?? "Provider test failed.", key)
        };
    }

    public Task<AiModelCatalogResult> DiscoverModelsAsync(AiProviderSettings settings,
        string? transientApiKey, AiModelCatalogService catalog, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(catalog);
        cancellationToken.ThrowIfCancellationRequested();
        var captured = settings.Clone();
        _secretStore.BindLegacyScope(LegacyScope());
        if (string.IsNullOrWhiteSpace(transientApiKey) &&
            _secretStore.HasSecretFor(captured.SecretScope) &&
            _secretStore.IsPasswordConfigured && !_secretStore.IsUnlocked)
            return Task.FromResult(new AiModelCatalogResult(Array.Empty<string>(), false,
                "Unlock the keystore before loading models for this provider.", ModelErrorCategory.Configuration));
        var key = string.IsNullOrWhiteSpace(transientApiKey) ? LoadApiKey(captured) : transientApiKey;
        return catalog.DiscoverAsync(captured, key, cancellationToken);
    }
    private string? ResolveSelectedId(AiProviderCatalog catalog) =>
        catalog.Profiles.Any(profile => profile.ProfileId == _selectedProfileId)
            ? _selectedProfileId : catalog.DefaultProfileId;

    private string LegacyScope()
    {
        var original = _settingsService.Load();
        return (original.ProviderKind is AiProviderKind.LocalOpenAiCompatible or
            AiProviderKind.CommercialOpenAiCompatible or AiProviderKind.Anthropic) &&
            original.TryGetEndpoint(out _)
            ? original.SecretScope : string.Empty;
    }

    private void RequireNoOrphanedKey(string scope)
    {
        if (_secretStore.HasSecretFor(scope) && _secretStore.IsPasswordConfigured && !_secretStore.IsUnlocked)
            throw new InvalidOperationException("Unlock AI key storage before removing this profile or changing its endpoint.");
        if (_secretStore.HasSecretFor(scope))
            throw new InvalidOperationException("Clear the saved API key for this endpoint before removing its last profile or changing its endpoint.");
    }

    private IModelProvider CreateProvider(AiProviderSettings settings)
    {
        var apiKey = LoadApiKey(settings);
        return CreateProvider(settings, apiKey);
    }

    private IModelProvider CreateProvider(AiProviderSettings settings, string apiKey)
    {
        if (settings.IsEnabled && !settings.TryValidateTransport(apiKey, out var error))
            throw new InvalidOperationException(error);
        return _providerFactory(settings, apiKey);
    }

    private string LoadApiKey(AiProviderSettings settings)
    {
        if (!settings.IsEnabled) return string.Empty;
        if (!_secretStore.HasSecretFor(settings.SecretScope)) return string.Empty;
        if (_secretStore.IsPasswordConfigured && !_secretStore.IsUnlocked)
            throw new InvalidOperationException("Unlock AI key storage before using a provider.");
        return _secretStore.LoadSecretFor(settings.SecretScope);
    }
}
