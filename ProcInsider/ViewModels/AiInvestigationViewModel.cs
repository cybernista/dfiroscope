using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public sealed class AiProviderOption
{
    public AiProviderKind ProviderKind { get; init; }
    public string DisplayName { get; init; } = string.Empty;
}

public sealed class AiProviderProfileRow : ObservableObject
{
    public required AiProviderSettings Settings { get; init; }
    public bool IsSelected { get; init; }
    public bool IsDefault { get; init; }
    public bool RequiresAuthentication { get; init; }
    public bool IsAvailable { get; init; } = true;
    public string ReadinessMessage { get; init; } = string.Empty;
    public ObservableCollection<string> ModelOptions { get; } = [];
    public bool IsRefreshingModels { get; private set; }
    internal void RefreshModelOptions(IEnumerable<string> models)
    {
        IsRefreshingModels = true;
        try
        {
            ModelOptions.Clear();
            if (!string.IsNullOrWhiteSpace(ModelName)) ModelOptions.Add(ModelName);
            foreach (var model in models)
                if (!ModelOptions.Contains(model)) ModelOptions.Add(model);
            // Clearing the collection clears WPF SelectedItem without changing the saved name.
            // Reapply the OneWay selection binding while refresh events remain suppressed.
            OnPropertyChanged(nameof(ModelName));
        }
        finally { IsRefreshingModels = false; }
    }
    private string _modelCatalogStatus = "Open the model list to refresh available models.";
    public string ModelCatalogStatus { get => _modelCatalogStatus; set => SetProperty(ref _modelCatalogStatus, value); }
    public string ModelName => Settings.ModelName;
    public string Name => Settings.ProfileName;
    public string Destination => Settings.DestinationDisplay;
    public string Endpoint => Settings.EndpointDisplay;
    public string DefaultLabel => IsDefault ? "Default" : string.Empty;
}

/// <summary>Presentation for application provider profiles and session transport permission.</summary>
public partial class AiInvestigationViewModel : ViewModelBase, IDisposable
{
    private readonly AiInvestigationService _aiService;
    private readonly FeatureAccessService _featureAccess;
    private readonly AiModelCatalogService _modelCatalog;
    private bool _loading;
    private bool _disposed;
    private long _generation;
    private CancellationTokenSource? _connectionTest;
    private string _editingProfileId = string.Empty;
    private bool _persistedAllowPrivateNetworkHttp;

    public AiInvestigationViewModel(AiInvestigationService aiService, FeatureAccessService featureAccess, AiModelCatalogService? modelCatalog = null)
    {
        _aiService = aiService;
        _featureAccess = featureAccess;
        _modelCatalog = modelCatalog ?? new AiModelCatalogService();
        ProviderOptions =
        [
            new() { ProviderKind = AiProviderKind.LocalOpenAiCompatible, DisplayName = "OpenAI compatible" },
            new() { ProviderKind = AiProviderKind.CommercialOpenAiCompatible, DisplayName = "OpenAI" },
            new() { ProviderKind = AiProviderKind.Anthropic, DisplayName = "Claude" }
        ];
        ReloadSettings();
    }

    public ObservableCollection<AiProviderOption> ProviderOptions { get; }
    public ObservableCollection<AiProviderProfileRow> Profiles { get; } = [];
    public ObservableCollection<AiProviderProfileRow> AuthenticatedProfiles { get; } = [];
    public ObservableCollection<AiProviderProfileRow> AuthenticationFreeProfiles { get; } = [];
    public ObservableCollection<string> ModelOptions { get; } = [];
    public string VaultStateLabel => !IsVaultStatusAvailable ? "[STATUS UNAVAILABLE]" : IsVaultUnlocked ? "[UNLOCKED]" : "[LOCKED]";
    public string VaultActionLabel => !IsVaultStatusAvailable ? "Keystore unavailable" : IsVaultUnlocked ? "Lock" : "Unlock Keystore";
    public string ModelCatalogStatus { get; private set; } = "Load models explicitly from this provider.";
    public event EventHandler? EditorDestinationChanged;
    [ObservableProperty] private string profileName = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsCloudProvider))]
    [NotifyPropertyChangedFor(nameof(ProviderStatusDisplay))]
    [NotifyPropertyChangedFor(nameof(PrivacyWarning))]
    private AiProviderOption? selectedProviderOption;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PrivacyWarning))]
    private string baseUrl = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProviderStatusDisplay))]
    private string modelName = string.Empty;
    [ObservableProperty] private bool allowPrivateNetworkHttp;
    [ObservableProperty] private int timeoutSeconds = AiProviderSettings.DefaultTimeoutSeconds;
    [ObservableProperty] private int maxContextCharacters = 12000;
    [ObservableProperty] private int maxResponseCharacters = 4000;
    [ObservableProperty] private int? contextWindowTokens;
    [ObservableProperty] private int? maximumOutputTokens;
    [ObservableProperty] private bool? supportsTools;
    [ObservableProperty] private bool? supportsStructuredOutput;
    [ObservableProperty] private string statusMessage = "Add a provider to enable AI actions.";
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private bool hasApiKey;
    [ObservableProperty] private bool isPasswordConfigured;
    [ObservableProperty] private bool isVaultUnlocked;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(VaultStateLabel))]
    [NotifyPropertyChangedFor(nameof(VaultActionLabel))]
    private bool isVaultStatusAvailable = true;
    [ObservableProperty] private string settingsPathDisplay = string.Empty;
    [ObservableProperty] private string secretPathDisplay = string.Empty;

    public bool IsEditing => !string.IsNullOrEmpty(_editingProfileId);
    public string EditorHeading => IsEditing ? "Edit provider" : "Add provider";
    public bool IsCloudProvider => BuildSettings().IsCloudProvider;
    public string ProviderStatusDisplay => $"{BuildSettings().DestinationDisplay}; {BuildSettings().EndpointDisplay}; " +
        (HasApiKey ? "stored profile key saved" : "no saved key for this profile");
    public string PrivacyWarning => IsCloudProvider
        ? $"External destination: selected evidence is sent to {BuildSettings().EndpointDisplay} only when you submit an AI action. Provider API usage is billed separately from consumer chat subscriptions."
        : BuildSettings().IsEnabled
            ? $"Local destination: {BuildSettings().EndpointDisplay}. Evidence is sent only when you submit an AI action."
            : "AI is disabled. Evidence is not sent to any AI provider.";

    public void ReloadSettings()
    {
        CancelConnectionTest();
        if (_disposed) return;
        EditorDestinationChanged?.Invoke(this, EventArgs.Empty);
        try
        {
            var selected = _aiService.LoadSettings();
            var catalog = _aiService.LoadProfiles();
            RefreshProfileRows(catalog);
            SettingsPathDisplay = _aiService.SettingsPath;
            SecretPathDisplay = _aiService.SecretPath;
            _loading = true;
            AllowPrivateNetworkHttp = selected.AllowPrivateNetworkHttp;
            _persistedAllowPrivateNetworkHttp = selected.AllowPrivateNetworkHttp;
            _loading = false;
            var edited = Profiles.FirstOrDefault(row => row.Settings.ProfileId == _editingProfileId);
            if (edited is not null) LoadEditor(edited.Settings);
            else if (SelectedProviderOption is null || IsEditing) NewProfile();
            StatusMessage = !IsVaultStatusAvailable
                ? "AI provider settings or saved key status could not be read. Check the provider in Explorer > AI providers."
                : Profiles.Count == 0 ? "Add a provider to enable AI actions."
                : $"Loaded {Profiles.Count} provider profile(s).";
        }
        catch (Exception) { StatusMessage = "Provider profiles could not be loaded. Check AI provider settings and key storage."; }
        finally { _loading = false; NotifyCommandState(); }
    }

    private void RefreshProfileRows(AiProviderCatalog catalog)
    {
        Profiles.Clear();
        AuthenticatedProfiles.Clear();
        AuthenticationFreeProfiles.Clear();
        try
        {
            IsPasswordConfigured = _aiService.IsPasswordConfigured;
            IsVaultUnlocked = _aiService.IsVaultUnlocked;
            IsVaultStatusAvailable = true;
        }
        catch (Exception)
        {
            IsPasswordConfigured = false;
            IsVaultUnlocked = false;
            IsVaultStatusAvailable = false;
        }
        foreach (var profile in catalog.Profiles)
        {
            var readiness = _aiService.GetProviderReadiness(profile);
            var inventoryAvailable = IsVaultStatusAvailable && readiness.Code != "provider.status-unavailable";
            var hasKey = false;
            if (inventoryAvailable)
            {
                try { hasKey = _aiService.HasApiKeyFor(profile); }
                catch (Exception) { inventoryAvailable = false; }
            }
            var authenticated = profile.RequiresApiKey || hasKey || !inventoryAvailable;
            var row = new AiProviderProfileRow { Settings = profile,
                RequiresAuthentication = authenticated, IsAvailable = inventoryAvailable && (!hasKey || IsVaultUnlocked),
                ReadinessMessage = readiness.Message,
                IsSelected = profile.ProfileId == _aiService.SelectedProfileId,
                IsDefault = profile.ProfileId == catalog.DefaultProfileId };
            if (!string.IsNullOrWhiteSpace(profile.ModelName)) row.ModelOptions.Add(profile.ModelName);
            Profiles.Add(row);
            (authenticated ? AuthenticatedProfiles : AuthenticationFreeProfiles).Add(row);
        }
        NotifyCommandState();
    }

    // Admission runs before WPF constructs a dialog; visibility is not an execution guard.
    public bool TryBeginNewProfileDialog()
    {
        if (_disposed || IsBusy || !RequirePublished()) return false;
        NewProfile();
        return true;
    }
    public bool TryBeginEditProfileDialog(AiProviderProfileRow? row)
    {
        if (_disposed || IsBusy || !RequirePublished() || row is null || !IsProfileAvailable(row)) return false;
        EditProfile(row);
        return _editingProfileId == row.Settings.ProfileId;
    }
    public bool TryOpenKeystoreDialog(bool changePassword)
    {
        if (_disposed || IsBusy || !RequirePublished()) return false;
        if (!changePassword) return true;
        try { return _aiService.IsPasswordConfigured; }
        catch (Exception)
        {
            StatusMessage = "Keystore state is unavailable. Verify saved key storage before changing its password.";
            return false;
        }
    }

    [RelayCommand]
    public void NewProfile()
    {
        CancelConnectionTest();
        _editingProfileId = string.Empty;
        LoadEditor(AiProviderPresets.CreateConnection(AiProviderKind.CommercialOpenAiCompatible));
    }

    [RelayCommand]
    public void EditProfile(AiProviderProfileRow? row)
    {
        if (row is null || !IsProfileAvailable(row) || !RequirePublished()) return;
        CancelConnectionTest();
        _editingProfileId = row.Settings.ProfileId;
        LoadEditor(row.Settings);
    }

    private void LoadEditor(AiProviderSettings settings)
    {
        _loading = true;
        try
        {
            // Clear controls before replacing any destination under the notification-suppression guard.
            CancelConnectionTest();
            EditorDestinationChanged?.Invoke(this, EventArgs.Empty);
            ProfileName = settings.ProfileName;
            SelectedProviderOption = ProviderOptions.FirstOrDefault(option => option.ProviderKind == settings.ProviderKind)
                ?? ProviderOptions[0];
            BaseUrl = settings.BaseUrl;
            ModelOptions.Clear();
            if (!string.IsNullOrWhiteSpace(settings.ModelName)) ModelOptions.Add(settings.ModelName);
            ModelName = settings.ModelName;
            SetCatalogStatus("Load models explicitly; saved selection retained if discovery fails.");
            TimeoutSeconds = settings.TimeoutSeconds;
            MaxContextCharacters = settings.MaxContextCharacters;
            MaxResponseCharacters = settings.MaxResponseCharacters;
            ContextWindowTokens = settings.ContextWindowTokens;
            MaximumOutputTokens = settings.MaximumOutputTokens;
            SupportsTools = settings.SupportsTools;
            SupportsStructuredOutput = settings.SupportsStructuredOutput;
            try { HasApiKey = IsEditing && _aiService.HasApiKeyFor(settings); }
            catch
            {
                HasApiKey = false;
                StatusMessage = "The saved key inventory is unavailable for this profile.";
            }
        }
        finally
        {
            _loading = false;
            OnPropertyChanged(nameof(IsEditing));
            OnPropertyChanged(nameof(EditorHeading));
            OnPropertyChanged(nameof(IsCloudProvider));
            OnPropertyChanged(nameof(ProviderStatusDisplay));
            OnPropertyChanged(nameof(PrivacyWarning));
            NotifyCommandState();
        }
    }

    public bool SaveProfile(string? apiKey, string? firstPassword)
    {
        if (!RequirePublished() || IsBusy) return false;
        try
        {
            var settings = BuildSettings();
            if (string.IsNullOrWhiteSpace(settings.ModelName))
                throw new InvalidOperationException("Select a model before saving this provider.");
            var hasNewKey = !string.IsNullOrEmpty(apiKey);
            var hasSavedKey = !hasNewKey && _aiService.HasApiKeyFor(settings);
            if (!_aiService.IsPasswordConfigured && (hasNewKey || hasSavedKey))
            {
                if (!settings.IsEnabled || string.IsNullOrWhiteSpace(settings.SecretScope))
                    throw new InvalidOperationException("Select a provider with a valid endpoint.");
                if (settings.MaximumOutputTokens is < 1 or > 64000)
                    throw new InvalidOperationException("AI output token limit must be between 1 and 64000.");
                if (!settings.TryValidateTransport(hasSavedKey ? "saved key" : apiKey, out var transportError))
                    throw new InvalidOperationException(transportError);
                _aiService.InitializePassword(firstPassword ?? string.Empty);
            }
            var saved = _aiService.SaveProfile(settings, apiKey);
            _editingProfileId = saved.ProfileId;
            ReloadSettings();
            StatusMessage = $"Saved provider profile '{saved.ProfileName}'.";
            return true;
        }
        catch (Exception error) { StatusMessage = "Failed to save provider: " + error.Message; return false; }
    }

    [RelayCommand(CanExecute = nameof(CanRemoveProfile))]
    public void RemoveProfile(AiProviderProfileRow? row)
    {
        if (row is null || !IsProfileAvailable(row) || !RequirePublished()) return;
        try
        {
            _aiService.RemoveProfile(row.Settings.ProfileId);
            if (_editingProfileId == row.Settings.ProfileId) NewProfile();
            ReloadSettings();
            StatusMessage = $"Removed provider profile '{row.Name}'.";
        }
        catch (Exception error) { StatusMessage = "Failed to remove provider: " + error.Message; }
    }

    [RelayCommand(CanExecute = nameof(CanSetDefaultProfile))]
    public void SetDefaultProfile(AiProviderProfileRow? row)
    {
        if (row is null || !IsProfileAvailable(row) || !RequirePublished()) return;
        try { _aiService.SetDefaultProfile(row.Settings.ProfileId); ReloadSettings();
            StatusMessage = $"Default provider: {row.Name}."; }
        catch (Exception error) { StatusMessage = "Failed to set default provider: " + error.Message; }
    }

    public void SelectProfile(AiProviderProfileRow? row)
    {
        if (row is null || !IsProfileAvailable(row) || !RequirePublished()) return;
        if (row.IsSelected) return;
        try { _aiService.SelectProfile(row.Settings.ProfileId); ReloadSettings();
            StatusMessage = $"Next interaction will use {row.Name}."; }
        catch (Exception error) { StatusMessage = "Failed to select provider: " + error.Message; }
    }

    public bool Unlock(string password)
    {
        if (!RequirePublished()) return false;
        CancelConnectionTest();
        try { if (!_aiService.IsPasswordConfigured) _aiService.InitializePassword(password);
            else IsVaultUnlocked = _aiService.Unlock(password);
            ReloadSettings();
            StatusMessage = IsVaultUnlocked ? "Saved keys unlocked for this Viewer run." : "Incorrect password."; }
        catch (Exception error) { StatusMessage = "Unable to unlock saved keys: " + error.Message; return false; }
        return IsVaultUnlocked;
    }

    [RelayCommand]
    public void Lock()
    {
        if (!RequirePublished()) return;
        CancelConnectionTest();
        try { _aiService.Lock(); IsVaultUnlocked = false; ReloadSettings(); StatusMessage = "Saved keys locked."; }
        catch (Exception error) { StatusMessage = "Unable to lock saved keys: " + error.Message; }
    }

    public bool ChangePassword(string oldPassword, string newPassword)
    {
        if (!RequirePublished()) return false;
        CancelConnectionTest();
        try { _aiService.ChangePassword(oldPassword, newPassword); IsVaultUnlocked = _aiService.IsVaultUnlocked; ReloadSettings();
            StatusMessage = "Vault password changed."; }
        catch (Exception error) { StatusMessage = "Unable to change vault password: " + error.Message; return false; }
        return true;
    }

    [RelayCommand(CanExecute = nameof(CanTestConnection))]
    public Task TestConnectionAsync() => TestConnectionWithKeyAsync(null);

    public async Task TestConnectionWithKeyAsync(string? transientApiKey)
    {
        if (_disposed || IsBusy || !RequirePublished()) return;
        var settings = BuildSettings();
        CancelConnectionTest();
        var request = new CancellationTokenSource();
        _connectionTest = request;
        var generation = _generation;
        bool Current() => !_disposed && generation == _generation &&
            ReferenceEquals(request, _connectionTest) && !request.IsCancellationRequested;
        try
        {
            IsBusy = true;
            StatusMessage = "Testing AI provider connection...";
            var result = await _aiService.TestConnectionAsync(settings, request.Token, transientApiKey);
            if (Current()) StatusMessage = ModelDiagnosticRedactor.Sanitize(result.Message, transientApiKey);
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception error) { if (Current()) StatusMessage = "AI provider test failed: " +
            ModelDiagnosticRedactor.Sanitize(error.Message, transientApiKey); }
        finally
        {
            if (ReferenceEquals(request, _connectionTest)) { _connectionTest = null; IsBusy = false; }
            request.Dispose();
        }
    }

    [RelayCommand(CanExecute = nameof(CanClearApiKey))]
    public void ClearApiKey()
    {
        if (!RequirePublished()) return;
        CancelConnectionTest();
        try
        {
            var original = Profiles.FirstOrDefault(row => row.Settings.ProfileId == _editingProfileId)?.Settings;
            if (original is null) return;
            _aiService.ClearApiKey(original);
            HasApiKey = false;
            RefreshProfileRows(_aiService.LoadProfiles());
            StatusMessage = "Cleared the saved key for this profile's stored endpoint.";
        }
        catch (Exception error) { StatusMessage = "Failed to clear AI API key: " + error.Message; }
    }

    partial void OnSelectedProviderOptionChanged(AiProviderOption? value)
    {
        if (_loading || value is null) return;
        CancelConnectionTest();
        if (!IsEditing && ProviderOptions.Any(option => option.DisplayName == ProfileName)) ProfileName = value.DisplayName;
        BaseUrl = value.ProviderKind switch
        {
            AiProviderKind.LocalOpenAiCompatible => "http://localhost:1234/v1",
            AiProviderKind.CommercialOpenAiCompatible => "https://api.openai.com/v1",
            AiProviderKind.Anthropic => "https://api.anthropic.com/v1",
            _ => BaseUrl
        };
        InvalidateModelCatalog();
        if (!IsEditing) ApplyDefaultConnection(value.ProviderKind);
        RefreshApiKeyStatus();
    }

    partial void OnBaseUrlChanged(string value)
    {
        if (!_loading) { CancelConnectionTest(); InvalidateModelCatalog(); }
        RefreshApiKeyStatus();
        OnPropertyChanged(nameof(IsCloudProvider));
        OnPropertyChanged(nameof(ProviderStatusDisplay));
        OnPropertyChanged(nameof(PrivacyWarning));
    }
    partial void OnModelNameChanged(string value)
    {
        if (_loading) return;
        CancelConnectionTest();
        var settings = BuildSettings();
        AiProviderPresets.ApplyModelCapabilities(settings, value);
        ContextWindowTokens = settings.ContextWindowTokens;
        MaximumOutputTokens = settings.MaximumOutputTokens;
        SupportsTools = settings.SupportsTools;
        SupportsStructuredOutput = settings.SupportsStructuredOutput;
    }
    private void ApplyDefaultConnection(AiProviderKind kind)
    {
        var settings = AiProviderPresets.CreateConnection(kind);
        TimeoutSeconds = settings.TimeoutSeconds;
        MaxResponseCharacters = settings.MaxResponseCharacters;
        ModelName = settings.ModelName;
        ContextWindowTokens = settings.ContextWindowTokens;
        MaximumOutputTokens = settings.MaximumOutputTokens;
        SupportsTools = settings.SupportsTools;
        SupportsStructuredOutput = settings.SupportsStructuredOutput;
    }
    partial void OnAllowPrivateNetworkHttpChanged(bool value)
    {
        if (_loading) return;
        CancelConnectionTest();
        try
        {
            if (!RequirePublished()) throw new InvalidOperationException(StatusMessage);
            _aiService.SetAllowPrivateNetworkHttp(value);
            _persistedAllowPrivateNetworkHttp = value;
        }
        catch (Exception error)
        {
            _loading = true;
            try { AllowPrivateNetworkHttp = _aiService.LoadSettings().AllowPrivateNetworkHttp; }
            catch { AllowPrivateNetworkHttp = _persistedAllowPrivateNetworkHttp; }
            finally { _loading = false; }
            StatusMessage = "Unable to save session HTTP permission: " + error.Message;
        }
    }

    public async Task LoadModelsAsync(string? transientApiKey)
    {
        if (!RequirePublished()) return;
        var settings = BuildSettings();
        CancelConnectionTest();
        var request = new CancellationTokenSource();
        _connectionTest = request;
        var generation = _generation;
        bool Current() => !_disposed && generation == _generation && ReferenceEquals(request, _connectionTest)
            && !request.IsCancellationRequested && settings.SecretScope == BuildSettings().SecretScope && CanUseFeature();
        try
        {
            IsBusy = true;
            SetCatalogStatus("Loading models...");
            var result = await _aiService.DiscoverModelsAsync(settings, transientApiKey, _modelCatalog, request.Token);
            if (!Current()) return;
            var retained = ModelName;
            _loading = true;
            try
            {
                ModelOptions.Clear();
                if (!string.IsNullOrWhiteSpace(retained)) ModelOptions.Add(retained);
                foreach (var id in result.ModelIds)
                    if (!ModelOptions.Contains(id)) ModelOptions.Add(id);
                ModelName = retained;
            }
            finally { _loading = false; }
            SetCatalogStatus(result.StatusMessage);
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception) { if (Current()) SetCatalogStatus("Models unavailable. Check endpoint, authentication and keystore state; saved selection retained."); }
        finally
        {
            if (ReferenceEquals(request, _connectionTest)) { _connectionTest = null; IsBusy = false; }
            request.Dispose();
        }
    }
    public async Task LoadProfileModelsAsync(AiProviderProfileRow row)
    {
        if (_disposed || !Profiles.Contains(row) || !IsProfileAvailable(row) || !RequirePublished()) return;
        CancelConnectionTest();
        var request = new CancellationTokenSource();
        _connectionTest = request;
        var generation = _generation;
        bool Current() => !_disposed && generation == _generation && ReferenceEquals(request, _connectionTest)
            && !request.IsCancellationRequested && Profiles.Contains(row) && IsProfileAvailable(row) && CanUseFeature();
        try
        {
            IsBusy = true;
            row.ModelCatalogStatus = "Loading models...";
            var settings = row.Settings.Clone();
            settings.AllowPrivateNetworkHttp = AllowPrivateNetworkHttp;
            var result = await _aiService.DiscoverModelsAsync(settings, null, _modelCatalog, request.Token);
            if (!Current()) return;
            row.RefreshModelOptions(result.ModelIds);
            row.ModelCatalogStatus = result.StatusMessage;
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception) { if (Current()) row.ModelCatalogStatus = "Models unavailable; saved selection retained."; }
        finally
        {
            if (ReferenceEquals(request, _connectionTest)) { _connectionTest = null; IsBusy = false; }
            request.Dispose();
        }
    }
    public bool SetProfileModel(AiProviderProfileRow row, string model)
    {
        if (_disposed || !Profiles.Contains(row) || !IsProfileAvailable(row) || !RequirePublished()) return false;
        if (row.ModelName == model) return true;
        if (!row.ModelOptions.Contains(model)) return false;
        CancelConnectionTest();
        try
        {
            _aiService.SetProfileModel(row.Settings.ProfileId, model);
            ReloadSettings();
            StatusMessage = $"Saved model '{model}' for {row.Name}. Review capability overrides in Edit if needed.";
            return true;
        }
        catch (Exception) { StatusMessage = "Unable to save the selected model; previous model retained."; return false; }
    }
    private void SetCatalogStatus(string status)
    {
        ModelCatalogStatus = status;
        OnPropertyChanged(nameof(ModelCatalogStatus));
    }
    private void InvalidateModelCatalog()
    {
        ModelOptions.Clear();
        ModelName = string.Empty;
        if (!IsEditing && SelectedProviderOption is { } option) ApplyDefaultConnection(option.ProviderKind);
        SetCatalogStatus("Destination changed. Load models for this endpoint.");
        EditorDestinationChanged?.Invoke(this, EventArgs.Empty);
    }
    partial void OnIsVaultUnlockedChanged(bool value)
    {
        OnPropertyChanged(nameof(VaultStateLabel));
        OnPropertyChanged(nameof(VaultActionLabel));
    }

    public void CancelConnectionTest()
    {
        _generation++;
        var pending = _connectionTest;
        _connectionTest = null;
        pending?.Cancel();
        if (pending is not null && ModelCatalogStatus == "Loading models...")
            SetCatalogStatus("Model loading cancelled. Load again for the current provider details.");
        IsBusy = false;
    }
    public void DetachWorkspace()
    {
        CancelConnectionTest();
        EditorDestinationChanged?.Invoke(this, EventArgs.Empty);
        StatusMessage = "Open a session to use the Investigative Assistant.";
    }
    private void RefreshApiKeyStatus()
    {
        if (_loading || !CanUseFeature()) return;
        try
        {
            var original = Profiles.FirstOrDefault(row => row.Settings.ProfileId == _editingProfileId)?.Settings;
            HasApiKey = original is not null && original.SecretScope == BuildSettings().SecretScope && _aiService.HasApiKeyFor(original);
        }
        catch { HasApiKey = false; StatusMessage = "The saved key is unavailable for this provider and endpoint."; }
    }
    partial void OnHasApiKeyChanged(bool value)
    {
        OnPropertyChanged(nameof(ProviderStatusDisplay));
        ClearApiKeyCommand.NotifyCanExecuteChanged();
    }
    partial void OnIsBusyChanged(bool value) => NotifyCommandState();
    private AiProviderSettings BuildSettings() => new()
    {
        ProfileId = _editingProfileId,
        ProviderKind = SelectedProviderOption?.ProviderKind ?? AiProviderKind.Disabled,
        ProfileName = ProfileName.Trim(),
        BaseUrl = BaseUrl, ModelName = ModelName, TimeoutSeconds = TimeoutSeconds,
        AllowPrivateNetworkHttp = AllowPrivateNetworkHttp,
        MaxContextCharacters = MaxContextCharacters, MaxResponseCharacters = MaxResponseCharacters,
        ContextWindowTokens = ContextWindowTokens, MaximumOutputTokens = MaximumOutputTokens,
        SupportsTools = SupportsTools, SupportsStructuredOutput = SupportsStructuredOutput
    };
    private bool IsProfileAvailable(AiProviderProfileRow? row)
    {
        if (row is null || _disposed || !row.IsAvailable || !IsVaultStatusAvailable) return false;
        try { return !_aiService.HasApiKeyFor(row.Settings) || _aiService.IsVaultUnlocked; }
        catch { return false; }
    }
    private bool CanRemoveProfile(AiProviderProfileRow? row) => IsProfileAvailable(row) &&
        _featureAccess.CanExecute(FeatureIds.AiAssistance, !IsBusy);
    private bool CanSetDefaultProfile(AiProviderProfileRow? row) => IsProfileAvailable(row) &&
        _featureAccess.CanExecute(FeatureIds.AiAssistance, !IsBusy);
    private bool CanTestConnection() => _featureAccess.CanExecute(FeatureIds.AiAssistance, !IsBusy);
    private bool CanClearApiKey() => _featureAccess.CanExecute(FeatureIds.AiAssistance, HasApiKey && !IsBusy);
    private bool CanUseFeature() => _featureAccess.IsPublished(FeatureIds.AiAssistance);
    private bool RequirePublished()
    {
        if (_featureAccess.TryAccess(FeatureIds.AiAssistance, out var unavailableMessage)) return true;
        StatusMessage = unavailableMessage;
        return false;
    }
    private void NotifyCommandState()
    {
        TestConnectionCommand.NotifyCanExecuteChanged();
        ClearApiKeyCommand.NotifyCanExecuteChanged();
        RemoveProfileCommand.NotifyCanExecuteChanged();
        SetDefaultProfileCommand.NotifyCanExecuteChanged();
    }
    public void Dispose()
    {
        _disposed = true;
        CancelConnectionTest();
        EditorDestinationChanged?.Invoke(this, EventArgs.Empty);
    }
}
