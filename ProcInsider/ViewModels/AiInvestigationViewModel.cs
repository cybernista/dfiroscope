using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public sealed class AiProviderOption
{
    public AiProviderKind ProviderKind { get; init; }

    public string DisplayName { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;
}

public partial class AiEvidenceSourceOption : ObservableObject
{
    [ObservableProperty]
    private bool isSelected;

    public AiEvidenceSourceKind SourceKind { get; init; }

    public string DisplayName { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    public event EventHandler? SelectionChanged;

    partial void OnIsSelectedChanged(bool value)
    {
        SelectionChanged?.Invoke(this, EventArgs.Empty);
    }
}

public partial class AiInvestigationViewModel : ViewModelBase, IDisposable
{
    private readonly AiInvestigationService _aiService;
    private readonly FeatureAccessService _featureAccess;
    private readonly AiEvidencePackBuilder _evidencePackBuilder;
    private readonly AiPromptCatalog _promptCatalog = new();
    private AnnotationDatabaseService? _annotationStore;
    private ProcessRowViewModel? _selectedProcess;
    private long _selectionLoadGeneration;
    private AnnotationTarget? _currentTarget;
    private bool _isLoadingSettings;
    private CancellationTokenSource? _requestCts;

    public AiInvestigationViewModel(
        AiInvestigationService aiService,
        AiEvidencePackBuilder evidencePackBuilder,
        AnnotationDatabaseService? annotationStore,
        FeatureAccessService? featureAccess = null)
    {
        _aiService = aiService;
        _featureAccess = featureAccess ?? new FeatureAccessService(CurrentEducationalReleaseProfile.RuntimeCatalog);
        _evidencePackBuilder = evidencePackBuilder;
        _annotationStore = annotationStore;

        ProviderOptions =
        [
            new AiProviderOption
            {
                ProviderKind = AiProviderKind.Disabled,
                DisplayName = "Disabled",
                Description = "AI actions report setup needed and never send evidence."
            },
            new AiProviderOption
            {
                ProviderKind = AiProviderKind.LocalOpenAiCompatible,
                DisplayName = "Local OpenAI-compatible",
                Description = "Recommended local-first mode for Ollama, LM Studio, or another /v1/chat/completions endpoint."
            },
            new AiProviderOption
            {
                ProviderKind = AiProviderKind.CommercialOpenAiCompatible,
                DisplayName = "Commercial/cloud OpenAI-compatible",
                Description = "Explicit cloud mode. Evidence is sent to the configured endpoint only when you run an AI action."
            }
        ];

        foreach (var template in _promptCatalog.GetTemplates())
        {
            PromptTemplates.Add(template);
        }

        AddEvidenceSource(AiEvidenceSourceKind.ProcessProperties, "Properties", "Selected process identity, lineage, execution, file, and artifact counter fields.", true);
        AddEvidenceSource(AiEvidenceSourceKind.ProcessDescription, "Process Description/App Info", "SQLite application metadata when that tab is available.", false);
        AddEvidenceSource(AiEvidenceSourceKind.Modules, "Modules", "Bounded loaded/unloaded module rows for the selected process.", true);
        AddEvidenceSource(AiEvidenceSourceKind.Handles, "Handles", "Bounded open/closed handle rows for the selected process.", true);
        AddEvidenceSource(AiEvidenceSourceKind.RuntimeEvents, "Runtime Events", "Bounded runtime process events.", true);
        AddEvidenceSource(AiEvidenceSourceKind.EtwEvents, "ETW", "Bounded ETW events for the selected process.", true);
        AddEvidenceSource(AiEvidenceSourceKind.SecurityEvents, "Security", "Bounded Windows Security events for the selected process.", true);
        AddEvidenceSource(AiEvidenceSourceKind.PowerShellEvents, "PowerShell", "Bounded PowerShell log events for the selected process.", true);
        AddEvidenceSource(AiEvidenceSourceKind.WindowsOtherEvents, "Windows Logs (Other)", "Bounded events from other configured Windows logs.", true);
        AddEvidenceSource(AiEvidenceSourceKind.SysmonEvents, "Sysmon", "Bounded Sysmon events for the selected process.", true);
        AddEvidenceSource(AiEvidenceSourceKind.MemoryDumps, "Memory Dumps", "Bounded process dump metadata rows.", false);
        AddEvidenceSource(AiEvidenceSourceKind.PeOnDisk, "PE On Disk", "Bounded process-image PE analysis records.", false);
        AddEvidenceSource(AiEvidenceSourceKind.PeFromMemoryDump, "PE From Memory/Dump", "Bounded PE analysis records derived from dumps or files.", false);
        AddEvidenceSource(AiEvidenceSourceKind.ZeekArtifacts, "Zeek Artifacts", "Bounded process-correlated Zeek network artifacts.", false);
        AddEvidenceSource(AiEvidenceSourceKind.FilesystemArtifacts, "Filesystem Artifacts", "Bounded process-related filesystem or Prefetch artifacts.", false);

        SelectedPromptTemplate = _promptCatalog.GetDefaultTemplate();
        ReloadSettings();
    }

    public ObservableCollection<AiProviderOption> ProviderOptions { get; }

    public ObservableCollection<AiPromptTemplate> PromptTemplates { get; } = new();

    public ObservableCollection<AiInvestigationRecord> InvestigationHistory { get; } = new();

    public ObservableCollection<AiEvidenceSourceOption> EvidenceSourceOptions { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsCloudProvider))]
    [NotifyPropertyChangedFor(nameof(ProviderStatusDisplay))]
    [NotifyPropertyChangedFor(nameof(PrivacyWarning))]
    private AiProviderOption? selectedProviderOption;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PrivacyWarning))]
    private string baseUrl = string.Empty;

    [ObservableProperty]
    private string modelName = string.Empty;

    [ObservableProperty]
    private string newApiKey = string.Empty;

    [ObservableProperty]
    private int timeoutSeconds = AiProviderSettings.DefaultTimeoutSeconds;

    [ObservableProperty]
    private int maxContextCharacters = 12000;

    [ObservableProperty]
    private int maxResponseCharacters = 4000;

    [ObservableProperty]
    private AiPromptTemplate? selectedPromptTemplate;

    [ObservableProperty]
    private string analystPromptSuffix = "Focus on suspicious process ancestry, command line, image path, hash, module/handle collection state, and event-source gaps.";

    [ObservableProperty]
    private string evidencePreview = string.Empty;

    [ObservableProperty]
    private string evidenceSummary = "No evidence pack built.";

    [ObservableProperty]
    private string responseText = string.Empty;

    [ObservableProperty]
    private string statusMessage = "AI provider disabled. Configure a local provider to begin.";

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private bool hasProcessSelected;

    [ObservableProperty]
    private bool hasApiKey;

    [ObservableProperty]
    private string currentTargetDisplay = "No process selected";

    [ObservableProperty]
    private string settingsPathDisplay = string.Empty;

    [ObservableProperty]
    private string secretPathDisplay = string.Empty;

    [ObservableProperty]
    private AiInvestigationRecord? selectedInvestigation;

    public bool IsCloudProvider => SelectedProviderOption?.ProviderKind == AiProviderKind.CommercialOpenAiCompatible;

    public string ProviderStatusDisplay
    {
        get
        {
            var provider = SelectedProviderOption?.DisplayName ?? "Disabled";
            var keyState = HasApiKey ? "key saved with DPAPI" : "no saved key";
            return $"{provider}; {keyState}";
        }
    }

    public string PrivacyWarning
    {
        get
        {
            if (IsCloudProvider)
            {
                var endpoint = string.IsNullOrWhiteSpace(BaseUrl) ? "the configured endpoint" : BaseUrl;
                return $"Cloud/commercial provider selected: selected evidence is sent to {endpoint} only when Investigate is clicked.";
            }

            if (SelectedProviderOption?.ProviderKind == AiProviderKind.LocalOpenAiCompatible)
            {
                return "Local-first provider selected. Evidence stays on this host if the endpoint is local.";
            }

            return "AI is disabled. Evidence is not sent to any AI provider.";
        }
    }

    public void SetAnnotationStore(AnnotationDatabaseService? annotationStore)
    {
        _annotationStore = annotationStore;
        _evidencePackBuilder.SetAnnotationStore(annotationStore);
        _ = LoadForProcessAsync(_selectedProcess);
    }

    public void ReloadSettings()
    {
        _isLoadingSettings = true;
        try
        {
            var settings = _aiService.LoadSettings();
            SelectedProviderOption = ProviderOptions.FirstOrDefault(option => option.ProviderKind == settings.ProviderKind)
                ?? ProviderOptions[0];
            BaseUrl = settings.BaseUrl;
            ModelName = settings.ModelName;
            TimeoutSeconds = settings.TimeoutSeconds;
            MaxContextCharacters = settings.MaxContextCharacters;
            MaxResponseCharacters = settings.MaxResponseCharacters;
            NewApiKey = string.Empty;
            HasApiKey = _aiService.HasApiKey;
            SettingsPathDisplay = _aiService.SettingsPath;
            SecretPathDisplay = _aiService.SecretPath;
            StatusMessage = settings.ProviderKind == AiProviderKind.Disabled
                ? "AI provider disabled. Configure a local or commercial provider before running AI analysis."
                : $"Loaded AI settings for {settings.ProviderDisplayName}.";
        }
        finally
        {
            _isLoadingSettings = false;
            NotifyCommandState();
            OnPropertyChanged(nameof(IsCloudProvider));
            OnPropertyChanged(nameof(ProviderStatusDisplay));
            OnPropertyChanged(nameof(PrivacyWarning));
        }
    }

    public void Clear()
    {
        _selectionLoadGeneration++;
        _selectedProcess = null;
        _currentTarget = null;
        HasProcessSelected = false;
        CurrentTargetDisplay = "No process selected";
        EvidencePreview = string.Empty;
        ResponseText = string.Empty;
        InvestigationHistory.Clear();
        SelectedInvestigation = null;
        NotifyCommandState();
    }

    [RelayCommand(CanExecute = nameof(CanUseFeature))]
    public Task LoadForProcessAsync(ProcessRowViewModel? process) =>
        LoadForProcessSelectionAsync(process, CancellationToken.None);

    public async Task LoadForProcessSelectionAsync(
        ProcessRowViewModel? process,
        CancellationToken cancellationToken)
    {
        if (!RequirePublished())
        {
            return;
        }

        var generation = ++_selectionLoadGeneration;
        _selectedProcess = process;
        InvestigationHistory.Clear();
        SelectedInvestigation = null;
        ResponseText = string.Empty;

        if (process == null)
        {
            _currentTarget = null;
            HasProcessSelected = false;
            CurrentTargetDisplay = "No process selected";
            EvidencePreview = string.Empty;
            EvidenceSummary = "No process selected.";
            StatusMessage = "Select a process before running AI analysis.";
            NotifyCommandState();
            return;
        }

        _currentTarget = CreateProcessAnnotationTarget(process);
        HasProcessSelected = true;
        CurrentTargetDisplay = $"{process.ProcessName} (PID {process.ProcessId})";
        RefreshEvidencePreview();

        if (_annotationStore == null)
        {
            StatusMessage = "Annotation database is unavailable; AI outputs cannot be persisted.";
            NotifyCommandState();
            return;
        }

        try
        {
            var target = _currentTarget;
            cancellationToken.ThrowIfCancellationRequested();
            var history = await _annotationStore.LoadAiInvestigationsAsync(target);
            cancellationToken.ThrowIfCancellationRequested();
            if (generation != _selectionLoadGeneration || !ReferenceEquals(_selectedProcess, process))
            {
                return;
            }

            foreach (var record in history)
            {
                InvestigationHistory.Add(record);
            }

            SelectedInvestigation = InvestigationHistory.FirstOrDefault();
            StatusMessage = history.Count == 0
                ? $"Ready to run AI for {CurrentTargetDisplay}."
                : $"Loaded {history.Count} AI investigation output(s) for {CurrentTargetDisplay}.";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            if (generation == _selectionLoadGeneration && ReferenceEquals(_selectedProcess, process))
            {
                StatusMessage = $"Failed to load AI output history: {ex.Message}";
            }
        }
        finally
        {
            if (generation == _selectionLoadGeneration && ReferenceEquals(_selectedProcess, process))
            {
                NotifyCommandState();
            }
        }
    }

    [RelayCommand(CanExecute = nameof(CanUseFeature))]
    public void RefreshEvidencePreview()
    {
        if (!RequirePublished())
        {
            return;
        }

        if (_selectedProcess == null)
        {
            EvidencePreview = string.Empty;
            EvidenceSummary = "No process selected.";
            return;
        }

        var pack = BuildCurrentEvidencePack(_selectedProcess);
        EvidencePreview = pack.EvidenceText;
        EvidenceSummary = string.IsNullOrWhiteSpace(pack.Summary)
            ? "No selected Data tab evidence."
            : pack.Summary;
    }

    [RelayCommand(CanExecute = nameof(CanSaveSettings))]
    public void SaveSettings()
    {
        if (!RequirePublished())
        {
            return;
        }

        var settings = BuildSettings();
        try
        {
            _aiService.SaveSettings(settings, NewApiKey);
            NewApiKey = string.Empty;
            HasApiKey = _aiService.HasApiKey;
            StatusMessage = $"Saved AI settings to {SettingsPathDisplay}.";
            OnPropertyChanged(nameof(ProviderStatusDisplay));
            OnPropertyChanged(nameof(PrivacyWarning));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to save AI settings: {ex.Message}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanTestConnection))]
    public async Task TestConnectionAsync()
    {
        if (!RequirePublished())
        {
            return;
        }

        var settings = BuildSettings();
        try
        {
            IsBusy = true;
            SaveSettings();
            StatusMessage = "Testing AI provider connection...";
            var result = await _aiService.TestConnectionAsync(settings, CancellationToken.None);
            StatusMessage = result.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanRunInvestigation))]
    public async Task RunInvestigationAsync()
    {
        if (!RequirePublished())
        {
            return;
        }

        if (_selectedProcess == null || _currentTarget == null)
        {
            StatusMessage = "Select a process before running AI analysis.";
            return;
        }

        if (_annotationStore == null)
        {
            StatusMessage = "Annotation database is unavailable; AI outputs cannot be persisted.";
            return;
        }

        var settings = BuildSettings();
        var template = SelectedPromptTemplate ?? _promptCatalog.GetDefaultTemplate();
        _requestCts?.Cancel();
        _requestCts?.Dispose();
        _requestCts = new CancellationTokenSource();

        try
        {
            IsBusy = true;
            SaveSettings();
            ResponseText = string.Empty;
            StatusMessage = settings.IsCloudProvider
                ? "Running AI analysis with explicit cloud/commercial provider configuration..."
                : "Running AI analysis...";

            var evidencePack = BuildCurrentEvidencePack(_selectedProcess);
            EvidencePreview = evidencePack.EvidenceText;
            EvidenceSummary = evidencePack.Summary;

            var request = new AiInvestigationRequest
            {
                SourceScope = BuildSelectedProcessScope(_selectedProcess, evidencePack.Summary),
                PromptTemplate = template,
                AnalystPromptSuffix = AnalystPromptSuffix,
                EvidenceText = evidencePack.EvidenceText,
                Settings = settings
            };

            var record = await _aiService.RunInvestigationAsync(request, _requestCts.Token);
            await _annotationStore.SaveAiInvestigationAsync(record);

            InvestigationHistory.Insert(0, record);
            SelectedInvestigation = record;
            ResponseText = string.IsNullOrWhiteSpace(record.ResponseText)
                ? record.ErrorText
                : record.ResponseText;
            StatusMessage = record.Status == AiInvestigationStatus.Succeeded
                ? $"AI output saved for {CurrentTargetDisplay}."
                : $"AI analysis did not complete: {record.ErrorText}";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "AI analysis canceled.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"AI analysis failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanCancelInvestigation))]
    public void CancelInvestigation()
    {
        if (!RequirePublished())
        {
            return;
        }

        _requestCts?.Cancel();
    }

    [RelayCommand(CanExecute = nameof(CanClearApiKey))]
    public void ClearApiKey()
    {
        if (!RequirePublished())
        {
            return;
        }

        try
        {
            _aiService.ClearApiKey();
            HasApiKey = false;
            NewApiKey = string.Empty;
            StatusMessage = "Cleared saved AI API key/token.";
            OnPropertyChanged(nameof(ProviderStatusDisplay));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to clear AI API key/token: {ex.Message}";
        }
    }

    partial void OnSelectedProviderOptionChanged(AiProviderOption? value)
    {
        if (_isLoadingSettings || value == null)
        {
            return;
        }

        if (value.ProviderKind == AiProviderKind.LocalOpenAiCompatible && string.IsNullOrWhiteSpace(BaseUrl))
        {
            BaseUrl = "http://localhost:11434/v1";
        }
        else if (value.ProviderKind == AiProviderKind.CommercialOpenAiCompatible && string.IsNullOrWhiteSpace(BaseUrl))
        {
            BaseUrl = "https://api.openai.com/v1";
        }

        StatusMessage = value.ProviderKind == AiProviderKind.Disabled
            ? "AI provider disabled. Evidence will not be sent to any provider."
            : $"Selected {value.DisplayName}. Save settings before relying on this profile.";
        OnPropertyChanged(nameof(IsCloudProvider));
        OnPropertyChanged(nameof(ProviderStatusDisplay));
        OnPropertyChanged(nameof(PrivacyWarning));
    }

    partial void OnBaseUrlChanged(string value)
    {
        OnPropertyChanged(nameof(PrivacyWarning));
    }

    partial void OnHasApiKeyChanged(bool value)
    {
        OnPropertyChanged(nameof(ProviderStatusDisplay));
        ClearApiKeyCommand.NotifyCanExecuteChanged();
    }

    partial void OnIsBusyChanged(bool value)
    {
        NotifyCommandState();
    }

    partial void OnHasProcessSelectedChanged(bool value)
    {
        RunInvestigationCommand.NotifyCanExecuteChanged();
    }

    partial void OnSelectedInvestigationChanged(AiInvestigationRecord? value)
    {
        if (value == null)
        {
            return;
        }

        ResponseText = string.IsNullOrWhiteSpace(value.ResponseText)
            ? value.ErrorText
            : value.ResponseText;
        StatusMessage = $"Selected AI output from {value.RequestedDisplay} ({value.Status}).";
    }

    private AiProviderSettings BuildSettings()
    {
        var kind = SelectedProviderOption?.ProviderKind ?? AiProviderKind.Disabled;
        return new AiProviderSettings
        {
            ProviderKind = kind,
            ProfileName = SelectedProviderOption?.DisplayName ?? "Disabled",
            BaseUrl = BaseUrl,
            ModelName = ModelName,
            TimeoutSeconds = TimeoutSeconds,
            MaxContextCharacters = MaxContextCharacters,
            MaxResponseCharacters = MaxResponseCharacters
        };
    }

    private bool CanSaveSettings() => _featureAccess.CanExecute(FeatureIds.AiAssistance, !IsBusy);

    private bool CanTestConnection() => _featureAccess.CanExecute(FeatureIds.AiAssistance, !IsBusy);

    private bool CanRunInvestigation() =>
        _featureAccess.CanExecute(FeatureIds.AiAssistance, HasProcessSelected && !IsBusy);

    private bool CanCancelInvestigation() => _featureAccess.CanExecute(FeatureIds.AiAssistance, IsBusy);

    private bool CanClearApiKey() =>
        _featureAccess.CanExecute(FeatureIds.AiAssistance, HasApiKey && !IsBusy);

    private bool CanUseFeature() => _featureAccess.IsPublished(FeatureIds.AiAssistance);

    private bool RequirePublished()
    {
        if (_featureAccess.TryAccess(FeatureIds.AiAssistance, out var unavailableMessage))
        {
            return true;
        }

        StatusMessage = unavailableMessage;
        return false;
    }

    private void NotifyCommandState()
    {
        SaveSettingsCommand.NotifyCanExecuteChanged();
        TestConnectionCommand.NotifyCanExecuteChanged();
        RunInvestigationCommand.NotifyCanExecuteChanged();
        CancelInvestigationCommand.NotifyCanExecuteChanged();
        ClearApiKeyCommand.NotifyCanExecuteChanged();
    }

    private void AddEvidenceSource(
        AiEvidenceSourceKind sourceKind,
        string displayName,
        string description,
        bool isSelected)
    {
        var option = new AiEvidenceSourceOption
        {
            SourceKind = sourceKind,
            DisplayName = displayName,
            Description = description,
            IsSelected = isSelected
        };
        option.SelectionChanged += OnEvidenceSourceSelectionChanged;
        EvidenceSourceOptions.Add(option);
    }

    private void OnEvidenceSourceSelectionChanged(object? sender, EventArgs e) => RefreshEvidencePreview();

    public void Dispose()
    {
        _requestCts?.Cancel();
        _requestCts?.Dispose();
        _requestCts = null;
        foreach (var option in EvidenceSourceOptions)
        {
            option.SelectionChanged -= OnEvidenceSourceSelectionChanged;
        }

        Clear();
    }

    private static AnnotationTarget CreateProcessAnnotationTarget(ProcessRowViewModel row)
    {
        var process = row.ProcessInfo;
        return new AnnotationTarget
        {
            TargetKind = "Process",
            TargetTable = "Processes",
            TargetId = row.ProcessKey,
            ProcessKey = row.ProcessKey,
            ProcessId = row.ProcessId,
            ProcessName = row.ProcessName,
            Label = $"{row.ProcessName} (PID {row.ProcessId})",
            DisplayPath = row.ProcessPath,
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId
        };
    }

    private static AiSourceScope BuildSelectedProcessScope(ProcessRowViewModel row, string evidenceSummary)
    {
        var process = row.ProcessInfo;
        return new AiSourceScope
        {
            ScopeKind = "SelectedProcess",
            TargetKind = "Process",
            TargetTable = "Processes",
            TargetId = row.ProcessKey,
            ProcessKey = row.ProcessKey,
            ProcessId = row.ProcessId,
            ProcessName = row.ProcessName,
            Label = $"{row.ProcessName} (PID {row.ProcessId})",
            DisplayPath = row.ProcessPath,
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            Summary = $"Selected process {row.ProcessName} (PID {row.ProcessId}, ProcessKey {row.ProcessKey}). Data tab evidence: {evidenceSummary}"
        };
    }

    private AiEvidencePack BuildCurrentEvidencePack(ProcessRowViewModel row)
    {
        var selectedSources = EvidenceSourceOptions
            .Where(source => source.IsSelected)
            .Select(source => source.SourceKind);
        return _evidencePackBuilder.BuildForSelectedProcess(row.ProcessInfo, selectedSources);
    }
}
