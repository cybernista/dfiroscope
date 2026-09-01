using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public partial class AiDetailsInvestigationViewModel : ViewModelBase, IDisposable
{
    private readonly AiInvestigationService _aiService;
    private readonly FeatureAccessService _featureAccess;
    private readonly InspectorPaneViewModel _inspector;
    private readonly AiPromptCatalog _promptCatalog = new();
    private AnnotationDatabaseService? _annotationStore;
    private ProcessRowViewModel? _selectedProcess;
    private InspectorPayload? _currentPayload;
    private AnnotationTarget? _currentTarget;
    private AiProviderSettings _settings = AiProviderSettings.CreateDefault();
    private CancellationTokenSource? _requestCts;

    public AiDetailsInvestigationViewModel(
        AiInvestigationService aiService,
        InspectorPaneViewModel inspector,
        AnnotationDatabaseService? annotationStore,
        FeatureAccessService? featureAccess = null)
    {
        _aiService = aiService;
        _featureAccess = featureAccess ?? new FeatureAccessService(CurrentEducationalReleaseProfile.RuntimeCatalog);
        _inspector = inspector;
        _annotationStore = annotationStore;
        _inspector.CurrentPayloadChanged += OnCurrentPayloadChanged;

        ArtifactPrompt = _promptCatalog.GetArtifactTemplate().UserPromptPrefix;
        ReloadSettings();
        _ = LoadForPayloadAsync(_inspector.CurrentPayload);
    }

    private void OnCurrentPayloadChanged(object? sender, InspectorPayload? payload) =>
        _ = LoadForPayloadAsync(payload);

    public void Dispose()
    {
        _inspector.CurrentPayloadChanged -= OnCurrentPayloadChanged;
        _requestCts?.Cancel();
        _requestCts?.Dispose();
        _requestCts = null;
        InvestigationHistory.Clear();
    }

    public ObservableCollection<AiInvestigationRecord> InvestigationHistory { get; } = new();

    [ObservableProperty]
    private string artifactPrompt = string.Empty;

    [ObservableProperty]
    private string evidencePreview = string.Empty;

    [ObservableProperty]
    private string evidenceSummary = "No Details artifact selected.";

    [ObservableProperty]
    private string responseText = string.Empty;

    [ObservableProperty]
    private string statusMessage = "Select a Details artifact before running AI investigation.";

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private bool hasArtifactSelected;

    [ObservableProperty]
    private string currentTargetDisplay = "No artifact selected";

    [ObservableProperty]
    private AiInvestigationRecord? selectedInvestigation;

    public string ProviderStatusDisplay
    {
        get
        {
            var keyState = _aiService.HasApiKey ? "key saved with DPAPI" : "no saved key";
            return $"{_settings.ProviderDisplayName}; {keyState}";
        }
    }

    public string PrivacyWarning
    {
        get
        {
            if (_settings.IsCloudProvider)
            {
                var endpoint = string.IsNullOrWhiteSpace(_settings.BaseUrl) ? "the configured endpoint" : _settings.BaseUrl;
                return $"Cloud/commercial provider selected: this artifact evidence is sent to {endpoint} only when Investigate is clicked.";
            }

            if (_settings.ProviderKind == AiProviderKind.LocalOpenAiCompatible)
            {
                return "Local-first provider selected. Artifact evidence stays on this host if the endpoint is local.";
            }

            return "AI is disabled. Artifact evidence is not sent to any AI provider.";
        }
    }

    public void SetAnnotationStore(AnnotationDatabaseService? annotationStore)
    {
        _annotationStore = annotationStore;
        _ = LoadForPayloadAsync(_currentPayload);
    }

    public void SetSelectedProcessContext(ProcessRowViewModel? process)
    {
        _selectedProcess = process;
        if (_currentPayload != null && string.IsNullOrWhiteSpace(_currentPayload.ProcessKey))
        {
            RefreshEvidencePreview();
        }
    }

    public void ReloadSettings()
    {
        _settings = _aiService.LoadSettings();
        OnPropertyChanged(nameof(ProviderStatusDisplay));
        OnPropertyChanged(nameof(PrivacyWarning));
    }

    [RelayCommand(CanExecute = nameof(CanUseFeature))]
    public async Task LoadForPayloadAsync(InspectorPayload? payload)
    {
        if (!RequirePublished())
        {
            return;
        }

        _currentPayload = payload;
        InvestigationHistory.Clear();
        SelectedInvestigation = null;
        ResponseText = string.Empty;

        if (payload == null || payload.ArtifactKind == InspectorArtifactKind.None)
        {
            _currentTarget = null;
            HasArtifactSelected = false;
            CurrentTargetDisplay = "No artifact selected";
            EvidencePreview = string.Empty;
            EvidenceSummary = "No Details artifact selected.";
            StatusMessage = "Select an artifact in Details before running AI investigation.";
            NotifyCommandState();
            return;
        }

        _currentTarget = CreateAnnotationTarget(payload);
        HasArtifactSelected = true;
        CurrentTargetDisplay = _currentTarget.Label;
        RefreshEvidencePreview();

        if (_annotationStore == null)
        {
            StatusMessage = "Annotation database is unavailable; Details AI outputs cannot be persisted.";
            NotifyCommandState();
            return;
        }

        try
        {
            var history = await _annotationStore.LoadAiInvestigationsAsync(_currentTarget);
            foreach (var record in history)
            {
                InvestigationHistory.Add(record);
            }

            SelectedInvestigation = InvestigationHistory.FirstOrDefault();
            StatusMessage = history.Count == 0
                ? $"Ready to investigate {CurrentTargetDisplay}."
                : $"Loaded {history.Count} AI output(s) for {CurrentTargetDisplay}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to load Details AI history: {ex.Message}";
        }
        finally
        {
            NotifyCommandState();
        }
    }

    [RelayCommand(CanExecute = nameof(CanUseFeature))]
    public void RefreshEvidencePreview()
    {
        if (!RequirePublished())
        {
            return;
        }

        if (_currentPayload == null)
        {
            EvidencePreview = string.Empty;
            EvidenceSummary = "No Details artifact selected.";
            return;
        }

        EvidencePreview = BuildEvidenceText(_currentPayload);
        EvidenceSummary = $"{_currentPayload.ArtifactKind} artifact evidence from the Details pane.";
    }

    [RelayCommand(CanExecute = nameof(CanRunInvestigation))]
    public async Task RunInvestigationAsync()
    {
        if (!RequirePublished())
        {
            return;
        }

        if (_currentPayload == null || _currentTarget == null)
        {
            StatusMessage = "Select an artifact in Details before running AI investigation.";
            return;
        }

        if (_annotationStore == null)
        {
            StatusMessage = "Annotation database is unavailable; Details AI outputs cannot be persisted.";
            return;
        }

        ReloadSettings();
        _requestCts?.Cancel();
        _requestCts?.Dispose();
        _requestCts = new CancellationTokenSource();

        try
        {
            IsBusy = true;
            ResponseText = string.Empty;
            StatusMessage = _settings.IsCloudProvider
                ? "Running Details AI with explicit cloud/commercial provider configuration..."
                : "Running Details AI investigation...";

            var evidenceText = BuildEvidenceText(_currentPayload);
            EvidencePreview = evidenceText;
            EvidenceSummary = $"{_currentPayload.ArtifactKind} artifact evidence from the Details pane.";

            var request = new AiInvestigationRequest
            {
                SourceScope = BuildSourceScope(_currentPayload, _currentTarget),
                PromptTemplate = BuildPromptTemplate(),
                AnalystPromptSuffix = string.Empty,
                EvidenceText = evidenceText,
                Settings = _settings
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
                : $"AI investigation did not complete: {record.ErrorText}";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Details AI investigation canceled.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Details AI investigation failed: {ex.Message}";
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

    partial void OnIsBusyChanged(bool value)
    {
        NotifyCommandState();
    }

    partial void OnHasArtifactSelectedChanged(bool value)
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
        StatusMessage = $"Selected Details AI output from {value.RequestedDisplay} ({value.Status}).";
    }

    private bool CanRunInvestigation() =>
        _featureAccess.CanExecute(FeatureIds.AiAssistance, HasArtifactSelected && !IsBusy);

    private bool CanCancelInvestigation() => _featureAccess.CanExecute(FeatureIds.AiAssistance, IsBusy);

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
        RunInvestigationCommand.NotifyCanExecuteChanged();
        CancelInvestigationCommand.NotifyCanExecuteChanged();
    }

    private AiPromptTemplate BuildPromptTemplate()
    {
        var template = _promptCatalog.GetArtifactTemplate();
        return new AiPromptTemplate
        {
            Id = template.Id,
            Title = template.Title,
            Description = template.Description,
            SystemPrompt = template.SystemPrompt,
            UserPromptPrefix = string.IsNullOrWhiteSpace(ArtifactPrompt)
                ? template.UserPromptPrefix
                : ArtifactPrompt.Trim()
        };
    }

    private AnnotationTarget CreateAnnotationTarget(InspectorPayload payload)
    {
        var process = _selectedProcess?.ProcessInfo;
        var targetKind = string.IsNullOrWhiteSpace(payload.TargetKind)
            ? payload.ArtifactKind.ToString()
            : payload.TargetKind;
        var targetId = string.IsNullOrWhiteSpace(payload.TargetId)
            ? BuildFallbackTargetId(payload)
            : payload.TargetId;
        var label = string.IsNullOrWhiteSpace(payload.Header)
            ? targetKind
            : payload.Header;
        var displayPath = FirstNonEmpty(payload.DisplayPath, payload.Subtitle, process?.ProcessPath);

        return new AnnotationTarget
        {
            TargetKind = targetKind,
            TargetTable = payload.TargetTable,
            TargetId = targetId,
            ArtifactId = payload.ArtifactId,
            CaseId = FirstNonEmpty(payload.CaseId, process?.CaseId),
            EvidenceSessionId = FirstNonEmpty(payload.EvidenceSessionId, process?.EvidenceSessionId),
            CaptureId = FirstNonEmpty(payload.CaptureId, process?.CaptureId),
            SourceIdentityId = FirstNonEmpty(payload.SourceIdentityId, process?.SourceIdentityId),
            HostId = FirstNonEmpty(payload.HostId, process?.HostId),
            ProcessKey = FirstNonEmpty(payload.ProcessKey, _selectedProcess?.ProcessKey),
            ProcessId = payload.ProcessId != 0 ? payload.ProcessId : _selectedProcess?.ProcessId ?? 0,
            ProcessName = FirstNonEmpty(payload.ProcessName, _selectedProcess?.ProcessName),
            Label = label,
            DisplayPath = displayPath
        };
    }

    private AiSourceScope BuildSourceScope(InspectorPayload payload, AnnotationTarget target)
    {
        return new AiSourceScope
        {
            ScopeKind = "DetailsArtifact",
            TargetKind = target.TargetKind,
            TargetTable = target.TargetTable,
            TargetId = target.TargetId,
            ArtifactId = target.ArtifactId,
            ProcessKey = target.ProcessKey,
            ProcessId = target.ProcessId,
            ProcessName = target.ProcessName,
            Label = target.Label,
            DisplayPath = target.DisplayPath,
            CaseId = target.CaseId,
            EvidenceSessionId = target.EvidenceSessionId,
            CaptureId = target.CaptureId,
            SourceIdentityId = target.SourceIdentityId,
            HostId = target.HostId,
            ExecutionRootId = payload.ExecutionRootId,
            Summary = $"{payload.ArtifactKind} Details artifact '{target.Label}' with target id {target.TargetId}."
        };
    }

    private string BuildEvidenceText(InspectorPayload payload)
    {
        var target = _currentTarget ?? CreateAnnotationTarget(payload);
        var builder = new StringBuilder();
        builder.AppendLine("Details artifact evidence");
        builder.AppendLine($"Artifact kind: {payload.ArtifactKind}");
        builder.AppendLine($"Target kind: {target.TargetKind}");
        builder.AppendLine($"Target table: {target.TargetTable}");
        builder.AppendLine($"Target id: {target.TargetId}");
        builder.AppendLine($"Artifact id: {NullIfEmpty(target.ArtifactId)}");
        builder.AppendLine($"Header: {payload.Header}");
        builder.AppendLine($"Subtitle: {payload.Subtitle}");
        builder.AppendLine($"Display path: {NullIfEmpty(target.DisplayPath)}");
        builder.AppendLine($"Process: {FormatProcess(target)}");
        builder.AppendLine($"Case id: {NullIfEmpty(target.CaseId)}");
        builder.AppendLine($"Evidence session id: {NullIfEmpty(target.EvidenceSessionId)}");
        builder.AppendLine($"Capture id: {NullIfEmpty(target.CaptureId)}");
        builder.AppendLine($"Source identity id: {NullIfEmpty(target.SourceIdentityId)}");
        builder.AppendLine($"Host id: {NullIfEmpty(target.HostId)}");
        builder.AppendLine();
        builder.AppendLine("Properties:");

        if (payload.Properties.Count == 0)
        {
            builder.AppendLine("- <none>");
        }
        else
        {
            foreach (var property in payload.Properties)
            {
                builder.AppendLine($"- {property.Group} / {property.Name}: {property.Value}");
            }
        }

        if (!string.IsNullOrWhiteSpace(payload.RawText))
        {
            builder.AppendLine();
            builder.AppendLine("Raw content:");
            builder.AppendLine(payload.RawText);
        }

        if (payload.ContentSections.Count > 0)
        {
            builder.AppendLine();
            builder.AppendLine("Structured content:");
            foreach (var section in payload.ContentSections)
            {
                builder.AppendLine($"- {section.Title}: {section.Description}");
                foreach (var row in section.Rows)
                {
                    builder.AppendLine($"  - {row.Item}: {row.Value}{(string.IsNullOrWhiteSpace(row.Details) ? string.Empty : $" ({row.Details})")}");
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(payload.RawXml))
        {
            builder.AppendLine();
            builder.AppendLine("Raw XML:");
            builder.AppendLine(payload.RawXml);
        }

        return builder.ToString();
    }

    private string BuildFallbackTargetId(InspectorPayload payload)
    {
        var processKey = FirstNonEmpty(payload.ProcessKey, _selectedProcess?.ProcessKey);
        var material = new StringBuilder();
        material.AppendLine(payload.ArtifactKind.ToString());
        material.AppendLine(payload.ArtifactId);
        material.AppendLine(payload.Header);
        material.AppendLine(payload.Subtitle);
        material.AppendLine(payload.RawText);
        foreach (var section in payload.ContentSections)
        {
            material.AppendLine(section.Title);
            material.AppendLine(section.Description);
            foreach (var row in section.Rows)
            {
                material.AppendLine(row.Item);
                material.AppendLine(row.Value);
                material.AppendLine(row.Details);
            }
        }
        foreach (var property in payload.Properties)
        {
            material.AppendLine(property.Group);
            material.AppendLine(property.Name);
            material.AppendLine(property.Value);
        }

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material.ToString())));
        var prefix = string.IsNullOrWhiteSpace(processKey) ? "artifact" : processKey;
        return $"{prefix}:{payload.ArtifactKind}:{hash[..16]}";
    }

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private static string NullIfEmpty(string value)
        => string.IsNullOrWhiteSpace(value) ? "<none>" : value;

    private static string FormatProcess(AnnotationTarget target)
    {
        if (string.IsNullOrWhiteSpace(target.ProcessKey) &&
            string.IsNullOrWhiteSpace(target.ProcessName) &&
            target.ProcessId == 0)
        {
            return "<none supplied>";
        }

        var name = string.IsNullOrWhiteSpace(target.ProcessName) ? "<unknown>" : target.ProcessName;
        var key = string.IsNullOrWhiteSpace(target.ProcessKey) ? "<none>" : target.ProcessKey;
        return $"{name} (PID {target.ProcessId}, ProcessKey {key})";
    }
}
