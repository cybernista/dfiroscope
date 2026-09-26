using System.Collections.ObjectModel;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.ApplicationCatalog;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public partial class ApplicationSecurityAssessmentViewModel : ViewModelBase, IDisposable
{
    private readonly Func<AiInvestigationService?> _aiServiceFactory;
    private readonly Func<AiEvidencePackBuilder?> _evidencePackBuilderFactory;
    private readonly FeatureAccessService _featureAccess;
    private readonly NsrlLookupViewModel? _nsrl;
    private readonly AiPromptCatalog _promptCatalog = new();
    private AnnotationDatabaseService? _annotationStore;
    private ProcessRowViewModel? _selectedProcess;
    private ApplicationComparisonEvidenceSource? _comparisonEvidence;
    private string _profileEvidence = string.Empty;
    private long _contextGeneration;
    private CancellationTokenSource? _requestCts;

    public ApplicationSecurityAssessmentViewModel(
        Func<AiInvestigationService?> aiServiceFactory,
        Func<AiEvidencePackBuilder?> evidencePackBuilderFactory,
        FeatureAccessService featureAccess,
        AnnotationDatabaseService? annotationStore,
        NsrlLookupViewModel? nsrl)
    {
        _aiServiceFactory = aiServiceFactory ?? throw new ArgumentNullException(nameof(aiServiceFactory));
        _evidencePackBuilderFactory = evidencePackBuilderFactory ?? throw new ArgumentNullException(nameof(evidencePackBuilderFactory));
        _featureAccess = featureAccess ?? throw new ArgumentNullException(nameof(featureAccess));
        _annotationStore = annotationStore;
        _nsrl = nsrl;

        AddEvidenceSource(AiEvidenceSourceKind.ProcessProperties, "Properties", "Selected process identity, lineage, execution, file, and artifact counters.", true);
        AddEvidenceSource(AiEvidenceSourceKind.ProcessDescription, "Saved App Info annotation", "Current saved session App Info row when available; the resolved reference profile is always included separately.", false);
        AddEvidenceSource(AiEvidenceSourceKind.Modules, "Modules", "Bounded loaded/unloaded module rows.", true);
        AddEvidenceSource(AiEvidenceSourceKind.Handles, "Handles", "Bounded open/closed handle rows.", true);
        AddEvidenceSource(AiEvidenceSourceKind.RuntimeEvents, "Runtime Events", "Bounded runtime process events.", true);
        AddEvidenceSource(AiEvidenceSourceKind.EtwEvents, "ETW", "Bounded ETW events.", false);
        AddEvidenceSource(AiEvidenceSourceKind.SecurityEvents, "Security", "Bounded Windows Security events.", true);
        AddEvidenceSource(AiEvidenceSourceKind.PowerShellEvents, "PowerShell", "Bounded PowerShell log events.", true);
        AddEvidenceSource(AiEvidenceSourceKind.WindowsOtherEvents, "Windows Logs (Other)", "Bounded configured Windows log events.", false);
        AddEvidenceSource(AiEvidenceSourceKind.SysmonEvents, "Sysmon", "Bounded Sysmon events.", true);
        AddEvidenceSource(AiEvidenceSourceKind.MemoryDumps, "Memory Dumps", "Bounded process dump metadata.", false);
        AddEvidenceSource(AiEvidenceSourceKind.PeOnDisk, "PE On Disk", "Bounded process-image PE analysis.", false);
        AddEvidenceSource(AiEvidenceSourceKind.PeFromMemoryDump, "PE From Memory/Dump", "Bounded PE analysis from dumps or files.", false);
        AddEvidenceSource(AiEvidenceSourceKind.ZeekArtifacts, "Zeek / Network", "Bounded process-correlated Zeek network artifacts.", false);
        AddEvidenceSource(AiEvidenceSourceKind.FilesystemArtifacts, "Filesystem", "Bounded process-related filesystem or Prefetch artifacts.", false);
    }

    public ObservableCollection<AiEvidenceSourceOption> EvidenceSourceOptions { get; } = [];
    public ObservableCollection<AiInvestigationRecord> AssessmentHistory { get; } = [];

    public bool IsKnownFileReferenceDataPublished =>
        _nsrl != null && _featureAccess.IsPublished(FeatureIds.KnownFileReferenceData);

    [ObservableProperty]
    private bool isTabSelected;

    [ObservableProperty]
    private bool includeNsrlContext;

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private bool hasProcessSelected;

    [ObservableProperty]
    private string currentTargetDisplay = "No process selected";

    [ObservableProperty]
    private string analystPromptSuffix = "Focus on deviations that are supported by the selected evidence. Do not convert observed properties into expected behavior.";

    [ObservableProperty]
    private string evidencePreview = string.Empty;

    [ObservableProperty]
    private string evidenceSummary = "Activate Security Assessment to build a bounded evidence preview.";

    [ObservableProperty]
    private string responseText = string.Empty;

    [ObservableProperty]
    private string statusMessage = "Select a process and activate this tab.";

    [ObservableProperty]
    private AiInvestigationRecord? selectedAssessment;

    public string PrivacyWarning
    {
        get
        {
            if (!_featureAccess.IsPublished(FeatureIds.AiAssistance))
            {
                return $"AI assistance is not published in educational release '{_featureAccess.Catalog.ReleaseId}'.";
            }

            var service = _aiServiceFactory();
            if (service == null)
            {
                return "AI assistance could not be activated. See viewer status for diagnostics.";
            }

            var settings = service.LoadSettings();
            if (settings.IsCloudProvider)
            {
                var endpoint = string.IsNullOrWhiteSpace(settings.BaseUrl) ? "the configured endpoint" : settings.BaseUrl;
                return $"PRIVACY: selected bounded evidence is sent to {endpoint} only when Run Security Assessment is clicked.";
            }

            if (settings.ProviderKind == AiProviderKind.LocalOpenAiCompatible)
            {
                return "Local-first provider selected. Evidence stays on this host if the configured endpoint is local.";
            }

            return "AI is disabled. Running the assessment gives setup guidance and sends no evidence.";
        }
    }

    public void SetAnnotationStore(AnnotationDatabaseService? annotationStore)
    {
        _annotationStore = annotationStore;
        InvalidateContext("Annotation workspace changed; any active assessment was canceled.");
    }

    public void SetContext(
        ProcessRowViewModel? process,
        string profileEvidence,
        ApplicationComparisonEvidenceSource? comparisonEvidence)
    {
        InvalidateContext("Selected process or App Info context changed; any active assessment was canceled.");
        _selectedProcess = process;
        _profileEvidence = profileEvidence;
        _comparisonEvidence = comparisonEvidence;
        HasProcessSelected = process != null;
        CurrentTargetDisplay = process == null
            ? "No process selected"
            : $"{process.ProcessName} (PID {process.ProcessId})";
        EvidencePreview = string.Empty;
        EvidenceSummary = process == null
            ? "No process selected."
            : "Activate this tab or refresh to build bounded evidence.";
        AssessmentHistory.Clear();
        SelectedAssessment = null;
        ResponseText = string.Empty;
        StatusMessage = process == null
            ? "Select a process before running Security Assessment."
            : "Ready to build the review-only Security Assessment evidence pack.";
        NotifyCommandState();
        if (IsTabSelected && process != null)
        {
            _ = ActivateAsync();
        }
    }

    public void UpdateReferenceContext(
        string profileEvidence,
        ApplicationComparisonEvidenceSource? comparisonEvidence)
    {
        _profileEvidence = profileEvidence;
        _comparisonEvidence = comparisonEvidence;
        if (IsTabSelected && _selectedProcess != null && !IsBusy)
        {
            RefreshEvidencePreview();
        }
    }

    public void Shutdown() => InvalidateContext("Viewer shutdown canceled the assessment.");

    [RelayCommand(CanExecute = nameof(CanRefreshEvidence))]
    public void RefreshEvidencePreview()
    {
        if (!RequirePublished() || _selectedProcess == null)
        {
            return;
        }

        try
        {
            var pack = BuildEvidencePack(_selectedProcess);
            EvidencePreview = pack.EvidenceText;
            EvidenceSummary = pack.Summary;
            StatusMessage = "Bounded Security Assessment evidence preview refreshed. No provider request was made.";
        }
        catch (Exception ex)
        {
            EvidencePreview = string.Empty;
            EvidenceSummary = "Evidence preview unavailable.";
            StatusMessage = $"Evidence preview failed safely: {ex.Message}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanRunAssessment))]
    public async Task RunAssessmentAsync()
    {
        if (!RequirePublished() || _selectedProcess == null)
        {
            return;
        }

        if (_annotationStore == null)
        {
            StatusMessage = "Annotation database is unavailable; Security Assessment outputs cannot be persisted.";
            return;
        }

        var service = _aiServiceFactory();
        if (service == null)
        {
            StatusMessage = "AI assistance could not be activated. See viewer status for diagnostics.";
            return;
        }

        var generation = Volatile.Read(ref _contextGeneration);
        var process = _selectedProcess;
        var cancellation = new CancellationTokenSource();
        var previous = Interlocked.Exchange(ref _requestCts, cancellation);
        previous?.Cancel();
        previous?.Dispose();
        try
        {
            IsBusy = true;
            ResponseText = string.Empty;
            var settings = service.LoadSettings();
            var pack = BuildEvidencePack(process);
            EvidencePreview = pack.EvidenceText;
            EvidenceSummary = pack.Summary;
            StatusMessage = settings.IsCloudProvider
                ? "Running Security Assessment after explicit cloud/commercial submission..."
                : "Running Security Assessment...";
            var template = _promptCatalog.GetSecurityAssessmentTemplate();
            var request = new AiInvestigationRequest
            {
                SourceScope = BuildScope(process, pack.Summary),
                PromptTemplate = template,
                AnalystPromptSuffix = AnalystPromptSuffix,
                EvidenceText = pack.EvidenceText,
                Settings = settings
            };
            var record = await service.RunInvestigationAsync(request, cancellation.Token);
            if (!IsCurrent(generation, process, cancellation))
            {
                return;
            }

            if (record.Status == AiInvestigationStatus.Succeeded)
            {
                var parsed = ApplicationInfoAiResponseParser.ParseAssessment(record.ResponseText);
                if (parsed.Success)
                {
                    record.ResponseText = parsed.NormalizedText;
                    record.ResponseCharacterCount = record.ResponseText.Length;
                }
                else
                {
                    record.Status = AiInvestigationStatus.Failed;
                    record.ErrorText = parsed.Error;
                }
            }

            await _annotationStore.SaveAiInvestigationAsync(record);
            if (!IsCurrent(generation, process, cancellation))
            {
                return;
            }

            AssessmentHistory.Insert(0, record);
            SelectedAssessment = record;
            ResponseText = string.IsNullOrWhiteSpace(record.ResponseText) ? record.ErrorText : record.ResponseText;
            StatusMessage = record.Status == AiInvestigationStatus.Succeeded
                ? "Security Assessment saved to AI output history as an analyst annotation."
                : $"Security Assessment did not complete: {record.ErrorText}";
        }
        catch (OperationCanceledException)
        {
            if (IsCurrent(generation, process, cancellation))
            {
                StatusMessage = "Security Assessment canceled without changing evidence or App Info.";
            }
        }
        catch (Exception ex)
        {
            if (IsCurrent(generation, process, cancellation))
            {
                StatusMessage = $"Security Assessment failed safely: {ex.Message}";
            }
        }
        finally
        {
            if (ReferenceEquals(Interlocked.CompareExchange(ref _requestCts, null, cancellation), cancellation))
            {
                cancellation.Dispose();
            }
            if (generation == Volatile.Read(ref _contextGeneration) && ReferenceEquals(_selectedProcess, process))
            {
                IsBusy = false;
            }
        }
    }

    [RelayCommand(CanExecute = nameof(CanCancelAssessment))]
    public void CancelAssessment() => _requestCts?.Cancel();

    partial void OnIsTabSelectedChanged(bool value)
    {
        if (value)
        {
            _ = ActivateAsync();
        }
        else
        {
            _requestCts?.Cancel();
        }
    }

    partial void OnIncludeNsrlContextChanged(bool value)
    {
        if (IsTabSelected && _selectedProcess != null && !IsBusy)
        {
            RefreshEvidencePreview();
        }
    }

    partial void OnSelectedAssessmentChanged(AiInvestigationRecord? value)
    {
        if (value != null)
        {
            ResponseText = string.IsNullOrWhiteSpace(value.ResponseText) ? value.ErrorText : value.ResponseText;
        }
    }

    partial void OnIsBusyChanged(bool value) => NotifyCommandState();
    partial void OnHasProcessSelectedChanged(bool value) => NotifyCommandState();

    private async Task ActivateAsync()
    {
        if (!RequirePublished() || _selectedProcess == null)
        {
            return;
        }

        RefreshEvidencePreview();
        if (_annotationStore == null)
        {
            StatusMessage = "Annotation database is unavailable; assessment history cannot be loaded.";
            return;
        }

        var generation = Volatile.Read(ref _contextGeneration);
        var process = _selectedProcess;
        try
        {
            var target = CreateTarget(process);
            var history = await _annotationStore.LoadAiInvestigationsAsync(target, 100);
            if (generation != Volatile.Read(ref _contextGeneration) || !ReferenceEquals(process, _selectedProcess))
            {
                return;
            }

            AssessmentHistory.Clear();
            foreach (var record in history.Where(record => string.Equals(
                         record.PromptTemplateId,
                         AiPromptCatalog.SecurityAssessmentTemplateId,
                         StringComparison.Ordinal)))
            {
                AssessmentHistory.Add(record);
            }

            SelectedAssessment = AssessmentHistory.FirstOrDefault();
        }
        catch (Exception ex)
        {
            if (generation == Volatile.Read(ref _contextGeneration) && ReferenceEquals(process, _selectedProcess))
            {
                StatusMessage = $"Assessment history failed safely: {ex.Message}";
            }
        }
    }

    private AiEvidencePack BuildEvidencePack(ProcessRowViewModel process)
    {
        var builder = _evidencePackBuilderFactory()
                      ?? throw new InvalidOperationException("AI evidence builder is unavailable.");
        var selectedSources = EvidenceSourceOptions
            .Where(option => option.IsSelected)
            .Select(option => option.SourceKind);
        var selected = builder.BuildForSelectedProcess(process.ProcessInfo, selectedSources);
        var evidence = new StringBuilder();
        evidence.AppendLine("## Reference context: resolved App Info profile");
        evidence.AppendLine("Classification: reference knowledge, not source-native evidence and not a benign verdict.");
        evidence.AppendLine(string.IsNullOrWhiteSpace(_profileEvidence) ? "No resolved profile content is available." : _profileEvidence);
        evidence.AppendLine();
        evidence.AppendLine("## Derived context: Expected vs Actual");
        evidence.AppendLine("Classification: deterministic display-time comparison, not persisted evidence and not a verdict.");
        evidence.AppendLine(_comparisonEvidence?.Text ?? "No comparison rows are currently available.");
        evidence.AppendLine();
        var nsrlSummary = "NSRL external reference context: not selected";
        if (IncludeNsrlContext && IsKnownFileReferenceDataPublished)
        {
            evidence.AppendLine("## External reference context: NSRL / hashlookup-server");
            evidence.AppendLine("Classification: external reference context, not source-native evidence and never a known-good verdict.");
            if (_nsrl is not null && _nsrl.TryBuildAiExternalReferenceContext(out var nsrlContext))
            {
                evidence.AppendLine(nsrlContext);
                nsrlSummary = "NSRL external reference context: current bounded result included explicitly";
            }
            else
            {
                evidence.AppendLine("Not included: there is no current bounded Match/No match result with provider provenance for this selection.");
                nsrlSummary = "NSRL external reference context: selected but unavailable";
            }
            evidence.AppendLine();
        }

        evidence.Append(selected.EvidenceText);
        return new AiEvidencePack
        {
            EvidenceText = evidence.ToString(),
            Summary = $"Resolved profile and Expected vs Actual included; {nsrlSummary}; selected evidence: {selected.Summary}"
        };
    }

    private void AddEvidenceSource(AiEvidenceSourceKind kind, string name, string description, bool selected)
    {
        var option = new AiEvidenceSourceOption
        {
            SourceKind = kind,
            DisplayName = name,
            Description = description,
            IsSelected = selected
        };
        option.SelectionChanged += OnEvidenceSelectionChanged;
        EvidenceSourceOptions.Add(option);
    }

    private void OnEvidenceSelectionChanged(object? sender, EventArgs e)
    {
        if (IsTabSelected && _selectedProcess != null && !IsBusy)
        {
            RefreshEvidencePreview();
        }
    }

    private bool RequirePublished()
    {
        if (_featureAccess.TryAccess(FeatureIds.AiAssistance, out var unavailable))
        {
            return true;
        }

        StatusMessage = unavailable;
        return false;
    }

    private bool CanRefreshEvidence() => _featureAccess.CanExecute(FeatureIds.AiAssistance, HasProcessSelected && !IsBusy);
    private bool CanRunAssessment() => _featureAccess.CanExecute(FeatureIds.AiAssistance, HasProcessSelected && !IsBusy);
    private bool CanCancelAssessment() => _featureAccess.CanExecute(FeatureIds.AiAssistance, IsBusy);

    private bool IsCurrent(long generation, ProcessRowViewModel process, CancellationTokenSource cancellation)
        => generation == Volatile.Read(ref _contextGeneration) &&
           ReferenceEquals(process, _selectedProcess) &&
           ReferenceEquals(cancellation, _requestCts);

    private void InvalidateContext(string message)
    {
        Interlocked.Increment(ref _contextGeneration);
        var active = Interlocked.Exchange(ref _requestCts, null);
        active?.Cancel();
        active?.Dispose();
        IsBusy = false;
        StatusMessage = message;
    }

    private void NotifyCommandState()
    {
        RefreshEvidencePreviewCommand.NotifyCanExecuteChanged();
        RunAssessmentCommand.NotifyCanExecuteChanged();
        CancelAssessmentCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(PrivacyWarning));
    }

    private static AnnotationTarget CreateTarget(ProcessRowViewModel row) => new()
    {
        TargetKind = "Process",
        TargetTable = "Processes",
        TargetId = row.ProcessKey,
        ProcessKey = row.ProcessKey,
        ProcessId = row.ProcessId,
        ProcessName = row.ProcessName,
        Label = $"{row.ProcessName} (PID {row.ProcessId})",
        DisplayPath = row.ProcessPath,
        CaseId = row.ProcessInfo.CaseId,
        EvidenceSessionId = row.ProcessInfo.EvidenceSessionId,
        CaptureId = row.ProcessInfo.CaptureId,
        SourceIdentityId = row.ProcessInfo.SourceIdentityId,
        HostId = row.ProcessInfo.HostId
    };

    private static AiSourceScope BuildScope(ProcessRowViewModel row, string summary) => new()
    {
        ScopeKind = "AppInfoSecurityAssessment",
        TargetKind = "Process",
        TargetTable = "Processes",
        TargetId = row.ProcessKey,
        ProcessKey = row.ProcessKey,
        ProcessId = row.ProcessId,
        ProcessName = row.ProcessName,
        Label = $"{row.ProcessName} (PID {row.ProcessId})",
        DisplayPath = row.ProcessPath,
        CaseId = row.ProcessInfo.CaseId,
        EvidenceSessionId = row.ProcessInfo.EvidenceSessionId,
        CaptureId = row.ProcessInfo.CaptureId,
        SourceIdentityId = row.ProcessInfo.SourceIdentityId,
        HostId = row.ProcessInfo.HostId,
        ExecutionRootId = row.ProcessInfo.ExecutionRootId,
        Summary = summary
    };

    public void Dispose()
    {
        Shutdown();
        foreach (var option in EvidenceSourceOptions)
        {
            option.SelectionChanged -= OnEvidenceSelectionChanged;
        }
    }
}
