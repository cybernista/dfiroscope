using System.IO;
using System.Collections.ObjectModel;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.ApplicationCatalog;
using ProcInsider.Models.Features;
using ProcInsider.Models.Telemetry;
using ProcInsider.Services;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public partial class ProcessDescriptionViewModel : ViewModelBase
{
    public const string DefaultAppInfoPrompt =
        "Draft a review-only Windows application reference profile. Keep reusable expected knowledge separate from the selected process observations and state uncertainty plainly.";

    private readonly Func<AiInvestigationService?> _aiServiceFactory;
    private readonly Func<AiEvidencePackBuilder?> _aiEvidencePackBuilderFactory;
    private readonly FeatureAccessService _featureAccess;
    private readonly ApplicationInfoResolutionService _resolutionService;
    private readonly IApplicationComparisonEvidenceService _comparisonEvidenceService;
    private readonly ApplicationProfileComparisonService _comparisonService = new();
    private readonly bool _hasCatalog;
    private AnnotationDatabaseService? _annotationStore;
    private ProcessRowViewModel? _selectedProcess;
    private string _applicationId = string.Empty;
    private bool _isLoading;
    private bool _isDirty;
    private long _selectionLoadGeneration;
    private CancellationTokenSource? _activeSelectionLoad;
    private string _baseProfileId = string.Empty;
    private string _baseProfileRevision = string.Empty;
    private string _baseCatalogRevision = string.Empty;
    private List<ApplicationProfileSourceReference> _sourceReferences = [];
    private string _catalogProvenance = string.Empty;
    private DateTime? _profileLastReviewedUtc;
    private DateTime _createdUtc;
    private ApplicationProfileOrigin _recordOrigin = ApplicationProfileOrigin.UnsavedDraft;
    private ApplicationProfileDefinition? _comparisonCatalogProfile;
    private IReadOnlyList<ApplicationCatalogMatch> _comparisonCandidates = [];
    private ApplicationComparisonActualContext? _comparisonActual;
    private string _comparisonSelectionReason = string.Empty;
    private string _matchReason = string.Empty;
    private ApplicationMetadataRecord? _resolvedRecordBeforeAiDraft;
    private CancellationTokenSource? _activeAiDraftRequest;
    private long _aiDraftGeneration;
    private readonly Func<string, bool> _confirmReplace;
    private AiProviderKind _currentAiProviderKind = AiProviderKind.Disabled;
    private string _currentAiEndpointMode = string.Empty;
    private string _currentAiPromptTemplateId = string.Empty;
    private DateTime? _currentAiRequestedUtc;
    private bool _currentAiSourceClaimsUnverified;
    private ApplicationProfileReviewState _displayedReviewState = ApplicationProfileReviewState.Unreviewed;
    private DateTime? _displayedReviewedUtc;
    private ApplicationInfoEvaluationResolutionResult? _evaluationResolution;
    private ApplicationMetadataRecord? _recordBeforeEvaluation;
    private bool _metadataExistsBeforeEvaluation;
    private bool _isDirtyBeforeEvaluation;
    private bool _hasAiDraftBeforeEvaluation;
    private ApplicationProfileDefinition? _comparisonCatalogProfileBeforeEvaluation;
    private IReadOnlyList<ApplicationCatalogMatch> _comparisonCandidatesBeforeEvaluation = [];
    private string _comparisonSelectionReasonBeforeEvaluation = string.Empty;
    private string _matchReasonBeforeEvaluation = string.Empty;
    private string _statusMessageBeforeEvaluation = string.Empty;
    private List<ApplicationInfoDraftDifferenceViewModel> _draftDifferencesBeforeEvaluation = [];

    public ProcessDescriptionViewModel(
        AnnotationDatabaseService? annotationStore,
        Func<AiInvestigationService?> aiServiceFactory,
        FeatureAccessService featureAccess,
        ApplicationCatalogService? applicationCatalog,
        IApplicationComparisonEvidenceService comparisonEvidenceService,
        NsrlLookupViewModel? nsrlLookupViewModel = null,
        Func<AiEvidencePackBuilder?>? aiEvidencePackBuilderFactory = null,
        Func<string, bool>? confirmReplace = null)
    {
        _annotationStore = annotationStore;
        _aiServiceFactory = aiServiceFactory;
        _aiEvidencePackBuilderFactory = aiEvidencePackBuilderFactory ?? (() => null);
        _featureAccess = featureAccess;
        _confirmReplace = confirmReplace ?? (_ => false);
        _resolutionService = new ApplicationInfoResolutionService(applicationCatalog);
        _comparisonEvidenceService = comparisonEvidenceService
            ?? throw new ArgumentNullException(nameof(comparisonEvidenceService));
        Nsrl = _featureAccess.IsPublished(FeatureIds.KnownFileReferenceData)
            ? nsrlLookupViewModel
            : null;
        SecurityAssessment = _featureAccess.IsPublished(FeatureIds.AiAssistance)
            ? new ApplicationSecurityAssessmentViewModel(
                _aiServiceFactory,
                _aiEvidencePackBuilderFactory,
                _featureAccess,
                _annotationStore,
                Nsrl)
            : null;
        _hasCatalog = applicationCatalog != null;
        Prompt = DefaultAppInfoPrompt;
    }

    public ObservableCollection<ApplicationComparisonRowViewModel> ComparisonRows { get; } = [];

    public ObservableCollection<ApplicationInfoDraftDifferenceViewModel> DraftDifferences { get; } = [];

    public ObservableCollection<AiInvestigationRecord> AppInfoGenerationHistory { get; } = [];

    public ApplicationComparisonEvidenceSource? ComparisonEvidenceSource { get; private set; }

    public NsrlLookupViewModel? Nsrl { get; }

    public ApplicationSecurityAssessmentViewModel? SecurityAssessment { get; }

    public bool IsAiAssistancePublished => _featureAccess.IsPublished(FeatureIds.AiAssistance);

    public bool IsApplicationComparisonPublished =>
        _featureAccess.IsPublished(FeatureIds.ApplicationComparison);

    public bool IsKnownFileReferenceDataPublished =>
        Nsrl != null && _featureAccess.IsPublished(FeatureIds.KnownFileReferenceData);

    [ObservableProperty]
    private bool hasProcessSelected;

    [ObservableProperty]
    private bool hasMetadata;

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private bool hasAiDraft;

    [ObservableProperty]
    private bool hasSavedOverride;

    [ObservableProperty]
    private bool hasEvaluationCandidate;

    [ObservableProperty]
    private bool isEvaluatingBundledAiDraft;

    [ObservableProperty]
    private string evaluationStatusDisplay = string.Empty;

    [ObservableProperty]
    private string catalogProvenanceDisplay = "Not recorded";

    [ObservableProperty]
    private string currentTargetDisplay = "No process selected";

    [ObservableProperty]
    private string matchStatus = "Select a process to load application metadata.";

    [ObservableProperty]
    private string displayName = string.Empty;

    [ObservableProperty]
    private string executableNamePattern = string.Empty;

    [ObservableProperty]
    private bool isRegexPattern;

    [ObservableProperty]
    private string companyVendor = string.Empty;

    [ObservableProperty]
    private string productName = string.Empty;

    [ObservableProperty]
    private string pathPattern = string.Empty;

    [ObservableProperty]
    private string packageFamilyName = string.Empty;

    [ObservableProperty]
    private string appUserModelId = string.Empty;

    [ObservableProperty]
    private string description = string.Empty;

    [ObservableProperty]
    private string applicationCategory = string.Empty;

    [ObservableProperty]
    private string expectedResponsibilities = string.Empty;

    [ObservableProperty]
    private string normalBehavior = string.Empty;

    [ObservableProperty]
    private string launchTriggers = string.Empty;

    [ObservableProperty]
    private string expectedContext = string.Empty;

    [ObservableProperty]
    private string commandLineExpectations = string.Empty;

    [ObservableProperty]
    private string filesystemRegistryExpectations = string.Empty;

    [ObservableProperty]
    private string childProcessExpectations = string.Empty;

    [ObservableProperty]
    private string networkExpectations = string.Empty;

    [ObservableProperty]
    private string normalVariants = string.Empty;

    [ObservableProperty]
    private string analystValidationChecks = string.Empty;

    [ObservableProperty]
    private string knownBenignNotes = string.Empty;

    [ObservableProperty]
    private string cybersecurityNotes = string.Empty;

    [ObservableProperty]
    private string source = "Manual";

    [ObservableProperty]
    private double confidence = 0.5;

    [ObservableProperty]
    private bool isAiGenerated;

    [ObservableProperty]
    private string providerName = string.Empty;

    [ObservableProperty]
    private string modelName = string.Empty;

    [ObservableProperty]
    private string prompt = string.Empty;

    [ObservableProperty]
    private string provenanceDisplay = string.Empty;

    [ObservableProperty]
    private string aiDraftValidationDisplay = string.Empty;

    [ObservableProperty]
    private string aiSourceClaimsDisplay = string.Empty;

    [ObservableProperty]
    private string aiUncertaintyDisplay = string.Empty;

    [ObservableProperty]
    private string reviewStateDisplay = string.Empty;

    [ObservableProperty]
    private string catalogSourcesDisplay = string.Empty;

    [ObservableProperty]
    private string profileLastReviewedDisplay = "Not recorded";

    [ObservableProperty]
    private string selectedProfileDisplay = "No profile selected";

    [ObservableProperty]
    private string profileSelectionReason = "Select a process to resolve a profile.";

    [ObservableProperty]
    private string ambiguousCandidatesDisplay = "No catalog candidates.";

    [ObservableProperty]
    private bool hasAmbiguousCandidates;

    [ObservableProperty]
    private string comparisonStatus = "Select a process to compare expected and actual values.";

    [ObservableProperty]
    private string peAvailability = "PE data has not been loaded.";

    [ObservableProperty]
    private string statusMessage = "No process selected.";

    public bool IsApplicationProfileEditable => HasProcessSelected && !IsEvaluatingBundledAiDraft;

    public bool ShowEvaluateBundledAiDraftAction =>
        IsAiAssistancePublished && HasEvaluationCandidate && !IsEvaluatingBundledAiDraft;

    public string EvaluationCandidateWarning => ApplicationInfoResolutionService.EvaluationCandidateWarning;

    public string PrivacyWarning
    {
        get
        {
            if (!_featureAccess.IsPublished(FeatureIds.AiAssistance))
            {
                return $"AI assistance is not published in educational release '{_featureAccess.Catalog.ReleaseId}'.";
            }

            var aiService = _aiServiceFactory();
            if (aiService == null)
            {
                return "AI assistance could not be activated. See the viewer status for diagnostics.";
            }

            var settings = aiService.LoadSettings();
            if (settings.IsCloudProvider)
            {
                var endpoint = string.IsNullOrWhiteSpace(settings.BaseUrl) ? "the configured endpoint" : settings.BaseUrl;
                return $"Cloud/commercial provider selected: process metadata is sent to {endpoint} only when AI Generate App Info is clicked.";
            }

            if (settings.ProviderKind == AiProviderKind.LocalOpenAiCompatible)
            {
                return "Local-first provider selected. App-info prompts stay on this host if the endpoint is local.";
            }

            return "AI is disabled. Generate App Info will report setup needed and will not send process metadata.";
        }
    }

    public void SetAnnotationStore(AnnotationDatabaseService? annotationStore)
    {
        _annotationStore = annotationStore;
        SecurityAssessment?.SetAnnotationStore(annotationStore);
        _ = LoadForProcessAsync(_selectedProcess);
    }

    public void SetWorkspace(InvestigationSessionPaths? paths, long workspaceGeneration)
    {
        ResetEvaluationForContextChange(restoreDisplayedRecord: true);
        CancelAiDraftRequest();
        Nsrl?.SetWorkspace(paths?.NsrlSettingsPath ?? string.Empty, workspaceGeneration);
    }

    public void Shutdown()
    {
        Interlocked.Exchange(ref _activeSelectionLoad, null)?.Cancel();
        CancelAiDraftRequest();
        SecurityAssessment?.Shutdown();
        Nsrl?.Shutdown();
    }

    [RelayCommand]
    public Task LoadForProcessAsync(ProcessRowViewModel? process) =>
        LoadForProcessSelectionAsync(process, CancellationToken.None);

    public async Task LoadForProcessSelectionAsync(
        ProcessRowViewModel? process,
        CancellationToken cancellationToken)
    {
        var generation = ++_selectionLoadGeneration;
        ResetEvaluationForContextChange(restoreDisplayedRecord: true);
        CancelAiDraftRequest();
        var previousLoad = Interlocked.Exchange(ref _activeSelectionLoad, null);
        previousLoad?.Cancel();
        var sameProcess = _selectedProcess != null &&
                          string.Equals(_selectedProcess.ProcessKey, process?.ProcessKey, StringComparison.Ordinal);
        var unsavedDraft = sameProcess && _isDirty ? BuildRecord() : null;
        _selectedProcess = process;
        Nsrl?.SetSelectedProcess(process?.ProcessInfo);
        SecurityAssessment?.SetContext(process, string.Empty, null);
        if (process == null)
        {
            Clear();
            return;
        }

        using var loadCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var displacedLoad = Interlocked.Exchange(ref _activeSelectionLoad, loadCancellation);
        displacedLoad?.Cancel();
        var loadToken = loadCancellation.Token;

        HasProcessSelected = true;
        CurrentTargetDisplay = $"{process.ProcessName} (PID {process.ProcessId})";
        StatusMessage = IsApplicationComparisonPublished
            ? "Loading application profile and bounded comparison evidence..."
            : "Loading application profile...";
        IsBusy = true;
        try
        {
            loadToken.ThrowIfCancellationRequested();
            var sessionOverrideTask = _annotationStore == null
                ? Task.FromResult<ApplicationMetadataRecord?>(null)
                : _annotationStore.LoadApplicationMetadataForProcessAsync(process.ProcessInfo);
            var generationHistoryTask = _annotationStore == null
                ? Task.FromResult<IReadOnlyList<AiInvestigationRecord>>([])
                : _annotationStore.LoadAiInvestigationsAsync(CreateProcessAnnotationTarget(process), 100);
            var comparisonActualTask = IsApplicationComparisonPublished
                ? _comparisonEvidenceService.LoadAsync(process.ProcessInfo, loadToken)
                : null;
            if (comparisonActualTask == null)
            {
                await Task.WhenAll(sessionOverrideTask, generationHistoryTask);
            }
            else
            {
                await Task.WhenAll(sessionOverrideTask, generationHistoryTask, comparisonActualTask);
            }

            loadToken.ThrowIfCancellationRequested();
            if (generation != _selectionLoadGeneration || !ReferenceEquals(_selectedProcess, process))
            {
                return;
            }

            var actual = comparisonActualTask?.Result;
            var lookupContext = actual?.CreateLookupContext() ??
                                ApplicationInfoResolutionService.CreateLookupContext(process.ProcessInfo);
            var resolution = _resolutionService.ResolveDetailed(
                process.ProcessInfo,
                lookupContext,
                unsavedDraft,
                sessionOverrideTask.Result);
            var evaluation = _resolutionService.ResolveEvaluationDetailed(
                process.ProcessInfo,
                lookupContext);
            var record = resolution.Record ?? CreateDraftRecord(process);
            _comparisonCatalogProfile = resolution.CatalogProfile;
            _comparisonCandidates = resolution.Candidates;
            _comparisonActual = actual;
            Nsrl?.SetSelectedProcess(process.ProcessInfo, actual?.ProcessImageFileSizeBytes);
            _comparisonSelectionReason = resolution.SelectionReason;
            SetEvaluationAvailability(evaluation);
            _matchReason = string.IsNullOrWhiteSpace(record.MatchReason)
                ? resolution.SelectionReason
                : record.MatchReason;
            record.MatchReason = _matchReason;
            LoadRecord(record, metadataExists: resolution.Record != null);
            HasSavedOverride = sessionOverrideTask.Result != null;
            HasAiDraft = record.ReviewState == ApplicationProfileReviewState.AiDraft &&
                         record.RecordOrigin == ApplicationProfileOrigin.UnsavedDraft;
            _resolvedRecordBeforeAiDraft = HasAiDraft ? null : CloneRecord(record);
            DraftDifferences.Clear();
            AppInfoGenerationHistory.Clear();
            foreach (var historyRecord in generationHistoryTask.Result.Where(historyRecord => string.Equals(
                         historyRecord.PromptTemplateId,
                         AiPromptCatalog.AppInfoDraftTemplateId,
                         StringComparison.Ordinal)))
            {
                AppInfoGenerationHistory.Add(historyRecord);
            }
            _isDirty = resolution.Record?.RecordOrigin == ApplicationProfileOrigin.UnsavedDraft;
            RebuildComparison();
            UpdateSecurityAssessmentContext();
            StatusMessage = resolution.Record?.RecordOrigin switch
            {
                ApplicationProfileOrigin.UnsavedDraft => "Kept the unsaved in-memory draft for this process.",
                ApplicationProfileOrigin.SessionAnalystOverride or ApplicationProfileOrigin.SessionAiOverride or ApplicationProfileOrigin.LegacySessionMetadata
                    => IsApplicationComparisonPublished
                        ? $"Loaded session metadata from {record.ProvenanceDisplay} and derived a non-persisted comparison."
                        : $"Loaded session metadata from {record.ProvenanceDisplay}.",
                ApplicationProfileOrigin.BuiltInCatalog
                    => IsApplicationComparisonPublished
                        ? "Loaded a read-only built-in profile and derived a non-persisted comparison. Editing and saving creates only a session override."
                        : "Loaded a read-only built-in profile. Editing and saving creates only a session override.",
                _ when !_hasCatalog
                    => "Built-in application catalog is unavailable. Using an editable unsaved draft.",
                _ => "No session override or built-in profile matched. Edit and save, or generate an AI draft."
            };
        }
        catch (OperationCanceledException) when (
            generation != _selectionLoadGeneration || !ReferenceEquals(_selectedProcess, process))
        {
            return;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            if (generation != _selectionLoadGeneration || !ReferenceEquals(_selectedProcess, process))
            {
                return;
            }

            LoadRecord(CreateDraftRecord(process), metadataExists: false);
            HasSavedOverride = false;
            HasAiDraft = false;
            _resolvedRecordBeforeAiDraft = CloneRecord(BuildRecord());
            DraftDifferences.Clear();
            AppInfoGenerationHistory.Clear();
            _comparisonCatalogProfile = null;
            _comparisonCandidates = [];
            _comparisonActual = null;
            _comparisonSelectionReason = string.Empty;
            ResetEvaluationAvailability();
            ClearComparison($"Comparison unavailable because App Info loading failed safely: {ex.Message}");
            UpdateSecurityAssessmentContext();
            StatusMessage = $"Failed to load app metadata: {ex.Message}";
        }
        finally
        {
            Interlocked.CompareExchange(ref _activeSelectionLoad, null, loadCancellation);
            if (generation == _selectionLoadGeneration && ReferenceEquals(_selectedProcess, process))
            {
                IsBusy = false;
                NotifyCommandState();
            }
        }
    }

    [RelayCommand(CanExecute = nameof(CanEvaluateBundledAiDraft))]
    public void EvaluateBundledAiDraft()
    {
        if (!_featureAccess.TryAccess(FeatureIds.AiAssistance, out var unavailableMessage))
        {
            StatusMessage = unavailableMessage;
            return;
        }

        var evaluation = _evaluationResolution;
        if (!CanEvaluateBundledAiDraft() ||
            _selectedProcess == null ||
            evaluation?.Record == null ||
            evaluation.CatalogProfile == null)
        {
            StatusMessage = "No unambiguous bundled AI draft is available for this process.";
            return;
        }

        _recordBeforeEvaluation = CaptureDisplayedRecord();
        _metadataExistsBeforeEvaluation = HasMetadata;
        _isDirtyBeforeEvaluation = _isDirty;
        _hasAiDraftBeforeEvaluation = HasAiDraft;
        _comparisonCatalogProfileBeforeEvaluation = _comparisonCatalogProfile;
        _comparisonCandidatesBeforeEvaluation = _comparisonCandidates;
        _comparisonSelectionReasonBeforeEvaluation = _comparisonSelectionReason;
        _matchReasonBeforeEvaluation = _matchReason;
        _statusMessageBeforeEvaluation = StatusMessage;
        _draftDifferencesBeforeEvaluation = DraftDifferences.ToList();

        IsEvaluatingBundledAiDraft = true;
        HasAiDraft = false;
        DraftDifferences.Clear();
        _comparisonCatalogProfile = evaluation.CatalogProfile;
        _comparisonCandidates = evaluation.Candidates;
        _comparisonSelectionReason = evaluation.SelectionReason;
        _matchReason = string.IsNullOrWhiteSpace(evaluation.Record.MatchReason)
            ? evaluation.SelectionReason
            : evaluation.Record.MatchReason;
        evaluation.Record.MatchReason = _matchReason;
        LoadRecord(CloneRecord(evaluation.Record), metadataExists: true);
        _isDirty = false;
        RebuildComparison();
        UpdateSecurityAssessmentContext();
        StatusMessage = $"Evaluating bundled AI draft '{evaluation.CatalogProfile.DisplayName}'. It is unreviewed, read-only, and not a benign verdict.";
        NotifyCommandState();
    }

    [RelayCommand(CanExecute = nameof(CanReturnToNormalProfile))]
    public void ReturnToNormalProfile()
    {
        if (!RestoreRecordBeforeEvaluation())
        {
            StatusMessage = "No normal App Info profile is available to restore.";
            return;
        }

        StatusMessage = "Returned to the normal App Info profile. The bundled AI draft was not saved.";
    }

    [RelayCommand(CanExecute = nameof(CanSaveMetadata))]
    public async Task SaveMetadataAsync()
    {
        if (IsEvaluatingBundledAiDraft)
        {
            StatusMessage = "Bundled AI draft evaluation is read-only. Return to the normal profile before saving.";
            return;
        }

        if (HasSavedOverride)
        {
            StatusMessage = "A saved session override already exists. Use Replace saved override so the replacement is explicit and confirmed.";
            return;
        }

        await PersistMetadataAsync("Saved a new session App Info override");
    }

    [RelayCommand(CanExecute = nameof(CanReplaceSavedOverride))]
    public async Task ReplaceSavedOverrideAsync()
    {
        if (IsEvaluatingBundledAiDraft)
        {
            StatusMessage = "Bundled AI draft evaluation is read-only. Return to the normal profile before replacing an override.";
            return;
        }

        if (!_confirmReplace("Replace the existing session App Info override with the currently reviewed draft? The shipped catalog will not be changed."))
        {
            StatusMessage = "Replace saved override canceled. The existing saved profile was not changed.";
            return;
        }

        await PersistMetadataAsync("Replaced the saved session App Info override");
    }

    [RelayCommand(CanExecute = nameof(CanDiscardAiDraft))]
    public void DiscardAiDraft()
    {
        if (!_featureAccess.TryAccess(FeatureIds.AiAssistance, out var unavailableMessage))
        {
            StatusMessage = unavailableMessage;
            return;
        }

        if (_resolvedRecordBeforeAiDraft == null)
        {
            StatusMessage = "No resolved saved or built-in profile is available to restore.";
            return;
        }

        CancelAiDraftRequest();
        var restored = CloneRecord(_resolvedRecordBeforeAiDraft);
        LoadRecord(restored, metadataExists: restored.RecordOrigin != ApplicationProfileOrigin.UnsavedDraft);
        HasAiDraft = false;
        DraftDifferences.Clear();
        AiDraftValidationDisplay = string.Empty;
        AiSourceClaimsDisplay = string.Empty;
        AiUncertaintyDisplay = string.Empty;
        _isDirty = restored.RecordOrigin == ApplicationProfileOrigin.UnsavedDraft;
        RebuildComparison();
        UpdateSecurityAssessmentContext();
        StatusMessage = "Discarded the AI draft and restored the previously resolved saved/built-in profile.";
        NotifyCommandState();
    }

    private async Task PersistMetadataAsync(string successPrefix)
    {
        if (_annotationStore == null)
        {
            StatusMessage = "Annotation database is unavailable.";
            return;
        }

        try
        {
            IsBusy = true;
            var record = BuildRecord();
            await _annotationStore.SaveApplicationMetadataAsync(record);
            LoadRecord(record, metadataExists: true);
            HasSavedOverride = true;
            HasAiDraft = false;
            _resolvedRecordBeforeAiDraft = CloneRecord(record);
            DraftDifferences.Clear();
            _isDirty = false;
            RebuildComparison();
            UpdateSecurityAssessmentContext();
            StatusMessage = $"{successPrefix} for {CurrentTargetDisplay}. The shipped catalog was unchanged.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to save app metadata: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            NotifyCommandState();
        }
    }

    [RelayCommand(CanExecute = nameof(CanGenerateAppInfo))]
    public async Task GenerateAppInfoAsync()
    {
        if (IsEvaluatingBundledAiDraft)
        {
            StatusMessage = "Return to the normal profile before starting the separate AI generation workflow.";
            return;
        }

        if (!_featureAccess.TryAccess(FeatureIds.AiAssistance, out var unavailableMessage))
        {
            StatusMessage = unavailableMessage;
            return;
        }

        if (_selectedProcess == null)
        {
            StatusMessage = "Select a process before generating app info.";
            return;
        }

        if (_annotationStore == null)
        {
            StatusMessage = "Annotation database is unavailable; AI draft provenance/history cannot be persisted.";
            return;
        }

        var aiService = _aiServiceFactory();
        if (aiService == null)
        {
            StatusMessage = "AI assistance could not be activated. See the viewer status for diagnostics.";
            return;
        }

        var process = _selectedProcess;
        var generation = Interlocked.Increment(ref _aiDraftGeneration);
        var cancellation = new CancellationTokenSource();
        var previous = Interlocked.Exchange(ref _activeAiDraftRequest, cancellation);
        previous?.Cancel();
        previous?.Dispose();
        var recordBeforeRequest = CloneRecord(BuildRecord());
        try
        {
            IsBusy = true;
            StatusMessage = "Generating a bounded structured App Info draft. Nothing will be saved automatically.";
            var settings = aiService.LoadSettings();
            var template = new AiPromptCatalog().GetAppInfoDraftTemplate();
            var request = new AiInvestigationRequest
            {
                SourceScope = BuildAppInfoDraftScope(process),
                PromptTemplate = template,
                AnalystPromptSuffix = Prompt,
                EvidenceText = BuildAppInfoDraftEvidence(process, recordBeforeRequest),
                Settings = settings
            };
            var historyRecord = await aiService.RunInvestigationAsync(request, cancellation.Token);
            if (!IsCurrentAiDraftRequest(generation, process, cancellation))
            {
                return;
            }

            ApplicationInfoAiDraftParseResult? parsed = null;
            if (historyRecord.Status == AiInvestigationStatus.Succeeded)
            {
                parsed = ApplicationInfoAiResponseParser.ParseDraft(historyRecord.ResponseText);
                if (!parsed.Success)
                {
                    historyRecord.Status = AiInvestigationStatus.Failed;
                    historyRecord.ErrorText = parsed.Error;
                }
            }

            await _annotationStore.SaveAiInvestigationAsync(historyRecord);
            if (!IsCurrentAiDraftRequest(generation, process, cancellation))
            {
                return;
            }

            AppInfoGenerationHistory.Insert(0, historyRecord);
            if (historyRecord.Status != AiInvestigationStatus.Succeeded || parsed?.Draft == null)
            {
                StatusMessage = $"AI App Info draft was not applied: {historyRecord.ErrorText}";
                return;
            }

            var discardBaseline = ResolveDiscardBaseline(recordBeforeRequest);
            _resolvedRecordBeforeAiDraft = CloneRecord(discardBaseline);
            ApplyAiDraft(parsed.Draft, historyRecord, recordBeforeRequest, discardBaseline);
            StatusMessage = parsed.Draft.IsFreeTextFallback
                ? "Provider returned free text. A bounded low-confidence AI Draft was loaded for review; nothing was saved."
                : "Structured AI Draft loaded with a field-level diff. Review, then Save/Replace explicitly or Discard.";
        }
        catch (OperationCanceledException)
        {
            if (IsCurrentAiDraftRequest(generation, process, cancellation))
            {
                StatusMessage = "AI App Info generation canceled; saved metadata and current edits were preserved.";
            }
        }
        catch (Exception ex)
        {
            if (IsCurrentAiDraftRequest(generation, process, cancellation))
            {
                StatusMessage = $"AI App Info draft failed safely: {ex.Message}. Saved metadata and current edits were preserved.";
            }
        }
        finally
        {
            if (ReferenceEquals(Interlocked.CompareExchange(ref _activeAiDraftRequest, null, cancellation), cancellation))
            {
                cancellation.Dispose();
            }
            if (generation == Volatile.Read(ref _aiDraftGeneration) && ReferenceEquals(_selectedProcess, process))
            {
                IsBusy = false;
                NotifyCommandState();
            }
        }
    }

    public void Clear()
    {
        _selectionLoadGeneration++;
        ResetEvaluationForContextChange(restoreDisplayedRecord: false);
        Interlocked.Exchange(ref _activeSelectionLoad, null)?.Cancel();
        CancelAiDraftRequest();
        _selectedProcess = null;
        Nsrl?.SetSelectedProcess(null);
        SecurityAssessment?.SetContext(null, string.Empty, null);
        IsBusy = false;
        _applicationId = string.Empty;
        _isLoading = true;
        try
        {
            HasProcessSelected = false;
            HasMetadata = false;
            CurrentTargetDisplay = "No process selected";
            MatchStatus = "Select a process to load application metadata.";
            DisplayName = string.Empty;
            ExecutableNamePattern = string.Empty;
            IsRegexPattern = false;
            CompanyVendor = string.Empty;
            ProductName = string.Empty;
            PathPattern = string.Empty;
            PackageFamilyName = string.Empty;
            AppUserModelId = string.Empty;
            Description = string.Empty;
            ApplicationCategory = string.Empty;
            ExpectedResponsibilities = string.Empty;
            NormalBehavior = string.Empty;
            LaunchTriggers = string.Empty;
            ExpectedContext = string.Empty;
            CommandLineExpectations = string.Empty;
            FilesystemRegistryExpectations = string.Empty;
            ChildProcessExpectations = string.Empty;
            NetworkExpectations = string.Empty;
            NormalVariants = string.Empty;
            AnalystValidationChecks = string.Empty;
            KnownBenignNotes = string.Empty;
            CybersecurityNotes = string.Empty;
            Source = "Manual";
            Confidence = 0.5;
            IsAiGenerated = false;
            ProviderName = string.Empty;
            ModelName = string.Empty;
            Prompt = DefaultAppInfoPrompt;
            ProvenanceDisplay = string.Empty;
            AiDraftValidationDisplay = string.Empty;
            AiSourceClaimsDisplay = string.Empty;
            AiUncertaintyDisplay = string.Empty;
            ReviewStateDisplay = string.Empty;
            CatalogSourcesDisplay = string.Empty;
            ProfileLastReviewedDisplay = "Not recorded";
            StatusMessage = "No process selected.";
            _baseProfileId = string.Empty;
            _baseProfileRevision = string.Empty;
            _baseCatalogRevision = string.Empty;
            _sourceReferences = [];
            _catalogProvenance = string.Empty;
            _profileLastReviewedUtc = null;
            _createdUtc = default;
            _recordOrigin = ApplicationProfileOrigin.UnsavedDraft;
            _currentAiProviderKind = AiProviderKind.Disabled;
            _currentAiEndpointMode = string.Empty;
            _currentAiPromptTemplateId = string.Empty;
            _currentAiRequestedUtc = null;
            _currentAiSourceClaimsUnverified = false;
            _displayedReviewState = ApplicationProfileReviewState.Unreviewed;
            _displayedReviewedUtc = null;
            CatalogProvenanceDisplay = "Not recorded";
            _comparisonCatalogProfile = null;
            _comparisonCandidates = [];
            _comparisonActual = null;
            _comparisonSelectionReason = string.Empty;
            _matchReason = string.Empty;
            HasAiDraft = false;
            HasSavedOverride = false;
            _resolvedRecordBeforeAiDraft = null;
            DraftDifferences.Clear();
            AppInfoGenerationHistory.Clear();
            _isDirty = false;
            ClearComparison("Select a process to compare expected and actual values.");
        }
        finally
        {
            _isLoading = false;
            NotifyCommandState();
        }
    }

    partial void OnIsBusyChanged(bool value) => NotifyCommandState();

    partial void OnHasProcessSelectedChanged(bool value)
    {
        OnPropertyChanged(nameof(IsApplicationProfileEditable));
        NotifyCommandState();
    }

    partial void OnHasAiDraftChanged(bool value) => NotifyCommandState();

    partial void OnHasSavedOverrideChanged(bool value) => NotifyCommandState();

    partial void OnHasEvaluationCandidateChanged(bool value)
    {
        OnPropertyChanged(nameof(ShowEvaluateBundledAiDraftAction));
        NotifyCommandState();
    }

    partial void OnIsEvaluatingBundledAiDraftChanged(bool value)
    {
        OnPropertyChanged(nameof(IsApplicationProfileEditable));
        OnPropertyChanged(nameof(ShowEvaluateBundledAiDraftAction));
        NotifyCommandState();
    }

    partial void OnPromptChanged(string value)
    {
        if (!_isLoading)
        {
            _isDirty = true;
            GenerateAppInfoCommand.NotifyCanExecuteChanged();
        }
    }

    partial void OnExecutableNamePatternChanged(string value)
    {
        if (!_isLoading)
        {
            _isDirty = true;
            SaveMetadataCommand.NotifyCanExecuteChanged();
            RebuildComparison();
        }
    }

    partial void OnDisplayNameChanged(string value) => MarkDraftDirty();
    partial void OnIsRegexPatternChanged(bool value) => MarkDraftDirty();
    partial void OnCompanyVendorChanged(string value) => MarkDraftDirty();
    partial void OnProductNameChanged(string value) => MarkDraftDirty();
    partial void OnPathPatternChanged(string value) => MarkDraftDirty();
    partial void OnPackageFamilyNameChanged(string value) => MarkDraftDirty();
    partial void OnAppUserModelIdChanged(string value) => MarkDraftDirty();
    partial void OnDescriptionChanged(string value) => MarkDraftDirty();
    partial void OnApplicationCategoryChanged(string value) => MarkDraftDirty();
    partial void OnExpectedResponsibilitiesChanged(string value) => MarkDraftDirty();
    partial void OnNormalBehaviorChanged(string value) => MarkDraftDirty();
    partial void OnLaunchTriggersChanged(string value) => MarkDraftDirty();
    partial void OnExpectedContextChanged(string value) => MarkDraftDirty();
    partial void OnCommandLineExpectationsChanged(string value) => MarkDraftDirty();
    partial void OnFilesystemRegistryExpectationsChanged(string value) => MarkDraftDirty();
    partial void OnChildProcessExpectationsChanged(string value) => MarkDraftDirty();
    partial void OnNetworkExpectationsChanged(string value) => MarkDraftDirty();
    partial void OnNormalVariantsChanged(string value) => MarkDraftDirty();
    partial void OnAnalystValidationChecksChanged(string value) => MarkDraftDirty();
    partial void OnKnownBenignNotesChanged(string value) => MarkDraftDirty();
    partial void OnCybersecurityNotesChanged(string value) => MarkDraftDirty();
    partial void OnSourceChanged(string value) => MarkDraftDirty();
    partial void OnConfidenceChanged(double value) => MarkDraftDirty();

    private void LoadRecord(ApplicationMetadataRecord record, bool metadataExists)
    {
        _isLoading = true;
        try
        {
            _applicationId = record.ApplicationId;
            HasMetadata = metadataExists;
            DisplayName = record.DisplayName;
            ExecutableNamePattern = record.ExecutableNamePattern;
            IsRegexPattern = record.IsRegexPattern;
            CompanyVendor = record.CompanyVendor;
            ProductName = record.ProductName;
            PathPattern = record.PathPattern;
            PackageFamilyName = record.PackageFamilyName;
            AppUserModelId = record.AppUserModelId;
            _baseProfileId = record.BaseProfileId;
            _baseProfileRevision = record.BaseProfileRevision;
            _baseCatalogRevision = record.BaseCatalogRevision;
            _sourceReferences = record.SourceReferences.Select(source => new ApplicationProfileSourceReference
            {
                Title = source.Title,
                Publisher = source.Publisher,
                Uri = source.Uri,
                RetrievedUtc = source.RetrievedUtc,
                SupportingNote = source.SupportingNote
            }).ToList();
            _catalogProvenance = record.CatalogProvenance;
            _profileLastReviewedUtc = record.ProfileLastReviewedUtc;
            _createdUtc = record.CreatedUtc;
            _recordOrigin = record.RecordOrigin;
            _matchReason = record.MatchReason;
            _currentAiProviderKind = record.AiProviderKind;
            _currentAiEndpointMode = record.AiEndpointMode;
            _currentAiPromptTemplateId = record.AiPromptTemplateId;
            _currentAiRequestedUtc = record.AiRequestedUtc;
            _currentAiSourceClaimsUnverified = record.AiSourceClaimsUnverified;
            _displayedReviewState = record.ReviewState;
            _displayedReviewedUtc = record.ReviewedUtc;
            Description = record.Description;
            ApplicationCategory = record.ApplicationCategory;
            ExpectedResponsibilities = record.ExpectedResponsibilities;
            NormalBehavior = record.NormalBehavior;
            LaunchTriggers = record.LaunchTriggers;
            ExpectedContext = record.ExpectedContext;
            CommandLineExpectations = record.CommandLineExpectations;
            FilesystemRegistryExpectations = record.FilesystemRegistryExpectations;
            ChildProcessExpectations = record.ChildProcessExpectations;
            NetworkExpectations = record.NetworkExpectations;
            NormalVariants = record.NormalVariants;
            AnalystValidationChecks = record.AnalystValidationChecks;
            KnownBenignNotes = record.KnownBenignNotes;
            CybersecurityNotes = record.CybersecurityNotes;
            Source = string.IsNullOrWhiteSpace(record.Source) ? "Manual" : record.Source;
            Confidence = Math.Clamp(record.Confidence <= 0 ? 0.5 : record.Confidence, 0, 1);
            IsAiGenerated = record.IsAiGenerated;
            ProviderName = record.ProviderName;
            ModelName = record.ModelName;
            Prompt = string.IsNullOrWhiteSpace(record.Prompt) ? DefaultAppInfoPrompt : record.Prompt;
            ProvenanceDisplay = record.ProvenanceDisplay;
            CatalogProvenanceDisplay = string.IsNullOrWhiteSpace(record.CatalogProvenance)
                ? "Not recorded"
                : record.CatalogProvenance;
            AiDraftValidationDisplay = record.AiValidationWarnings;
            AiUncertaintyDisplay = record.AiUncertainty;
            AiSourceClaimsDisplay = FormatAiSourceClaims(record);
            ReviewStateDisplay = FormatReviewState(record);
            CatalogSourcesDisplay = FormatSources(record.SourceReferences);
            ProfileLastReviewedDisplay = record.ProfileLastReviewedUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                ?? "Not recorded";
            MatchStatus = metadataExists
                ? $"Matched by {record.MatchReason}."
                : "Draft metadata initialized from selected process fields.";
            OnPropertyChanged(nameof(PrivacyWarning));
        }
        finally
        {
            _isLoading = false;
        }
    }

    private ApplicationMetadataRecord BuildRecord()
    {
        return new ApplicationMetadataRecord
        {
            ApplicationId = string.IsNullOrWhiteSpace(_applicationId) ? Guid.NewGuid().ToString("N") : _applicationId,
            DisplayName = DisplayName.Trim(),
            ExecutableNamePattern = ExecutableNamePattern.Trim(),
            IsRegexPattern = IsRegexPattern,
            PackageFamilyName = PackageFamilyName.Trim(),
            AppUserModelId = AppUserModelId.Trim(),
            BaseProfileId = _baseProfileId,
            BaseProfileRevision = _baseProfileRevision,
            BaseCatalogRevision = _baseCatalogRevision,
            RecordOrigin = IsAiGenerated
                ? ApplicationProfileOrigin.SessionAiOverride
                : ApplicationProfileOrigin.SessionAnalystOverride,
            ReviewState = IsAiGenerated
                ? ApplicationProfileReviewState.AiDraft
                : ApplicationProfileReviewState.AnalystReviewed,
            PathPattern = PathPattern.Trim(),
            CompanyVendor = CompanyVendor.Trim(),
            ProductName = ProductName.Trim(),
            Description = Description.Trim(),
            ApplicationCategory = ApplicationCategory.Trim(),
            ExpectedResponsibilities = ExpectedResponsibilities.Trim(),
            NormalBehavior = NormalBehavior.Trim(),
            LaunchTriggers = LaunchTriggers.Trim(),
            ExpectedContext = ExpectedContext.Trim(),
            CommandLineExpectations = CommandLineExpectations.Trim(),
            FilesystemRegistryExpectations = FilesystemRegistryExpectations.Trim(),
            ChildProcessExpectations = ChildProcessExpectations.Trim(),
            NetworkExpectations = NetworkExpectations.Trim(),
            NormalVariants = NormalVariants.Trim(),
            AnalystValidationChecks = AnalystValidationChecks.Trim(),
            KnownBenignNotes = KnownBenignNotes.Trim(),
            CybersecurityNotes = CybersecurityNotes.Trim(),
            Source = string.IsNullOrWhiteSpace(Source) ? "Manual" : Source.Trim(),
            Confidence = Math.Clamp(Confidence, 0, 1),
            IsAiGenerated = IsAiGenerated,
            ProviderName = ProviderName.Trim(),
            ModelName = ModelName.Trim(),
            Prompt = Prompt.Trim(),
            AiProviderKind = IsAiGenerated ? _currentAiProviderKind : AiProviderKind.Disabled,
            AiEndpointMode = IsAiGenerated ? _currentAiEndpointMode : string.Empty,
            AiPromptTemplateId = IsAiGenerated ? _currentAiPromptTemplateId : string.Empty,
            AiRequestedUtc = IsAiGenerated ? _currentAiRequestedUtc : null,
            AiUncertainty = IsAiGenerated ? AiUncertaintyDisplay.Trim() : string.Empty,
            AiValidationWarnings = IsAiGenerated ? AiDraftValidationDisplay.Trim() : string.Empty,
            AiSourceClaimsUnverified = IsAiGenerated && _currentAiSourceClaimsUnverified,
            SourceReferences = _sourceReferences.Select(source => new ApplicationProfileSourceReference
            {
                Title = source.Title,
                Publisher = source.Publisher,
                Uri = source.Uri,
                RetrievedUtc = source.RetrievedUtc,
                SupportingNote = source.SupportingNote
            }).ToList(),
            CatalogProvenance = _catalogProvenance,
            ProfileLastReviewedUtc = _profileLastReviewedUtc,
            ReviewedUtc = IsAiGenerated ? null : DateTime.UtcNow,
            CreatedUtc = _createdUtc == default ? DateTime.UtcNow : _createdUtc,
            UpdatedUtc = DateTime.UtcNow,
            MatchReason = _matchReason
        };
    }

    private ApplicationMetadataRecord CreateDraftRecord(ProcessRowViewModel process)
    {
        var info = process.ProcessInfo;
        var executableName = GetExecutableName(process);
        return new ApplicationMetadataRecord
        {
            ApplicationId = Guid.NewGuid().ToString("N"),
            DisplayName = process.ProcessName,
            ExecutableNamePattern = executableName,
            IsRegexPattern = false,
            CompanyVendor = CleanMetadataValue(info.CompanyName),
            ProductName = CleanMetadataValue(info.FileDescription),
            PathPattern = CleanPathPattern(info.ProcessPath),
            Source = "Manual",
            Confidence = 0.5,
            Prompt = DefaultAppInfoPrompt,
            RecordOrigin = ApplicationProfileOrigin.UnsavedDraft,
            ReviewState = ApplicationProfileReviewState.Unreviewed
        };
    }

    private static string BuildAppInfoDraftEvidence(
        ProcessRowViewModel process,
        ApplicationMetadataRecord resolved)
    {
        var info = process.ProcessInfo;
        return $"""
            ## Resolved reference profile before generation
            Classification: reusable reference knowledge; it is not source-native evidence and not a benign verdict.
            Display name: {resolved.DisplayName}
            Executable matcher: {resolved.ExecutableNamePattern}
            Role summary: {resolved.Description}
            Category: {resolved.ApplicationCategory}
            Expected responsibilities: {resolved.ExpectedResponsibilities}
            Normal behavior: {resolved.NormalBehavior}
            Launch triggers: {resolved.LaunchTriggers}
            Typical context: {resolved.ExpectedContext}
            Command line expectations: {resolved.CommandLineExpectations}
            Filesystem/registry expectations: {resolved.FilesystemRegistryExpectations}
            Child process expectations: {resolved.ChildProcessExpectations}
            Network expectations: {resolved.NetworkExpectations}
            Variants/caveats: {resolved.NormalVariants}
            Abuse/masquerading: {resolved.CybersecurityNotes}
            Analyst checks: {resolved.AnalystValidationChecks}
            Existing sources: {FormatSources(resolved.SourceReferences)}

            ## Selected-process lookup/context hints
            Classification: observed hints only. None of these values proves what is expected; do not copy an observed anomaly into an expected field merely because it appears here.
            Process name: {process.ProcessName}
            Image path hint: {process.ProcessPath}
            Parent hint: {info.ParentProcessName}
            Account/session hint: {info.UserName}; session {info.SessionId}
            Command-line hint: {info.CommandLine}
            Company/file-description hints: {info.CompanyName}; {info.FileDescription}
            SHA-256 lookup hint: {info.Sha256Hash}
            Process status hint: {info.Status}
            """;
    }

    private static AiSourceScope BuildAppInfoDraftScope(ProcessRowViewModel row) => new()
    {
        ScopeKind = "AppInfoStructuredDraft",
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
        Summary = "Resolved App Info reference profile plus selected-process lookup/context hints; observed hints are not expected facts."
    };

    private void ApplyAiDraft(
        ApplicationInfoAiDraft draft,
        AiInvestigationRecord historyRecord,
        ApplicationMetadataRecord currentBeforeRequest,
        ApplicationMetadataRecord resolvedBaseline)
    {
        var draftRecord = CloneRecord(currentBeforeRequest);
        draftRecord.RecordOrigin = ApplicationProfileOrigin.UnsavedDraft;
        draftRecord.ReviewState = ApplicationProfileReviewState.AiDraft;
        draftRecord.Description = draft.RoleSummary;
        draftRecord.ApplicationCategory = draft.ApplicationCategory;
        draftRecord.ExpectedResponsibilities = draft.ExpectedResponsibilities;
        draftRecord.NormalBehavior = draft.NormalBehavior;
        draftRecord.LaunchTriggers = draft.LaunchTriggers;
        draftRecord.ExpectedContext = draft.ExpectedContext;
        draftRecord.CommandLineExpectations = draft.CommandLineExpectations;
        draftRecord.FilesystemRegistryExpectations = draft.FilesystemRegistryExpectations;
        draftRecord.ChildProcessExpectations = draft.ChildProcessExpectations;
        draftRecord.NetworkExpectations = draft.NetworkExpectations;
        draftRecord.NormalVariants = draft.NormalVariants;
        draftRecord.CybersecurityNotes = draft.CommonAbuseAndMasquerading;
        draftRecord.AnalystValidationChecks = draft.AnalystValidationChecks;
        draftRecord.Source = "AI Draft (unreviewed)";
        draftRecord.Confidence = draft.Confidence;
        draftRecord.IsAiGenerated = true;
        draftRecord.ProviderName = historyRecord.ProviderName;
        draftRecord.ModelName = historyRecord.ModelName;
        draftRecord.Prompt = DefaultAppInfoPrompt;
        draftRecord.SourceReferences = draft.ClaimedSources.Select(source => new ApplicationProfileSourceReference
        {
            Title = source.Title,
            Publisher = source.Publisher,
            Uri = source.Uri
        }).ToList();
        draftRecord.AiProviderKind = historyRecord.ProviderKind;
        draftRecord.AiEndpointMode = historyRecord.ProviderKind switch
        {
            AiProviderKind.LocalOpenAiCompatible => "Local OpenAI-compatible",
            AiProviderKind.CommercialOpenAiCompatible => "Commercial/cloud OpenAI-compatible",
            _ => "Disabled"
        };
        draftRecord.AiPromptTemplateId = historyRecord.PromptTemplateId;
        draftRecord.AiRequestedUtc = historyRecord.RequestedUtc;
        draftRecord.AiUncertainty = draft.Uncertainty;
        draftRecord.AiValidationWarnings = string.Join(Environment.NewLine, draft.ValidationWarnings.Select(warning => $"- {warning}"));
        draftRecord.AiSourceClaimsUnverified = true;

        BuildDraftDifferences(resolvedBaseline, draftRecord);
        LoadRecord(draftRecord, metadataExists: true);
        HasAiDraft = true;
        _isDirty = true;
        RebuildComparison();
        UpdateSecurityAssessmentContext();
        NotifyCommandState();
    }

    private void BuildDraftDifferences(
        ApplicationMetadataRecord resolved,
        ApplicationMetadataRecord draft)
    {
        DraftDifferences.Clear();
        AddDifference("Role summary", resolved.Description, draft.Description);
        AddDifference("Application category", resolved.ApplicationCategory, draft.ApplicationCategory);
        AddDifference("Expected responsibilities", resolved.ExpectedResponsibilities, draft.ExpectedResponsibilities);
        AddDifference("Normal behavior", resolved.NormalBehavior, draft.NormalBehavior);
        AddDifference("Launch triggers", resolved.LaunchTriggers, draft.LaunchTriggers);
        AddDifference("Typical context", resolved.ExpectedContext, draft.ExpectedContext);
        AddDifference("Command line", resolved.CommandLineExpectations, draft.CommandLineExpectations);
        AddDifference("Filesystem / registry", resolved.FilesystemRegistryExpectations, draft.FilesystemRegistryExpectations);
        AddDifference("Child processes", resolved.ChildProcessExpectations, draft.ChildProcessExpectations);
        AddDifference("Network", resolved.NetworkExpectations, draft.NetworkExpectations);
        AddDifference("Variants / caveats", resolved.NormalVariants, draft.NormalVariants);
        AddDifference("Abuse / masquerading", resolved.CybersecurityNotes, draft.CybersecurityNotes);
        AddDifference("Analyst validation checks", resolved.AnalystValidationChecks, draft.AnalystValidationChecks);
        AddDifference("Uncertainty", resolved.AiUncertainty, draft.AiUncertainty);
        AddDifference("Confidence", resolved.Confidence.ToString("F2"), draft.Confidence.ToString("F2"));
        AddDifference("Claimed sources", FormatSources(resolved.SourceReferences), FormatSources(draft.SourceReferences));
    }

    private void AddDifference(string field, string resolved, string draft)
    {
        DraftDifferences.Add(new ApplicationInfoDraftDifferenceViewModel
        {
            FieldName = field,
            ResolvedValue = string.IsNullOrWhiteSpace(resolved) ? "<empty>" : resolved,
            DraftValue = string.IsNullOrWhiteSpace(draft) ? "<empty>" : draft,
            IsChanged = !string.Equals(
                NormalizeDifferenceValue(resolved),
                NormalizeDifferenceValue(draft),
                StringComparison.Ordinal)
        });
    }

    private static string NormalizeDifferenceValue(string value)
        => string.Join(" ", (value ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private bool CanSaveMetadata()
        => HasProcessSelected &&
           !HasSavedOverride &&
           !IsBusy &&
           !IsEvaluatingBundledAiDraft &&
           !string.IsNullOrWhiteSpace(ExecutableNamePattern);

    private bool CanReplaceSavedOverride()
        => HasProcessSelected &&
           HasSavedOverride &&
           !IsBusy &&
           !IsEvaluatingBundledAiDraft &&
           !string.IsNullOrWhiteSpace(ExecutableNamePattern);

    private bool CanDiscardAiDraft()
        => _featureAccess.CanExecute(
            FeatureIds.AiAssistance,
            HasProcessSelected &&
            HasAiDraft &&
            !IsBusy &&
            !IsEvaluatingBundledAiDraft &&
            _resolvedRecordBeforeAiDraft != null);

    private bool CanGenerateAppInfo()
        => _featureAccess.CanExecute(
            FeatureIds.AiAssistance,
            HasProcessSelected &&
            !IsBusy &&
            !IsEvaluatingBundledAiDraft &&
            !string.IsNullOrWhiteSpace(Prompt));

    private bool CanEvaluateBundledAiDraft()
        => _featureAccess.CanExecute(
            FeatureIds.AiAssistance,
            HasProcessSelected &&
            HasEvaluationCandidate &&
            !IsBusy &&
            !IsEvaluatingBundledAiDraft &&
            _evaluationResolution?.Record != null);

    private bool CanReturnToNormalProfile()
        => _featureAccess.CanExecute(
            FeatureIds.AiAssistance,
            HasProcessSelected &&
            IsEvaluatingBundledAiDraft &&
            !IsBusy &&
            _recordBeforeEvaluation != null);

    private void NotifyCommandState()
    {
        SaveMetadataCommand.NotifyCanExecuteChanged();
        ReplaceSavedOverrideCommand.NotifyCanExecuteChanged();
        DiscardAiDraftCommand.NotifyCanExecuteChanged();
        GenerateAppInfoCommand.NotifyCanExecuteChanged();
        EvaluateBundledAiDraftCommand.NotifyCanExecuteChanged();
        ReturnToNormalProfileCommand.NotifyCanExecuteChanged();
    }

    private void MarkDraftDirty()
    {
        if (!_isLoading && HasProcessSelected)
        {
            _isDirty = true;
            RebuildComparison();
        }
    }

    private void RebuildComparison()
    {
        if (!IsApplicationComparisonPublished)
        {
            ClearComparison("Application Comparison is not published in this educational release.");
            return;
        }

        if (_selectedProcess == null || _comparisonActual == null)
        {
            return;
        }

        var metadata = BuildRecord();
        metadata.RecordOrigin = _isDirty ? ApplicationProfileOrigin.UnsavedDraft : _recordOrigin;
        metadata.MatchReason = _matchReason;
        var report = _comparisonService.Compare(
            metadata,
            _comparisonCatalogProfile,
            _comparisonActual,
            _comparisonCandidates,
            _comparisonSelectionReason);
        ComparisonRows.Clear();
        foreach (var row in report.Rows)
        {
            ComparisonRows.Add(new ApplicationComparisonRowViewModel(row));
        }

        SelectedProfileDisplay = report.SelectedProfileDisplay;
        ProfileSelectionReason = report.SelectionReason;
        AmbiguousCandidatesDisplay = report.CandidateSummary;
        HasAmbiguousCandidates = report.HasAmbiguousCandidates;
        PeAvailability = _comparisonActual.PeAvailability;
        var matches = report.Rows.Count(row => row.Result == ApplicationComparisonResult.Match);
        var mismatches = report.Rows.Count(row => row.Result == ApplicationComparisonResult.Mismatch);
        var unknown = report.Rows.Count(row => row.Result == ApplicationComparisonResult.Unknown);
        var notApplicable = report.Rows.Count(row => row.Result == ApplicationComparisonResult.NotApplicable);
        ComparisonStatus =
            $"Derived at display time; not persisted. Match {matches}, Mismatch {mismatches}, Unknown {unknown}, Not applicable {notApplicable}.";
        ComparisonEvidenceSource = report.BuildEvidenceSource();
        OnPropertyChanged(nameof(ComparisonEvidenceSource));
        UpdateSecurityAssessmentContext();
    }

    private void ClearComparison(string status)
    {
        ComparisonRows.Clear();
        SelectedProfileDisplay = "No profile selected";
        ProfileSelectionReason = status;
        AmbiguousCandidatesDisplay = "No catalog candidates.";
        HasAmbiguousCandidates = false;
        ComparisonStatus = status;
        PeAvailability = "PE data has not been loaded.";
        ComparisonEvidenceSource = null;
        OnPropertyChanged(nameof(ComparisonEvidenceSource));
    }

    private void UpdateSecurityAssessmentContext()
    {
        SecurityAssessment?.UpdateReferenceContext(
            BuildReferenceProfileEvidence(),
            ComparisonEvidenceSource);
    }

    private string BuildReferenceProfileEvidence()
    {
        if (!HasProcessSelected)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        builder.AppendLine($"Origin/review: {_recordOrigin}; {ReviewStateDisplay}");
        builder.AppendLine($"Profile: {SelectedProfileDisplay}");
        builder.AppendLine($"Role summary: {Description}");
        builder.AppendLine($"Category: {ApplicationCategory}");
        builder.AppendLine($"Expected responsibilities: {ExpectedResponsibilities}");
        builder.AppendLine($"Normal behavior: {NormalBehavior}");
        builder.AppendLine($"Launch triggers: {LaunchTriggers}");
        builder.AppendLine($"Typical context: {ExpectedContext}");
        builder.AppendLine($"Command line expectations: {CommandLineExpectations}");
        builder.AppendLine($"Filesystem/registry expectations: {FilesystemRegistryExpectations}");
        builder.AppendLine($"Child process expectations: {ChildProcessExpectations}");
        builder.AppendLine($"Network expectations: {NetworkExpectations}");
        builder.AppendLine($"Variants/caveats: {NormalVariants}");
        builder.AppendLine($"Abuse/masquerading: {CybersecurityNotes}");
        builder.AppendLine($"Analyst checks: {AnalystValidationChecks}");
        builder.AppendLine($"Sources: {CatalogSourcesDisplay}");
        if (HasAiDraft || IsEvaluatingBundledAiDraft)
        {
            builder.AppendLine("Draft warning: this is an unsaved, unreviewed AI draft and not approved catalog content.");
        }

        var text = builder.ToString();
        return text.Length <= 16000 ? text.TrimEnd() : text[..16000] + "…";
    }

    private void SetEvaluationAvailability(ApplicationInfoEvaluationResolutionResult evaluation)
    {
        if (!IsAiAssistancePublished)
        {
            ResetEvaluationAvailability();
            return;
        }

        _evaluationResolution = evaluation;
        HasEvaluationCandidate = evaluation.Record != null;
        EvaluationStatusDisplay = evaluation.Record != null && evaluation.CatalogProfile != null
            ? $"A bundled AI draft matches this process: {evaluation.CatalogProfile.DisplayName}. It remains hidden until explicitly evaluated."
            : evaluation.IsAmbiguous
                ? evaluation.SelectionReason
                : string.Empty;
    }

    private void ResetEvaluationAvailability()
    {
        _evaluationResolution = null;
        HasEvaluationCandidate = false;
        EvaluationStatusDisplay = string.Empty;
    }

    private ApplicationMetadataRecord CaptureDisplayedRecord()
    {
        var record = BuildRecord();
        record.RecordOrigin = _recordOrigin;
        record.ReviewState = _displayedReviewState;
        record.ReviewedUtc = _displayedReviewedUtc;
        return record;
    }

    private bool RestoreRecordBeforeEvaluation()
    {
        if (!IsEvaluatingBundledAiDraft || _recordBeforeEvaluation == null)
        {
            return false;
        }

        var record = CloneRecord(_recordBeforeEvaluation);
        var metadataExists = _metadataExistsBeforeEvaluation;
        var isDirty = _isDirtyBeforeEvaluation;
        var hasAiDraft = _hasAiDraftBeforeEvaluation;
        _comparisonCatalogProfile = _comparisonCatalogProfileBeforeEvaluation;
        _comparisonCandidates = _comparisonCandidatesBeforeEvaluation;
        _comparisonSelectionReason = _comparisonSelectionReasonBeforeEvaluation;
        _matchReason = _matchReasonBeforeEvaluation;
        var priorStatus = _statusMessageBeforeEvaluation;
        var priorDifferences = _draftDifferencesBeforeEvaluation;
        ClearEvaluationSnapshot();
        IsEvaluatingBundledAiDraft = false;
        LoadRecord(record, metadataExists);
        HasAiDraft = hasAiDraft;
        DraftDifferences.Clear();
        foreach (var difference in priorDifferences)
        {
            DraftDifferences.Add(difference);
        }

        _isDirty = isDirty;
        RebuildComparison();
        UpdateSecurityAssessmentContext();
        StatusMessage = priorStatus;
        NotifyCommandState();
        return true;
    }

    private void ResetEvaluationForContextChange(bool restoreDisplayedRecord)
    {
        if (restoreDisplayedRecord)
        {
            _ = RestoreRecordBeforeEvaluation();
        }

        ClearEvaluationSnapshot();
        IsEvaluatingBundledAiDraft = false;
        ResetEvaluationAvailability();
    }

    private void ClearEvaluationSnapshot()
    {
        _recordBeforeEvaluation = null;
        _metadataExistsBeforeEvaluation = false;
        _isDirtyBeforeEvaluation = false;
        _hasAiDraftBeforeEvaluation = false;
        _comparisonCatalogProfileBeforeEvaluation = null;
        _comparisonCandidatesBeforeEvaluation = [];
        _comparisonSelectionReasonBeforeEvaluation = string.Empty;
        _matchReasonBeforeEvaluation = string.Empty;
        _statusMessageBeforeEvaluation = string.Empty;
        _draftDifferencesBeforeEvaluation = [];
    }

    private bool IsCurrentAiDraftRequest(
        long generation,
        ProcessRowViewModel process,
        CancellationTokenSource cancellation)
        => generation == Volatile.Read(ref _aiDraftGeneration) &&
           ReferenceEquals(_selectedProcess, process) &&
           ReferenceEquals(_activeAiDraftRequest, cancellation);

    private void CancelAiDraftRequest()
    {
        Interlocked.Increment(ref _aiDraftGeneration);
        var active = Interlocked.Exchange(ref _activeAiDraftRequest, null);
        active?.Cancel();
        active?.Dispose();
    }

    private ApplicationMetadataRecord ResolveDiscardBaseline(ApplicationMetadataRecord current)
    {
        return CloneRecord(_resolvedRecordBeforeAiDraft ?? current);
    }

    private static AnnotationTarget CreateProcessAnnotationTarget(ProcessRowViewModel row) => new()
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

    private static string FormatAiSourceClaims(ApplicationMetadataRecord record)
    {
        if (!record.IsAiGenerated)
        {
            return string.Empty;
        }

        var prefix = record.AiSourceClaimsUnverified ? "UNVERIFIED source claim" : "Source";
        return record.SourceReferences.Count == 0
            ? "UNVERIFIED: no retrieved citations were supplied; model memory is not a verified source."
            : string.Join(Environment.NewLine, record.SourceReferences.Select(source =>
                $"{prefix}: {source.Publisher} — {source.Title} ({source.Uri})"));
    }

    private static ApplicationMetadataRecord CloneRecord(ApplicationMetadataRecord record) => new()
    {
        ApplicationId = record.ApplicationId,
        DisplayName = record.DisplayName,
        ExecutableNamePattern = record.ExecutableNamePattern,
        IsRegexPattern = record.IsRegexPattern,
        PackageFamilyName = record.PackageFamilyName,
        AppUserModelId = record.AppUserModelId,
        BaseProfileId = record.BaseProfileId,
        BaseProfileRevision = record.BaseProfileRevision,
        BaseCatalogRevision = record.BaseCatalogRevision,
        RecordOrigin = record.RecordOrigin,
        ReviewState = record.ReviewState,
        PathPattern = record.PathPattern,
        CompanyVendor = record.CompanyVendor,
        ProductName = record.ProductName,
        Description = record.Description,
        ApplicationCategory = record.ApplicationCategory,
        ExpectedResponsibilities = record.ExpectedResponsibilities,
        NormalBehavior = record.NormalBehavior,
        LaunchTriggers = record.LaunchTriggers,
        ExpectedContext = record.ExpectedContext,
        CommandLineExpectations = record.CommandLineExpectations,
        FilesystemRegistryExpectations = record.FilesystemRegistryExpectations,
        ChildProcessExpectations = record.ChildProcessExpectations,
        NetworkExpectations = record.NetworkExpectations,
        NormalVariants = record.NormalVariants,
        AnalystValidationChecks = record.AnalystValidationChecks,
        KnownBenignNotes = record.KnownBenignNotes,
        CybersecurityNotes = record.CybersecurityNotes,
        Source = record.Source,
        Confidence = record.Confidence,
        IsAiGenerated = record.IsAiGenerated,
        ProviderName = record.ProviderName,
        ModelName = record.ModelName,
        Prompt = record.Prompt,
        AiProviderKind = record.AiProviderKind,
        AiEndpointMode = record.AiEndpointMode,
        AiPromptTemplateId = record.AiPromptTemplateId,
        AiRequestedUtc = record.AiRequestedUtc,
        AiUncertainty = record.AiUncertainty,
        AiValidationWarnings = record.AiValidationWarnings,
        AiSourceClaimsUnverified = record.AiSourceClaimsUnverified,
        SourceReferences = record.SourceReferences.Select(source => new ApplicationProfileSourceReference
        {
            Title = source.Title,
            Publisher = source.Publisher,
            Uri = source.Uri,
            RetrievedUtc = source.RetrievedUtc,
            SupportingNote = source.SupportingNote
        }).ToList(),
        CatalogProvenance = record.CatalogProvenance,
        ProfileLastReviewedUtc = record.ProfileLastReviewedUtc,
        ReviewedUtc = record.ReviewedUtc,
        CreatedUtc = record.CreatedUtc,
        UpdatedUtc = record.UpdatedUtc,
        LastMatchedUtc = record.LastMatchedUtc,
        MatchReason = record.MatchReason
    };

    private static string FormatReviewState(ApplicationMetadataRecord record)
    {
        var reviewed = record.ReviewedUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm") ?? "not recorded";
        return $"{record.ReviewState}; reviewed {reviewed}";
    }

    private static string FormatSources(IReadOnlyList<ApplicationProfileSourceReference> sources)
    {
        if (sources.Count == 0)
        {
            return "No structured sources recorded.";
        }

        return string.Join(Environment.NewLine, sources.Select(source =>
        {
            var retrieved = source.RetrievedUtc == default
                ? string.Empty
                : $"; retrieved {source.RetrievedUtc:yyyy-MM-dd}";
            var support = string.IsNullOrWhiteSpace(source.SupportingNote)
                ? string.Empty
                : $"; supports {source.SupportingNote}";
            return $"{source.Publisher}: {source.Title} ({source.Uri}){retrieved}{support}";
        }));
    }

    private static string GetExecutableName(ProcessRowViewModel process)
        => ApplicationInfoResolutionService.ResolveExecutableFilename(process.ProcessInfo);

    private static string CleanMetadataValue(string value)
    {
        return string.IsNullOrWhiteSpace(value) || value.StartsWith("<", StringComparison.Ordinal)
            ? string.Empty
            : value.Trim();
    }

    private static string CleanPathPattern(string value)
    {
        return string.IsNullOrWhiteSpace(value) || value.StartsWith("<", StringComparison.Ordinal)
            ? string.Empty
            : Path.GetDirectoryName(value) ?? string.Empty;
    }
}
