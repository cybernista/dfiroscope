using System.IO;
using System.Collections.ObjectModel;
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
    private readonly Func<string, bool> _confirmReplace;
    private AiProviderKind _currentAiProviderKind = AiProviderKind.Disabled;
    private string _currentAiEndpointMode = string.Empty;
    private string _currentAiPromptTemplateId = string.Empty;
    private DateTime? _currentAiRequestedUtc;
    private bool _currentAiSourceClaimsUnverified;

    public ProcessDescriptionViewModel(
        AnnotationDatabaseService? annotationStore,
        FeatureAccessService featureAccess,
        ApplicationCatalogService? applicationCatalog,
        IApplicationComparisonEvidenceService comparisonEvidenceService,
        NsrlLookupViewModel? nsrlLookupViewModel = null,
        Func<string, bool>? confirmReplace = null)
    {
        _annotationStore = annotationStore;
        _featureAccess = featureAccess;
        _confirmReplace = confirmReplace ?? (_ => false);
        _resolutionService = new ApplicationInfoResolutionService(applicationCatalog);
        _comparisonEvidenceService = comparisonEvidenceService
            ?? throw new ArgumentNullException(nameof(comparisonEvidenceService));
        Nsrl = _featureAccess.IsPublished(FeatureIds.KnownFileReferenceData)
            ? nsrlLookupViewModel
            : null;
        _hasCatalog = applicationCatalog != null;
    }

    public ObservableCollection<ApplicationComparisonRowViewModel> ComparisonRows { get; } = [];

    public ApplicationComparisonEvidenceSource? ComparisonEvidenceSource { get; private set; }

    public NsrlLookupViewModel? Nsrl { get; }

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
    private bool hasSavedOverride;

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

    public bool IsApplicationProfileEditable => HasProcessSelected;

    public void SetAnnotationStore(AnnotationDatabaseService? annotationStore, bool reloadSelection = true)
    {
        _annotationStore = annotationStore;
        if (reloadSelection) _ = LoadForProcessAsync(_selectedProcess);
    }

    public void SetWorkspace(InvestigationSessionPaths? paths, long workspaceGeneration)
    {
        Nsrl?.SetWorkspace(paths?.NsrlSettingsPath ?? string.Empty, workspaceGeneration);
    }

    public void Shutdown()
    {
        CancelPendingPresentationRequests();
        Nsrl?.Shutdown();
    }

    internal void CancelPendingPresentationRequests()
    {
        Interlocked.Exchange(ref _activeSelectionLoad, null)?.Cancel();
        Nsrl?.CancelPendingLookup();
    }

    [RelayCommand]
    public Task LoadForProcessAsync(ProcessRowViewModel? process) =>
        LoadForProcessSelectionAsync(process, CancellationToken.None);

    public async Task LoadForProcessSelectionAsync(
        ProcessRowViewModel? process,
        CancellationToken cancellationToken)
    {
        var generation = ++_selectionLoadGeneration;
        var previousLoad = Interlocked.Exchange(ref _activeSelectionLoad, null);
        previousLoad?.Cancel();
        var sameProcess = _selectedProcess != null &&
                          string.Equals(_selectedProcess.ProcessKey, process?.ProcessKey, StringComparison.Ordinal);
        var unsavedDraft = sameProcess && _isDirty ? BuildRecord() : null;
        _selectedProcess = process;
        Nsrl?.SetSelectedProcess(process?.ProcessInfo);
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
            var comparisonActualTask = IsApplicationComparisonPublished
                ? _comparisonEvidenceService.LoadAsync(process.ProcessInfo, loadToken)
                : null;
            if (comparisonActualTask == null)
            {
                await sessionOverrideTask;
            }
            else
            {
                await Task.WhenAll(sessionOverrideTask, comparisonActualTask);
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
            var record = resolution.Record ?? CreateDraftRecord(process);
            _comparisonCatalogProfile = resolution.CatalogProfile;
            _comparisonCandidates = resolution.Candidates;
            _comparisonActual = actual;
            Nsrl?.SetSelectedProcess(process.ProcessInfo, actual?.ProcessImageFileSizeBytes);
            _comparisonSelectionReason = resolution.SelectionReason;
            _matchReason = string.IsNullOrWhiteSpace(record.MatchReason)
                ? resolution.SelectionReason
                : record.MatchReason;
            record.MatchReason = _matchReason;
            LoadRecord(record, metadataExists: resolution.Record != null);
            HasSavedOverride = sessionOverrideTask.Result != null;
            _isDirty = resolution.Record?.RecordOrigin == ApplicationProfileOrigin.UnsavedDraft;
            RebuildComparison();
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
                _ => "No session override or built-in profile matched. Edit and save a session override."
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
            _comparisonCatalogProfile = null;
            _comparisonCandidates = [];
            _comparisonActual = null;
            _comparisonSelectionReason = string.Empty;
            ClearComparison($"Comparison unavailable because App Info loading failed safely: {ex.Message}");
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

    [RelayCommand(CanExecute = nameof(CanSaveMetadata))]
    public async Task SaveMetadataAsync()
    {
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
        if (!_confirmReplace("Replace the existing session App Info override with the currently reviewed draft? The shipped catalog will not be changed."))
        {
            StatusMessage = "Replace saved override canceled. The existing saved profile was not changed.";
            return;
        }

        await PersistMetadataAsync("Replaced the saved session App Info override");
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
            _isDirty = false;
            RebuildComparison();
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

    public void Clear()
    {
        _selectionLoadGeneration++;
        Interlocked.Exchange(ref _activeSelectionLoad, null)?.Cancel();
        _selectedProcess = null;
        Nsrl?.SetSelectedProcess(null);
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
            Prompt = string.Empty;
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
            CatalogProvenanceDisplay = "Not recorded";
            _comparisonCatalogProfile = null;
            _comparisonCandidates = [];
            _comparisonActual = null;
            _comparisonSelectionReason = string.Empty;
            _matchReason = string.Empty;
            HasSavedOverride = false;
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

    partial void OnHasSavedOverrideChanged(bool value) => NotifyCommandState();

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
            Prompt = record.Prompt;
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
            Prompt = string.Empty,
            RecordOrigin = ApplicationProfileOrigin.UnsavedDraft,
            ReviewState = ApplicationProfileReviewState.Unreviewed
        };
    }

    private bool CanSaveMetadata()
        => HasProcessSelected &&
           !HasSavedOverride &&
           !IsBusy &&
           !string.IsNullOrWhiteSpace(ExecutableNamePattern);

    private bool CanReplaceSavedOverride()
        => HasProcessSelected &&
           HasSavedOverride &&
           !IsBusy &&
           !string.IsNullOrWhiteSpace(ExecutableNamePattern);

    private void NotifyCommandState()
    {
        SaveMetadataCommand.NotifyCanExecuteChanged();
        ReplaceSavedOverrideCommand.NotifyCanExecuteChanged();
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
