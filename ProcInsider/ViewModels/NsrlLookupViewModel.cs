using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.KnownFiles;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class NsrlLookupViewModel : ViewModelBase
{
    private readonly KnownFileLookupSettingsService _settingsService;
    private readonly IKnownFileLookupProviderFactory _providerFactory;
    private readonly Func<NsrlReferenceDataViewModel>? _referenceDataFactory;
    private CancellationTokenSource? _activeRequest;
    private ProcessInfo? _selectedProcess;
    private long? _selectedFileSizeBytes;
    private string _selectionIdentity = string.Empty;
    private long _workspaceGeneration;
    private long _requestGeneration;
    private bool _settingsLoaded;
    private bool _isApplyingSettings;
    private bool _settingsDirty;
    private int _maxResponseBytes = KnownFileLookupSettings.DefaultMaxResponseBytes;
    private int _maxRecords = KnownFileLookupSettings.DefaultMaxRecords;
    private KnownFileLookupResult? _currentResult;
    private string _currentResultSelectionIdentity = string.Empty;
    private bool _managedEndpointVerified;

    public NsrlLookupViewModel(
        KnownFileLookupSettingsService settingsService,
        IKnownFileLookupProviderFactory providerFactory,
        Func<NsrlReferenceDataViewModel>? referenceDataFactory = null)
    {
        _settingsService = settingsService ?? throw new ArgumentNullException(nameof(settingsService));
        _providerFactory = providerFactory ?? throw new ArgumentNullException(nameof(providerFactory));
        _referenceDataFactory = referenceDataFactory;
    }

    public ObservableCollection<KnownFilePackageRecordRowViewModel> Records { get; } = [];

    public IReadOnlyList<KnownFileLookupProviderMode> ProviderModes { get; } =
        Enum.GetValues<KnownFileLookupProviderMode>();

    [ObservableProperty]
    private NsrlReferenceDataViewModel? referenceData;

    [ObservableProperty]
    private KnownFileLookupProviderMode selectedProviderMode = KnownFileLookupProviderMode.ExternalCompatible;

    [ObservableProperty]
    private bool isTabSelected;

    [ObservableProperty]
    private bool hasSelection;

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private string endpoint = KnownFileLookupSettings.DefaultEndpoint;

    [ObservableProperty]
    private int timeoutSeconds = KnownFileLookupSettings.DefaultTimeoutSeconds;

    [ObservableProperty]
    private bool allowNonLoopback;

    [ObservableProperty]
    private string settingsStatus = "Settings load only when the NSRL tab is activated.";

    [ObservableProperty]
    private string selectedFileName = "<no process selected>";

    [ObservableProperty]
    private string selectedSha256 = "<not available>";

    [ObservableProperty]
    private string selectedFileSize = "<not available>";

    [ObservableProperty]
    private string outcomeDisplay = "Idle";

    [ObservableProperty]
    private string statusMessage = "Activate this tab to perform one exact SHA-256 lookup.";

    [ObservableProperty]
    private string verdictGuidance = "NSRL is a reference-file index, not a clean-file whitelist.";

    [ObservableProperty]
    private string providerStatus = "Not contacted";

    [ObservableProperty]
    private string providerVersionDisplay = "<not reported>";

    [ObservableProperty]
    private string catalogVersionDisplay = "<not reported>";

    [ObservableProperty]
    private string lookupTimeDisplay = "<not run>";

    [ObservableProperty]
    private string providerProvenance = "No provider request has been made.";

    [ObservableProperty]
    private string recordSummary = "No lookup records.";

    public string FilenameSearchStatus =>
        "Filename search is unavailable for the hashlookup-server REST adapter; this surface performs exact SHA-256 lookup only.";

    public bool TryBuildAiExternalReferenceContext(out string context)
    {
        var result = _currentResult;
        if (result == null ||
            !string.Equals(_currentResultSelectionIdentity, _selectionIdentity, StringComparison.Ordinal) ||
            result.Outcome is not (KnownFileLookupOutcome.Match or KnownFileLookupOutcome.NoMatch) ||
            string.IsNullOrWhiteSpace(result.ProviderProvenance))
        {
            context = string.Empty;
            return false;
        }

        var builder = new StringBuilder();
        builder.AppendLine($"Outcome: {(result.Outcome == KnownFileLookupOutcome.Match ? "Match" : "No match")}");
        builder.AppendLine("Interpretation: external reference lookup only; Match is not a known-good verdict and No match is not evidence of maliciousness.");
        builder.AppendLine($"Selected filename: {SelectedFileName}");
        builder.AppendLine($"Selected SHA-256: {SelectedSha256}");
        builder.AppendLine($"Provider: {result.ProviderName}");
        builder.AppendLine($"Provider version: {Empty(result.ProviderVersion)}");
        builder.AppendLine($"Catalog/RDS version: {Empty(result.CatalogVersion)}");
        builder.AppendLine($"Provider provenance: {result.ProviderProvenance}");
        builder.AppendLine($"Lookup UTC: {(result.LookupUtc == default ? "<not reported>" : result.LookupUtc.ToUniversalTime().ToString("O"))}");
        builder.AppendLine($"Records available: {result.TotalRecordCount}; included: {result.Records.Count}; truncated: {result.IsTruncated}");
        foreach (var record in result.Records.Take(20))
        {
            builder.AppendLine($"- Files={string.Join(", ", record.FileNames.Take(8))}; Size={record.FileSizeBytes}; Product={record.ProductName}; Version={record.ProductVersion}; Manufacturer={record.Manufacturer}; OS={record.OperatingSystemName} {record.OperatingSystemVersion}; Language={record.Language}; Type={record.ApplicationType}; ProviderSource={record.ProviderSource}");
        }

        context = builder.ToString().Length <= 12000
            ? builder.ToString().TrimEnd()
            : builder.ToString()[..12000] + "…";
        return true;
    }

    public string PrivacyWarning
    {
        get
        {
            var settings = BuildSettings();
            if (settings.ProviderMode == KnownFileLookupProviderMode.ManagedLocal && !_managedEndpointVerified)
            {
                return "Managed local mode is selected, but lookup is blocked until Connect/Refresh status verifies the exact adjacent same-user server and Use managed server is clicked.";
            }
            if (!KnownFileLookupSettingsService.TryResolveEndpoint(settings, out var uri, out var error))
            {
                return $"Lookup blocked: {error}";
            }

            if (KnownFileLookupSettingsService.IsLoopback(uri))
            {
                return "Loopback endpoint: activation/refresh sends only the selected SHA-256 in the request URL plus direct TCP/HTTP metadata. No filename, size, file bytes, command line, evidence rows, or annotations are sent.";
            }

            if (AllowNonLoopback && _settingsDirty)
            {
                return $"Lookup blocked until the explicit non-loopback disclosure settings for {uri.GetLeftPart(UriPartial.Authority)} are saved to this session.";
            }

            return AllowNonLoopback
                ? $"PRIVACY: activation/refresh sends only the selected SHA-256 in the request URL plus direct TCP/HTTP metadata to {uri.GetLeftPart(UriPartial.Authority)}. No filename, size, file bytes, command line, evidence rows, or annotations are sent."
                : $"Lookup blocked: {uri.GetLeftPart(UriPartial.Authority)} is not loopback. Enable the explicit non-loopback disclosure mode before any request.";
        }
    }

    public void SetWorkspace(string settingsPath, long workspaceGeneration)
    {
        if (_workspaceGeneration == workspaceGeneration &&
            string.Equals(_settingsService.SettingsPath, settingsPath, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _workspaceGeneration = workspaceGeneration;
        _settingsService.SetPath(settingsPath ?? string.Empty);
        _settingsLoaded = false;
        ApplySettings(new KnownFileLookupSettings());
        _managedEndpointVerified = false;
        ReferenceData?.SetSettings(new KnownFileLookupSettings(), workspaceGeneration);
        InvalidateLookup(
            string.IsNullOrWhiteSpace(settingsPath)
                ? "No active session NSRL settings path."
                : "Workspace changed. Activate the NSRL tab to load this session's settings.",
            clearRecords: true);
        SettingsStatus = string.IsNullOrWhiteSpace(settingsPath)
            ? "NSRL settings are unavailable without an active session."
            : "Settings load only when the NSRL tab is activated.";
        NotifyCommandState();
    }

    public void SetSelectedProcess(ProcessInfo? process, long? fileSizeBytes = null)
    {
        var identity = process == null
            ? string.Empty
            : $"{process.ProcessEntityId}\u001f{process.GetUniqueKey()}";
        if (string.Equals(identity, _selectionIdentity, StringComparison.Ordinal))
        {
            var fileName = process == null ? "<no process selected>" : ResolveFileName(process);
            var sha256 = process == null ? "<not available>" : CleanHash(process.Sha256Hash);
            var targetChanged = !string.Equals(fileName, SelectedFileName, StringComparison.Ordinal) ||
                                !string.Equals(sha256, SelectedSha256, StringComparison.Ordinal);
            _selectedProcess = process;
            _selectedFileSizeBytes = fileSizeBytes;
            SelectedFileName = fileName;
            SelectedSha256 = sha256;
            SelectedFileSize = KnownFilePackageRecordRowViewModel.FormatBytes(fileSizeBytes);
            if (targetChanged)
            {
                InvalidateLookup(
                    "Selected file hash or filename changed. Reactivate the tab or click Refresh lookup; the evidence update alone sends no request.",
                    clearRecords: true);
            }
            return;
        }

        _selectionIdentity = identity;
        _selectedProcess = process;
        _selectedFileSizeBytes = fileSizeBytes;
        HasSelection = process != null;
        SelectedFileName = process == null ? "<no process selected>" : ResolveFileName(process);
        SelectedSha256 = process == null ? "<not available>" : CleanHash(process.Sha256Hash);
        SelectedFileSize = KnownFilePackageRecordRowViewModel.FormatBytes(fileSizeBytes);
        InvalidateLookup(
            process == null
                ? "Select a process before querying the reference service."
                : "Selection changed. Reactivate the tab or click Refresh lookup; selection alone sends no request.",
            clearRecords: true);
        NotifyCommandState();
    }

    public Task ActivateAsync()
    {
        EnsureSettingsLoaded();
        EnsureReferenceDataManagement();
        return LookupAsync("tab activation");
    }

    public void Shutdown()
    {
        InvalidateLookup("Viewer shutdown canceled the lookup.", clearRecords: false);
        if (ReferenceData is not null)
        {
            ReferenceData.ManagedProviderSelected -= OnManagedProviderSelected;
            ReferenceData.Dispose();
            ReferenceData = null;
        }
    }

    [RelayCommand(CanExecute = nameof(CanRefreshLookup))]
    private Task RefreshLookupAsync()
    {
        EnsureSettingsLoaded();
        return LookupAsync("analyst refresh");
    }

    [RelayCommand(CanExecute = nameof(CanSaveSettings))]
    private void SaveSettings()
    {
        try
        {
            var settings = KnownFileLookupSettingsService.Normalize(BuildSettings());
            if (!KnownFileLookupSettingsService.TryResolveEndpoint(settings, out var uri, out var error))
            {
                SettingsStatus = error;
                return;
            }

            if (!KnownFileLookupSettingsService.IsLoopback(uri) && !settings.AllowNonLoopback)
            {
                SettingsStatus = "Non-loopback settings were not saved because explicit disclosure mode is disabled.";
                return;
            }

            _settingsService.Save(settings);
            ApplySettings(settings);
            _settingsLoaded = true;
            SettingsStatus = $"Saved session NSRL settings to {_settingsService.SettingsPath}.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            SettingsStatus = $"Failed to save session NSRL settings: {ex.Message}";
        }
    }

    partial void OnIsTabSelectedChanged(bool value)
    {
        if (value)
        {
            _ = ActivateAsync();
            return;
        }

        if (IsBusy)
        {
            InvalidateLookup("Lookup canceled because the NSRL tab was left.", clearRecords: false);
            OutcomeDisplay = "Canceled";
            ProviderStatus = "Canceled";
            VerdictGuidance = "No reference conclusion is available from a canceled lookup.";
        }
    }

    partial void OnEndpointChanged(string value) => OnSettingsEdited();

    partial void OnTimeoutSecondsChanged(int value) => OnSettingsEdited();

    partial void OnAllowNonLoopbackChanged(bool value) => OnSettingsEdited();

    partial void OnSelectedProviderModeChanged(KnownFileLookupProviderMode value)
    {
        if (!_isApplyingSettings && value != KnownFileLookupProviderMode.ManagedLocal)
        {
            _managedEndpointVerified = false;
        }
        OnSettingsEdited();
    }

    partial void OnIsBusyChanged(bool value) => NotifyCommandState();

    partial void OnHasSelectionChanged(bool value) => NotifyCommandState();

    private async Task LookupAsync(string trigger)
    {
        if (_selectedProcess == null)
        {
            ApplyUnavailable("No process is selected; no request was sent.");
            return;
        }

        var sha256 = CleanHash(_selectedProcess.Sha256Hash);
        if (!IsValidSha256(sha256))
        {
            ApplyUnavailable("The selected process has no valid SHA-256; no request was sent.");
            return;
        }

        var settings = KnownFileLookupSettingsService.Normalize(BuildSettings());
        if (settings.ProviderMode == KnownFileLookupProviderMode.ManagedLocal && !_managedEndpointVerified)
        {
            ApplyUnavailable("Managed local lookup requires an explicit authenticated Connect/Refresh status followed by Use managed server; no request was sent.");
            return;
        }
        if (!KnownFileLookupSettingsService.TryResolveEndpoint(settings, out var uri, out var endpointError))
        {
            ApplyUnavailable($"{endpointError} No request was sent.");
            return;
        }

        if (!KnownFileLookupSettingsService.IsLoopback(uri) && !settings.AllowNonLoopback)
        {
            ApplyUnavailable("The endpoint is non-loopback and explicit disclosure mode is disabled; no request was sent.");
            return;
        }

        if (!KnownFileLookupSettingsService.IsLoopback(uri) && _settingsDirty)
        {
            ApplyUnavailable("Save the explicit non-loopback disclosure settings for this session before lookup; no request was sent.");
            return;
        }

        var generation = Interlocked.Increment(ref _requestGeneration);
        var workspaceGeneration = _workspaceGeneration;
        var selectionIdentity = _selectionIdentity;
        var cancellation = new CancellationTokenSource();
        var previous = Interlocked.Exchange(ref _activeRequest, cancellation);
        previous?.Cancel();
        IsBusy = true;
        OutcomeDisplay = "Loading";
        ProviderStatus = "Request in progress";
        StatusMessage = $"Performing one bounded exact-hash lookup after {trigger}...";
        VerdictGuidance = "No verdict is inferred while the reference lookup is pending.";

        try
        {
            using var provider = _providerFactory.Create(settings);
            var result = await provider.LookupSha256Async(
                new KnownFileLookupRequest(sha256, SelectedFileName, ResolveFileSize()),
                cancellation.Token);
            if (!IsCurrent(generation, workspaceGeneration, selectionIdentity, cancellation))
            {
                return;
            }

            ApplyResult(result);
        }
        catch (OperationCanceledException) when (!IsCurrent(
            generation,
            workspaceGeneration,
            selectionIdentity,
            cancellation))
        {
            // Selection/workspace/endpoint/tab changes deliberately suppress stale results.
        }
        catch (OperationCanceledException)
        {
            if (IsCurrent(generation, workspaceGeneration, selectionIdentity, cancellation))
            {
                OutcomeDisplay = "Canceled";
                ProviderStatus = "Canceled";
                StatusMessage = "Lookup was canceled without changing evidence or annotations.";
                VerdictGuidance = "No reference conclusion is available from a canceled lookup.";
            }
        }
        catch (Exception ex)
        {
            if (IsCurrent(generation, workspaceGeneration, selectionIdentity, cancellation))
            {
                OutcomeDisplay = "Error";
                ProviderStatus = "Failed safely";
                StatusMessage = $"Lookup failed safely: {ex.Message}";
                VerdictGuidance = "Provider failure is not evidence about the selected file.";
            }
        }
        finally
        {
            Interlocked.CompareExchange(ref _activeRequest, null, cancellation);
            if (generation == Volatile.Read(ref _requestGeneration))
            {
                IsBusy = false;
            }

            cancellation.Dispose();
        }
    }

    private void ApplyResult(KnownFileLookupResult result)
    {
        _currentResult = result;
        _currentResultSelectionIdentity = _selectionIdentity;
        Records.Clear();
        foreach (var record in result.Records)
        {
            Records.Add(new KnownFilePackageRecordRowViewModel(record));
        }

        OutcomeDisplay = result.Outcome switch
        {
            KnownFileLookupOutcome.Match => "Match",
            KnownFileLookupOutcome.NoMatch => "No match",
            KnownFileLookupOutcome.Unavailable => "Unavailable",
            KnownFileLookupOutcome.Error => "Error",
            KnownFileLookupOutcome.Canceled => "Canceled",
            _ => "Unavailable"
        };
        ProviderStatus = result.HttpStatusCode.HasValue
            ? $"{result.ProviderName}; HTTP {result.HttpStatusCode.Value}"
            : result.ProviderName;
        ProviderVersionDisplay = Empty(result.ProviderVersion);
        CatalogVersionDisplay = Empty(result.CatalogVersion);
        LookupTimeDisplay = result.LookupUtc == default
            ? "<not reported>"
            : $"{result.LookupUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}; {result.Elapsed.TotalMilliseconds:N0} ms";
        ProviderProvenance = string.IsNullOrWhiteSpace(result.ProviderProvenance)
            ? "Provider provenance was not reported."
            : result.ProviderProvenance;
        StatusMessage = result.StatusDetail;
        RecordSummary = result.Outcome == KnownFileLookupOutcome.Match
            ? $"Provider reported {result.TotalRecordCount:N0} record(s); displaying {Records.Count:N0}{(result.IsTruncated ? " (bounded/truncated)" : string.Empty)} in deterministic order."
            : "No package records are displayed for this outcome.";
        VerdictGuidance = result.Outcome switch
        {
            KnownFileLookupOutcome.Match => "Known application file; not a known-good verdict. A match never suppresses deviations or other evidence.",
            KnownFileLookupOutcome.NoMatch => "No exact reference match. Absence is not evidence of maliciousness.",
            KnownFileLookupOutcome.Unavailable => "The reference service was unavailable. This says nothing about file intent or legitimacy.",
            KnownFileLookupOutcome.Error => "The response could not be safely interpreted. This says nothing about file intent or legitimacy.",
            _ => "No reference conclusion is available from a canceled lookup."
        };
    }

    private void ApplyUnavailable(string message)
    {
        _currentResult = null;
        _currentResultSelectionIdentity = string.Empty;
        OutcomeDisplay = "Unavailable";
        ProviderStatus = "Not contacted";
        StatusMessage = message;
        VerdictGuidance = "Unavailable reference context is not evidence about the selected file.";
        ProviderVersionDisplay = "<not reported>";
        CatalogVersionDisplay = "<not reported>";
        LookupTimeDisplay = "<not run>";
        ProviderProvenance = "No provider request was made.";
        Records.Clear();
        RecordSummary = "No lookup records.";
    }

    private void EnsureSettingsLoaded()
    {
        if (_settingsLoaded)
        {
            return;
        }

        var settings = _settingsService.Load(out var diagnostic);
        ApplySettings(settings);
        _settingsLoaded = true;
        SettingsStatus = string.IsNullOrWhiteSpace(diagnostic)
            ? File.Exists(_settingsService.SettingsPath)
                ? $"Loaded session NSRL settings from {_settingsService.SettingsPath}."
                : "Using safe loopback defaults; save to persist them for this session."
            : diagnostic;
    }

    private void ApplySettings(KnownFileLookupSettings settings)
    {
        _isApplyingSettings = true;
        try
        {
            var normalized = KnownFileLookupSettingsService.Normalize(settings);
            SelectedProviderMode = normalized.ProviderMode;
            Endpoint = normalized.Endpoint;
            TimeoutSeconds = normalized.TimeoutSeconds;
            AllowNonLoopback = normalized.AllowNonLoopback;
            _maxResponseBytes = normalized.MaxResponseBytes;
            _maxRecords = normalized.MaxRecords;
            _settingsDirty = false;
            ReferenceData?.SetSettings(normalized, _workspaceGeneration);
            OnPropertyChanged(nameof(PrivacyWarning));
        }
        finally
        {
            _isApplyingSettings = false;
        }
    }

    private KnownFileLookupSettings BuildSettings() => new()
    {
        ProviderMode = SelectedProviderMode,
        Endpoint = Endpoint,
        TimeoutSeconds = TimeoutSeconds,
        AllowNonLoopback = AllowNonLoopback,
        MaxResponseBytes = _maxResponseBytes,
        MaxRecords = _maxRecords,
        ManagedCatalogRoot = ReferenceData?.CatalogRoot ?? string.Empty,
        ManagedValidationReceiptPath = ReferenceData?.ValidationReceiptPath ?? string.Empty,
        ManagedControlPipeName = ReferenceData?.ControlPipeName ?? NsrlServerProtocol.DefaultControlPipeName
    };

    private void EnsureReferenceDataManagement()
    {
        if (ReferenceData is not null || _referenceDataFactory is null)
        {
            return;
        }

        ReferenceData = _referenceDataFactory();
        ReferenceData.ManagedProviderSelected += OnManagedProviderSelected;
        ReferenceData.SetSettings(BuildSettings(), _workspaceGeneration);
    }

    private void OnManagedProviderSelected(KnownFileLookupSettings managed)
    {
        try
        {
            var settings = BuildSettings();
            settings.ProviderMode = KnownFileLookupProviderMode.ManagedLocal;
            settings.Endpoint = managed.Endpoint;
            settings.ManagedCatalogRoot = managed.ManagedCatalogRoot;
            settings.ManagedValidationReceiptPath = managed.ManagedValidationReceiptPath;
            settings.ManagedControlPipeName = managed.ManagedControlPipeName;
            settings.AllowNonLoopback = false;
            _managedEndpointVerified = true;
            ApplySettings(settings);
            _settingsService.Save(settings);
            _settingsLoaded = true;
            SettingsStatus = "Saved the exact authenticated managed loopback provider for this session.";
            InvalidateLookup("Managed local provider selected. Click Refresh lookup to query the selected SHA-256 explicitly.", clearRecords: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _managedEndpointVerified = false;
            SettingsStatus = "Managed provider selection was not saved: " + ex.Message;
        }
    }

    private void OnSettingsEdited()
    {
        OnPropertyChanged(nameof(PrivacyWarning));
        if (_isApplyingSettings)
        {
            return;
        }

        SettingsStatus = "Settings have unsaved changes.";
        _settingsDirty = true;
        InvalidateLookup(
            "Endpoint or disclosure settings changed. Activate the tab or click Refresh lookup to use the new generation.",
            clearRecords: true);
        NotifyCommandState();
    }

    private void InvalidateLookup(string status, bool clearRecords)
    {
        _currentResult = null;
        _currentResultSelectionIdentity = string.Empty;
        Interlocked.Increment(ref _requestGeneration);
        Interlocked.Exchange(ref _activeRequest, null)?.Cancel();
        IsBusy = false;
        OutcomeDisplay = "Idle";
        ProviderStatus = "Not contacted";
        StatusMessage = status;
        VerdictGuidance = "NSRL is a reference-file index, not a clean-file whitelist.";
        ProviderVersionDisplay = "<not reported>";
        CatalogVersionDisplay = "<not reported>";
        LookupTimeDisplay = "<not run>";
        ProviderProvenance = "No provider request has been made for the current generation.";
        if (clearRecords)
        {
            Records.Clear();
            RecordSummary = "No lookup records.";
        }
    }

    private bool IsCurrent(
        long generation,
        long workspaceGeneration,
        string selectionIdentity,
        CancellationTokenSource cancellation)
        => generation == Volatile.Read(ref _requestGeneration) &&
           workspaceGeneration == _workspaceGeneration &&
           string.Equals(selectionIdentity, _selectionIdentity, StringComparison.Ordinal) &&
           ReferenceEquals(cancellation, _activeRequest);

    private bool CanRefreshLookup()
        => HasSelection && !IsBusy;

    private bool CanSaveSettings()
        => !IsBusy && !string.IsNullOrWhiteSpace(_settingsService.SettingsPath);

    private void NotifyCommandState()
    {
        RefreshLookupCommand.NotifyCanExecuteChanged();
        SaveSettingsCommand.NotifyCanExecuteChanged();
    }

    private long? ResolveFileSize()
        => _selectedFileSizeBytes;

    private static string ResolveFileName(ProcessInfo process)
    {
        var fileName = Path.GetFileName(process.ProcessPath);
        if (!string.IsNullOrWhiteSpace(fileName) && !fileName.StartsWith('<'))
        {
            return fileName;
        }

        return string.IsNullOrWhiteSpace(process.ProcessName)
            ? "<not available>"
            : process.ProcessName;
    }

    private static string CleanHash(string value)
    {
        var trimmed = value?.Trim() ?? string.Empty;
        return IsValidSha256(trimmed)
            ? trimmed.ToUpperInvariant()
            : "<not available>";
    }

    private static bool IsValidSha256(string value)
        => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static string Empty(string value)
        => string.IsNullOrWhiteSpace(value) ? "<not reported>" : value;
}
