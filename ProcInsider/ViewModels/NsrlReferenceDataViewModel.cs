using System.IO;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.ViewModels;

public partial class NsrlReferenceDataViewModel : ViewModelBase, IDisposable
{
    private readonly IKnownFileServerLifecycleService _lifecycle;
    private readonly INsrlControlClient _control;
    private readonly Func<string, bool> _confirm;
    private CancellationTokenSource? _activeWork;
    private KnownFileServerConnection? _connection;
    private NsrlManagementOperationSnapshot? _operation;
    private long _generation;
    private bool _disposed;

    public NsrlReferenceDataViewModel(
        IKnownFileServerLifecycleService lifecycle,
        INsrlControlClient control,
        Func<string, bool>? confirm = null)
    {
        _lifecycle = lifecycle ?? throw new ArgumentNullException(nameof(lifecycle));
        _control = control ?? throw new ArgumentNullException(nameof(control));
        _confirm = confirm ?? (_ => false);
    }

    public event Action<KnownFileLookupSettings>? ManagedProviderSelected;

    [ObservableProperty]
    private string catalogRoot = string.Empty;

    [ObservableProperty]
    private string validationReceiptPath = string.Empty;

    [ObservableProperty]
    private string endpoint = NsrlServerProtocol.DefaultEndpoint;

    [ObservableProperty]
    private string controlPipeName = NsrlServerProtocol.DefaultControlPipeName;

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private bool isConnected;

    [ObservableProperty]
    private string serverState = "Not checked";

    [ObservableProperty]
    private string statusMessage = "No server, network, control, or filesystem action occurs until an analyst command is clicked.";

    [ObservableProperty]
    private string protocolDisplay = "<not connected>";

    [ObservableProperty]
    private string catalogIdentity = "No active managed catalog.";

    [ObservableProperty]
    private string derivedIdentity = "No derived exact-hash index.";

    [ObservableProperty]
    private string storageDisplay = "Storage has not been checked.";

    [ObservableProperty]
    private string validationDisplay = "No successful validation reported.";

    [ObservableProperty]
    private string releaseDisplay = "Click Check for NIST release; checking does not install anything.";

    [ObservableProperty]
    private string preflightDisplay = "No download preflight is available.";

    [ObservableProperty]
    private string progressDisplay = "Idle";

    [ObservableProperty]
    private double progressPercent;

    public string CorpusBoundary =>
        "The full Modern Minimal corpus is reusable reference data outside the investigation session. Match means present in that RDS generation, not benign or authorized; No match is not maliciousness.";

    public string DownloadActionLabel => string.IsNullOrWhiteSpace(_connection?.Server.ActiveGenerationId)
        ? "Download / Install"
        : "Update";

    public void SetSettings(KnownFileLookupSettings settings, long generation)
    {
        _generation = generation;
        CancelLocalWork("Workspace or settings generation changed; stale management results were suppressed.");
        var normalized = Services.KnownFileLookupSettingsService.Normalize(settings);
        CatalogRoot = normalized.ManagedCatalogRoot;
        ValidationReceiptPath = normalized.ManagedValidationReceiptPath;
        Endpoint = normalized.Endpoint;
        ControlPipeName = normalized.ManagedControlPipeName;
    }

    [RelayCommand(CanExecute = nameof(CanRunLifecycleCommand))]
    private Task RefreshStatusAsync() => RunLifecycleAsync(start: false);

    [RelayCommand(CanExecute = nameof(CanStart))]
    private Task StartAsync() => RunLifecycleAsync(start: true);

    [RelayCommand(CanExecute = nameof(CanStop))]
    private async Task StopAsync()
    {
        var generation = _generation;
        await RunExclusiveAsync(async cancellationToken =>
        {
            var result = await _lifecycle.StopAsync(BuildConfiguration(), cancellationToken);
            if (generation != _generation)
            {
                return;
            }

            ApplyLifecycle(result);
        });
    }

    [RelayCommand(CanExecute = nameof(CanUseManagedProvider))]
    private void UseManagedProvider()
    {
        if (_connection is null || !IsConnected)
        {
            return;
        }

        ManagedProviderSelected?.Invoke(new KnownFileLookupSettings
        {
            ProviderMode = KnownFileLookupProviderMode.ManagedLocal,
            Endpoint = _connection.Configuration.Endpoint.AbsoluteUri,
            ManagedCatalogRoot = CatalogRoot,
            ManagedValidationReceiptPath = ValidationReceiptPath,
            ManagedControlPipeName = ControlPipeName
        });
        StatusMessage = "The exact authenticated loopback server was selected for this session's lazy App Info lookups.";
    }

    [RelayCommand(CanExecute = nameof(CanSendControl))]
    private Task CheckReleaseAsync() => BeginAndPollAsync(NsrlControlCommand.BeginCheckLatestModernMinimalFull);

    [RelayCommand(CanExecute = nameof(CanAcquire))]
    private Task DownloadOrUpdateAsync()
    {
        if (_operation?.Release is null || _operation.Preflight is null)
        {
            StatusMessage = "Check the supported NIST release and review preflight before download/install.";
            return Task.CompletedTask;
        }

        if (!string.IsNullOrWhiteSpace(_connection?.Server.ActiveGenerationId) &&
            !_confirm($"Replace the active managed NSRL generation '{_connection.Server.ActiveGenerationId}' with checked release '{_operation.Release.ReleaseId}' after all server-side validation passes?"))
        {
            StatusMessage = "Update was not started; the current valid generation remains active.";
            return Task.CompletedTask;
        }

        return BeginAndPollAsync(
            NsrlControlCommand.BeginAcquireLatestModernMinimalFull,
            expectedReleaseId: _operation.Release.ReleaseId);
    }

    [RelayCommand(CanExecute = nameof(CanRollback))]
    private Task RollbackAsync()
    {
        var active = _connection?.Server.ActiveGenerationId ?? string.Empty;
        if (!_confirm($"Roll back from active managed NSRL generation '{active}' to the retained previous complete generation?"))
        {
            StatusMessage = "Rollback was not started.";
            return Task.CompletedTask;
        }

        return BeginAndPollAsync(NsrlControlCommand.BeginRollback);
    }

    [RelayCommand(CanExecute = nameof(CanCancel))]
    private async Task CancelAsync()
    {
        var connection = _connection;
        var operation = _operation;
        if (connection is null || operation?.State != NsrlManagementOperationState.Running)
        {
            return;
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            var response = await _control.SendAuthenticatedAsync(
                ControlPipeName,
                connection.Server,
                new NsrlControlRequest
                {
                    Command = NsrlControlCommand.CancelOperation,
                    ExpectedOperationId = operation.OperationId
                },
                timeout.Token);
            StatusMessage = response.Detail;
            if (response.Succeeded)
            {
                _activeWork?.Cancel();
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or HttpRequestException or OperationCanceledException)
        {
            StatusMessage = "Cancellation could not be confirmed; refresh status before retrying: " + Bound(ex.Message);
        }
    }

    public void Shutdown()
    {
        _generation++;
        CancelLocalWork("Viewer shutdown canceled local observation; server-side work is not falsely reported as canceled.");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Shutdown();
        _lifecycle.Dispose();
        _control.Dispose();
    }

    private async Task RunLifecycleAsync(bool start)
    {
        var generation = _generation;
        await RunExclusiveAsync(async cancellationToken =>
        {
            KnownFileServerLifecycleResult result;
            try
            {
                result = start
                    ? await _lifecycle.StartAsync(BuildConfiguration(), cancellationToken)
                    : await _lifecycle.ConnectAsync(BuildConfiguration(), cancellationToken);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                result = new KnownFileServerLifecycleResult(KnownFileServerLifecycleOutcome.Failed, "Managed NSRL lifecycle failed safely: " + Bound(ex.Message));
            }

            if (generation == _generation)
            {
                ApplyLifecycle(result);
            }
        });
    }

    private async Task BeginAndPollAsync(NsrlControlCommand command, string expectedReleaseId = "")
    {
        var generation = _generation;
        await RunExclusiveAsync(async cancellationToken =>
        {
            var lifecycle = await _lifecycle.ConnectAsync(BuildConfiguration(), cancellationToken);
            if (!lifecycle.IsConnected || lifecycle.Connection is null)
            {
                if (generation == _generation)
                {
                    ApplyLifecycle(lifecycle);
                }
                return;
            }

            _connection = lifecycle.Connection;
            var begin = await _control.SendAuthenticatedAsync(
                ControlPipeName,
                _connection.Server,
                new NsrlControlRequest
                {
                    Command = command,
                    ExpectedActiveGenerationId = _connection.Server.ActiveGenerationId,
                    ExpectedReleaseId = expectedReleaseId
                },
                cancellationToken);
            if (!begin.Succeeded || begin.Operation is null)
            {
                if (generation == _generation)
                {
                    StatusMessage = begin.Detail;
                    ApplyOperation(begin.Operation);
                }
                return;
            }

            var operationId = begin.Operation.OperationId;
            ApplyOperation(begin.Operation);
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(500, cancellationToken);
                var status = await _control.SendAuthenticatedAsync(
                    ControlPipeName,
                    _connection.Server,
                    new NsrlControlRequest { Command = NsrlControlCommand.Status },
                    cancellationToken);
                if (generation != _generation ||
                    status.Operation is null ||
                    !string.Equals(status.Operation.OperationId, operationId, StringComparison.Ordinal))
                {
                    return;
                }

                ApplyOperation(status.Operation);
                if (status.Operation.State != NsrlManagementOperationState.Running)
                {
                    var refreshed = await _lifecycle.ConnectAsync(BuildConfiguration(), cancellationToken);
                    if (generation == _generation)
                    {
                        ApplyLifecycle(refreshed);
                        ApplyOperation(status.Operation);
                    }
                    return;
                }
            }
        });
    }

    private async Task RunExclusiveAsync(Func<CancellationToken, Task> action)
    {
        if (IsBusy || _disposed)
        {
            return;
        }

        var cancellation = new CancellationTokenSource();
        var previous = Interlocked.Exchange(ref _activeWork, cancellation);
        previous?.Cancel();
        IsBusy = true;
        try
        {
            await action(cancellation.Token);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or HttpRequestException or UnauthorizedAccessException or ObjectDisposedException)
        {
            StatusMessage = "Managed NSRL operation failed safely: " + Bound(ex.Message);
        }
        finally
        {
            Interlocked.CompareExchange(ref _activeWork, null, cancellation);
            IsBusy = false;
            cancellation.Dispose();
        }
    }

    private void ApplyLifecycle(KnownFileServerLifecycleResult result)
    {
        _connection = result.Connection;
        IsConnected = result.IsConnected && result.Connection is not null;
        ServerState = result.Outcome.ToString();
        StatusMessage = result.Detail;
        if (_connection is null)
        {
            ProtocolDisplay = "<not connected>";
            CatalogIdentity = "No active managed catalog.";
            DerivedIdentity = "No derived exact-hash index.";
            StorageDisplay = "Storage has not been checked.";
            ValidationDisplay = "No successful validation reported.";
        }
        else
        {
            var server = _connection.Server;
            ServerState = $"{server.Readiness} — PID {server.ProcessId}; started {server.ProcessStartUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}";
            ProtocolDisplay = $"{server.CompatibilityVersion}; server {server.ServerReleaseId}; provider {server.ProviderVersion}";
            CatalogIdentity = string.IsNullOrWhiteSpace(server.ActiveGenerationId)
                ? "No active managed catalog."
                : $"{server.CatalogVersion} {server.DataSet}/{server.Profile}; generation {server.ActiveGenerationId}";
            DerivedIdentity = string.IsNullOrWhiteSpace(server.DerivedGenerationId)
                ? "No derived exact-hash index."
                : $"{server.DerivedTransformVersion}; generation {server.DerivedGenerationId}; SHA-256 {server.DerivedDatabaseSha256}";
            StorageDisplay = $"Official {FormatBytes(server.OfficialDatabaseBytes)}; derived {FormatBytes(server.DerivedDatabaseBytes)}; total {FormatBytes(server.TotalStorageBytes)}.";
            ValidationDisplay = server.LastSuccessfulValidationUtc.HasValue
                ? $"{server.StartupValidationMode}; accepted {server.LastSuccessfulValidationUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}; receipt {server.AcceptedGenerationReceiptId}; startup admission {server.StartupAdmissionElapsedMilliseconds:N0} ms."
                : "No successful validation reported.";
        }

        OnPropertyChanged(nameof(DownloadActionLabel));
        NotifyCommands();
    }

    private void ApplyOperation(NsrlManagementOperationSnapshot? operation)
    {
        _operation = operation;
        if (operation is null)
        {
            ProgressDisplay = "Idle";
            ProgressPercent = 0;
            NotifyCommands();
            return;
        }

        ProgressDisplay = $"{operation.State}: {operation.Phase} — {operation.Detail}";
        ProgressPercent = operation.BytesTotal is > 0
            ? Math.Clamp(operation.BytesCompleted * 100d / operation.BytesTotal.Value, 0, 100)
            : operation.State == NsrlManagementOperationState.Succeeded ? 100 : 0;
        if (operation.Release is not null)
        {
            ReleaseDisplay = $"RDS {operation.Release.ReleaseId}; {operation.Release.DataSet}/{operation.Release.Profile}; source {operation.Release.ArchiveUri.GetLeftPart(UriPartial.Authority)}; compressed {FormatBytes(operation.Release.ArchiveSizeBytes ?? 0)}.";
        }
        if (operation.Preflight is not null)
        {
            var preflight = operation.Preflight;
            PreflightDisplay = $"Required {FormatBytes(preflight.RequiredFreeSpaceBytes)}; free {FormatBytes(preflight.AvailableFreeSpaceBytes)}; extracted estimate {FormatBytes(preflight.EstimatedExtractedSizeBytes)}; {(preflight.HasEnoughFreeSpace ? "enough space" : "insufficient space")}.";
        }
        StatusMessage = operation.Detail;
        NotifyCommands();
    }

    private KnownFileServerConfiguration BuildConfiguration()
    {
        if (!Uri.TryCreate(Endpoint, UriKind.Absolute, out var endpoint))
        {
            throw new InvalidDataException("The managed endpoint is invalid.");
        }

        return new KnownFileServerConfiguration(CatalogRoot, ValidationReceiptPath, endpoint, ControlPipeName);
    }

    private bool CanRunLifecycleCommand() => !IsBusy &&
                                             !string.IsNullOrWhiteSpace(CatalogRoot) &&
                                             !string.IsNullOrWhiteSpace(ValidationReceiptPath);
    private bool CanStart() => CanRunLifecycleCommand() && !IsConnected;
    private bool CanStop() => !IsBusy && IsConnected;
    private bool CanUseManagedProvider() => !IsBusy && IsConnected && _connection is not null;
    private bool CanSendControl() => !IsBusy && IsConnected;
    private bool CanAcquire() => CanSendControl() && _operation?.State == NsrlManagementOperationState.Succeeded &&
                                 _operation.Release is not null && _operation.Preflight?.HasEnoughFreeSpace == true;
    private bool CanRollback() => CanSendControl() && !string.IsNullOrWhiteSpace(_connection?.Server.ActiveGenerationId);
    private bool CanCancel() => IsBusy && _operation?.State == NsrlManagementOperationState.Running;

    partial void OnIsBusyChanged(bool value) => NotifyCommands();
    partial void OnIsConnectedChanged(bool value) => NotifyCommands();
    partial void OnCatalogRootChanged(string value) => NotifyCommands();
    partial void OnValidationReceiptPathChanged(string value) => NotifyCommands();

    private void NotifyCommands()
    {
        RefreshStatusCommand.NotifyCanExecuteChanged();
        StartCommand.NotifyCanExecuteChanged();
        StopCommand.NotifyCanExecuteChanged();
        UseManagedProviderCommand.NotifyCanExecuteChanged();
        CheckReleaseCommand.NotifyCanExecuteChanged();
        DownloadOrUpdateCommand.NotifyCanExecuteChanged();
        RollbackCommand.NotifyCanExecuteChanged();
        CancelCommand.NotifyCanExecuteChanged();
    }

    private void CancelLocalWork(string message)
    {
        Interlocked.Exchange(ref _activeWork, null)?.Cancel();
        IsBusy = false;
        StatusMessage = message;
    }

    private static string FormatBytes(long value) => KnownFilePackageRecordRowViewModel.FormatBytes(value);

    private static string Bound(string value)
    {
        var text = value?.Trim() ?? string.Empty;
        return text.Length <= 512 ? text : text[..512];
    }
}
