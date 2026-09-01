using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.EvidenceSources;
using ProcInsider.Services.Features;

namespace ProcInsider.Agent;

internal sealed class AgentNamedPipeServer : IAsyncDisposable
{
    private readonly AgentOptions _options;
    private readonly AgentJobQueue _jobQueue;
    private readonly AgentConfiguredCapturePauseCoordinator? _configuredCapturePause;
    private readonly AgentStagingWriter _stagingWriter;
    private readonly AgentRuntimeDiagnosticsSampler _diagnosticsSampler;
    private readonly NetworkCaptureService _networkCaptureService;
    private readonly AgentConfigurationCheckService _configurationChecks;
    private readonly AgentMonitoringConfigurationService _monitoringConfiguration;
    private readonly AgentCaptureConfigurationService _captureConfiguration;
    private readonly CaptureCompatibilityAssessment _captureCompatibility;
    private readonly IFeatureCatalog _featureCatalog;
    private readonly IReadOnlyList<EvidenceSourceAdapterDescriptor> _evidenceSourceAdapters;
    private readonly Func<CaptureHealthReport> _getCaptureHealth;
    private readonly Func<Guid, bool> _requestLiveCaptureStop;
    private readonly Func<string, bool> _requestLiveCaptureSourceStop;
    private readonly Func<string, bool> _requestLiveCaptureSourceStart;
    private readonly Action _requestShutdown;
    private readonly TextWriter _log;
    private readonly string _pipeName;
    private readonly bool _shutdownOnly;
    private readonly AgentIpcTransportPolicy _transportPolicy;
    private readonly IAgentPipeConnectionAuthorizer _connectionAuthorizer;
    private readonly AgentIpcConnectionLimiter _connectionLimiter;
    private readonly AgentPairingRuntime? _pairingRuntime;
    private static readonly DateTime ProcessStartedAtUtc = GetProcessStartedAtUtc();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly ConcurrentDictionary<int, Task> _connections = new();
    private readonly Task _serverTask;
    private volatile DatabaseChangedNotification? _latestDatabaseChanged;
    private int _nextConnectionId;

    public AgentNamedPipeServer(
        AgentOptions options,
        AgentJobQueue jobQueue,
        AgentStagingWriter stagingWriter,
        AgentRuntimeDiagnosticsSampler diagnosticsSampler,
        NetworkCaptureService networkCaptureService,
        AgentConfigurationCheckService configurationChecks,
        AgentMonitoringConfigurationService monitoringConfiguration,
        AgentCaptureConfigurationService captureConfiguration,
        CaptureCompatibilityAssessment captureCompatibility,
        IFeatureCatalog featureCatalog,
        IReadOnlyList<EvidenceSourceAdapterDescriptor> evidenceSourceAdapters,
        Func<CaptureHealthReport> getCaptureHealth,
        Func<Guid, bool> requestLiveCaptureStop,
        Func<string, bool> requestLiveCaptureSourceStop,
        Func<string, bool> requestLiveCaptureSourceStart,
        Action requestShutdown,
        TextWriter log,
        AgentPairingRuntime? pairingRuntime,
        string? pipeName = null,
        bool shutdownOnly = false,
        AgentIpcTransportPolicy? transportPolicy = null,
        IAgentPipeConnectionAuthorizer? connectionAuthorizer = null,
        AgentConfiguredCapturePauseCoordinator? configuredCapturePause = null,
        bool commandRuntimeOnly = false)
    {
        _options = options;
        _jobQueue = jobQueue;
        _configuredCapturePause = configuredCapturePause;
        _stagingWriter = stagingWriter;
        _diagnosticsSampler = diagnosticsSampler;
        _networkCaptureService = networkCaptureService;
        _configurationChecks = configurationChecks;
        _monitoringConfiguration = monitoringConfiguration;
        _captureConfiguration = captureConfiguration;
        _captureCompatibility = captureCompatibility ?? throw new ArgumentNullException(nameof(captureCompatibility));
        _featureCatalog = featureCatalog ?? throw new ArgumentNullException(nameof(featureCatalog));
        _evidenceSourceAdapters = evidenceSourceAdapters ?? throw new ArgumentNullException(nameof(evidenceSourceAdapters));
        _getCaptureHealth = getCaptureHealth;
        _requestLiveCaptureStop = requestLiveCaptureStop;
        _requestLiveCaptureSourceStop = requestLiveCaptureSourceStop;
        _requestLiveCaptureSourceStart = requestLiveCaptureSourceStart;
        _requestShutdown = requestShutdown;
        _log = log;
        _pairingRuntime = commandRuntimeOnly
            ? pairingRuntime
            : pairingRuntime ?? throw new ArgumentNullException(nameof(pairingRuntime));
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? AgentContracts.PipeName : pipeName;
        _shutdownOnly = shutdownOnly;
        _transportPolicy = transportPolicy ?? AgentIpcTransportPolicy.InteractiveLocal;
        _connectionAuthorizer = connectionAuthorizer ?? new CurrentUserAgentPipeConnectionAuthorizer();
        _connectionLimiter = new AgentIpcConnectionLimiter(_transportPolicy.MaxConcurrentConnectionsPerEndpoint);
        _latestDatabaseChanged = _stagingWriter.GetLatestDatabaseChangedNotification();
        if (!_shutdownOnly)
        {
            _jobQueue.JobProgressChanged += OnJobProgressChanged;
            _stagingWriter.DatabaseCommitted += OnDatabaseCommitted;
        }
        _serverTask = commandRuntimeOnly ? Task.CompletedTask : Task.Run(RunAsync);
    }

    public async ValueTask DisposeAsync()
    {
        if (!_shutdownOnly)
        {
            _jobQueue.JobProgressChanged -= OnJobProgressChanged;
            _stagingWriter.DatabaseCommitted -= OnDatabaseCommitted;
        }
        _shutdown.Cancel();
        try
        {
            await _serverTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
        }

        if (!_connections.IsEmpty)
        {
            await Task.WhenAll(_connections.Values).ConfigureAwait(false);
        }

        _connectionLimiter.Dispose();
        _shutdown.Dispose();
    }

    private async Task RunAsync()
    {
        var pipeRole = _shutdownOnly ? "shutdown control" : "IPC";
        _log.WriteLine(
            $"[{DateTimeOffset.Now:O}] Named-pipe {pipeRole} listening on {_pipeName}; " +
            $"authorization=current-account-sid; active-limit={_transportPolicy.MaxConcurrentConnectionsPerEndpoint}; " +
            $"request-limit={_transportPolicy.MaxRequestBytes} bytes; " +
            $"request-timeout={_transportPolicy.RequestReadTimeout.TotalSeconds:0} seconds.");
        while (!_shutdown.IsCancellationRequested)
        {
            var pipe = AgentNamedPipeServerStreamFactory.Create(
                _pipeName,
                _transportPolicy.MaxPipeServerInstances);

            var waitResult = await AgentPipeListenerConnectionBoundary.RunAsync(
                cancellationToken => pipe.WaitForConnectionAsync(cancellationToken),
                _shutdown.Token,
                ex => LogRecoverableConnectionFailure("accept", ex)).ConfigureAwait(false);
            if (waitResult != AgentPipeListenerOperationResult.Completed)
            {
                var disposeResult = await AgentPipeListenerConnectionBoundary.RunAsync(
                    _ => pipe.DisposeAsync().AsTask(),
                    _shutdown.Token,
                    ex => LogRecoverableConnectionFailure("accept-dispose", ex)).ConfigureAwait(false);
                if (waitResult == AgentPipeListenerOperationResult.Shutdown ||
                    disposeResult == AgentPipeListenerOperationResult.Shutdown)
                {
                    return;
                }

                continue;
            }

            if (!_connectionLimiter.TryAcquire(out var connectionLease))
            {
                var saturatedResult = await AgentPipeListenerConnectionBoundary.RunAsync(
                    async cancellationToken =>
                    {
                        await using (pipe.ConfigureAwait(false))
                        {
                            await HandleSaturatedConnectionAsync(pipe, cancellationToken).ConfigureAwait(false);
                        }
                    },
                    _shutdown.Token,
                    ex => LogRecoverableConnectionFailure("saturated-connection", ex)).ConfigureAwait(false);
                if (saturatedResult == AgentPipeListenerOperationResult.Shutdown)
                {
                    return;
                }

                continue;
            }

            var connectionId = Interlocked.Increment(ref _nextConnectionId);
            var connectionTask = Task.Run(async () =>
            {
                using (connectionLease)
                {
                    await AgentPipeListenerConnectionBoundary.RunAsync(
                        async cancellationToken =>
                        {
                            await using (pipe.ConfigureAwait(false))
                            {
                                await HandleConnectionAsync(pipe, cancellationToken).ConfigureAwait(false);
                            }
                        },
                        _shutdown.Token,
                        ex => LogRecoverableConnectionFailure("connected-dispose", ex)).ConfigureAwait(false);
                }
            });
            _connections[connectionId] = connectionTask;
            _ = connectionTask.ContinueWith(
                _ => _connections.TryRemove(connectionId, out Task? _),
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }

    private void LogRecoverableConnectionFailure(string phase, IOException exception)
    {
        var message = string.IsNullOrWhiteSpace(exception.Message)
            ? "none"
            : exception.Message.Replace('\r', ' ').Replace('\n', ' ');
        if (message.Length > 160)
        {
            message = message[..160];
        }

        _log.WriteLine(
            $"[{DateTimeOffset.Now:O}] Named-pipe connection ended before completion; " +
            $"endpoint={(_shutdownOnly ? "shutdown-control" : "command")}; pipe={_pipeName}; phase={phase}; " +
            $"exception={exception.GetType().Name}; message={message}.");
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var requestLabel = "unread request";
        try
        {
            var authorization = AuthorizeConnection(pipe);
            var dispatch = await AgentIpcRequestDispatcher.DispatchAsync(
                pipe,
                authorization,
                _transportPolicy,
                HandleRequestJsonAsync,
                cancellationToken).ConfigureAwait(false);
            requestLabel = dispatch.RequestJson is null
                ? DescribeTransportDiagnostic(dispatch.DiagnosticCode)
                : DescribeRequestJson(dispatch.RequestJson);
            await WriteResponseAsync(pipe, dispatch.Response, cancellationToken).ConfigureAwait(false);
            LogIpcRequest(requestLabel, dispatch.Response, stopwatch.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Named-pipe {requestLabel} failed after {stopwatch.Elapsed.TotalMilliseconds:F1} ms: {ex.Message}");
        }
    }

    private void LogIpcRequest(string requestLabel, AgentIpcResponse response, TimeSpan elapsed)
    {
        var error = string.IsNullOrWhiteSpace(response.ErrorCode) ? "none" : response.ErrorCode;
        var cachedDatabaseDiagnostics = response.Health?.Runtime.LiveDatabaseDiagnosticsCached == true ? "yes" : "no";
        _log.WriteLine(
            $"[{DateTimeOffset.Now:O}] IPC {requestLabel} completed in {elapsed.TotalMilliseconds:F1} ms; " +
            $"success={response.Success}; error={error}; cached_db_diagnostics={cachedDatabaseDiagnostics}.");
    }

    private static string DescribeRequestJson(string? requestJson)
    {
        if (string.IsNullOrWhiteSpace(requestJson))
        {
            return "empty request";
        }

        try
        {
            return DescribeRequest(JsonSerializer.Deserialize<AgentIpcRequest>(requestJson, AgentIpcJson.JsonOptions));
        }
        catch (JsonException)
        {
            return "invalid JSON request";
        }
    }

    private static string DescribeRequest(AgentIpcRequest? request)
    {
        if (request == null)
        {
            return "null request";
        }

        return request.Kind switch
        {
            AgentIpcRequestKind.Health => "Health request",
            AgentIpcRequestKind.SubmitCommand => $"{request.CommandKind} command",
            AgentIpcRequestKind.GetJobStatus when request.JobId.HasValue => $"job-status request {request.JobId.Value}",
            AgentIpcRequestKind.GetJobStatus => "job-status request",
            AgentIpcRequestKind.PairingChallenge => "pairing challenge",
            AgentIpcRequestKind.RotatePairing => "pairing rotation",
            AgentIpcRequestKind.RevokePairing => "pairing revocation",
            _ => $"{request.Kind} request"
        };
    }

    private async Task<AgentIpcResponse> HandleRequestJsonAsync(string requestJson, CancellationToken cancellationToken)
    {
        AgentIpcRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<AgentIpcRequest>(requestJson, AgentIpcJson.JsonOptions);
        }
        catch (JsonException ex)
        {
            return AgentIpcResponse.Failure(Guid.Empty, "InvalidJson", $"The agent could not parse the pipe request: {ex.Message}");
        }

        if (request is null)
        {
            return AgentIpcResponse.Failure(Guid.Empty, "InvalidRequest", "The agent received an empty request body.");
        }

        if (request.ContractVersion != AgentContracts.ContractVersion)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ContractVersionMismatch",
                $"Viewer contract {request.ContractVersion} is not compatible with agent contract {AgentContracts.ContractVersion}.");
        }

        if (request.Kind == AgentIpcRequestKind.PairingChallenge)
        {
            return _pairingRuntime!.CreateChallenge(_pipeName, request);
        }

        var pairing = _pairingRuntime!.Authenticate(_pipeName, request);
        if (!pairing.Allowed)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                pairing.ErrorCode,
                pairing.ErrorMessage);
        }

        if (_shutdownOnly &&
            (request.Kind != AgentIpcRequestKind.SubmitCommand ||
             request.CommandKind != AgentCommandKind.ShutdownAgent))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ShutdownControlOnly",
                "The dedicated shutdown-control pipe accepts only ShutdownAgentCommand.");
        }

        try
        {
            return request.Kind switch
            {
                AgentIpcRequestKind.Health => HandleHealth(request),
                AgentIpcRequestKind.SubmitCommand => await HandleCommandAsync(request, cancellationToken).ConfigureAwait(false),
                AgentIpcRequestKind.GetJobStatus => HandleJobStatus(request),
                AgentIpcRequestKind.RotatePairing when !_shutdownOnly =>
                    AgentIpcResponse.Ok(request.RequestId) with
                    {
                        PairingStatus = _pairingRuntime!.Rotate()
                    },
                AgentIpcRequestKind.RevokePairing when !_shutdownOnly =>
                    AgentIpcResponse.Ok(request.RequestId) with
                    {
                        PairingStatus = _pairingRuntime!.Revoke()
                    },
                _ => AgentIpcResponse.Failure(request.RequestId, "UnknownRequest", $"Unknown agent IPC request kind: {request.Kind}.")
            };
        }
        catch (JsonException ex)
        {
            return AgentIpcResponse.Failure(request.RequestId, "InvalidCommandJson", $"The agent could not parse the command payload: {ex.Message}");
        }
        catch (AgentQueueSaturatedException ex)
        {
            return AgentIpcResponse.Failure(request.RequestId, "QueueSaturated", ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return AgentIpcResponse.Failure(request.RequestId, "InvalidCommand", ex.Message);
        }
        catch (ArgumentException ex)
        {
            return AgentIpcResponse.Failure(request.RequestId, "InvalidCommand", ex.Message);
        }
    }

    private AgentIpcResponse HandleHealth(AgentIpcRequest request)
    {
        var writerSnapshot = _stagingWriter.GetSnapshot();
        var diagnostics = _diagnosticsSampler.GetSnapshot();
        var captureHealth = _getCaptureHealth();
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            Health = new AgentHealthSnapshot
            {
                AgentVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? string.Empty,
                ProcessId = Environment.ProcessId,
                MachineName = Environment.MachineName,
                DatabasePath = _options.DatabasePath,
                SessionId = _options.SessionPaths?.SessionId ?? string.Empty,
                Host = _options.Host,
                WorkspaceMode = _options.CaptureSealed
                    ? CaptureWorkspaceMode.ArchivedCapture
                    : CaptureWorkspaceMode.LiveCapture,
                CaptureSealed = _options.CaptureSealed,
                CaptureCompatibility = _captureCompatibility,
                ReleaseProfile = AgentCommandFeaturePolicy.CreateReleaseProfileSnapshot(
                    _featureCatalog,
                    request.ViewerReleaseId),
                EvidenceSourceAdapters = _evidenceSourceAdapters,
                StartedAtUtc = ProcessStartedAtUtc,
                KnownJobCount = _jobQueue.KnownJobCount,
                Runtime = _jobQueue.GetRuntimeSnapshot() with
                {
                    WriterQueueCapacity = writerSnapshot.QueueCapacity,
                    WriterPendingWorkItemCount = writerSnapshot.PendingWorkItemCount,
                    WriterPeakPendingWorkItemCount = writerSnapshot.PeakPendingWorkItemCount,
                    WriterCompletedWorkItemCount = writerSnapshot.CompletedWorkItemCount,
                    WriterFailedWorkItemCount = writerSnapshot.FailedWorkItemCount,
                    WriterCompletedRowCount = writerSnapshot.CompletedRowCount,
                    WriterFailedRowCount = writerSnapshot.FailedRowCount,
                    WriterLastQueueDelayMilliseconds = writerSnapshot.LastQueueDelayMilliseconds,
                    WriterMaxQueueDelayMilliseconds = writerSnapshot.MaxQueueDelayMilliseconds,
                    WriterLastTransactionMilliseconds = writerSnapshot.LastTransactionMilliseconds,
                    WriterMaxTransactionMilliseconds = writerSnapshot.MaxTransactionMilliseconds,
                    WriterLastBatchRowCount = writerSnapshot.LastBatchRowCount,
                    WriterMaxBatchRowCount = writerSnapshot.MaxBatchRowCount,
                    WriterLastOperation = writerSnapshot.LastOperationName,
                    WriterBusyOrLockedFailureCount = writerSnapshot.BusyOrLockedFailureCount,
                    WriterLastSqliteError = writerSnapshot.LastSqliteError,
                    WriterLastSqliteErrorUtc = writerSnapshot.LastSqliteErrorUtc,
                    WriterMaxRowsPerTransaction = writerSnapshot.MaxRowsPerTransaction,
                    WriterMaxBatchLatencyMilliseconds = writerSnapshot.MaxBatchLatencyMilliseconds,
                    WriterBackpressureWarningWorkItemCount = writerSnapshot.BackpressureWarningWorkItemCount,
                    WriterBackpressureActive = writerSnapshot.IsBackpressureActive,
                    WriterCheckpointWalThresholdBytes = writerSnapshot.CheckpointWalThresholdBytes,
                    WriterCheckpointMinIntervalSeconds = writerSnapshot.CheckpointMinIntervalSeconds,
                    WriterLastCheckpointSummary = writerSnapshot.LastCheckpointSummary,
                    WriterLastCheckpointUtc = writerSnapshot.LastCheckpointUtc,
                    LiveDatabaseDiagnostics = diagnostics.DatabaseDiagnostics,
                    LiveDatabaseDiagnosticsCapturedAtUtc = diagnostics.DatabaseDiagnosticsCapturedAtUtc,
                    LiveDatabaseDiagnosticsCached = diagnostics.DatabaseDiagnostics != null,
                    LiveDatabaseDiagnosticsCacheStatus = diagnostics.DatabaseDiagnosticsCacheStatus,
                    CaptureDiagnosticsLogPath = diagnostics.LogPath,
                    CaptureDiagnosticsLastSampleUtc = diagnostics.LastSampleUtc,
                    CaptureDiagnosticsSummary = diagnostics.Summary
                },
                CaptureHealth = captureHealth,
                Control = _jobQueue.GetControlSnapshot(captureHealth)
            },
            DatabaseChanged = LatestDatabaseChanged
        };
    }

    private async Task<AgentIpcResponse> HandleCommandAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        if (request.Payload is null)
        {
            return AgentIpcResponse.Failure(request.RequestId, "MissingPayload", "The command request did not include a command payload.");
        }

        var featureFailure = ValidateCommandFeaturePolicy(request);
        if (featureFailure != null)
        {
            return featureFailure;
        }

        var compatibilityFailure = ValidateCommandCompatibility(request);
        if (compatibilityFailure != null)
        {
            return compatibilityFailure;
        }

        var policyFailure = ValidateCommandWritePolicy(request);
        if (policyFailure != null)
        {
            return policyFailure;
        }

        var sealedTargetFailure = ValidateSealedDerivedTarget(request);
        if (sealedTargetFailure != null)
        {
            return sealedTargetFailure;
        }

        return request.CommandKind switch
        {
            AgentCommandKind.QueueBackfill => AgentIpcResponse.Failure(
                request.RequestId,
                "CommandNotAvailable",
                AgentCommandFeaturePolicy.BackfillUnavailableReason),
            AgentCommandKind.QueueImport => await EnqueueImportAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.QueueEnrichment => await EnqueueEnrichmentAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.QueueProcessDump => await EnqueueProcessDumpAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.QueueZeekAnalysis => await EnqueueZeekAnalysisAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.QueueArtifactImport => await EnqueueArtifactImportAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.QueueMemoryImageImport => await EnqueueMemoryImageImportAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.QueueMemoryAcquisition => await EnqueueMemoryAcquisitionAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.QueueVolatilityAnalysis => await EnqueueVolatilityAnalysisAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.StartProcessMonitorCapture => await StartProcessMonitorCaptureAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.StopProcessMonitorCapture => await StopProcessMonitorCaptureAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.QueueProcessMonitorImport => await EnqueueProcessMonitorImportAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.QueueSqliteBenchmark => await EnqueueSqliteBenchmarkAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.StartNetworkCapture => await StartNetworkCaptureAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.StopNetworkCapture => await StopNetworkCaptureAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.StartLiveCapture => await StartLiveCaptureAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.StopLiveCapture => await StopLiveCaptureAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.StopEtwCapture => StopEtwCapture(request),
            AgentCommandKind.StopLiveCaptureSource => StopLiveCaptureSource(request),
            AgentCommandKind.StartLiveCaptureSource => StartLiveCaptureSource(request),
            AgentCommandKind.ShutdownAgent => ShutdownAgent(request),
            AgentCommandKind.CancelJob => await CancelJobAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.GetHostMonitoringConfiguration => GetHostMonitoringConfiguration(request),
            AgentCommandKind.SaveHostMonitoringConfiguration => SaveHostMonitoringConfiguration(request),
            AgentCommandKind.CheckHostMonitoringConfiguration => CheckHostMonitoringConfiguration(request),
            AgentCommandKind.DeployHostMonitoringConfiguration => DeployHostMonitoringConfiguration(request),
            AgentCommandKind.ReverseHostMonitoringDeployment => ReverseHostMonitoringDeployment(request),
            AgentCommandKind.CheckCaptureConfiguration => CheckCaptureConfiguration(request),
            AgentCommandKind.GetCaptureConfiguration => GetCaptureConfiguration(request),
            AgentCommandKind.SaveCaptureConfiguration => SaveCaptureConfiguration(request),
            AgentCommandKind.StartConfiguredCapture => await StartConfiguredCaptureAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.StopConfiguredCapture => await StopConfiguredCaptureAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.PauseJob => await PauseConfiguredCaptureAsync(request, cancellationToken).ConfigureAwait(false),
            AgentCommandKind.ResumeJob => await ResumeConfiguredCaptureAsync(request, cancellationToken).ConfigureAwait(false),
            _ => AgentIpcResponse.Failure(request.RequestId, "UnknownCommand", $"Unknown agent command kind: {request.CommandKind}.")
        };
    }

    private AgentIpcResponse CheckHostMonitoringConfiguration(AgentIpcRequest request)
    {
        var command = DeserializeCommand<CheckHostMonitoringConfigurationCommand>(request);
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            ConfigurationCheck = _configurationChecks.CheckHostMonitoringConfiguration(command)
        };
    }

    private AgentIpcResponse GetHostMonitoringConfiguration(AgentIpcRequest request)
    {
        var command = DeserializeCommand<GetHostMonitoringConfigurationCommand>(request);
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            HostMonitoringConfiguration = _monitoringConfiguration.GetHostMonitoringConfiguration(command)
        };
    }

    private AgentIpcResponse SaveHostMonitoringConfiguration(AgentIpcRequest request)
    {
        var command = DeserializeCommand<SaveHostMonitoringConfigurationCommand>(request);
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            HostMonitoringConfiguration = _monitoringConfiguration.SaveHostMonitoringConfiguration(command)
        };
    }

    private AgentIpcResponse DeployHostMonitoringConfiguration(AgentIpcRequest request)
    {
        var command = DeserializeCommand<DeployHostMonitoringConfigurationCommand>(request);
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            MonitoringDeployment = _monitoringConfiguration.DeployHostMonitoringConfiguration(command)
        };
    }

    private AgentIpcResponse ReverseHostMonitoringDeployment(AgentIpcRequest request)
    {
        var command = DeserializeCommand<ReverseHostMonitoringDeploymentCommand>(request);
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            MonitoringDeployment = _monitoringConfiguration.ReverseHostMonitoringDeployment(command)
        };
    }

    private AgentIpcResponse CheckCaptureConfiguration(AgentIpcRequest request)
    {
        var command = DeserializeCommand<CheckCaptureConfigurationCommand>(request);
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            ConfigurationCheck = _configurationChecks.CheckCaptureConfiguration(command)
        };
    }

    private AgentIpcResponse GetCaptureConfiguration(AgentIpcRequest request)
    {
        var command = DeserializeCommand<GetCaptureConfigurationCommand>(request);
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            CaptureConfiguration = _captureConfiguration.GetCaptureConfiguration(command)
        };
    }

    private AgentIpcResponse SaveCaptureConfiguration(AgentIpcRequest request)
    {
        var command = DeserializeCommand<SaveCaptureConfigurationCommand>(request);
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            CaptureConfiguration = _captureConfiguration.SaveCaptureConfiguration(command)
        };
    }

    private async Task<AgentIpcResponse> StartLiveCaptureAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<StartLiveCaptureCommand>(request);
        return await StartLiveCaptureCoreAsync(request, command, "Agent live capture", captureLifecycle: null, cancellationToken).ConfigureAwait(false);
    }

    private async Task<AgentIpcResponse> StartLiveCaptureCoreAsync(
        AgentIpcRequest request,
        StartLiveCaptureCommand command,
        string sourceDisplayName,
        AgentCaptureLifecycleResult? captureLifecycle,
        CancellationToken cancellationToken)
    {
        if (_jobQueue.TryGetActiveJob(JobKind.LiveCapture, out var activeProgress))
        {
            return AgentIpcResponse.Ok(request.RequestId) with
            {
                AcceptedJobId = activeProgress.JobId,
                Job = activeProgress,
                DatabaseChanged = LatestDatabaseChanged,
                CaptureLifecycle = captureLifecycle
            };
        }

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.LiveCapture,
            SourceType = "AgentLiveCapture",
            SourceDisplayName = sourceDisplayName,
            EvidenceSourceAdapterId = RuntimeProcessSnapshotEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = RuntimeProcessSnapshotEvidenceSourceAdapter.Version,
            ParserVersion = RuntimeProcessSnapshotEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(
                RuntimeProcessSnapshotEvidenceSourceAdapter.Id,
                command.CaptureId),
            CaptureId = command.CaptureId,
            IsCaptureScoped = true,
            IsLiveSource = true,
            Ownership = captureLifecycle == null
                ? AgentJobOwnership.AnalystInitiated
                : AgentJobOwnership.ConfiguredCapture,
            Parameters = new
            {
                command.CaptureId,
                command.IssuedAtUtc,
                command.ProcessRefreshIntervalSeconds,
                command.EtwProfileId,
                command.EtwProfileDisplayName,
                command.EtwProfilePath,
                command.CollectRuntimeEvents,
                command.CollectEtwEvents,
                command.CollectSecurityEvents,
                command.CollectPowerShellEvents,
                command.CollectOtherWindowsEvents,
                command.CollectSysmonEvents,
                sources = new[]
                    {
                        command.CollectRuntimeEvents ? "Runtime" : string.Empty,
                        command.CollectEtwEvents ? "ETW" : string.Empty,
                        command.CollectSecurityEvents ? "Security" : string.Empty,
                        command.CollectPowerShellEvents ? "PowerShell" : string.Empty,
                        command.CollectOtherWindowsEvents ? "WindowsOther" : string.Empty,
                        command.CollectSysmonEvents ? "Sysmon" : string.Empty
                    }
                    .Where(source => !string.IsNullOrWhiteSpace(source))
                    .ToArray(),
                sourceOptions = new
                {
                    command.CollectRuntimeEvents,
                    command.CollectEtwEvents,
                    command.CollectSecurityEvents,
                    command.CollectPowerShellEvents,
                    command.CollectOtherWindowsEvents,
                    command.CollectSysmonEvents
                }
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId) with
        {
            CaptureLifecycle = captureLifecycle
        };
    }

    private async Task<AgentIpcResponse> StopLiveCaptureAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        _ = DeserializeCommand<StopLiveCaptureCommand>(request);
        if (!_jobQueue.TryGetActiveJob(JobKind.LiveCapture, out var activeProgress))
        {
            return AgentIpcResponse.Failure(request.RequestId, "LiveCaptureNotRunning", "Live capture is not running.");
        }

        if (!_requestLiveCaptureStop(activeProgress.JobId))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "LiveCaptureStopNotAccepted",
                "Live capture is active in the job queue, but the capture handler did not accept the stop request.");
        }

        _jobQueue.MarkJobStopRequested(activeProgress.JobId);

        return AgentIpcResponse.Ok(request.RequestId) with
        {
            AcceptedJobId = activeProgress.JobId,
            Job = _jobQueue.TryGetJobStatus(activeProgress.JobId, out var progress) ? progress : activeProgress,
            DatabaseChanged = LatestDatabaseChanged
        };
    }

    private AgentIpcResponse StopEtwCapture(AgentIpcRequest request)
    {
        _ = DeserializeCommand<StopEtwCaptureCommand>(request);
        return StopLiveCaptureSource(request, "ETW");
    }

    internal Task<AgentIpcResponse> ExecuteAuthenticatedCommandAsync(
        AgentIpcRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return request.Kind == AgentIpcRequestKind.SubmitCommand
            ? HandleCommandAsync(request, cancellationToken)
            : Task.FromResult(AgentIpcResponse.Failure(
                request.RequestId,
                "InfrastructureCommandKindRejected",
                "The authenticated Infrastructure command adapter accepts only typed command submissions."));
    }

    private static DateTime GetProcessStartedAtUtc()
    {
        using var process = Process.GetCurrentProcess();
        return process.StartTime.ToUniversalTime();
    }

    private AgentIpcResponse StopLiveCaptureSource(AgentIpcRequest request)
    {
        var command = DeserializeCommand<StopLiveCaptureSourceCommand>(request);
        return StopLiveCaptureSource(request, command.Source);
    }

    private AgentIpcResponse StopLiveCaptureSource(AgentIpcRequest request, string source)
    {
        if (!_requestLiveCaptureSourceStop(source))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "LiveCaptureSourceNotRunning",
                $"{source} capture is not active in the current live-capture job.");
        }

        return AgentIpcResponse.Ok(request.RequestId) with
        {
            DatabaseChanged = LatestDatabaseChanged
        };
    }

    private AgentIpcResponse? ValidateCommandWritePolicy(AgentIpcRequest request)
    {
        var context = request.Payload!.Value.Deserialize<AgentCommandWriteContext>(AgentIpcJson.JsonOptions)
            ?? throw new InvalidOperationException("The command write context was empty.");
        var expectedCategory = CaptureWritePolicy.GetCategory(request.CommandKind);
        if (context.RequestedWriteCategory != expectedCategory)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "WriteCategoryMismatch",
                $"Command '{request.CommandKind}' declared {context.RequestedWriteCategory}, but policy requires {expectedCategory}.");
        }

        var expectedMode = _options.CaptureSealed
            ? CaptureWorkspaceMode.ArchivedCapture
            : CaptureWorkspaceMode.LiveCapture;
        if (context.TargetWorkspaceMode != expectedMode)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "WorkspaceModeMismatch",
                $"Command targets {context.TargetWorkspaceMode}, but this agent is running as {expectedMode}.");
        }

        var expectedSessionId = _options.SessionPaths?.SessionId ?? string.Empty;
        if (string.IsNullOrWhiteSpace(context.TargetSessionId) ||
            !string.Equals(context.TargetSessionId, expectedSessionId, StringComparison.Ordinal))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "TargetSessionMismatch",
                $"Command target session '{context.TargetSessionId}' does not match agent session '{expectedSessionId}'.");
        }

        if (!PathsEqual(context.TargetDatabasePath, _options.DatabasePath))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "TargetDatabaseMismatch",
                $"Command target database '{context.TargetDatabasePath}' does not match agent database '{_options.DatabasePath}'.");
        }

        if (!CaptureWritePolicy.IsAllowed(expectedMode, expectedCategory))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ArchivedCaptureSealed",
                $"{CaptureWritePolicy.ArchivedCaptureSealedMessage} '{request.CommandKind}' requests {expectedCategory}.");
        }

        return null;
    }

    private AgentIpcResponse? ValidateCommandFeaturePolicy(AgentIpcRequest request)
    {
        var decision = AgentCommandFeaturePolicy.EvaluateRequest(_featureCatalog, request);
        return decision.Allowed
            ? null
            : AgentIpcResponse.Failure(
                request.RequestId,
                decision.ErrorCode,
                decision.ErrorMessage,
                decision.IsRetryable);
    }

    private AgentIpcResponse? ValidateCommandCompatibility(AgentIpcRequest request)
    {
        var required = _options.CaptureSealed
            ? CaptureOpenCapability.MaintainAnalysisState
            : CaptureOpenCapability.WritePrimaryEvidence;
        return _captureCompatibility.Allows(required)
            ? null
            : AgentIpcResponse.Failure(
                request.RequestId,
                _captureCompatibility.StatusCode,
                CaptureCompatibilityPolicy.FormatDiagnostic(
                    _captureCompatibility,
                    _options.DatabasePath));
    }

    private AgentIpcResponse? ValidateSealedDerivedTarget(AgentIpcRequest request)
    {
        if (!_options.CaptureSealed ||
            CaptureWritePolicy.GetCategory(request.CommandKind) != CaptureWriteCategory.DerivedEnrichment)
        {
            return null;
        }

        var query = new SqliteStagingQueryService(
            _options.DatabasePath,
            openContext: _options.CaptureSealed
                ? CaptureOpenContext.ArchivedAnalysisMaintenance
                : CaptureOpenContext.AgentWritableLive,
            expectedEvidenceSessionId: _options.SessionPaths?.SessionId ?? string.Empty);
        if (request.CommandKind == AgentCommandKind.QueueEnrichment)
        {
            var command = DeserializeCommand<QueueEnrichmentCommand>(request);
            var missingEntityId = command.ProcessEntityIds?
                .Where(id => !string.IsNullOrWhiteSpace(id))
                .FirstOrDefault(id => !query.GetProcessByEntityId(id).IsFound);
            if (missingEntityId != null)
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "ArchivedProcessNotFound",
                    $"Archived enrichment target '{missingEntityId}' is not recorded in the current capture.");
            }
            var missingKey = command.ProcessKeys?
                .Where(key => !string.IsNullOrWhiteSpace(key))
                .FirstOrDefault(key => !query.GetProcessByKey(key).IsFound);
            return missingKey == null
                ? null
                : AgentIpcResponse.Failure(
                    request.RequestId,
                    "ArchivedProcessNotFound",
                    $"Archived enrichment target '{missingKey}' is not recorded in the current capture.");
        }

        if (request.CommandKind == AgentCommandKind.QueueZeekAnalysis)
        {
            var command = DeserializeCommand<QueueZeekAnalysisCommand>(request);
            var capture = string.IsNullOrWhiteSpace(command.CaptureId)
                ? null
                : query.GetNetworkCaptureById(command.CaptureId);
            if (capture == null)
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "ArchivedPcapNotFound",
                    "Archived Zeek analysis requires a PCAP already recorded in the current capture.");
            }

            if (!string.IsNullOrWhiteSpace(command.PcapPath) && !PathsEqual(command.PcapPath, capture.FilePath))
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "ArchivedPcapPathMismatch",
                    "Archived Zeek analysis cannot substitute a new PCAP path for the recorded capture artifact.");
            }
        }

        if (request.CommandKind == AgentCommandKind.QueueVolatilityAnalysis)
        {
            var command = DeserializeCommand<QueueVolatilityAnalysisCommand>(request);
            var image = string.IsNullOrWhiteSpace(command.ImageId)
                ? null
                : query.GetMemoryImageById(command.ImageId);
            if (image == null)
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "ArchivedMemoryImageNotFound",
                    "Archived Volatility analysis requires a memory image already recorded in the current capture.");
            }

            if (!string.IsNullOrWhiteSpace(command.ImagePath) && !PathsEqual(command.ImagePath, image.FilePath))
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "ArchivedMemoryImagePathMismatch",
                    "Archived Volatility analysis cannot substitute a new image path for the recorded artifact.");
            }
        }

        return null;
    }

    private static bool PathsEqual(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right))
        {
            return false;
        }

        try
        {
            return string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private AgentPipeAuthorizationResult AuthorizeConnection(NamedPipeServerStream pipe)
    {
        try
        {
            var result = _connectionAuthorizer.Authorize(pipe);
            if (!result.Allowed)
            {
                _log.WriteLine(
                    $"[{DateTimeOffset.Now:O}] Named-pipe authorization rejected; " +
                    $"endpoint={(_shutdownOnly ? "shutdown-control" : "command")}; code={result.DiagnosticCode}.");
            }

            return result;
        }
        catch
        {
            _log.WriteLine(
                $"[{DateTimeOffset.Now:O}] Named-pipe authorization rejected; " +
                $"endpoint={(_shutdownOnly ? "shutdown-control" : "command")}; code=AuthorizerFailure.");
            return AgentPipeAuthorizationResult.Deny("AuthorizerFailure");
        }
    }

    private async Task HandleSaturatedConnectionAsync(
        NamedPipeServerStream pipe,
        CancellationToken cancellationToken)
    {
        var authorization = AuthorizeConnection(pipe);
        var response = authorization.Allowed
            ? AgentIpcResponse.Failure(
                Guid.Empty,
                "ServerBusy",
                $"The local agent pipe is serving its {_transportPolicy.MaxConcurrentConnectionsPerEndpoint} active connection limit; retry later.")
            : AgentIpcResponse.Failure(
                Guid.Empty,
                "UnauthorizedCaller",
                "The local agent pipe caller is not authorized for this interactive agent.");
        await WriteResponseAsync(pipe, response, cancellationToken).ConfigureAwait(false);
        _log.WriteLine(
            $"[{DateTimeOffset.Now:O}] Named-pipe connection rejected before request read; " +
            $"endpoint={(_shutdownOnly ? "shutdown-control" : "command")}; error={response.ErrorCode}; " +
            $"active={_connectionLimiter.ActiveCount}; limit={_connectionLimiter.MaxConcurrentConnections}.");
    }

    private async Task WriteResponseAsync(
        NamedPipeServerStream pipe,
        AgentIpcResponse response,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_transportPolicy.ResponseWriteTimeout);
        await using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
        var responseJson = JsonSerializer.Serialize(response, AgentIpcJson.JsonOptions);
        await writer.WriteLineAsync(responseJson.AsMemory(), timeout.Token).ConfigureAwait(false);
    }

    private static string DescribeTransportDiagnostic(string diagnosticCode)
    {
        return diagnosticCode switch
        {
            "RequestTimeout" => "timed-out request",
            "RequestTooLarge" => "oversized request",
            "EmptyRequest" => "empty request",
            "Dispatched" => "request",
            _ => "unauthorized request"
        };
    }

    private sealed record AgentCommandWriteContext
    {
        public string TargetSessionId { get; init; } = string.Empty;
        public string TargetDatabasePath { get; init; } = string.Empty;
        public CaptureWorkspaceMode TargetWorkspaceMode { get; init; } = CaptureWorkspaceMode.None;
        public CaptureWriteCategory RequestedWriteCategory { get; init; } = CaptureWriteCategory.Unspecified;
    }

    private AgentIpcResponse StartLiveCaptureSource(AgentIpcRequest request)
    {
        var command = DeserializeCommand<StartLiveCaptureSourceCommand>(request);
        if (!_requestLiveCaptureSourceStart(command.Source))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "LiveCaptureSourceNotStopped",
                $"{command.Source} capture is not a stopped source in the current live-capture job.");
        }

        return AgentIpcResponse.Ok(request.RequestId) with
        {
            DatabaseChanged = LatestDatabaseChanged,
            PairingStatus = _pairingRuntime is null
                ? null
                : _pairingRuntime.Status with { State = AgentPairingState.Connected }
        };
    }

    private AgentIpcResponse ShutdownAgent(AgentIpcRequest request)
    {
        var command = DeserializeCommand<ShutdownAgentCommand>(request);
        if (string.IsNullOrWhiteSpace(command.ExpectedDatabasePath))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "MissingExpectedDatabasePath",
                "Shutdown refused because the viewer did not include its verified active-session database path.");
        }

        if (!IsExpectedDatabasePath(command.ExpectedDatabasePath))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "SessionMismatch",
                $"Shutdown refused because the agent database '{_options.DatabasePath}' does not match the viewer-verified active database '{command.ExpectedDatabasePath}'.");
        }

        var reason = string.IsNullOrWhiteSpace(command.Reason)
            ? "viewer request"
            : command.Reason;
        _log.WriteLine($"[{DateTimeOffset.Now:O}] Agent shutdown requested over IPC: {reason}.");

        _ = Task.Run(async () =>
        {
            await Task.Delay(100).ConfigureAwait(false);
            _requestShutdown();
        });

        return AgentIpcResponse.Ok(request.RequestId) with
        {
            DatabaseChanged = LatestDatabaseChanged
        };
    }

    private bool IsExpectedDatabasePath(string expectedDatabasePath)
    {
        if (string.IsNullOrWhiteSpace(expectedDatabasePath) ||
            string.IsNullOrWhiteSpace(_options.DatabasePath))
        {
            return false;
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(_options.DatabasePath),
                Path.GetFullPath(expectedDatabasePath),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private async Task<AgentIpcResponse> EnqueueImportAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<QueueImportCommand>(request);
        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.Import,
            SourceType = "AgentIpc",
            SourceDisplayName = "IPC import",
            SourcePath = command.ArchivePath,
            InputPath = command.ArchivePath,
            EvidenceSourceAdapterId = LegacyProcessSnapshotEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = LegacyProcessSnapshotEvidenceSourceAdapter.Version,
            ParserVersion = LegacyProcessSnapshotEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(LegacyProcessSnapshotEvidenceSourceAdapter.Id, string.Empty),
            Parameters = new
            {
                command.ArchivePath
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private async Task<AgentIpcResponse> EnqueueEnrichmentAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<QueueEnrichmentCommand>(request);
        var hasEntityIds = command.ProcessEntityIds is { Length: > 0 };
        var hasProcessKeys = command.ProcessKeys is { Length: > 0 };
        var scopeKinds = (command.AllProcesses ? 1 : 0) + (hasEntityIds ? 1 : 0) + (hasProcessKeys ? 1 : 0);
        if (scopeKinds != 1)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "EnrichmentScopeInvalid",
                "Enrichment requires exactly one explicit scope: all processes, process entity IDs, or exact process keys.");
        }

        string[]? processEntityIds = null;
        if (hasEntityIds && !AgentEvidenceActionPolicy.TryNormalizeProcessEntityIds(
                command.ProcessEntityIds,
                out processEntityIds,
                out var entityError))
        {
            return AgentIpcResponse.Failure(request.RequestId, "EnrichmentEntityScopeInvalid", entityError);
        }

        string[]? processKeys = null;
        if (hasProcessKeys && !AgentEvidenceActionPolicy.TryNormalizeProcessKeys(
                command.ProcessKeys,
                out processKeys,
                out var keyError))
        {
            return AgentIpcResponse.Failure(request.RequestId, "EnrichmentProcessKeyScopeInvalid", keyError);
        }

        var jobKind = AgentEnrichmentPlanning.GetJobKind(
            command.CaptureModules,
            command.CaptureHandles,
            command.CapturePe);
        if (jobKind == JobKind.Unknown)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "NoEnrichmentSelected",
                "Enrichment commands must enable module, handle, or PE analysis.");
        }

        if (!Enum.IsDefined(command.PeStringExtractionMode) ||
            !command.CapturePe && command.PeStringExtractionMode != PeStringExtractionMode.Deferred)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "PeStringExtractionModeInvalid",
                "PE string extraction mode must be a known value and is valid only with PE enrichment.");
        }

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = jobKind,
            SourceType = "AgentIpc",
            SourceDisplayName = jobKind == JobKind.PeAnalysis ? "IPC PE analysis" : "IPC artifact enrichment",
            RequestedWorkloads = AgentRequestedWorkloads.ForEnrichment(
                command.CaptureModules,
                command.CaptureHandles,
                command.CapturePe),
            Parameters = new
            {
                command.AllProcesses,
                ProcessEntityIds = processEntityIds,
                ProcessKeys = processKeys,
                command.CaptureModules,
                command.CaptureHandles,
                command.CapturePe,
                command.PeStringExtractionMode
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private async Task<AgentIpcResponse> EnqueueProcessDumpAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<QueueProcessDumpCommand>(request);
        if (string.IsNullOrWhiteSpace(command.ProcessKey))
        {
            return AgentIpcResponse.Failure(request.RequestId, "MissingProcessKey", "Process dump commands require a ProcessKey.");
        }

        if (!AgentEvidenceActionPolicy.TryNormalizeExactProcessKey(command.ProcessKey, out var processKey))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "InvalidProcessKey",
                "Process dump commands require exact PID_StartTimeTicks identity; PID-only targets are rejected.");
        }

        if (!Enum.IsDefined(command.DumpKind))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "InvalidProcessDumpKind",
                "Process dump kind must be Full or Mini.");
        }

        var expectedDumpsDirectory = _options.SessionPaths?.DumpsDirectory ?? string.Empty;
        if (string.IsNullOrWhiteSpace(expectedDumpsDirectory) ||
            string.IsNullOrWhiteSpace(command.OutputDirectory) ||
            !PathsEqual(command.OutputDirectory, expectedDumpsDirectory) ||
            command.OverwriteExisting)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessDumpOutputRejected",
                "Process dumps must use the active session Dumps directory and cannot request overwrite.");
        }

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.ProcessDump,
            SourceType = "AgentIpc",
            SourceDisplayName = "IPC process dump",
            Parameters = new
            {
                ProcessKey = processKey,
                command.DumpKind,
                OutputDirectory = Path.GetFullPath(expectedDumpsDirectory),
                OverwriteExisting = false
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private async Task<AgentIpcResponse> EnqueueZeekAnalysisAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<QueueZeekAnalysisCommand>(request);
        var hasCaptureId = !string.IsNullOrWhiteSpace(command.CaptureId);
        var hasPcapPath = !string.IsNullOrWhiteSpace(command.PcapPath);
        if (hasCaptureId == hasPcapPath)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ZeekSourceInvalid",
                "Zeek analysis requires exactly one capture id or explicit PCAP/PCAPNG path.");
        }

        var captureId = string.Empty;
        if (hasCaptureId && !AgentToolActionPolicy.TryNormalizeCaptureId(command.CaptureId, out captureId))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ZeekCaptureIdInvalid",
                "Zeek capture id is malformed or exceeds the bounded identifier length.");
        }

        var pcapPath = string.Empty;
        if (hasPcapPath &&
            (!TryNormalizeExistingFile(command.PcapPath, out pcapPath) ||
             !AgentToolActionPolicy.IsSupportedPcapPath(pcapPath)))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ZeekPcapInvalid",
                "Zeek explicit input must be an existing absolute PCAP or PCAPNG file.");
        }

        if (!AgentToolActionPolicy.TryNormalizeZeekToolMode(
                command.ZeekPath,
                command.WslDistributionName,
                command.WslZeekCommand,
                out _,
                out var zeekPath,
                out var wslDistribution,
                out var wslCommand,
                out var modeError))
        {
            return AgentIpcResponse.Failure(request.RequestId, "ZeekToolModeInvalid", modeError);
        }

        if (zeekPath.Length > 0 && !File.Exists(zeekPath))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ZeekExecutableUnavailable",
                "The explicit native Zeek executable does not exist or is inaccessible.");
        }

        var expectedZeekDirectory = _options.SessionPaths?.ZeekDirectory ?? string.Empty;
        if (string.IsNullOrWhiteSpace(expectedZeekDirectory) ||
            string.IsNullOrWhiteSpace(command.OutputDirectory) ||
            !AgentToolActionPolicy.IsStrictChildPath(expectedZeekDirectory, command.OutputDirectory))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ZeekOutputRejected",
                "Zeek output must be a contained child of the active session Zeek directory.");
        }

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.ZeekAnalysis,
            SourceType = "AgentZeek",
            SourceDisplayName = "Agent Zeek analysis",
            InputArtifactId = captureId,
            InputPath = pcapPath,
            EvidenceSourceAdapterId = ZeekNetworkEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = ZeekNetworkEvidenceSourceAdapter.Version,
            ParserVersion = ZeekNetworkEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(ZeekNetworkEvidenceSourceAdapter.Id, captureId),
            Parameters = new
            {
                CaptureId = captureId,
                PcapPath = pcapPath,
                ZeekPath = zeekPath,
                WslDistributionName = wslDistribution,
                WslZeekCommand = wslCommand,
                OutputDirectory = Path.GetFullPath(command.OutputDirectory)
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private async Task<AgentIpcResponse> EnqueueArtifactImportAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<QueueArtifactImportCommand>(request);
        if (string.IsNullOrWhiteSpace(command.Path))
        {
            return AgentIpcResponse.Failure(request.RequestId, "MissingArtifactPath", "Artifact import requires a file or folder path.");
        }

        string sourcePath;
        try
        {
            if (!Path.IsPathFullyQualified(command.Path))
            {
                throw new ArgumentException("The artifact path is not absolute.");
            }

            sourcePath = Path.GetFullPath(command.Path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ArtifactPathInvalid",
                "Artifact import requires a safely normalized absolute file or directory path.");
        }

        if (!File.Exists(sourcePath) && !Directory.Exists(sourcePath))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ArtifactPathNotFound",
                "Artifact import requires an existing file or directory path.");
        }

        if (File.Exists(sourcePath) && command.Recurse)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ArtifactRecurseInvalid",
                "Recursive artifact import is valid only for a directory source.");
        }

        if (!command.IncludeNtfs && !command.IncludePrefetch)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ArtifactFamilyMissing",
                "Artifact import requires NTFS, Prefetch, or both artifact families.");
        }

        if (command.MaxFiles is < 1 or > AgentEvidenceActionPolicy.MaximumFilesystemImportFiles)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ArtifactMaxFilesInvalid",
                $"Artifact import MaxFiles must be from 1 through {AgentEvidenceActionPolicy.MaximumFilesystemImportFiles}.");
        }

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.ArtifactImport,
            SourceType = "AgentArtifactImport",
            SourceDisplayName = "Agent filesystem artifact import",
            SourcePath = sourcePath,
            InputPath = sourcePath,
            EvidenceSourceAdapterId = FilesystemArtifactEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = FilesystemArtifactEvidenceSourceAdapter.Version,
            ParserVersion = FilesystemArtifactEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(
                FilesystemArtifactEvidenceSourceAdapter.Id,
                captureId: string.Empty),
            Parameters = new
            {
                Path = sourcePath,
                command.Recurse,
                command.IncludeNtfs,
                command.IncludePrefetch,
                command.MaxFiles
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private EvidenceIdentity CreateEvidenceIdentity(string sourceIdentityId, string captureId)
    {
        var evidenceSessionId = _options.SessionPaths?.SessionId ?? string.Empty;
        return new EvidenceIdentity
        {
            EvidenceSessionId = evidenceSessionId,
            CaptureId = captureId,
            SourceIdentityId = sourceIdentityId,
            HostId = Environment.MachineName,
            ExecutionRootId = evidenceSessionId
        };
    }

    private async Task<AgentIpcResponse> StartProcessMonitorCaptureAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<StartProcessMonitorCaptureCommand>(request);
        if (_jobQueue.TryGetInFlightJob(JobKind.ProcessMonitorCapture, out var activeProgress))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorCaptureAlreadyActive",
                $"Process Monitor capture job {activeProgress.JobId:D} is already active.");
        }

        if (!command.AcceptEula)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorEulaRequired",
                "Process Monitor capture requires explicit EULA acceptance.");
        }

        if (command.MaxRows is < 1 or > AgentToolActionPolicy.MaximumProcessMonitorRows)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorMaxRowsInvalid",
                $"Process Monitor MaxRows must be from 1 through {AgentToolActionPolicy.MaximumProcessMonitorRows}.");
        }

        if (!AgentToolActionPolicy.TryNormalizeCaptureId(command.CaptureId, out var captureId))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorCaptureIdInvalid",
                "Process Monitor capture requires one bounded canonical capture id.");
        }

        if (!TryNormalizeOptionalProcessMonitorExecutable(command.ProcmonPath, out var procmonPath))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorExecutableInvalid",
                "An explicit Process Monitor path must identify an existing Procmon.exe or Procmon64.exe.");
        }

        var processMonitorDirectory = _options.SessionPaths?.ProcessMonitorDirectory ?? string.Empty;
        if (string.IsNullOrWhiteSpace(processMonitorDirectory) ||
            !AgentToolActionPolicy.PathsEqual(command.OutputDirectory, processMonitorDirectory) ||
            !IsExpectedOwnedOutput(command.BackingFilePath, processMonitorDirectory, captureId, ".pml") ||
            !IsExpectedOwnedOutput(command.CsvOutputPath, processMonitorDirectory, captureId, ".csv"))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorOutputRejected",
                "Process Monitor capture outputs must use the active session ProcessMonitor directory and generated capture id.");
        }

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.ProcessMonitorCapture,
            SourceType = "AgentProcessMonitorCapture",
            SourceDisplayName = "Agent Process Monitor capture",
            CaptureId = captureId,
            EvidenceSourceAdapterId = ProcessMonitorEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = ProcessMonitorEvidenceSourceAdapter.Version,
            ParserVersion = ProcessMonitorEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(ProcessMonitorEvidenceSourceAdapter.Id, captureId),
            IsCaptureScoped = true,
            IsLiveSource = true,
            Parameters = new
            {
                ProcmonPath = procmonPath,
                CaptureId = captureId,
                OutputDirectory = Path.GetFullPath(processMonitorDirectory),
                BackingFilePath = Path.GetFullPath(command.BackingFilePath),
                CsvOutputPath = Path.GetFullPath(command.CsvOutputPath),
                AcceptEula = true,
                command.MaxRows
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private async Task<AgentIpcResponse> StopProcessMonitorCaptureAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<StopProcessMonitorCaptureCommand>(request);
        if (!TryNormalizeOptionalProcessMonitorExecutable(command.ProcmonPath, out _))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorExecutableInvalid",
                "An explicit Process Monitor path must identify an existing Procmon.exe or Procmon64.exe.");
        }

        if (!_jobQueue.TryGetInFlightJob(JobKind.ProcessMonitorCapture, out var activeProgress))
        {
            return AgentIpcResponse.Failure(request.RequestId, "ProcessMonitorCaptureNotRunning", "Process Monitor capture is not running.");
        }

        if (activeProgress.State is JobState.Queued or JobState.Running or JobState.Paused)
        {
            await _jobQueue.CancelJobAsync(activeProgress.JobId, cancellationToken).ConfigureAwait(false);
        }

        return AgentIpcResponse.Ok(request.RequestId) with
        {
            AcceptedJobId = activeProgress.JobId,
            Job = _jobQueue.TryGetJobStatus(activeProgress.JobId, out var progress) ? progress : activeProgress,
            DatabaseChanged = LatestDatabaseChanged
        };
    }

    private async Task<AgentIpcResponse> EnqueueProcessMonitorImportAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<QueueProcessMonitorImportCommand>(request);
        if (!TryNormalizeExistingFile(command.InputPath, out var inputPath) ||
            !AgentToolActionPolicy.IsSupportedProcessMonitorInputPath(inputPath))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorInputInvalid",
                "Process Monitor import requires one existing absolute CSV or PML file.");
        }

        if (!AgentToolActionPolicy.TryNormalizeCaptureId(command.CaptureId, out var captureId))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorCaptureIdInvalid",
                "Process Monitor import requires one bounded canonical capture id.");
        }

        if (!TryNormalizeOptionalProcessMonitorExecutable(command.ProcmonPath, out var procmonPath))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorExecutableInvalid",
                "An explicit Process Monitor path must identify an existing Procmon.exe or Procmon64.exe.");
        }

        if (command.MaxRows is < 1 or > AgentToolActionPolicy.MaximumProcessMonitorRows)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorMaxRowsInvalid",
                $"Process Monitor MaxRows must be from 1 through {AgentToolActionPolicy.MaximumProcessMonitorRows}.");
        }

        var processMonitorDirectory = _options.SessionPaths?.ProcessMonitorDirectory ?? string.Empty;
        if (string.IsNullOrWhiteSpace(processMonitorDirectory) ||
            !AgentToolActionPolicy.PathsEqual(command.OutputDirectory, processMonitorDirectory))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ProcessMonitorOutputRejected",
                "Process Monitor import output must use the active session ProcessMonitor directory.");
        }

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.ProcessMonitorImport,
            SourceType = "AgentProcessMonitorImport",
            SourceDisplayName = "Agent Process Monitor import",
            CaptureId = captureId,
            SourcePath = inputPath,
            InputPath = inputPath,
            EvidenceSourceAdapterId = ProcessMonitorEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = ProcessMonitorEvidenceSourceAdapter.Version,
            ParserVersion = ProcessMonitorEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(ProcessMonitorEvidenceSourceAdapter.Id, captureId),
            Parameters = new
            {
                InputPath = inputPath,
                ProcmonPath = procmonPath,
                CaptureId = captureId,
                OutputDirectory = Path.GetFullPath(processMonitorDirectory),
                command.MaxRows
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private async Task<AgentIpcResponse> EnqueueSqliteBenchmarkAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<QueueSqliteBenchmarkCommand>(request);
        if (_jobQueue.TryGetActiveJob(JobKind.SqliteBenchmark, out var activeBenchmark))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "SqliteBenchmarkAlreadyActive",
                $"SQLite benchmark job {activeBenchmark.JobId:D} is already active.");
        }

        if (!AgentToolActionPolicy.TryValidateBenchmark(command, out var benchmarkError))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "SqliteBenchmarkOptionsInvalid",
                benchmarkError);
        }

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.SqliteBenchmark,
            SourceType = "AgentBenchmark",
            SourceDisplayName = "SQLite benchmark",
            Parameters = new
            {
                command.PhaseDurationSeconds,
                command.MaxPhaseCount,
                command.InitialProcessBatchSize,
                command.InitialEventsPerProcess,
                command.MaxInFlightBatches,
                command.MaxPendingWriterWorkItems,
                command.ProgressIntervalMilliseconds,
                BenchmarkOnly = true
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private async Task<AgentIpcResponse> StartConfiguredCaptureAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<StartConfiguredCaptureCommand>(request);
        var savedConfiguration = _captureConfiguration.GetSavedCaptureConfigurationForReleasePolicy();
        if (savedConfiguration != null)
        {
            var configuredFeatureDecision = AgentCommandFeaturePolicy.EvaluateCaptureConfiguration(
                _featureCatalog,
                savedConfiguration,
                $"Configured capture command '{request.CommandKind}'");
            if (!configuredFeatureDecision.Allowed)
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    configuredFeatureDecision.ErrorCode,
                    configuredFeatureDecision.ErrorMessage,
                    configuredFeatureDecision.IsRetryable);
            }
        }

        var existingConfiguredWork = _jobQueue.GetConfiguredCaptureWork(command.CaptureId);
        if (existingConfiguredWork.Count == 0 && string.IsNullOrWhiteSpace(command.CaptureId))
        {
            existingConfiguredWork = _jobQueue.GetConfiguredCaptureWork();
        }

        if (existingConfiguredWork.Count == 0 && !string.IsNullOrWhiteSpace(command.CaptureId))
        {
            var otherConfiguredWork = _jobQueue.GetConfiguredCaptureWork();
            if (otherConfiguredWork.Count > 0)
            {
                var otherCaptureId = otherConfiguredWork
                    .Select(item => item.CaptureId)
                    .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? "<unknown>";
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "DifferentConfiguredCaptureActive",
                    $"Configured capture '{otherCaptureId}' is already active; '{command.CaptureId}' was not started.") with
                {
                    AcceptedJobs = otherConfiguredWork,
                    DatabaseChanged = LatestDatabaseChanged
                };
            }
        }

        if (existingConfiguredWork.Count > 0)
        {
            var existingCaptureId = existingConfiguredWork
                .Select(item => item.CaptureId)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? command.CaptureId;
            return ConfiguredCaptureResponse(
                request,
                existingConfiguredWork,
                new AgentCaptureLifecycleResult
                {
                    AgentId = command.AgentId,
                    HostId = command.HostId,
                    CaptureId = existingCaptureId,
                    ConfigurationVersion = command.ConfigurationVersion,
                    ConfigurationHash = command.ConfigurationHash,
                    Action = AgentCaptureLifecycleAction.Start,
                    Status = AgentConfigurationOperationStatus.Warning,
                    StartedAtUtc = existingConfiguredWork.Min(item => item.AcceptedAtUtc),
                    Message = "Configured capture is already active; returning its complete in-flight job set."
                },
                accepted: true);
        }

        if (_jobQueue.TryGetActiveJob(JobKind.LiveCapture, out _))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "UnrelatedLiveCaptureActive",
                "An analyst-initiated live capture is already active; configured capture was not started.") with
            {
                DatabaseChanged = LatestDatabaseChanged
            };
        }

        var plan = _captureConfiguration.CreateStartPlan(command);
        if (!plan.CanStart)
        {
            return AgentIpcResponse.Failure(request.RequestId, "ConfiguredCaptureNotStarted", plan.Lifecycle.Message) with
            {
                CaptureLifecycle = plan.Lifecycle,
                DatabaseChanged = LatestDatabaseChanged
            };
        }

        var acceptedJobs = new List<AgentActiveWorkItem>();
        _jobQueue.AllowConfiguredCapture(plan.Lifecycle.CaptureId);
        try
        {
            if (plan.LiveCaptureCommand != null)
            {
                var liveResponse = await StartLiveCaptureCoreAsync(
                    request,
                    plan.LiveCaptureCommand,
                    "Configured live capture",
                    plan.Lifecycle,
                    cancellationToken).ConfigureAwait(false);
                if (liveResponse.AcceptedJobId is { } liveJobId)
                {
                    acceptedJobs.Add(CreateConfiguredJobReference(
                        liveJobId,
                        JobKind.LiveCapture,
                        plan.Lifecycle.CaptureId,
                        isLiveSource: true));
                }
            }

            if (plan.StartNetworkCapture && !_jobQueue.TryGetInFlightJob(JobKind.NetworkCapture, out _))
            {
                var networkJobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
                {
                    OriginatingCommandId = command.CommandId,
                    JobKind = JobKind.NetworkCapture,
                    SourceType = "AgentConfiguredNetworkCapture",
                    SourceDisplayName = "Configured network capture",
                    CaptureId = plan.Lifecycle.CaptureId,
                    EvidenceSourceAdapterId = NetworkCaptureEvidenceSourceAdapter.Id,
                    EvidenceSourceAdapterVersion = NetworkCaptureEvidenceSourceAdapter.Version,
                    ParserVersion = NetworkCaptureEvidenceSourceAdapter.Version,
                    EvidenceIdentity = CreateEvidenceIdentity(
                        NetworkCaptureEvidenceSourceAdapter.Id,
                        plan.Lifecycle.CaptureId),
                    IsCaptureScoped = true,
                    IsLiveSource = true,
                    Ownership = AgentJobOwnership.ConfiguredCapture,
                    Parameters = new
                    {
                        CaptureId = plan.Lifecycle.CaptureId,
                        OutputDirectory = plan.NetworkOutputDirectory
                    }
                }, cancellationToken).ConfigureAwait(false);
                acceptedJobs.Add(CreateConfiguredJobReference(
                    networkJobId,
                    JobKind.NetworkCapture,
                    plan.Lifecycle.CaptureId,
                    isLiveSource: true));
            }

            if (plan.QueueArtifactEnrichment)
            {
                var jobKind = AgentEnrichmentPlanning.GetJobKind(
                    plan.CaptureModules,
                    plan.CaptureHandles,
                    plan.CapturePe);
                var workloads = AgentRequestedWorkloads.ForEnrichment(
                    plan.CaptureModules,
                    plan.CaptureHandles,
                    plan.CapturePe);
                var enrichmentJobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
                {
                    OriginatingCommandId = command.CommandId,
                    JobKind = jobKind,
                    SourceType = "AgentConfiguredArtifactEnrichment",
                    SourceDisplayName = jobKind == JobKind.PeAnalysis
                        ? "Configured PE analysis"
                        : "Configured artifact enrichment",
                    CaptureId = plan.Lifecycle.CaptureId,
                    IsCaptureScoped = true,
                    Ownership = AgentJobOwnership.ConfiguredCapture,
                    RequestedWorkloads = workloads,
                    Parameters = new
                    {
                        ProcessKeys = Array.Empty<string>(),
                        plan.CaptureModules,
                        plan.CaptureHandles,
                        CapturePe = plan.CapturePe,
                        PeStringExtractionMode = PeStringExtractionMode.Deferred,
                        Sweep = true
                    }
                }, cancellationToken).ConfigureAwait(false);
                acceptedJobs.Add(CreateConfiguredJobReference(
                    enrichmentJobId,
                    jobKind,
                    plan.Lifecycle.CaptureId,
                    requestedWorkloads: workloads));
            }
        }
        catch (Exception ex) when (ex is AgentQueueSaturatedException or OperationCanceledException)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ConfiguredCapturePartiallyStarted",
                $"Configured capture accepted {acceptedJobs.Count} job(s) before start failed: {ex.Message}",
                isRetryable: true) with
            {
                AcceptedJobId = acceptedJobs.FirstOrDefault()?.JobId,
                Job = TryGetProgress(acceptedJobs.FirstOrDefault()),
                AcceptedJobs = acceptedJobs,
                CaptureLifecycle = plan.Lifecycle with
                {
                    Status = AgentConfigurationOperationStatus.Warning,
                    Message = $"Configured capture partially started with {acceptedJobs.Count} accepted job(s).",
                    LastError = ex.Message
                },
                DatabaseChanged = LatestDatabaseChanged
            };
        }

        return ConfiguredCaptureResponse(
            request,
            acceptedJobs,
            plan.Lifecycle,
            accepted: true);
    }

    private async Task<AgentIpcResponse> StopConfiguredCaptureAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<StopConfiguredCaptureCommand>(request);
        var captureWork = _jobQueue.MarkConfiguredCaptureStopRequested(command.CaptureId);
        if (captureWork.Count == 0 && string.IsNullOrWhiteSpace(command.CaptureId))
        {
            captureWork = _jobQueue.MarkConfiguredCaptureStopRequested(string.Empty);
        }

        if (captureWork.Count == 0)
        {
            var notRunning = _captureConfiguration.CreateStopResult(
                command,
                AgentConfigurationOperationStatus.Failed,
                string.IsNullOrWhiteSpace(command.CaptureId)
                    ? "Configured capture is not running."
                    : $"Configured capture '{command.CaptureId}' is not running.");
            return AgentIpcResponse.Failure(request.RequestId, "ConfiguredCaptureNotRunning", notRunning.Message) with
            {
                CaptureLifecycle = notRunning,
                DatabaseChanged = LatestDatabaseChanged
            };
        }

        foreach (var work in captureWork)
        {
            if (work.JobKind == JobKind.LiveCapture)
            {
                _requestLiveCaptureStop(work.JobId);
                continue;
            }

            if (work.State is JobState.Queued or JobState.Running or JobState.Paused or JobState.Unknown)
            {
                await _jobQueue.CancelJobAsync(work.JobId, cancellationToken).ConfigureAwait(false);
            }
        }

        var result = _captureConfiguration.CreateStopResult(
            command,
            AgentConfigurationOperationStatus.Success,
            captureWork.Count == 1
                ? "Requested configured capture stop."
                : $"Requested stop for {captureWork.Count} configured capture jobs; terminal state remains authoritative through health polling.");

        return ConfiguredCaptureResponse(
            request,
            captureWork.Select(item => item with { StopRequested = true }).ToArray(),
            result,
            accepted: false);
    }

    private Task<AgentIpcResponse> PauseConfiguredCaptureAsync(
        AgentIpcRequest request,
        CancellationToken cancellationToken) =>
        TransitionConfiguredCaptureAsync(
            request,
            DeserializeCommand<PauseJobCommand>(request),
            AgentCaptureLifecycleAction.Pause,
            cancellationToken);

    private Task<AgentIpcResponse> ResumeConfiguredCaptureAsync(
        AgentIpcRequest request,
        CancellationToken cancellationToken) =>
        TransitionConfiguredCaptureAsync(
            request,
            DeserializeCommand<ResumeJobCommand>(request),
            AgentCaptureLifecycleAction.Resume,
            cancellationToken);

    private async Task<AgentIpcResponse> TransitionConfiguredCaptureAsync(
        AgentIpcRequest request,
        AgentCommand command,
        AgentCaptureLifecycleAction action,
        CancellationToken cancellationToken)
    {
        if (_configuredCapturePause == null)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "ConfiguredCaptureControlUnavailable",
                "This agent endpoint is not configured for authoritative capture pause/resume.");
        }

        var savedConfiguration = _captureConfiguration.GetSavedCaptureConfigurationForReleasePolicy();
        if (savedConfiguration != null)
        {
            var configuredFeatureDecision = AgentCommandFeaturePolicy.EvaluateCaptureConfiguration(
                _featureCatalog,
                savedConfiguration,
                $"Configured capture command '{request.CommandKind}'");
            if (!configuredFeatureDecision.Allowed)
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    configuredFeatureDecision.ErrorCode,
                    configuredFeatureDecision.ErrorMessage,
                    configuredFeatureDecision.IsRetryable);
            }
        }

        var result = command switch
        {
            PauseJobCommand pause => await _configuredCapturePause.PauseAsync(pause, cancellationToken).ConfigureAwait(false),
            ResumeJobCommand resume => await _configuredCapturePause.ResumeAsync(resume, cancellationToken).ConfigureAwait(false),
            _ => throw new InvalidOperationException($"Unsupported configured capture transition command '{command.Kind}'.")
        };
        var configuration = savedConfiguration ?? new AgentCaptureConfiguration();
        var lifecycle = new AgentCaptureLifecycleResult
        {
            AgentId = configuration.AgentId,
            HostId = configuration.HostId,
            CaptureId = command switch
            {
                PauseJobCommand pause => pause.CaptureId,
                ResumeJobCommand resume => resume.CaptureId,
                _ => string.Empty
            },
            ConfigurationVersion = configuration.ConfigurationVersion,
            ConfigurationHash = configuration.ConfigurationHash,
            Action = action,
            Status = result.Success
                ? result.IsIdempotent
                    ? AgentConfigurationOperationStatus.Warning
                    : AgentConfigurationOperationStatus.Success
                : AgentConfigurationOperationStatus.Failed,
            CompletedAtUtc = result.Success ? DateTime.UtcNow : null,
            Message = result.Message,
            LastError = result.Success ? string.Empty : result.Message
        };
        if (!result.Success)
        {
            return AgentIpcResponse.Failure(request.RequestId, result.ErrorCode, result.Message) with
            {
                AffectedJobs = result.AffectedWork,
                CaptureLifecycle = lifecycle,
                DatabaseChanged = LatestDatabaseChanged
            };
        }

        return ConfiguredCaptureResponse(
            request,
            result.AffectedWork,
            lifecycle,
            accepted: false);
    }

    private AgentIpcResponse ConfiguredCaptureResponse(
        AgentIpcRequest request,
        IReadOnlyList<AgentActiveWorkItem> jobs,
        AgentCaptureLifecycleResult lifecycle,
        bool accepted)
    {
        var legacy = jobs.FirstOrDefault();
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            AcceptedJobId = legacy?.JobId,
            Job = TryGetProgress(legacy),
            AcceptedJobs = accepted ? jobs : Array.Empty<AgentActiveWorkItem>(),
            AffectedJobs = accepted ? Array.Empty<AgentActiveWorkItem>() : jobs,
            CaptureLifecycle = lifecycle,
            DatabaseChanged = LatestDatabaseChanged
        };
    }

    private JobProgress? TryGetProgress(AgentActiveWorkItem? work)
        => work != null && _jobQueue.TryGetJobStatus(work.JobId, out var progress)
            ? progress
            : null;

    private AgentActiveWorkItem CreateConfiguredJobReference(
        Guid jobId,
        JobKind jobKind,
        string captureId,
        bool isLiveSource = false,
        AgentRequestedWorkloads? requestedWorkloads = null)
    {
        var progress = _jobQueue.TryGetJobStatus(jobId, out var current) ? current : null;
        return new AgentActiveWorkItem
        {
            JobId = jobId,
            JobKind = jobKind,
            State = progress?.State ?? JobState.Queued,
            CaptureId = captureId,
            OriginatingCommandId = progress?.OriginatingCommandId,
            Ownership = AgentJobOwnership.ConfiguredCapture,
            IsCaptureScoped = true,
            IsLiveSource = isLiveSource,
            AcceptedAtUtc = DateTime.UtcNow,
            StartedAtUtc = progress?.StartedAtUtc,
            UpdatedAtUtc = progress?.EmittedAtUtc ?? DateTime.UtcNow,
            RequestedWorkloads = requestedWorkloads ?? new AgentRequestedWorkloads()
        };
    }

    private async Task<AgentIpcResponse> EnqueueMemoryImageImportAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<QueueMemoryImageImportCommand>(request);
        if (!TryNormalizeMemoryImageImport(
                command,
                out command,
                out var errorCode,
                out var errorDetail))
        {
            return AgentIpcResponse.Failure(request.RequestId, errorCode, errorDetail);
        }

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.MemoryImageImport,
            SourceType = "AgentMemoryImageImport",
            SourceDisplayName = "Agent memory image import",
            SourcePath = command.ImagePath,
            InputPath = command.ImagePath,
            EvidenceSourceAdapterId = MemoryImageEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = MemoryImageEvidenceSourceAdapter.Version,
            ParserVersion = MemoryImageEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(MemoryImageEvidenceSourceAdapter.Id, string.Empty),
            Parameters = new
            {
                command.ImagePath,
                command.DisplayName,
                command.HostName,
                command.OsBuild,
                command.AcquisitionTool,
                command.AcquisitionToolVersion,
                command.AcquisitionCommandLine,
                command.PrivilegeState
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private async Task<AgentIpcResponse> EnqueueMemoryAcquisitionAsync(
        AgentIpcRequest request,
        CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<QueueMemoryAcquisitionCommand>(request);
        if (_options.SessionPaths == null)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "MemoryAcquisitionSessionUnavailable",
                "The agent has no active SessionPathService session for memory acquisition.");
        }

        if (_jobQueue.TryGetInFlightJob(JobKind.MemoryAcquisition, out var activeAcquisition))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "MemoryAcquisitionAlreadyActive",
                $"Memory acquisition job {activeAcquisition.JobId:D} is already active.");
        }

        var jobId = Guid.NewGuid();
        var preflight = new AgentMemoryAcquisitionService(_options.SessionPaths).CreatePlan(
            jobId,
            command.RequestedOutputFileName,
            command.TimeoutSeconds);
        if (!preflight.Success || preflight.Plan == null)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                preflight.ErrorCode,
                preflight.Detail);
        }

        var plan = preflight.Plan;
        await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            JobId = jobId,
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.MemoryAcquisition,
            SourceType = "AgentMemoryAcquisition",
            SourceDisplayName = "Agent full-memory acquisition",
            SourcePath = plan.OutputPath,
            SourceProvider = plan.ExecutablePath,
            SourceChannel = "ConfiguredMemoryAcquisition",
            ToolVersion = plan.ToolVersion,
            InputPath = plan.OutputPath,
            EvidenceSourceAdapterId = MemoryImageEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = MemoryImageEvidenceSourceAdapter.Version,
            ParserVersion = MemoryImageEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(MemoryImageEvidenceSourceAdapter.Id, string.Empty),
            SourceMetadataJson = JsonSerializer.Serialize(
                new
                {
                    plan.ToolName,
                    plan.ToolVersion,
                    plan.ExecutablePath,
                    plan.Arguments,
                    plan.OutputPath,
                    plan.ConfigurationDiagnostic,
                    plan.TimeoutSeconds
                },
                AgentJson.JsonOptions),
            Parameters = plan
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private async Task<AgentIpcResponse> EnqueueVolatilityAnalysisAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<QueueVolatilityAnalysisCommand>(request);
        if (_options.SessionPaths == null)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "VolatilitySessionUnavailable",
                "The agent has no active SessionPathService session for Volatility analysis.");
        }

        var hasImageId = !string.IsNullOrWhiteSpace(command.ImageId);
        var hasImagePath = !string.IsNullOrWhiteSpace(command.ImagePath);
        if (hasImageId == hasImagePath)
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "VolatilityImageSelectorInvalid",
                "Volatility analysis requires exactly one staged image id or explicit read-only image path.");
        }

        var imageId = string.Empty;
        var imagePath = string.Empty;
        if (hasImageId)
        {
            if (!AgentMemoryActionPolicy.TryNormalizeImageId(command.ImageId, out imageId))
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "VolatilityImageIdInvalid",
                    "The staged memory image id is malformed or exceeds the bounded identifier length.");
            }

            var query = new SqliteStagingQueryService(
                _options.DatabasePath,
                openContext: CaptureOpenContext.AgentWritableLive);
            if (query.GetMemoryImageById(imageId) == null)
            {
                return AgentIpcResponse.Failure(
                    request.RequestId,
                    "VolatilityImageNotFound",
                    "The requested staged memory image does not exist in the exact active evidence store.");
            }
        }
        else if (!TryNormalizeReadableMemoryImage(command.ImagePath, out imagePath))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "VolatilityImagePathInvalid",
                "The explicit Volatility image must be an existing readable non-empty absolute file with a supported extension.");
        }

        if (!AgentMemoryActionPolicy.TryNormalizePlugins(
                command.PluginNames,
                out var plugins,
                out var pluginError))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "VolatilityPluginsInvalid",
                pluginError);
        }

        if (!AgentMemoryActionPolicy.IsValidPluginTimeout(command.TimeoutSeconds))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "VolatilityTimeoutOutOfRange",
                $"Per-plugin timeout must be from {AgentMemoryActionPolicy.MinimumPluginTimeoutSeconds} through {AgentMemoryActionPolicy.MaximumPluginTimeoutSeconds} seconds.");
        }

        var expectedOutput = AgentMemoryActionPolicy.BuildVolatilityOutputDirectory(
            _options.SessionPaths.MemoryDirectory,
            imageId,
            imagePath);
        if (!AgentToolActionPolicy.PathsEqual(command.OutputDirectory, expectedOutput) ||
            !AgentToolActionPolicy.IsStrictChildPath(_options.SessionPaths.MemoryDirectory, expectedOutput))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "VolatilityOutputRejected",
                "Volatility output must use the derived active-session Memory directory.");
        }

        command = command with
        {
            ImageId = imageId,
            ImagePath = imagePath,
            PluginNames = plugins.Length == 0 ? null : plugins,
            OutputDirectory = expectedOutput
        };

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.VolatilityAnalysis,
            SourceType = "AgentVolatility",
            SourceDisplayName = "Agent Volatility analysis",
            InputArtifactId = command.ImageId,
            InputPath = command.ImagePath,
            EvidenceSourceAdapterId = VolatilityProcessEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = VolatilityProcessEvidenceSourceAdapter.Version,
            ParserVersion = VolatilityProcessEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(VolatilityProcessEvidenceSourceAdapter.Id, string.Empty),
            Parameters = new
            {
                command.ImageId,
                command.ImagePath,
                command.PluginNames,
                command.OutputDirectory,
                command.TimeoutSeconds
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private static bool TryNormalizeMemoryImageImport(
        QueueMemoryImageImportCommand supplied,
        out QueueMemoryImageImportCommand normalized,
        out string errorCode,
        out string errorDetail)
    {
        normalized = supplied;
        errorCode = string.Empty;
        errorDetail = string.Empty;
        if (!TryNormalizeReadableMemoryImage(supplied.ImagePath, out var imagePath))
        {
            errorCode = "MemoryImageSourceInvalid";
            errorDetail = "Memory image import requires one existing readable non-empty absolute file with a supported extension.";
            return false;
        }

        var fields = new[]
        {
            ("display name", supplied.DisplayName, AgentMemoryActionPolicy.MaximumMetadataLength),
            ("host name", supplied.HostName, AgentMemoryActionPolicy.MaximumMetadataLength),
            ("OS build", supplied.OsBuild, AgentMemoryActionPolicy.MaximumMetadataLength),
            ("acquisition tool", supplied.AcquisitionTool, AgentMemoryActionPolicy.MaximumMetadataLength),
            ("acquisition tool version", supplied.AcquisitionToolVersion, AgentMemoryActionPolicy.MaximumMetadataLength),
            ("acquisition command line", supplied.AcquisitionCommandLine, AgentMemoryActionPolicy.MaximumCommandLineMetadataLength),
            ("privilege state", supplied.PrivilegeState, AgentMemoryActionPolicy.MaximumMetadataLength)
        };
        var values = new string[fields.Length];
        for (var index = 0; index < fields.Length; index++)
        {
            if (!AgentMemoryActionPolicy.TryNormalizeOptionalMetadata(
                    fields[index].Item2,
                    fields[index].Item3,
                    out values[index]))
            {
                errorCode = "MemoryImageMetadataInvalid";
                errorDetail = $"Memory image {fields[index].Item1} is too long or contains control characters.";
                return false;
            }
        }

        normalized = supplied with
        {
            ImagePath = imagePath,
            DisplayName = values[0],
            HostName = values[1],
            OsBuild = values[2],
            AcquisitionTool = values[3],
            AcquisitionToolVersion = values[4],
            AcquisitionCommandLine = values[5],
            PrivilegeState = values[6]
        };
        return true;
    }

    private static bool TryNormalizeReadableMemoryImage(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (!AgentToolActionPolicy.TryNormalizeAbsolutePath(value, out var path) ||
            !AgentMemoryActionPolicy.IsSupportedImagePath(path) ||
            !File.Exists(path))
        {
            return false;
        }

        try
        {
            if (new FileInfo(path).Length <= 0)
            {
                return false;
            }

            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 1,
                FileOptions.SequentialScan);
            normalized = path;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }

    private async Task<AgentIpcResponse> StartNetworkCaptureAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<StartNetworkCaptureCommand>(request);
        if (_jobQueue.TryGetInFlightJob(JobKind.NetworkCapture, out var activeProgress))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "NetworkCaptureAlreadyActive",
                $"Network capture job {activeProgress.JobId:D} is already active or finalizing.");
        }

        var expectedNetworkDirectory = _options.SessionPaths?.NetworkCapturesDirectory ?? string.Empty;
        if (string.IsNullOrWhiteSpace(expectedNetworkDirectory) ||
            !AgentToolActionPolicy.PathsEqual(command.OutputDirectory, expectedNetworkDirectory))
        {
            return AgentIpcResponse.Failure(
                request.RequestId,
                "NetworkCaptureOutputRejected",
                "Network capture output must use the active session NetworkCaptures directory.");
        }

        var jobId = await _jobQueue.EnqueueAsync(new AgentJobRequest
        {
            OriginatingCommandId = command.CommandId,
            JobKind = JobKind.NetworkCapture,
            SourceType = "AgentNetworkCapture",
            SourceDisplayName = "Agent network capture",
            EvidenceSourceAdapterId = NetworkCaptureEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = NetworkCaptureEvidenceSourceAdapter.Version,
            ParserVersion = NetworkCaptureEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(NetworkCaptureEvidenceSourceAdapter.Id, string.Empty),
            IsCaptureScoped = true,
            IsLiveSource = true,
            Parameters = new
            {
                OutputDirectory = Path.GetFullPath(expectedNetworkDirectory)
            }
        }, cancellationToken).ConfigureAwait(false);

        return Accepted(request, jobId);
    }

    private async Task<AgentIpcResponse> StopNetworkCaptureAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        _ = DeserializeCommand<StopNetworkCaptureCommand>(request);
        if (!_jobQueue.TryGetInFlightJob(JobKind.NetworkCapture, out var activeProgress))
        {
            return await StopUntrackedNetworkCaptureAsync(request, cancellationToken).ConfigureAwait(false);
        }

        if (activeProgress.State is JobState.Queued or JobState.Running or JobState.Paused)
        {
            await _jobQueue.CancelJobAsync(activeProgress.JobId, cancellationToken).ConfigureAwait(false);
        }

        return AgentIpcResponse.Ok(request.RequestId) with
        {
            AcceptedJobId = activeProgress.JobId,
            Job = _jobQueue.TryGetJobStatus(activeProgress.JobId, out var progress) ? progress : activeProgress,
            DatabaseChanged = LatestDatabaseChanged
        };
    }

    private async Task<AgentIpcResponse> StopUntrackedNetworkCaptureAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var recoveryJobId = Guid.NewGuid();
        var requestedUtc = DateTime.UtcNow;
        var outputDirectory = _options.SessionPaths?.NetworkCapturesDirectory ?? string.Empty;
        var recoveryRequest = new AgentJobRequest
        {
            JobId = recoveryJobId,
            JobKind = JobKind.NetworkCapture,
            SourceType = "AgentNetworkCaptureRecovery",
            SourceDisplayName = "Recovered Packet Monitor capture",
            SourcePath = outputDirectory,
            EvidenceSourceAdapterId = NetworkCaptureEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = NetworkCaptureEvidenceSourceAdapter.Version,
            ParserVersion = NetworkCaptureEvidenceSourceAdapter.Version,
            EvidenceIdentity = CreateEvidenceIdentity(NetworkCaptureEvidenceSourceAdapter.Id, string.Empty),
            IsCaptureScoped = true,
            Parameters = new { OutputDirectory = outputDirectory, RecoveryStop = true }
        };
        var sourceRun = await _stagingWriter.CreateSourceRunAsync(recoveryRequest, cancellationToken)
            .ConfigureAwait(false);
        await _stagingWriter.CreateJobAsync(recoveryRequest, sourceRun, cancellationToken)
            .ConfigureAwait(false);
        using var provenance = _stagingWriter.BeginSourceRunScope(sourceRun.SourceRunId, recoveryJobId);

        try
        {
            var result = await _networkCaptureService.StopUntrackedCaptureAsync(
                recoveryJobId,
                outputDirectory,
                cancellationToken).ConfigureAwait(false);
            var record = CreateRecoveredNetworkCaptureRecord(recoveryJobId, requestedUtc, result);
            await _stagingWriter.UpsertNetworkCapturesAsync(new[] { record }, CancellationToken.None).ConfigureAwait(false);
            await _stagingWriter.UpdateSourceRunStatusAsync(
                sourceRun.SourceRunId,
                EvidenceSourceCompletionState.Completed.ToString(),
                DateTime.UtcNow,
                "{\"recoveryStop\":true}",
                CancellationToken.None).ConfigureAwait(false);
            var progress = CreateNetworkCaptureRecoveryProgress(
                recoveryJobId,
                JobState.Completed,
                "Stopped and finalized an untracked Packet Monitor capture.",
                string.Empty,
                requestedUtc);

            return AgentIpcResponse.Ok(request.RequestId) with
            {
                AcceptedJobId = recoveryJobId,
                Job = progress,
                DatabaseChanged = LatestDatabaseChanged
            };
        }
        catch (Exception ex)
        {
            var record = CreateFailedNetworkCaptureRecoveryRecord(recoveryJobId, requestedUtc, outputDirectory, ex.Message);
            await _stagingWriter.UpsertNetworkCapturesAsync(new[] { record }, CancellationToken.None).ConfigureAwait(false);
            await _stagingWriter.UpdateSourceRunStatusAsync(
                sourceRun.SourceRunId,
                EvidenceSourceCompletionState.Failed.ToString(),
                DateTime.UtcNow,
                "{\"recoveryStop\":true}",
                CancellationToken.None).ConfigureAwait(false);
            var progress = CreateNetworkCaptureRecoveryProgress(
                recoveryJobId,
                JobState.Failed,
                "Failed to stop an untracked Packet Monitor capture.",
                ex.Message,
                requestedUtc);

            return AgentIpcResponse.Failure(request.RequestId, "NetworkCaptureRecoveryStopFailed", ex.Message) with
            {
                AcceptedJobId = recoveryJobId,
                Job = progress,
                DatabaseChanged = LatestDatabaseChanged
            };
        }
    }

    private static NetworkCaptureRecord CreateRecoveredNetworkCaptureRecord(
        Guid recoveryJobId,
        DateTime requestedUtc,
        NetworkCaptureResult result)
    {
        return new NetworkCaptureRecord
        {
            CaptureId = $"{recoveryJobId:N}-recovered-segment-0001",
            JobId = recoveryJobId,
            SegmentIndex = 1,
            Status = NetworkCaptureStatus.Captured,
            RequestedUtc = requestedUtc,
            CompletedUtc = DateTime.UtcNow,
            OutputDirectory = result.OutputDirectory,
            EtlFilePath = result.EtlFilePath,
            FilePath = result.FilePath,
            FileSizeBytes = result.FileSizeBytes,
            Sha256Hash = result.Sha256Hash,
            ToolName = result.ToolName,
            CaptureSource = "LocalHost",
            FilterDescription = $"Recovered Packet Monitor capture stopped outside an active agent job. Diagnostic log: {result.LogFilePath}",
            Source = "AgentNetworkCaptureRecovery"
        };
    }

    private static NetworkCaptureRecord CreateFailedNetworkCaptureRecoveryRecord(
        Guid recoveryJobId,
        DateTime requestedUtc,
        string outputDirectory,
        string error)
    {
        return new NetworkCaptureRecord
        {
            CaptureId = $"{recoveryJobId:N}-recovered-segment-0001",
            JobId = recoveryJobId,
            SegmentIndex = 1,
            Status = NetworkCaptureStatus.Failed,
            RequestedUtc = requestedUtc,
            CompletedUtc = DateTime.UtcNow,
            OutputDirectory = outputDirectory,
            ToolName = "pktmon",
            CaptureSource = "LocalHost",
            FilterDescription = "Recovered Packet Monitor capture stop attempted outside an active agent job.",
            ErrorMessage = error,
            Source = "AgentNetworkCaptureRecovery"
        };
    }

    private static JobProgress CreateNetworkCaptureRecoveryProgress(
        Guid recoveryJobId,
        JobState state,
        string message,
        string error,
        DateTime requestedUtc)
    {
        return new JobProgress
        {
            JobId = recoveryJobId,
            JobKind = JobKind.NetworkCapture,
            State = state,
            ProgressMessage = message,
            ErrorText = error,
            ProcessedCount = state == JobState.Completed ? 1 : 0,
            TotalCount = 1,
            StartedAtUtc = requestedUtc,
            FinishedAtUtc = DateTime.UtcNow
        };
    }

    private async Task<AgentIpcResponse> CancelJobAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var command = DeserializeCommand<CancelJobCommand>(request);
        if (!_jobQueue.TryGetJobStatus(command.JobId, out _))
        {
            return AgentIpcResponse.Failure(request.RequestId, "JobNotFound", $"The agent does not know job {command.JobId}.");
        }

        await _jobQueue.CancelJobAsync(command.JobId, cancellationToken).ConfigureAwait(false);
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            AcceptedJobId = command.JobId,
            Job = _jobQueue.TryGetJobStatus(command.JobId, out var progress) ? progress : null,
            DatabaseChanged = LatestDatabaseChanged
        };
    }

    private AgentIpcResponse HandleJobStatus(AgentIpcRequest request)
    {
        if (request.JobId is not { } jobId)
        {
            return AgentIpcResponse.Failure(request.RequestId, "MissingJobId", "Job status requests must include a job id.");
        }

        return _jobQueue.TryGetJobStatus(jobId, out var progress)
            ? AgentIpcResponse.Ok(request.RequestId) with { Job = progress, DatabaseChanged = LatestDatabaseChanged }
            : AgentIpcResponse.Failure(request.RequestId, "JobNotFound", $"The agent does not know job {jobId}.");
    }

    private static bool TryNormalizeExistingFile(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (!AgentToolActionPolicy.TryNormalizeAbsolutePath(value, out var candidate) ||
            !File.Exists(candidate))
        {
            return false;
        }

        try
        {
            using var stream = new FileStream(
                candidate,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 1,
                FileOptions.SequentialScan);
            normalized = candidate;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }

    private static bool TryNormalizeOptionalProcessMonitorExecutable(
        string? value,
        out string normalized)
    {
        if (!AgentToolActionPolicy.TryNormalizeOptionalProcessMonitorPath(value, out normalized))
        {
            return false;
        }

        return normalized.Length == 0 || File.Exists(normalized);
    }

    private static bool IsExpectedOwnedOutput(
        string path,
        string outputDirectory,
        string captureId,
        string extension)
    {
        if (!AgentToolActionPolicy.TryNormalizeAbsolutePath(path, out var normalized) ||
            !AgentToolActionPolicy.IsStrictChildPath(outputDirectory, normalized) ||
            !string.Equals(Path.GetExtension(normalized), extension, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return string.Equals(
            Path.GetFileNameWithoutExtension(normalized),
            captureId,
            StringComparison.OrdinalIgnoreCase);
    }

    private static TCommand DeserializeCommand<TCommand>(AgentIpcRequest request)
    {
        return request.Payload!.Value.Deserialize<TCommand>(AgentIpcJson.JsonOptions)
            ?? throw new InvalidOperationException($"The {typeof(TCommand).Name} payload was empty.");
    }

    private AgentIpcResponse Accepted(AgentIpcRequest request, Guid jobId)
    {
        return AgentIpcResponse.Ok(request.RequestId) with
        {
            AcceptedJobId = jobId,
            Job = _jobQueue.TryGetJobStatus(jobId, out var progress) ? progress : null,
            DatabaseChanged = LatestDatabaseChanged
        };
    }

    private void OnJobProgressChanged(JobProgress progress)
    {
        _log.WriteLine($"[{DateTimeOffset.Now:O}] Job {progress.JobId} state changed to {progress.State}.");
    }

    private DatabaseChangedNotification? LatestDatabaseChanged
    {
        get
        {
            var latest = _stagingWriter.GetLatestDatabaseChangedNotification();
            if (latest != null)
            {
                _latestDatabaseChanged = latest;
            }

            return _latestDatabaseChanged;
        }
    }

    private void OnDatabaseCommitted(DatabaseChangedNotification notification) =>
        _latestDatabaseChanged = notification;
}
