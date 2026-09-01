using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models.Agent;
using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.EvidenceSources;
using ProcInsider.Services.Features;

namespace ProcInsider.Agent;

internal sealed class AgentHost
{
    private readonly AgentOptions _options;
    private readonly TextWriter _log;

    public AgentHost(AgentOptions options, TextWriter log)
    {
        _options = options;
        _log = log;
    }

    public async Task<int> RunAsync(
        CancellationToken cancellationToken,
        Action? runtimeReady = null)
    {
        var sessionPaths = _options.SessionPaths ?? ProcInsider.Services.SessionPathService.CreateForLiveDatabasePath(_options.DatabasePath);
        var databasePath = string.IsNullOrWhiteSpace(_options.DatabasePath)
            ? sessionPaths.LiveDatabasePath
            : _options.DatabasePath;

        Log($"Starting {ProductIdentity.AgentDisplayName}.");
        Log($"Host mode: {_options.Host.Mode}; effective identity: {_options.Host.EffectiveAccountName} ({_options.Host.EffectiveAccountSid}); " +
            $"LocalSystem={_options.Host.IsLocalSystem}; path scope={_options.Host.PathScope}.");
        Log($"Contract version: {AgentContracts.ContractVersion}");
        IFeatureCatalog releaseCatalog = _options.ForegroundMemoryAcquisitionSmoke
            ? CreateMemoryActionSmokeReleaseCatalog()
            : _options.ForegroundEvidenceActionSmoke
            ? CreateEvidenceActionSmokeReleaseCatalog()
            : _options.IpcStressTest
            ? CreateIpcStressReleaseCatalog()
            : _options.SelfTest
                ? CreateSelfTestReleaseCatalog()
                : CurrentEducationalReleaseProfile.RuntimeCatalog;
        Log($"Educational release profile: {releaseCatalog.ReleaseId}");
        using var preparedPairingRuntime = _options.PreparedPairingGeneration.HasValue
            ? AgentPairingRuntime.Start(
                sessionPaths,
                releaseCatalog.ReleaseId,
                _options.CaptureSealed
                    ? CaptureWorkspaceMode.ArchivedCapture
                    : CaptureWorkspaceMode.LiveCapture,
                _options.CaptureSealed,
                _options.PreparedPairingGeneration)
            : null;
        if (preparedPairingRuntime != null)
        {
            Log($"Local pairing contract {AgentContracts.PairingContractVersion} initialized; " +
                $"generation {preparedPairingRuntime.Status.PairingGeneration}; viewer-prepared generation adopted; credentials are stored outside the capture package.");
        }
        Log($"Session root: {sessionPaths.SessionRoot}");
        Log($"Staging database: {databasePath}");
        Log($"Capture write policy: {(_options.CaptureSealed ? "archived capture sealed; explicit derived analysis only" : "live capture")}.");
        Log($"Log file: {sessionPaths.AgentLogPath}");
        Log($"Workers: {_options.WorkerOptions.WorkerCount}; queue capacity: {_options.WorkerOptions.QueueCapacity}; " +
            $"limits: enrichment={_options.WorkerOptions.MaxParallelEnrichmentJobs}, import={_options.WorkerOptions.MaxParallelImportJobs}, " +
            $"dump={_options.WorkerOptions.MaxParallelProcessDumpJobs}, zeek={_options.WorkerOptions.MaxParallelZeekJobs}, " +
            $"artifactImport={_options.WorkerOptions.MaxParallelArtifactImportJobs}, volatility={_options.WorkerOptions.MaxParallelVolatilityJobs}.");
        Log($"PE analysis workers per enrichment job: {_options.WorkerOptions.PeAnalysisWorkers}.");
        var writerOptions = AgentStagingWriterOptions.FromWorkerOptions(_options.WorkerOptions);
        Log($"SQLite writer: queue capacity {writerOptions.QueueCapacity}; max batch rows {writerOptions.MaxRowsPerTransaction}; " +
            $"max queue wait {writerOptions.MaxBatchLatency.TotalMilliseconds:N0} ms; idle checkpoint WAL threshold {writerOptions.CheckpointWalThresholdBytes / 1024 / 1024:N0} MB.");
        var liveBufferOptions = AgentLiveEventBufferOptions.FromWorkerOptions(_options.WorkerOptions, sessionPaths.SessionRoot);
        Log($"Live event buffer: RAM limit {liveBufferOptions.MemoryLimitBytes / 1024 / 1024:N0} MB; disk spill directory {liveBufferOptions.SpillDirectory}.");

        using var liveDatabaseOwnership = _options.CaptureSealed
            ? null
            : SqliteLiveDatabaseOwnershipLease.Acquire(sessionPaths, databasePath);
        using var stagingStore = new SqliteStagingStore(databasePath, sessionPaths.SessionId);
        if (_options.CaptureSealed)
        {
            stagingStore.OpenExistingForArchivedAnalysisMaintenance();
            Log("Validated and opened the existing archived database through the explicit analysis-maintenance path.");
        }
        else
        {
            var migrationRunner = new SqliteEvidenceMigrationRunner(stagingStore);
            var migrationRequest = new SqliteEvidenceMigrationRequest
            {
                SessionPaths = sessionPaths,
                DatabasePath = databasePath,
                ExpectedEvidenceSessionId = sessionPaths.SessionId,
                AppliedByRelease = $"{releaseCatalog.ReleaseId}/" +
                                   (typeof(AgentHost).Assembly.GetName().Version?.ToString() ?? "unknown"),
                CaptureSealed = false,
                OwnershipLease = liveDatabaseOwnership
            };
            var migrationPlan = migrationRunner.Plan(migrationRequest);
            Log($"SQLite migration plan: {migrationPlan.StatusCode}; " +
                $"primary pending={migrationPlan.PendingSteps.Count}; " +
                $"analysis pending={migrationPlan.PendingAnalysisSteps.Count}; " +
                $"recovery copy required={migrationPlan.RecoveryCopyRequired}.");
            var migrationResult = migrationRunner.Execute(migrationRequest, cancellationToken);
            Log($"SQLite migration result: {migrationResult.StatusCode}; " +
                $"last applied={migrationResult.LastAppliedMigrationId}; " +
                $"recovery copy={migrationResult.RecoveryCopyPath}; {migrationResult.Message}");
            if (migrationResult.State == EvidenceMigrationResultState.Cancelled)
            {
                throw new OperationCanceledException(migrationResult.Message, cancellationToken);
            }

            if (migrationResult.State is not (
                    EvidenceMigrationResultState.Completed or
                    EvidenceMigrationResultState.NotRequired))
            {
                throw new InvalidDataException(
                    $"{migrationResult.StatusCode}: {migrationResult.Message}");
            }
        }

        var agentOpenContext = _options.CaptureSealed
            ? CaptureOpenContext.ArchivedAnalysisMaintenance
            : CaptureOpenContext.AgentWritableLive;
        var captureCompatibility = SessionPathService.InspectCapturePackage(
            sessionPaths.SessionRoot,
            agentOpenContext,
            SqliteStagingStore.AssessExistingDatabase).CompatibilityAssessment;
        CaptureCompatibilityPolicy.EnsureAllowed(
            captureCompatibility,
            _options.CaptureSealed
                ? CaptureOpenCapability.MaintainAnalysisState
                : CaptureOpenCapability.WritePrimaryEvidence);
        Log(CaptureCompatibilityPolicy.FormatDiagnostic(
            captureCompatibility,
            databasePath,
            packageLeftUntouched: false));
        Log($"SQLite staging database opened. {stagingStore.GetPerformanceStatus().Summary}");

        await using var stagingWriter = new AgentStagingWriter(
            stagingStore,
            _log,
            writerOptions,
            captureCompatibility);
        await using var preparedInfrastructure = PrepareInfrastructureRuntime(
            stagingWriter,
            sessionPaths);
        var runtimeProcessAdapter = new RuntimeProcessSnapshotEvidenceSourceAdapter();
        var lifecycleProcessAdapter = new ProcessLifecycleEvidenceSourceAdapter();
        var sysmonProcessAdapter = new SysmonProcessEvidenceSourceAdapter();
        var processMonitorAdapter = new ProcessMonitorEvidenceSourceAdapter();
        var volatilityProcessAdapter = new VolatilityProcessEvidenceSourceAdapter();
        var networkCaptureAdapter = new NetworkCaptureEvidenceSourceAdapter();
        var zeekNetworkAdapter = new ZeekNetworkEvidenceSourceAdapter();
        var memoryImageAdapter = new MemoryImageEvidenceSourceAdapter();
        var legacyProcessAdapter = new LegacyProcessSnapshotEvidenceSourceAdapter();
        var filesystemArtifactAdapter = new FilesystemArtifactEvidenceSourceAdapter(
            new FilesystemArtifactLoaderService());
        var evidenceSourceAdapters = new EvidenceSourceAdapterRegistry(
        [
            runtimeProcessAdapter,
            lifecycleProcessAdapter,
            sysmonProcessAdapter,
            processMonitorAdapter,
            volatilityProcessAdapter,
            networkCaptureAdapter,
            zeekNetworkAdapter,
            memoryImageAdapter,
            legacyProcessAdapter,
            filesystemArtifactAdapter
        ]);
        var evidenceSourcePublisher = new AgentEvidenceSourcePublisher(stagingWriter);
        var liveCaptureHandler = new AgentLiveCaptureJobHandler(
            stagingWriter,
            _log,
            liveBufferOptions,
            runtimeProcessAdapter,
            lifecycleProcessAdapter,
            sysmonProcessAdapter);
        var enrichmentStatistics = new AgentArtifactEnrichmentStatistics();
        var enrichmentHandler = new AgentArtifactEnrichmentJobHandler(
            databasePath,
            stagingWriter,
            new ModuleInspector(),
            new HandleInspector(),
            new PeAnalysisService(),
            _options.WorkerOptions.PeAnalysisWorkers,
            _log,
            enrichmentStatistics);
        var importHandler = new AgentImportJobHandler(
            stagingWriter,
            new TelemetryArchiveService(),
            legacyProcessAdapter,
            captureCompatibility);
        var processDumpHandler = new AgentProcessDumpJobHandler(
            databasePath,
            stagingWriter,
            new ProcessDumpService(sessionPaths));
        var networkCaptureService = new NetworkCaptureService(sessionPaths);
        var networkCaptureHandler = new AgentNetworkCaptureJobHandler(
            networkCaptureService,
            networkCaptureAdapter,
            evidenceSourcePublisher);
        var zeekAnalysisHandler = new AgentZeekAnalysisJobHandler(
            databasePath,
            new ZeekProcessingService(sessionPaths),
            zeekNetworkAdapter,
            evidenceSourcePublisher);
        var artifactImportHandler = new AgentArtifactImportJobHandler(
            evidenceSourceAdapters,
            evidenceSourcePublisher);
        var memoryImageImportHandler = new AgentMemoryImageImportJobHandler(
            new MemoryImageImportService(sessionPaths),
            memoryImageAdapter,
            evidenceSourcePublisher);
        var memoryAcquisitionService = new AgentMemoryAcquisitionService(sessionPaths);
        var memoryAcquisitionHandler = new AgentMemoryAcquisitionJobHandler(
            memoryAcquisitionService,
            new MemoryImageImportService(sessionPaths),
            memoryImageAdapter,
            evidenceSourcePublisher);
        var volatilityAnalysisHandler = new AgentVolatilityAnalysisJobHandler(
            databasePath,
            new VolatilityExecutionService(sessionPaths),
            volatilityProcessAdapter,
            evidenceSourcePublisher);
        var processMonitorService = new ProcessMonitorService(sessionPaths);
        var processMonitorCaptureHandler = new AgentProcessMonitorCaptureJobHandler(
            processMonitorService,
            processMonitorAdapter,
            evidenceSourcePublisher);
        var processMonitorImportHandler = new AgentProcessMonitorImportJobHandler(
            processMonitorService,
            processMonitorAdapter,
            evidenceSourcePublisher);
        var sqliteBenchmarkHandler = new AgentSqliteBenchmarkJobHandler(sessionPaths, _log);
        var configurationCheckService = new AgentConfigurationCheckService(_options, sessionPaths);
        var monitoringConfigurationService = new AgentMonitoringConfigurationService(
            sessionPaths,
            configurationCheckService,
            _log);
        var captureConfigurationService = new AgentCaptureConfigurationService(
            sessionPaths,
            configurationCheckService,
            _log);
        var jobHandler = new AgentJobHandlerRouter(
            liveCaptureHandler,
            enrichmentHandler,
            enrichmentHandler,
            importHandler,
            processDumpHandler,
            networkCaptureHandler,
            zeekAnalysisHandler,
            artifactImportHandler,
            memoryImageImportHandler,
            memoryAcquisitionHandler,
            volatilityAnalysisHandler,
            processMonitorCaptureHandler,
            processMonitorImportHandler,
            sqliteBenchmarkHandler,
            evidenceSourceAdapters,
            releaseCatalog,
            _options.CaptureSealed,
            new StubAgentJobHandler());
        await using var jobQueue = new AgentJobQueue(stagingWriter, jobHandler, _options.WorkerOptions, _log, enrichmentStatistics);
        var configuredCapturePause = new AgentConfiguredCapturePauseCoordinator(
            jobQueue,
            liveCaptureHandler,
            networkCaptureHandler);
        using var standalonePairingRuntime = _options.IsInteractiveHost &&
                                            preparedPairingRuntime == null &&
                                            (_options.IpcStressTest || (_options.Foreground && !_options.SelfTest))
            ? AgentPairingRuntime.Start(
                sessionPaths,
                releaseCatalog.ReleaseId,
                _options.CaptureSealed
                    ? CaptureWorkspaceMode.ArchivedCapture
                    : CaptureWorkspaceMode.LiveCapture,
                _options.CaptureSealed)
            : null;
        var pairingRuntime = preparedPairingRuntime ?? standalonePairingRuntime;
        if (standalonePairingRuntime != null)
        {
            Log($"Local pairing contract {AgentContracts.PairingContractVersion} initialized; " +
                $"generation {standalonePairingRuntime.Status.PairingGeneration}; standalone generation created; credentials are stored outside the capture package.");
        }
        if (_options.IpcStressTest)
        {
            await using var diagnosticsSampler = new AgentRuntimeDiagnosticsSampler(
                sessionPaths,
                jobQueue,
                stagingWriter,
                liveCaptureHandler.GetHealthSnapshot,
                _log);
            using var stressShutdown = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            await using var stressIpcServer = new AgentNamedPipeServer(
                _options,
                jobQueue,
                stagingWriter,
                diagnosticsSampler,
                networkCaptureService,
                configurationCheckService,
                monitoringConfigurationService,
                captureConfigurationService,
                captureCompatibility,
                releaseCatalog,
                evidenceSourceAdapters.Descriptors,
                liveCaptureHandler.GetHealthSnapshot,
                liveCaptureHandler.RequestStop,
                liveCaptureHandler.RequestSourceStop,
                liveCaptureHandler.RequestSourceStart,
                stressShutdown.Cancel,
                _log,
                pairingRuntime!,
                configuredCapturePause: configuredCapturePause);
            await using var stressLegacyIpcServer = new AgentNamedPipeServer(
                _options,
                jobQueue,
                stagingWriter,
                diagnosticsSampler,
                networkCaptureService,
                configurationCheckService,
                monitoringConfigurationService,
                captureConfigurationService,
                captureCompatibility,
                releaseCatalog,
                evidenceSourceAdapters.Descriptors,
                liveCaptureHandler.GetHealthSnapshot,
                liveCaptureHandler.RequestStop,
                liveCaptureHandler.RequestSourceStop,
                liveCaptureHandler.RequestSourceStart,
                stressShutdown.Cancel,
                _log,
                pairingRuntime!,
                pipeName: AgentContracts.LegacyPipeName,
                configuredCapturePause: configuredCapturePause);
            await using var stressShutdownControlServer = new AgentNamedPipeServer(
                _options,
                jobQueue,
                stagingWriter,
                diagnosticsSampler,
                networkCaptureService,
                configurationCheckService,
                monitoringConfigurationService,
                captureConfigurationService,
                captureCompatibility,
                releaseCatalog,
                evidenceSourceAdapters.Descriptors,
                liveCaptureHandler.GetHealthSnapshot,
                liveCaptureHandler.RequestStop,
                liveCaptureHandler.RequestSourceStop,
                liveCaptureHandler.RequestSourceStart,
                stressShutdown.Cancel,
                _log,
                pairingRuntime!,
                pipeName: AgentContracts.ShutdownControlPipeName,
                shutdownOnly: true);
            await using var stressLegacyShutdownControlServer = new AgentNamedPipeServer(
                _options,
                jobQueue,
                stagingWriter,
                diagnosticsSampler,
                networkCaptureService,
                configurationCheckService,
                monitoringConfigurationService,
                captureConfigurationService,
                captureCompatibility,
                releaseCatalog,
                evidenceSourceAdapters.Descriptors,
                liveCaptureHandler.GetHealthSnapshot,
                liveCaptureHandler.RequestStop,
                liveCaptureHandler.RequestSourceStop,
                liveCaptureHandler.RequestSourceStart,
                stressShutdown.Cancel,
                _log,
                pairingRuntime!,
                pipeName: AgentContracts.LegacyShutdownControlPipeName,
                shutdownOnly: true);
            return await RunIpcStressTestAsync(
                jobQueue,
                stagingWriter,
                releaseCatalog,
                cancellationToken).ConfigureAwait(false);
        }

        if (_options.StartCaptureOnLaunch && _options.IsLongRunningHost && !_options.SelfTest)
        {
            await QueueStartupLiveCaptureAsync(jobQueue, cancellationToken).ConfigureAwait(false);
        }

        if (_options.SelfTest)
        {
            var request = new AgentJobRequest
            {
                JobKind = JobKind.ModuleEnrichment,
                SourceType = "AgentSelfTest",
                SourceDisplayName = "Agent self-test",
                Ownership = AgentJobOwnership.Background,
                RequestedWorkloads = AgentRequestedWorkloads.ForEnrichment(true, false, false),
                Parameters = new
                {
                    mode = "self-test",
                    CaptureModules = true,
                    CaptureHandles = false,
                    ProcessKeys = Array.Empty<string>()
                }
            };
            var jobId = await jobQueue.EnqueueAsync(request, cancellationToken).ConfigureAwait(false);
            await jobQueue.WaitForJobAsync(jobId, cancellationToken).ConfigureAwait(false);
            if (!jobQueue.TryGetJobStatus(jobId, out var progress) || progress.State != JobState.Completed)
            {
                Log($"Self-test job {jobId} failed. Final state: {progress?.State.ToString() ?? "unknown"}; {progress?.ErrorText}");
                return 1;
            }

            Log($"Self-test job {jobId} queued, ran, and completed.");
            return 0;
        }

        if (!_options.IsLongRunningHost)
        {
            Log("Startup health check completed.");
            return 0;
        }

        if (_options.HostMode == AgentHostMode.WindowsService)
        {
            await using var serviceDiagnosticsSampler = new AgentRuntimeDiagnosticsSampler(
                sessionPaths,
                jobQueue,
                stagingWriter,
                liveCaptureHandler.GetHealthSnapshot,
                _log);
            using var serviceShutdown = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            await using var infrastructureCommandRuntime = preparedInfrastructure == null
                ? null
                : new AgentNamedPipeServer(
                    _options,
                    jobQueue,
                    stagingWriter,
                    serviceDiagnosticsSampler,
                    networkCaptureService,
                    configurationCheckService,
                    monitoringConfigurationService,
                    captureConfigurationService,
                    captureCompatibility,
                    releaseCatalog,
                    evidenceSourceAdapters.Descriptors,
                    liveCaptureHandler.GetHealthSnapshot,
                    liveCaptureHandler.RequestStop,
                    liveCaptureHandler.RequestSourceStop,
                    liveCaptureHandler.RequestSourceStart,
                    serviceShutdown.Cancel,
                    _log,
                    pairingRuntime: null,
                    configuredCapturePause: configuredCapturePause,
                    commandRuntimeOnly: true);
            var infrastructureRuntime = preparedInfrastructure?.Activate(
                releaseCatalog,
                (target, writeCategory) =>
                    target.Scope.WorkspaceMode == CaptureWorkspaceMode.LiveCapture &&
                    !target.Scope.CaptureSealed &&
                    CaptureWritePolicy.IsAllowed(CaptureWorkspaceMode.LiveCapture, writeCategory) &&
                    captureCompatibility.Allows(CaptureOpenCapability.WritePrimaryEvidence),
                infrastructureCommandRuntime!.ExecuteAuthenticatedCommandAsync,
                () => jobQueue.GetControlSnapshot(liveCaptureHandler.GetHealthSnapshot()),
                cancellation => jobQueue.DrainAcceptedWorkAsync(cancellation));
            if (infrastructureRuntime != null)
            {
                infrastructureRuntime.StateChanged += snapshot =>
                    Log($"Infrastructure runtime state={snapshot.State}; " +
                        $"attempts={snapshot.ConnectionAttempts}; error={snapshot.ErrorCode}.");
                infrastructureRuntime.Start();
            }
            await using var serviceEnrichmentScheduler = new AgentBackgroundEnrichmentScheduler(
                databasePath,
                jobQueue,
                _log,
                captureConfigurationService.GetBackgroundArtifactCapturePolicy,
                enableAutomaticScheduling: !_options.CaptureSealed);
            if (!_options.CaptureSealed)
            {
                liveCaptureHandler.ProcessRecordsPersisted += serviceEnrichmentScheduler.NotifyProcessRecordsPersisted;
            }

            runtimeReady?.Invoke();
            Log("Windows Agent Service runtime active; current-user named pipes and pairing remain disabled.");
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, serviceShutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (serviceShutdown.IsCancellationRequested)
            {
                Log("Service shutdown requested; draining accepted work through shared runtime disposal.");
            }

            if (infrastructureRuntime != null)
            {
                await infrastructureRuntime.StopAsync().ConfigureAwait(false);
            }

            Log($"{ProductIdentity.AgentDisplayName} service runtime stopped.");
            return 0;
        }

        Log("Foreground mode active. Press Ctrl+C to stop.");
        using var foregroundShutdown = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using var foregroundDiagnosticsSampler = new AgentRuntimeDiagnosticsSampler(
            sessionPaths,
            jobQueue,
            stagingWriter,
            liveCaptureHandler.GetHealthSnapshot,
            _log);
        await using var ipcServer = new AgentNamedPipeServer(
            _options,
            jobQueue,
            stagingWriter,
            foregroundDiagnosticsSampler,
            networkCaptureService,
            configurationCheckService,
            monitoringConfigurationService,
            captureConfigurationService,
            captureCompatibility,
            releaseCatalog,
            evidenceSourceAdapters.Descriptors,
            liveCaptureHandler.GetHealthSnapshot,
            liveCaptureHandler.RequestStop,
            liveCaptureHandler.RequestSourceStop,
            liveCaptureHandler.RequestSourceStart,
            foregroundShutdown.Cancel,
            _log,
            pairingRuntime!,
            configuredCapturePause: configuredCapturePause);
        await using var legacyIpcServer = new AgentNamedPipeServer(
            _options,
            jobQueue,
            stagingWriter,
            foregroundDiagnosticsSampler,
            networkCaptureService,
            configurationCheckService,
            monitoringConfigurationService,
            captureConfigurationService,
            captureCompatibility,
            releaseCatalog,
            evidenceSourceAdapters.Descriptors,
            liveCaptureHandler.GetHealthSnapshot,
            liveCaptureHandler.RequestStop,
            liveCaptureHandler.RequestSourceStop,
            liveCaptureHandler.RequestSourceStart,
            foregroundShutdown.Cancel,
            _log,
            pairingRuntime!,
            pipeName: AgentContracts.LegacyPipeName,
            configuredCapturePause: configuredCapturePause);
        await using var shutdownControlServer = new AgentNamedPipeServer(
            _options,
            jobQueue,
            stagingWriter,
            foregroundDiagnosticsSampler,
            networkCaptureService,
            configurationCheckService,
            monitoringConfigurationService,
            captureConfigurationService,
            captureCompatibility,
            releaseCatalog,
            evidenceSourceAdapters.Descriptors,
            liveCaptureHandler.GetHealthSnapshot,
            liveCaptureHandler.RequestStop,
            liveCaptureHandler.RequestSourceStop,
            liveCaptureHandler.RequestSourceStart,
            foregroundShutdown.Cancel,
            _log,
            pairingRuntime!,
            pipeName: AgentContracts.ShutdownControlPipeName,
            shutdownOnly: true);
        await using var legacyShutdownControlServer = new AgentNamedPipeServer(
            _options,
            jobQueue,
            stagingWriter,
            foregroundDiagnosticsSampler,
            networkCaptureService,
            configurationCheckService,
            monitoringConfigurationService,
            captureConfigurationService,
            captureCompatibility,
            releaseCatalog,
            evidenceSourceAdapters.Descriptors,
            liveCaptureHandler.GetHealthSnapshot,
            liveCaptureHandler.RequestStop,
            liveCaptureHandler.RequestSourceStop,
            liveCaptureHandler.RequestSourceStart,
            foregroundShutdown.Cancel,
            _log,
            pairingRuntime!,
            pipeName: AgentContracts.LegacyShutdownControlPipeName,
            shutdownOnly: true);
        await using var enrichmentScheduler = new AgentBackgroundEnrichmentScheduler(
            databasePath,
            jobQueue,
            _log,
            captureConfigurationService.GetBackgroundArtifactCapturePolicy,
            enableAutomaticScheduling: !_options.CaptureSealed);
        if (!_options.CaptureSealed)
        {
            liveCaptureHandler.ProcessRecordsPersisted += enrichmentScheduler.NotifyProcessRecordsPersisted;
        }

        runtimeReady?.Invoke();

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, foregroundShutdown.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (foregroundShutdown.IsCancellationRequested)
        {
            Log("Shutdown requested.");
        }

        Log($"{ProductIdentity.AgentDisplayName} stopped.");
        return 0;
    }

    private AgentInfrastructurePreparedRuntime? PrepareInfrastructureRuntime(
        AgentStagingWriter stagingWriter,
        InvestigationSessionPaths sessionPaths)
    {
        if (_options.HostMode != AgentHostMode.WindowsService)
        {
            return null;
        }
        var configuration = _options.InfrastructureConfiguration ??
            throw new InvalidOperationException(
                "The publication-authorized Agent Service did not retain its validated Infrastructure configuration.");
        var compositionFactory = _options.InfrastructureRuntimeCompositionFactory ??
            throw new InvalidOperationException(
                "The publication-authorized Agent Service has no protected Infrastructure runtime composition authority.");
        var composition = compositionFactory.Create(configuration, sessionPaths);
        var prepared = composition.Prepare(stagingWriter);
        Log("Infrastructure evidence publication prepared; the transactional outbox is active before Agent work can be queued.");
        return prepared;
    }

    private async Task<int> RunIpcStressTestAsync(
        AgentJobQueue jobQueue,
        AgentStagingWriter stagingWriter,
        IFeatureCatalog releaseCatalog,
        CancellationToken cancellationToken)
    {
        Log("IPC stress test started.");
        var client = new AgentNamedPipeClient(
            timeout: TimeSpan.FromSeconds(2),
            viewerReleaseId: releaseCatalog.ReleaseId);
        var legacyClient = new AgentNamedPipeClient(
            AgentContracts.LegacyPipeName,
            timeout: TimeSpan.FromSeconds(2),
            viewerReleaseId: releaseCatalog.ReleaseId);
        client.BindSession(_options.SessionPaths!);
        legacyClient.BindSession(_options.SessionPaths!);
        var failures = 0;
        var maxHealthMilliseconds = 0.0;

        failures += await RunIpcTransportSecurityStressTestAsync(
            jobQueue,
            stagingWriter,
            releaseCatalog,
            cancellationToken).ConfigureAwait(false);

        var legacyHealthResponse = await legacyClient.GetHealthAsync(cancellationToken).ConfigureAwait(false);
        if (!legacyHealthResponse.Success)
        {
            failures++;
            Log(
                "IPC stress legacy-alias health failed: " +
                $"code={legacyHealthResponse.ErrorCode}; message={legacyHealthResponse.ErrorMessage}.");
        }

        var beforeBackfillKnownJobCount = jobQueue.KnownJobCount;
        var beforeBackfillDatabaseRows = ReadDatabaseRowCounts(_options.DatabasePath);
        var legacyBackfillPayload = JsonSerializer.SerializeToElement(
            new
            {
                CommandId = Guid.NewGuid(),
                IssuedAtUtc = DateTime.UtcNow,
                TargetSessionId = _options.SessionPaths?.SessionId ?? string.Empty,
                TargetDatabasePath = _options.DatabasePath,
                TargetWorkspaceMode = _options.CaptureSealed
                    ? CaptureWorkspaceMode.ArchivedCapture
                    : CaptureWorkspaceMode.LiveCapture,
                RequestedWriteCategory = CaptureWriteCategory.PrimaryImport,
                FromUtc = (DateTime?)null,
                ToUtc = (DateTime?)null,
                ProcessKeys = Array.Empty<string>()
            },
            AgentIpcJson.JsonOptions);
        var legacyBackfillResponse = await legacyClient.SendAsync(
            new AgentIpcRequest
            {
                Kind = AgentIpcRequestKind.SubmitCommand,
                CommandKind = (AgentCommandKind)3,
                ViewerReleaseId = releaseCatalog.ReleaseId,
                Payload = legacyBackfillPayload
            },
            cancellationToken).ConfigureAwait(false);
        var afterBackfillDatabaseRows = ReadDatabaseRowCounts(_options.DatabasePath);
        if (legacyBackfillResponse.Success ||
            legacyBackfillResponse.ErrorCode != "CommandNotAvailable" ||
            legacyBackfillResponse.ErrorMessage != AgentCommandFeaturePolicy.BackfillUnavailableReason ||
            legacyBackfillResponse.IsRetryable ||
            legacyBackfillResponse.AcceptedJobId.HasValue ||
            legacyBackfillResponse.Job != null ||
            jobQueue.KnownJobCount != beforeBackfillKnownJobCount ||
            !DatabaseRowCountsEqual(beforeBackfillDatabaseRows, afterBackfillDatabaseRows))
        {
            failures++;
            Log(
                "IPC stress legacy backfill retirement failed: " +
                $"success={legacyBackfillResponse.Success}; code={legacyBackfillResponse.ErrorCode}; " +
                $"retryable={legacyBackfillResponse.IsRetryable}; " +
                $"jobs={beforeBackfillKnownJobCount}->{jobQueue.KnownJobCount}; " +
                $"databaseRowsUnchanged={DatabaseRowCountsEqual(beforeBackfillDatabaseRows, afterBackfillDatabaseRows)}.");
        }

        var benchmarkRequest = new AgentJobRequest
        {
            JobKind = JobKind.SqliteBenchmark,
            SourceType = "AgentIpcStressTest",
            SourceDisplayName = "Agent IPC stress test",
            Parameters = new QueueSqliteBenchmarkCommand
            {
                PhaseDurationSeconds = 2,
                MaxPhaseCount = 2,
                InitialProcessBatchSize = 100,
                InitialEventsPerProcess = 4,
                MaxInFlightBatches = 8,
                MaxPendingWriterWorkItems = 512,
                ProgressIntervalMilliseconds = 500
            }
        };
        var jobId = await jobQueue.EnqueueAsync(benchmarkRequest, cancellationToken).ConfigureAwait(false);

        var unpublishedResponse = await client.SubmitCommandAsync(
            new StartNetworkCaptureCommand(),
            cancellationToken).ConfigureAwait(false);
        if (unpublishedResponse.Success ||
            unpublishedResponse.ErrorCode != AgentFeaturePolicyErrorCodes.FeatureNotPublished ||
            unpublishedResponse.IsRetryable)
        {
            failures++;
            Log(
                "IPC stress unpublished-command policy failed: " +
                $"success={unpublishedResponse.Success}; code={unpublishedResponse.ErrorCode}; retryable={unpublishedResponse.IsRetryable}.");
        }

        var mismatchedClient = new AgentNamedPipeClient(
            timeout: TimeSpan.FromSeconds(2),
            viewerReleaseId: "self-test-mismatched-viewer-release");
        mismatchedClient.BindSession(_options.SessionPaths!);
        var mismatchResponse = await mismatchedClient.SubmitCommandAsync(
            new GetCaptureConfigurationCommand(),
            cancellationToken).ConfigureAwait(false);
        if (mismatchResponse.Success ||
            mismatchResponse.ErrorCode != "PairingReleaseMismatch" ||
            mismatchResponse.IsRetryable)
        {
            failures++;
            Log(
                "IPC stress release-mismatch policy failed: " +
                $"success={mismatchResponse.Success}; code={mismatchResponse.ErrorCode}; retryable={mismatchResponse.IsRetryable}.");
        }

        using (var unknownPayload = JsonDocument.Parse("{}"))
        {
            var unknownResponse = await client.SendAsync(
                new AgentIpcRequest
                {
                    Kind = AgentIpcRequestKind.SubmitCommand,
                    CommandKind = (AgentCommandKind)int.MaxValue,
                    ViewerReleaseId = releaseCatalog.ReleaseId,
                    Payload = unknownPayload.RootElement.Clone()
                },
                cancellationToken).ConfigureAwait(false);
            if (unknownResponse.Success ||
                unknownResponse.ErrorCode != AgentFeaturePolicyErrorCodes.UnknownCommandFeatureMapping ||
                unknownResponse.IsRetryable)
            {
                failures++;
                Log(
                    "IPC stress unknown-command policy failed: " +
                    $"success={unknownResponse.Success}; code={unknownResponse.ErrorCode}; retryable={unknownResponse.IsRetryable}.");
            }
        }

        for (var index = 1; index <= 60; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var stopwatch = Stopwatch.StartNew();
            var response = await client.GetHealthAsync(cancellationToken).ConfigureAwait(false);
            stopwatch.Stop();
            maxHealthMilliseconds = Math.Max(maxHealthMilliseconds, stopwatch.Elapsed.TotalMilliseconds);
            if (!response.Success)
            {
                failures++;
                Log($"IPC stress health request {index} failed after {stopwatch.Elapsed.TotalMilliseconds:N1} ms: {response.ErrorCode} {response.ErrorMessage}");
            }
            else if (index == 1 &&
                     (response.Health?.ReleaseProfile.Match != AgentReleaseProfileMatch.Match ||
                      !string.Equals(response.Health.ReleaseProfile.ReleaseId, releaseCatalog.ReleaseId, StringComparison.Ordinal) ||
                      response.Health.ReleaseProfile.PublishedCommandCapabilities.Any(
                          capability => capability.CommandKind == AgentCommandKind.StartNetworkCapture)))
            {
                failures++;
                Log("IPC stress health release profile did not report the matching test release and hidden network capability.");
            }

            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }

        await jobQueue.WaitForJobAsync(jobId, cancellationToken).ConfigureAwait(false);
        if (!jobQueue.TryGetJobStatus(jobId, out var progress) || progress.State is not JobState.Completed)
        {
            failures++;
            Log($"IPC stress benchmark job {jobId} did not complete successfully. Final state: {progress?.State.ToString() ?? "unknown"}.");
        }

        Log($"IPC stress test completed with {failures} health/job/policy failures; max health round-trip {maxHealthMilliseconds:N1} ms.");
        return failures == 0 ? 0 : 2;
    }

    private async Task<int> RunIpcTransportSecurityStressTestAsync(
        AgentJobQueue jobQueue,
        AgentStagingWriter stagingWriter,
        IFeatureCatalog releaseCatalog,
        CancellationToken cancellationToken)
    {
        var failures = 0;
        var beforeRuntime = jobQueue.GetRuntimeSnapshot();
        var beforeWriter = stagingWriter.GetSnapshot();
        var beforeDatabaseRows = ReadDatabaseRowCounts(_options.DatabasePath);

        failures += await ValidateAuthenticatedEndpointInventoryAsync(
            releaseCatalog,
            "preflight",
            cancellationToken).ConfigureAwait(false);

        var oversizedRequest = new string('x', AgentIpcTransportPolicy.DefaultMaxRequestBytes + 1);
        var oversizedResponse = await SendRawIpcRequestAsync(
            AgentContracts.LegacyPipeName,
            oversizedRequest,
            cancellationToken).ConfigureAwait(false);
        if (oversizedResponse.Success || oversizedResponse.ErrorCode != "RequestTooLarge")
        {
            failures++;
            Log(
                "IPC stress oversized request failed: " +
                $"success={oversizedResponse.Success}; code={oversizedResponse.ErrorCode}.");
        }

        var heldConnections = new List<System.IO.Pipes.NamedPipeClientStream>();
        try
        {
            for (var index = 0;
                 index < AgentIpcTransportPolicy.DefaultMaxConcurrentConnectionsPerEndpoint;
                 index++)
            {
                var held = CreateIdentifiedPipeClient(AgentContracts.PipeName);
                await held.ConnectAsync(cancellationToken).ConfigureAwait(false);
                heldConnections.Add(held);
            }

            await using var saturated = CreateIdentifiedPipeClient(AgentContracts.PipeName);
            await saturated.ConnectAsync(cancellationToken).ConfigureAwait(false);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            using var reader = new StreamReader(saturated, leaveOpen: true);
            var responseJson = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
            var saturatedResponse = string.IsNullOrWhiteSpace(responseJson)
                ? null
                : JsonSerializer.Deserialize<AgentIpcResponse>(responseJson, AgentIpcJson.JsonOptions);
            if (saturatedResponse?.Success != false || saturatedResponse.ErrorCode != "ServerBusy")
            {
                failures++;
                Log(
                    "IPC stress saturated connection failed: " +
                    $"success={saturatedResponse?.Success}; code={saturatedResponse?.ErrorCode ?? "<empty>"}.");
            }

            await using (var abandonedSaturated = CreateIdentifiedPipeClient(AgentContracts.PipeName))
            {
                await abandonedSaturated.ConnectAsync(cancellationToken).ConfigureAwait(false);
            }
            await Task.Delay(25, cancellationToken).ConfigureAwait(false);

            var healthRequest = JsonSerializer.Serialize(
                AgentIpcRequest.CreateHealthRequest(releaseCatalog.ReleaseId),
                AgentIpcJson.JsonOptions);
            foreach (var heldConnection in heldConnections)
            {
                var heldResponse = await SendConnectedPipeRequestAsync(
                    heldConnection,
                    healthRequest,
                    cancellationToken).ConfigureAwait(false);
                if (heldResponse.Success ||
                    heldResponse.ErrorCode != "PairingRequired" ||
                    heldResponse.Health != null)
                {
                    failures++;
                    Log(
                        "IPC stress unauthenticated held connection failed closed incorrectly: " +
                        $"success={heldResponse.Success}; code={heldResponse.ErrorCode}; healthDisclosed={heldResponse.Health != null}.");
                }
            }
        }
        finally
        {
            foreach (var heldConnection in heldConnections)
            {
                await heldConnection.DisposeAsync().ConfigureAwait(false);
            }
        }

        failures += await ValidateAuthenticatedEndpointInventoryAsync(
            releaseCatalog,
            "post-saturation recovery",
            cancellationToken).ConfigureAwait(false);

        var afterRuntime = jobQueue.GetRuntimeSnapshot();
        var afterWriter = stagingWriter.GetSnapshot();
        var afterDatabaseRows = ReadDatabaseRowCounts(_options.DatabasePath);
        if (!QueueStateEqual(beforeRuntime, afterRuntime) ||
            !WriterStateEqual(beforeWriter, afterWriter) ||
            !DatabaseRowCountsEqual(beforeDatabaseRows, afterDatabaseRows))
        {
            failures++;
            Log(
                "IPC stress transport rejections changed durable/runtime state: " +
                $"queueStateUnchanged={QueueStateEqual(beforeRuntime, afterRuntime)}; " +
                $"writerStateUnchanged={WriterStateEqual(beforeWriter, afterWriter)}; " +
                $"databaseRowsUnchanged={DatabaseRowCountsEqual(beforeDatabaseRows, afterDatabaseRows)}.");
        }

        return failures;
    }

    private async Task<int> ValidateAuthenticatedEndpointInventoryAsync(
        IFeatureCatalog releaseCatalog,
        string phase,
        CancellationToken cancellationToken)
    {
        var failures = 0;
        foreach (var endpoint in AgentIpcEndpointCatalog.Endpoints)
        {
            var endpointClient = new AgentNamedPipeClient(
                endpoint.PipeName,
                timeout: TimeSpan.FromSeconds(2),
                viewerReleaseId: releaseCatalog.ReleaseId,
                fallbackPipeNames: Array.Empty<string>());
            endpointClient.BindSession(_options.SessionPaths!);
            var response = await endpointClient.GetHealthAsync(cancellationToken).ConfigureAwait(false);
            if (endpoint.ShutdownOnly)
            {
                if (response.Success || response.ErrorCode != "ShutdownControlOnly" || response.Health != null)
                {
                    failures++;
                    Log(
                        $"IPC stress {phase} authenticated shutdown endpoint '{endpoint.PipeName}' failed: " +
                        $"success={response.Success}; code={response.ErrorCode}; healthDisclosed={response.Health != null}.");
                }
            }
            else if (!response.Success || response.Health == null)
            {
                failures++;
                Log(
                    $"IPC stress {phase} authenticated command endpoint '{endpoint.PipeName}' failed: " +
                    $"success={response.Success}; code={response.ErrorCode}.");
            }
        }

        return failures;
    }

    private static System.IO.Pipes.NamedPipeClientStream CreateIdentifiedPipeClient(string pipeName) =>
        new(
            ".",
            pipeName,
            System.IO.Pipes.PipeDirection.InOut,
            System.IO.Pipes.PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Identification);

    private static async Task<AgentIpcResponse> SendConnectedPipeRequestAsync(
        System.IO.Pipes.NamedPipeClientStream pipe,
        string requestJson,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        await using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
        using var reader = new StreamReader(pipe, leaveOpen: true);
        await writer.WriteLineAsync(requestJson.AsMemory(), timeout.Token).ConfigureAwait(false);
        var responseJson = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(responseJson))
        {
            throw new IOException("The connected agent pipe returned an empty response.");
        }

        return JsonSerializer.Deserialize<AgentIpcResponse>(responseJson, AgentIpcJson.JsonOptions)
            ?? throw new JsonException("The connected agent pipe returned an empty response object.");
    }

    private static async Task<AgentIpcResponse> SendRawIpcRequestAsync(
        string pipeName,
        string requestJson,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        await using var pipe = new System.IO.Pipes.NamedPipeClientStream(
            ".",
            pipeName,
            System.IO.Pipes.PipeDirection.InOut,
            System.IO.Pipes.PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
        await using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
        using var reader = new StreamReader(pipe, leaveOpen: true);
        await writer.WriteLineAsync(requestJson.AsMemory(), timeout.Token).ConfigureAwait(false);
        var responseJson = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(responseJson))
        {
            throw new IOException($"The agent pipe '{pipeName}' returned an empty response.");
        }

        return JsonSerializer.Deserialize<AgentIpcResponse>(responseJson, AgentIpcJson.JsonOptions)
            ?? throw new JsonException($"The agent pipe '{pipeName}' returned an empty response object.");
    }

    private static bool QueueStateEqual(AgentRuntimeSnapshot before, AgentRuntimeSnapshot after) =>
        before.QueuedJobCount == after.QueuedJobCount &&
        before.PeakQueuedJobCount == after.PeakQueuedJobCount &&
        before.RunningJobCount == after.RunningJobCount &&
        before.CompletedJobCount == after.CompletedJobCount &&
        before.RejectedJobCount == after.RejectedJobCount &&
        before.KnownJobCount == after.KnownJobCount;

    private static bool WriterStateEqual(
        AgentStagingWriterSnapshot before,
        AgentStagingWriterSnapshot after) =>
        before.PendingWorkItemCount == after.PendingWorkItemCount &&
        before.PeakPendingWorkItemCount == after.PeakPendingWorkItemCount &&
        before.CompletedWorkItemCount == after.CompletedWorkItemCount &&
        before.FailedWorkItemCount == after.FailedWorkItemCount &&
        before.CompletedRowCount == after.CompletedRowCount &&
        before.FailedRowCount == after.FailedRowCount &&
        before.BusyOrLockedFailureCount == after.BusyOrLockedFailureCount;

    private static IReadOnlyDictionary<string, long> ReadDatabaseRowCounts(string databasePath)
    {
        var result = new SortedDictionary<string, long>(StringComparer.Ordinal);
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Shared
        }.ToString();
        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        var tableNames = new List<string>();
        using (var tables = connection.CreateCommand())
        {
            tables.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name;";
            using var reader = tables.ExecuteReader();
            while (reader.Read())
            {
                tableNames.Add(reader.GetString(0));
            }
        }

        foreach (var tableName in tableNames)
        {
            using var count = connection.CreateCommand();
            count.CommandText = $"SELECT COUNT(*) FROM \"{tableName.Replace("\"", "\"\"")}\";";
            result[tableName] = Convert.ToInt64(count.ExecuteScalar());
        }

        return result;
    }

    private static bool DatabaseRowCountsEqual(
        IReadOnlyDictionary<string, long> before,
        IReadOnlyDictionary<string, long> after) =>
        before.Count == after.Count &&
        before.All(pair => after.TryGetValue(pair.Key, out var count) && count == pair.Value);

    private static IFeatureCatalog CreateIpcStressReleaseCatalog()
    {
        var current = CurrentEducationalReleaseProfile.Catalog;
        return new FeatureCatalog(
            $"{current.ReleaseId}-ipc-stress",
            current.Features.Select(definition => new FeatureDefinition(
                definition.Id,
                definition.Id == FeatureIds.NetworkAndZeek
                    ? FeatureReleaseState.ReadyHidden
                    : definition.Id == FeatureIds.EventTelemetry
                        ? FeatureReleaseState.Published
                        : definition.State,
                definition.Dependencies)));
    }

    private static IFeatureCatalog CreateSelfTestReleaseCatalog()
    {
        var current = CurrentEducationalReleaseProfile.Catalog;
        return new FeatureCatalog(
            $"{current.ReleaseId}-self-test",
            current.Features.Select(definition => new FeatureDefinition(
                definition.Id,
                definition.Id == FeatureIds.ModulesAndHandles
                    ? FeatureReleaseState.Published
                    : definition.State,
                definition.Dependencies)));
    }

    private static IFeatureCatalog CreateEvidenceActionSmokeReleaseCatalog()
    {
        var current = CurrentEducationalReleaseProfile.Catalog;
        var evidenceFeatures = new HashSet<FeatureId>
        {
            FeatureIds.ModulesAndHandles,
            FeatureIds.DumpsAndPeAnalysis,
            FeatureIds.FilesystemArtifacts
        };
        return new FeatureCatalog(
            current.ReleaseId,
            current.Features.Select(definition => new FeatureDefinition(
                definition.Id,
                evidenceFeatures.Contains(definition.Id)
                    ? FeatureReleaseState.Published
                    : definition.State,
                definition.Dependencies)));
    }

    private static IFeatureCatalog CreateMemoryActionSmokeReleaseCatalog()
    {
        var current = CurrentEducationalReleaseProfile.Catalog;
        return new FeatureCatalog(
            current.ReleaseId,
            current.Features.Select(definition => new FeatureDefinition(
                definition.Id,
                definition.Id == FeatureIds.SystemMemoryAndVolatility
                    ? FeatureReleaseState.Published
                    : definition.State,
                definition.Dependencies)));
    }

    private async Task QueueStartupLiveCaptureAsync(AgentJobQueue jobQueue, CancellationToken cancellationToken)
    {
        var captureId = $"deployed-capture-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}";
        var jobId = await jobQueue.EnqueueAsync(new AgentJobRequest
        {
            JobKind = JobKind.LiveCapture,
            SourceType = "AgentDeployment",
            SourceDisplayName = "Deployment live capture",
            EvidenceSourceAdapterId = RuntimeProcessSnapshotEvidenceSourceAdapter.Id,
            EvidenceSourceAdapterVersion = RuntimeProcessSnapshotEvidenceSourceAdapter.Version,
            ParserVersion = RuntimeProcessSnapshotEvidenceSourceAdapter.Version,
            EvidenceIdentity = new EvidenceIdentity
            {
                EvidenceSessionId = _options.SessionPaths?.SessionId ?? string.Empty,
                CaptureId = captureId,
                SourceIdentityId = RuntimeProcessSnapshotEvidenceSourceAdapter.Id,
                HostId = Environment.MachineName,
                ExecutionRootId = _options.SessionPaths?.SessionId ?? string.Empty
            },
            CaptureId = captureId,
            IsCaptureScoped = true,
            IsLiveSource = true,
            Parameters = new
            {
                CaptureId = captureId,
                IssuedAtUtc = DateTime.UtcNow,
                ProcessRefreshIntervalSeconds = 10,
                EtwProfileId = string.Empty,
                EtwProfileDisplayName = string.Empty,
                EtwProfilePath = string.Empty,
                CollectRuntimeEvents = true,
                CollectEtwEvents = true,
                CollectSecurityEvents = true,
                CollectPowerShellEvents = true,
                CollectOtherWindowsEvents = true,
                CollectSysmonEvents = true
            }
        }, cancellationToken).ConfigureAwait(false);

        Log($"Deployment live capture queued at startup: {jobId} ({captureId}).");
    }

    private void Log(string message)
    {
        _log.WriteLine($"[{DateTimeOffset.Now:O}] {message}");
    }
}
