using ProcInsider.Models.Agent;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services;
using ProcInsider.Services.Features;
using ProcInsider.Services.Infrastructure;

namespace ProcInsider.Agent;

internal sealed record AgentOptions
{
    public string DatabasePath { get; init; } = string.Empty;

    public InvestigationSessionPaths? SessionPaths { get; init; }

    public bool Foreground { get; init; }

    public AgentHostMode HostMode { get; init; } = AgentHostMode.Interactive;

    public AgentHostRuntimeSnapshot Host { get; init; } = new();

    internal InfrastructureMachineConfigurationStore? InfrastructureConfigurationStore { get; init; }

    internal InfrastructureModeAccessService? InfrastructureAccess { get; init; }

    internal InfrastructureConfigurationContracts.InfrastructureAgentConfiguration?
        InfrastructureConfiguration { get; init; }

    internal IAgentInfrastructureRuntimeCompositionFactory? InfrastructureRuntimeCompositionFactory { get; init; }

    public bool IsLongRunningHost => Foreground || HostMode == AgentHostMode.WindowsService;

    public bool IsInteractiveHost => HostMode == AgentHostMode.Interactive;

    public bool SelfTest { get; init; }

    public bool CheckIpc { get; init; }

    public bool IpcStressTest { get; init; }

    public bool ForegroundEvidenceActionSmoke { get; init; }

    public bool ForegroundMemoryAcquisitionSmoke { get; init; }

    public bool StartCaptureOnLaunch { get; init; }

    /// <summary>
    /// Non-secret pairing generation prepared by the viewer before explicit UAC launch.
    /// The agent must adopt the matching current-user DPAPI secret instead of rotating it.
    /// </summary>
    public long? PreparedPairingGeneration { get; init; }

    /// <summary>Allow explicit derived analysis while sealing archived evidence against acquisition/import writes.</summary>
    public bool CaptureSealed { get; init; }

    public bool ShowHelp { get; init; }

    public AgentWorkerOptions WorkerOptions { get; init; } = new();

    public static AgentOptions Parse(string[] args)
    {
        var options = new AgentOptions();

        for (var index = 0; index < args.Length; index++)
        {
            var arg = args[index];
            if (IsOption(arg, "--foreground", "-f"))
            {
                options = options with { Foreground = true };
                continue;
            }

            if (IsOption(arg, "--self-test"))
            {
                options = options with { SelfTest = true };
                continue;
            }

            if (IsOption(arg, "--check-ipc"))
            {
                options = options with { CheckIpc = true };
                continue;
            }

            if (IsOption(arg, "--windows-service-host"))
            {
                options = options with { HostMode = AgentHostMode.WindowsService };
                continue;
            }

            if (IsOption(arg, "--ipc-stress-test"))
            {
                options = options with { IpcStressTest = true };
                continue;
            }

            if (IsOption(arg, "--foreground-evidence-action-smoke"))
            {
                options = options with { ForegroundEvidenceActionSmoke = true };
                continue;
            }

            if (IsOption(arg, "--foreground-memory-acquisition-smoke"))
            {
                options = options with { ForegroundMemoryAcquisitionSmoke = true };
                continue;
            }

            if (IsOption(arg, "--start-capture", "--start-live-capture"))
            {
                options = options with { StartCaptureOnLaunch = true };
                continue;
            }

            if (IsOption(arg, "--capture-sealed"))
            {
                options = options with { CaptureSealed = true };
                continue;
            }

            if (IsOption(arg, "--prepared-pairing-generation"))
            {
                options = options with
                {
                    PreparedPairingGeneration = ReadPositiveLong(args, ref index, arg)
                };
                continue;
            }

            if (IsLongOption(arg, "--prepared-pairing-generation=", out var preparedPairingGeneration))
            {
                options = options with { PreparedPairingGeneration = preparedPairingGeneration };
                continue;
            }

            if (IsOption(arg, "--help", "-h", "/?"))
            {
                options = options with { ShowHelp = true };
                continue;
            }

            if (IsOption(arg, "--database", "--database-path", "-d"))
            {
                if (index + 1 >= args.Length || args[index + 1].StartsWith('-'))
                {
                    throw new ArgumentException($"{arg} requires a database path value.");
                }

                options = options with { DatabasePath = Path.GetFullPath(args[++index]) };
                continue;
            }

            if (arg.StartsWith("--database=", StringComparison.OrdinalIgnoreCase))
            {
                var value = arg["--database=".Length..];
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException("--database requires a database path value.");
                }

                options = options with { DatabasePath = Path.GetFullPath(value) };
                continue;
            }

            if (IsOption(arg, "--workers", "--worker-count"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        WorkerCount = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--workers=", out var workerCount) ||
                IsIntOption(arg, "--worker-count=", out workerCount))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { WorkerCount = workerCount }
                };
                continue;
            }

            if (IsOption(arg, "--queue-capacity"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        QueueCapacity = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--queue-capacity=", out var queueCapacity))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { QueueCapacity = queueCapacity }
                };
                continue;
            }

            if (IsOption(arg, "--writer-queue-capacity"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        WriterQueueCapacity = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--writer-queue-capacity=", out var writerQueueCapacity))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { WriterQueueCapacity = writerQueueCapacity }
                };
                continue;
            }

            if (IsOption(arg, "--writer-max-batch-rows"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        WriterMaxBatchRows = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--writer-max-batch-rows=", out var writerMaxBatchRows))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { WriterMaxBatchRows = writerMaxBatchRows }
                };
                continue;
            }

            if (IsOption(arg, "--writer-max-batch-latency-ms"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        WriterMaxBatchLatencyMilliseconds = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--writer-max-batch-latency-ms=", out var writerMaxBatchLatencyMilliseconds))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { WriterMaxBatchLatencyMilliseconds = writerMaxBatchLatencyMilliseconds }
                };
                continue;
            }

            if (IsOption(arg, "--writer-checkpoint-wal-mb"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        WriterCheckpointWalMegabytes = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--writer-checkpoint-wal-mb=", out var writerCheckpointWalMegabytes))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { WriterCheckpointWalMegabytes = writerCheckpointWalMegabytes }
                };
                continue;
            }

            if (IsOption(arg, "--writer-checkpoint-min-interval-seconds"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        WriterCheckpointMinIntervalSeconds = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--writer-checkpoint-min-interval-seconds=", out var writerCheckpointMinIntervalSeconds))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { WriterCheckpointMinIntervalSeconds = writerCheckpointMinIntervalSeconds }
                };
                continue;
            }

            if (IsOption(arg, "--pe-analysis-workers"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        PeAnalysisWorkers = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--pe-analysis-workers=", out var peAnalysisWorkers))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { PeAnalysisWorkers = peAnalysisWorkers }
                };
                continue;
            }

            if (IsOption(arg, "--live-buffer-memory-mb"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        LiveBufferMemoryMegabytes = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--live-buffer-memory-mb=", out var liveBufferMemoryMegabytes))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { LiveBufferMemoryMegabytes = liveBufferMemoryMegabytes }
                };
                continue;
            }

            if (IsOption(arg, "--max-enrichment-jobs"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        MaxParallelEnrichmentJobs = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--max-enrichment-jobs=", out var enrichmentLimit))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { MaxParallelEnrichmentJobs = enrichmentLimit }
                };
                continue;
            }

            if (IsOption(arg, "--max-import-jobs"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        MaxParallelImportJobs = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--max-import-jobs=", out var importLimit))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { MaxParallelImportJobs = importLimit }
                };
                continue;
            }

            if (IsOption(arg, "--max-process-dump-jobs"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        MaxParallelProcessDumpJobs = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--max-process-dump-jobs=", out var processDumpLimit))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { MaxParallelProcessDumpJobs = processDumpLimit }
                };
                continue;
            }

            if (IsOption(arg, "--max-zeek-jobs"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        MaxParallelZeekJobs = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--max-zeek-jobs=", out var zeekLimit))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { MaxParallelZeekJobs = zeekLimit }
                };
                continue;
            }

            if (IsOption(arg, "--max-artifact-import-jobs"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        MaxParallelArtifactImportJobs = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--max-artifact-import-jobs=", out var artifactImportLimit))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { MaxParallelArtifactImportJobs = artifactImportLimit }
                };
                continue;
            }

            if (IsOption(arg, "--max-volatility-jobs"))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with
                    {
                        MaxParallelVolatilityJobs = ReadPositiveInt(args, ref index, arg)
                    }
                };
                continue;
            }

            if (IsIntOption(arg, "--max-volatility-jobs=", out var volatilityLimit))
            {
                options = options with
                {
                    WorkerOptions = options.WorkerOptions with { MaxParallelVolatilityJobs = volatilityLimit }
                };
                continue;
            }

            throw new ArgumentException($"Unknown argument: {arg}");
        }

        if (options.CaptureSealed && options.StartCaptureOnLaunch)
        {
            throw new ArgumentException("--capture-sealed cannot be combined with --start-capture.");
        }

        if (options.HostMode == AgentHostMode.WindowsService &&
            (options.Foreground ||
             options.SelfTest ||
             options.CheckIpc ||
             options.IpcStressTest ||
             options.ForegroundEvidenceActionSmoke ||
             options.ForegroundMemoryAcquisitionSmoke ||
             options.CaptureSealed ||
             options.PreparedPairingGeneration.HasValue))
        {
            throw new ArgumentException(
                "--windows-service-host is non-interactive and cannot be combined with foreground, self-test, IPC, smoke, archived-maintenance, or current-user pairing modes.");
        }

        if (options.ForegroundEvidenceActionSmoke &&
            (!options.Foreground ||
             options.SelfTest ||
             options.CheckIpc ||
             options.IpcStressTest ||
             options.CaptureSealed ||
             !IsDisposableEvidenceActionSmokeDatabase(options.DatabasePath)))
        {
            throw new ArgumentException(
                "--foreground-evidence-action-smoke requires foreground mode and an explicit live database directly under a non-reparse ProcInsiderTest-* disposable child of the OS temporary directory; it cannot be combined with other test, IPC, or sealed modes.");
        }

        if (options.ForegroundMemoryAcquisitionSmoke &&
            (!options.Foreground ||
             options.ForegroundEvidenceActionSmoke ||
             options.SelfTest ||
             options.CheckIpc ||
             options.IpcStressTest ||
             options.CaptureSealed ||
             !IsDisposableEvidenceActionSmokeDatabase(options.DatabasePath)))
        {
            throw new ArgumentException(
                "--foreground-memory-acquisition-smoke requires foreground mode and an explicit live database directly under a non-reparse ProcInsiderTest-* disposable child of the OS temporary directory; it cannot be combined with other smoke, test, IPC, or sealed modes.");
        }

        if (options.PreparedPairingGeneration.HasValue &&
            (!options.Foreground ||
             options.SelfTest ||
             options.CheckIpc ||
             options.IpcStressTest ||
             options.ForegroundMemoryAcquisitionSmoke ||
             options.CaptureSealed ||
             string.IsNullOrWhiteSpace(options.DatabasePath)))
        {
            throw new ArgumentException(
                "--prepared-pairing-generation requires foreground live-agent startup with an explicit --database and cannot be combined with self-test, IPC-check/stress, or sealed-capture modes.");
        }

        return string.IsNullOrWhiteSpace(options.DatabasePath)
            ? options with { WorkerOptions = options.WorkerOptions.Normalize() }
            : options with { DatabasePath = Path.GetFullPath(options.DatabasePath), WorkerOptions = options.WorkerOptions.Normalize() };
    }

    public AgentOptions ResolveSessionPaths()
    {
        if (!string.IsNullOrWhiteSpace(DatabasePath))
        {
            var manifestPath = Path.Combine(
                Path.GetDirectoryName(DatabasePath) ?? string.Empty,
                SessionPathService.CapturePackageManifestFileName);
            var sessionPaths = File.Exists(manifestPath)
                ? CaptureSealed
                    ? SessionPathService.OpenExistingCapturePackage(
                        manifestPath,
                        ProcInsider.Models.CaptureOpenContext.ArchivedAnalysisMaintenance,
                        SqliteEvidenceMigrationRunner.AssessExistingDatabase)
                    : SessionPathService.OpenOrCreateAgentLiveCapturePackage(
                        manifestPath,
                        SqliteEvidenceMigrationRunner.AssessExistingDatabase)
                : CaptureSealed
                    ? SessionPathService.OpenExistingCapturePackage(
                        manifestPath,
                        ProcInsider.Models.CaptureOpenContext.ArchivedAnalysisMaintenance,
                        SqliteEvidenceMigrationRunner.AssessExistingDatabase)
                    : SessionPathService.CreateForLiveDatabasePath(DatabasePath);
            if (!string.Equals(
                    Path.GetFullPath(DatabasePath),
                    Path.GetFullPath(sessionPaths.LiveDatabasePath),
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The agent database path does not match the database recorded by session.json.");
            }

            var resolved = this with
            {
                DatabasePath = sessionPaths.LiveDatabasePath,
                SessionPaths = sessionPaths
            };
            return HostMode == AgentHostMode.WindowsService
                ? resolved with
                {
                    SessionPaths = SessionPathService.BindInfrastructureAgentMachineScope(sessionPaths)
                }
                : resolved;
        }

        var defaultSessionPaths = HostMode == AgentHostMode.WindowsService
            ? SessionPathService.CreateInfrastructureAgentServiceSession()
            : SessionPathService.CreateDefaultSession();
        return this with
        {
            DatabasePath = defaultSessionPaths.LiveDatabasePath,
            SessionPaths = defaultSessionPaths
        };
    }

    public static string GetHelpText()
    {
        return """
            DFIRoscope Live Agent

            Usage:
              DFIRoscope.Agent.exe [--database <path>] [--foreground] [--prepared-pairing-generation <n>] [--start-capture] [--capture-sealed] [--self-test] [--check-ipc] [--ipc-stress-test]

            Executable compatibility:
              ProcInsider.Agent.exe remains a build-output transition alias for existing automation.

            Options:
              --database, -d     SQLite staging database path to open or create.
                                  Defaults to the active session's live database.
              --foreground, -f   Attach to the parent console and wait for Ctrl+C.
              --prepared-pairing-generation <n>
                                  Adopt the exact non-secret pairing generation prepared by the
                                  viewer for this explicit foreground/UAC startup. The DPAPI secret
                                  remains account-local and is never passed on the command line.
              --start-capture    Queue live capture immediately after startup. Intended for deployment flows
                                  where the viewer has not explicitly connected yet.
              --capture-sealed   Open archived evidence for explicit derived analysis only. Acquisition,
                                  imports, dumps, and automatic enrichment sweeps are rejected.
              --self-test        Queue one stub job, persist its state transitions, and exit.
              --check-ipc        Send a health request to a running local agent and print the response.
                                  Requires --database to select the protected session pairing. Probes the
                                  DFIRoscope pipe first, then the former pipe when unavailable.
              --ipc-stress-test  Run a local named-pipe health stress test while a benchmark job is active.
              --foreground-evidence-action-smoke
                                 Test-only: publish evidence actions for a foreground agent bound to a non-reparse ProcInsiderTest-* direct child of the OS temp directory.
              --foreground-memory-acquisition-smoke
                                 Test-only: publish system-memory actions for a foreground agent bound to a non-reparse ProcInsiderTest-* direct child of the OS temp directory.
              --workers <n>      Background worker count. Use 1 for sequential troubleshooting.
              --queue-capacity <n>
                                  Maximum queued jobs accepted before submitters wait.
              --pe-analysis-workers <n>
                                  Concurrent process-image file analyses per enrichment job.
                                  Defaults to 2 and is clamped to 1-8 for storage safety.
              --writer-queue-capacity <n>
                                  Maximum queued SQLite writer work items.
              --writer-max-batch-rows <n>
                                  Maximum rows committed by one writer batch work item.
              --writer-max-batch-latency-ms <n>
                                  Maximum writer queue admission wait before backpressure failure.
              --writer-checkpoint-wal-mb <n>
                                  Passive WAL checkpoint threshold while the writer is idle.
              --writer-checkpoint-min-interval-seconds <n>
                                  Minimum interval between idle writer checkpoints.
              --live-buffer-memory-mb <n>
                                  Live event RAM buffer before disk spill. Values are clamped
                                  to the supported 500-2048 MB range.
              --max-enrichment-jobs <n>
                                  Parallel module/handle enrichment job limit.
              --max-import-jobs <n>
                                  Parallel import preparation limit. Snapshot replacement remains exclusive.
              --max-process-dump-jobs <n>
                                  Parallel process dump job limit; one dump per ProcessKey at a time.
              --max-zeek-jobs <n>
                                  Parallel Zeek analysis job limit.
              --max-artifact-import-jobs <n>
                                  Parallel filesystem artifact import job limit.
              --max-volatility-jobs <n>
                                  Parallel Volatility analysis job limit.
              --help, -h         Show this help text.
            """;
    }

    private static bool IsDisposableEvidenceActionSmokeDatabase(string? databasePath)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            return false;
        }

        try
        {
            var sessionRoot = Path.GetDirectoryName(Path.GetFullPath(databasePath));
            if (string.IsNullOrWhiteSpace(sessionRoot) ||
                !Path.GetFileName(sessionRoot).StartsWith("ProcInsiderTest-", StringComparison.Ordinal))
            {
                return false;
            }

            var tempRoot = Path.GetFullPath(Path.GetTempPath())
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var parent = Path.GetDirectoryName(
                sessionRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            if (!string.Equals(parent, tempRoot, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var sessionDirectory = new DirectoryInfo(sessionRoot);
            return sessionDirectory.Exists &&
                   (sessionDirectory.Attributes & FileAttributes.ReparsePoint) == 0;
        }
        catch (Exception ex) when (ex is
            ArgumentException or
            NotSupportedException or
            PathTooLongException or
            IOException or
            UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsOption(string value, params string[] names)
    {
        return names.Any(name => string.Equals(value, name, StringComparison.OrdinalIgnoreCase));
    }

    private static int ReadPositiveInt(string[] args, ref int index, string optionName)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith('-'))
        {
            throw new ArgumentException($"{optionName} requires a positive integer value.");
        }

        var raw = args[++index];
        if (!int.TryParse(raw, out var value) || value <= 0)
        {
            throw new ArgumentException($"{optionName} requires a positive integer value.");
        }

        return value;
    }

    private static long ReadPositiveLong(string[] args, ref int index, string optionName)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith('-'))
        {
            throw new ArgumentException($"{optionName} requires a positive integer value.");
        }

        var raw = args[++index];
        if (!long.TryParse(raw, out var value) || value <= 0)
        {
            throw new ArgumentException($"{optionName} requires a positive integer value.");
        }

        return value;
    }

    private static bool IsIntOption(string arg, string prefix, out int value)
    {
        value = 0;
        if (!arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var raw = arg[prefix.Length..];
        if (!int.TryParse(raw, out value) || value <= 0)
        {
            throw new ArgumentException($"{prefix.TrimEnd('=')} requires a positive integer value.");
        }

        return true;
    }

    private static bool IsLongOption(string arg, string prefix, out long value)
    {
        value = 0;
        if (!arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var raw = arg[prefix.Length..];
        if (!long.TryParse(raw, out value) || value <= 0)
        {
            throw new ArgumentException($"{prefix.TrimEnd('=')} requires a positive integer value.");
        }

        return true;
    }
}
