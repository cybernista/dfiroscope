using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed class AgentSqliteBenchmarkJobHandler : IAgentJobHandler
{
    private const string BenchmarkSource = "BenchmarkOnly";

    private readonly InvestigationSessionPaths _sessionPaths;
    private readonly TextWriter _log;

    public AgentSqliteBenchmarkJobHandler(InvestigationSessionPaths sessionPaths, TextWriter log)
    {
        _sessionPaths = sessionPaths;
        _log = log;
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var options = BenchmarkOptions.FromRequest(context.Request);
        Directory.CreateDirectory(_sessionPaths.BenchmarkDirectory);

        var runId = $"sqlite-benchmark-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{context.Request.JobId:N}";
        var databasePath = Path.Combine(_sessionPaths.BenchmarkDirectory, runId + ".sqlite3");
        var markdownPath = Path.Combine(_sessionPaths.BenchmarkDirectory, runId + ".md");
        var jsonPath = Path.Combine(_sessionPaths.BenchmarkDirectory, runId + ".json");

        using var store = new SqliteStagingStore(databasePath);
        store.Initialize();
        var performance = store.GetPerformanceStatus();
        await using var writer = new AgentStagingWriter(store, _log);

        var startedUtc = DateTime.UtcNow;
        var phases = new List<AgentSqliteBenchmarkPhaseResult>();
        var aggregateStopwatch = Stopwatch.StartNew();
        var finalReason = string.Empty;
        var failedBatches = 0L;
        var failedRecords = 0L;
        var droppedRecords = 0L;
        var attemptedRecords = 0L;
        var committedRecords = 0L;
        var maxRate = 0.0;

        await context.ReportBenchmarkProgressAsync(
            0,
            options.MaxPhaseCount,
            "SQLite benchmark initialized in isolated benchmark database.",
            CreateResult(
                startedUtc,
                null,
                "Running",
                "Initialized.",
                databasePath,
                markdownPath,
                jsonPath,
                performance,
                phases,
                aggregateStopwatch.Elapsed,
                attemptedRecords,
                committedRecords,
                droppedRecords,
                failedBatches,
                failedRecords,
                writer.GetSnapshot(),
                maxRate),
            context.CancellationToken).ConfigureAwait(false);

        for (var phaseNumber = 1; phaseNumber <= options.MaxPhaseCount; phaseNumber++)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var phase = BenchmarkPhase.Create(phaseNumber, options);
            var phaseResult = await RunPhaseAsync(
                phase,
                writer,
                context,
                startedUtc,
                databasePath,
                markdownPath,
                jsonPath,
                performance,
                phases,
                aggregateStopwatch,
                options,
                context.CancellationToken).ConfigureAwait(false);

            phases.Add(phaseResult);
            attemptedRecords += phaseResult.AttemptedRecords;
            committedRecords += phaseResult.CommittedRecords;
            droppedRecords += phaseResult.DroppedRecords;
            failedBatches += phaseResult.FailedBatches;
            failedRecords += phaseResult.FailedRecords;
            maxRate = Math.Max(maxRate, phaseResult.CommittedRecordsPerSecond);

            if (!string.IsNullOrWhiteSpace(phaseResult.ThresholdReason))
            {
                finalReason = phaseResult.ThresholdReason;
                break;
            }
        }

        aggregateStopwatch.Stop();
        finalReason = string.IsNullOrWhiteSpace(finalReason)
            ? "Completed all benchmark phases without crossing writer backlog or failure thresholds."
            : finalReason;

        var final = CreateResult(
            startedUtc,
            DateTime.UtcNow,
            "Completed",
            finalReason,
            databasePath,
            markdownPath,
            jsonPath,
            performance,
            phases,
            aggregateStopwatch.Elapsed,
            attemptedRecords,
            committedRecords,
            droppedRecords,
            failedBatches,
            failedRecords,
            writer.GetSnapshot(),
            maxRate);

        await File.WriteAllTextAsync(jsonPath, JsonSerializer.Serialize(final, AgentJson.JsonOptions), context.CancellationToken)
            .ConfigureAwait(false);
        await File.WriteAllTextAsync(markdownPath, BuildMarkdownReport(final), context.CancellationToken)
            .ConfigureAwait(false);

        await context.ReportBenchmarkProgressAsync(
            committedRecords,
            attemptedRecords,
            $"SQLite benchmark completed: {final.CommittedRecordsPerSecond:N0} committed records/sec. {final.ThresholdReason}",
            final,
            context.CancellationToken).ConfigureAwait(false);
    }

    private static async Task<AgentSqliteBenchmarkPhaseResult> RunPhaseAsync(
        BenchmarkPhase phase,
        AgentStagingWriter writer,
        AgentJobContext context,
        DateTime startedUtc,
        string databasePath,
        string markdownPath,
        string jsonPath,
        SqlitePerformanceStatus performance,
        IReadOnlyList<AgentSqliteBenchmarkPhaseResult> completedPhases,
        Stopwatch aggregateStopwatch,
        BenchmarkOptions options,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var inFlight = new List<Task<WriteBatchResult>>();
        var lastProgress = Stopwatch.StartNew();
        var attempted = 0L;
        var committed = 0L;
        var dropped = 0L;
        var failedBatches = 0L;
        var failedRecords = 0L;
        var batchNumber = 0;
        var thresholdReason = string.Empty;

        while (stopwatch.Elapsed < phase.Duration)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DrainCompleted(inFlight, ref committed, ref failedBatches, ref failedRecords);

            var snapshot = writer.GetSnapshot();
            if (snapshot.PendingWorkItemCount >= options.MaxPendingWriterWorkItems)
            {
                thresholdReason =
                    $"Writer backlog reached {snapshot.PendingWorkItemCount:N0} pending work items in phase {phase.PhaseNumber}.";
                break;
            }

            if (inFlight.Count >= phase.MaxInFlightBatches)
            {
                var completedTask = await Task.WhenAny(inFlight).ConfigureAwait(false);
                inFlight.Remove(completedTask);
                ApplyBatchResult(await completedTask.ConfigureAwait(false), ref committed, ref failedBatches, ref failedRecords);
                continue;
            }

            batchNumber++;
            var batch = SyntheticBatch.Create(phase, batchNumber);
            attempted += batch.RecordCount;
            inFlight.Add(WriteBatchAsync(writer, batch, cancellationToken));

            if (lastProgress.ElapsedMilliseconds >= options.ProgressIntervalMilliseconds)
            {
                var aggregateAttempted = completedPhases.Sum(item => item.AttemptedRecords) + attempted;
                var aggregateCommitted = completedPhases.Sum(item => item.CommittedRecords) + committed;
                await context.ReportBenchmarkProgressAsync(
                    phase.PhaseNumber,
                    options.MaxPhaseCount,
                    $"SQLite benchmark phase {phase.PhaseNumber}: {FormatRate(CalculateRate(committed, stopwatch.Elapsed))} committed, writer queue {snapshot.PendingWorkItemCount:N0}.",
                    CreateResult(
                        startedUtc,
                        null,
                        "Running",
                        $"Running phase {phase.PhaseNumber}: {phase.SourceMix}.",
                        databasePath,
                        markdownPath,
                        jsonPath,
                        performance,
                        completedPhases,
                        aggregateStopwatch.Elapsed,
                        aggregateAttempted,
                        aggregateCommitted,
                        dropped,
                        failedBatches,
                        failedRecords,
                        snapshot,
                        completedPhases.Select(item => item.CommittedRecordsPerSecond).DefaultIfEmpty(0).Max()),
                    cancellationToken).ConfigureAwait(false);
                lastProgress.Restart();
            }
        }

        while (inFlight.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var completedTask = await Task.WhenAny(inFlight).ConfigureAwait(false);
            inFlight.Remove(completedTask);
            ApplyBatchResult(await completedTask.ConfigureAwait(false), ref committed, ref failedBatches, ref failedRecords);
        }

        stopwatch.Stop();
        var finalSnapshot = writer.GetSnapshot();
        if (failedBatches > 0 && string.IsNullOrWhiteSpace(thresholdReason))
        {
            thresholdReason = $"Phase {phase.PhaseNumber} observed {failedBatches:N0} failed write batches.";
        }

        return new AgentSqliteBenchmarkPhaseResult
        {
            PhaseNumber = phase.PhaseNumber,
            SourceMix = phase.SourceMix,
            ProcessBatchSize = phase.ProcessBatchSize,
            EventsPerProcess = phase.EventsPerProcess,
            MaxInFlightBatches = phase.MaxInFlightBatches,
            DurationSeconds = stopwatch.Elapsed.TotalSeconds,
            AttemptedRecords = attempted,
            CommittedRecords = committed,
            AttemptedRecordsPerSecond = CalculateRate(attempted, stopwatch.Elapsed),
            CommittedRecordsPerSecond = CalculateRate(committed, stopwatch.Elapsed),
            WriterQueueDepth = finalSnapshot.PendingWorkItemCount,
            WriterPeakQueueDepth = finalSnapshot.PeakPendingWorkItemCount,
            DroppedRecords = dropped,
            FailedBatches = failedBatches,
            FailedRecords = failedRecords,
            ThresholdReason = thresholdReason
        };
    }

    private static async Task<WriteBatchResult> WriteBatchAsync(
        AgentStagingWriter writer,
        SyntheticBatch batch,
        CancellationToken cancellationToken)
    {
        try
        {
            await writer.UpsertProcessesAsync(batch.Processes, cancellationToken).ConfigureAwait(false);
            await writer.AddEventsAsync(batch.Events, cancellationToken).ConfigureAwait(false);
            return new WriteBatchResult(batch.RecordCount, 0, 0);
        }
        catch
        {
            return new WriteBatchResult(0, 1, batch.RecordCount);
        }
    }

    private static AgentSqliteBenchmarkResult CreateResult(
        DateTime startedUtc,
        DateTime? completedUtc,
        string status,
        string thresholdReason,
        string databasePath,
        string markdownPath,
        string jsonPath,
        SqlitePerformanceStatus performance,
        IReadOnlyList<AgentSqliteBenchmarkPhaseResult> phases,
        TimeSpan duration,
        long attemptedRecords,
        long committedRecords,
        long droppedRecords,
        long failedBatches,
        long failedRecords,
        AgentStagingWriterSnapshot writer,
        double maxSustainedRate)
    {
        return new AgentSqliteBenchmarkResult
        {
            StartedAtUtc = startedUtc,
            CompletedAtUtc = completedUtc,
            Status = status,
            ThresholdReason = thresholdReason,
            DatabasePath = databasePath,
            ReportPath = markdownPath,
            JsonReportPath = jsonPath,
            PerformanceProfile = performance.Summary,
            SourceMix = phases.Count == 0
                ? "Benchmark starting"
                : phases[^1].SourceMix,
            DurationSeconds = duration.TotalSeconds,
            AttemptedRecords = attemptedRecords,
            CommittedRecords = committedRecords,
            AttemptedRecordsPerSecond = CalculateRate(attemptedRecords, duration),
            CommittedRecordsPerSecond = CalculateRate(committedRecords, duration),
            MaxSustainedCommittedRecordsPerSecond = maxSustainedRate,
            WriterQueueDepth = writer.PendingWorkItemCount,
            WriterPeakQueueDepth = writer.PeakPendingWorkItemCount,
            WriterQueueCapacity = writer.QueueCapacity,
            DroppedRecords = droppedRecords,
            FailedBatches = failedBatches,
            FailedRecords = failedRecords,
            Phases = phases.ToArray()
        };
    }

    private static string BuildMarkdownReport(AgentSqliteBenchmarkResult result)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"# {ProductIdentity.DisplayName} SQLite Benchmark");
        builder.AppendLine();
        builder.AppendLine("Benchmark-only synthetic rows were written to an isolated SQLite database, not to the live evidence database.");
        builder.AppendLine();
        builder.AppendLine($"- Status: {result.Status}");
        builder.AppendLine($"- Started UTC: {result.StartedAtUtc:O}");
        builder.AppendLine($"- Completed UTC: {result.CompletedAtUtc:O}");
        builder.AppendLine($"- Duration: {result.DurationSeconds:N1} seconds");
        builder.AppendLine($"- Attempted records/sec: {result.AttemptedRecordsPerSecond:N1}");
        builder.AppendLine($"- Committed records/sec: {result.CommittedRecordsPerSecond:N1}");
        builder.AppendLine($"- Max sustained committed records/sec: {result.MaxSustainedCommittedRecordsPerSecond:N1}");
        builder.AppendLine($"- Writer queue: {result.WriterQueueDepth:N0}/{result.WriterQueueCapacity:N0}, peak {result.WriterPeakQueueDepth:N0}");
        builder.AppendLine($"- Dropped records: {result.DroppedRecords:N0}");
        builder.AppendLine($"- Failed batches: {result.FailedBatches:N0}");
        builder.AppendLine($"- Failed records: {result.FailedRecords:N0}");
        builder.AppendLine($"- Threshold reason: {result.ThresholdReason}");
        builder.AppendLine($"- Benchmark DB: `{result.DatabasePath}`");
        builder.AppendLine($"- JSON report: `{result.JsonReportPath}`");
        builder.AppendLine($"- SQLite profile: {result.PerformanceProfile}");
        builder.AppendLine();
        builder.AppendLine("| Phase | Source mix | Process batch | Events/process | Attempted/s | Committed/s | Queue peak | Failed batches | Threshold |");
        builder.AppendLine("|---:|---|---:|---:|---:|---:|---:|---:|---|");
        foreach (var phase in result.Phases)
        {
            builder.AppendLine(string.Format(
                CultureInfo.InvariantCulture,
                "| {0} | {1} | {2} | {3} | {4:N1} | {5:N1} | {6:N0} | {7:N0} | {8} |",
                phase.PhaseNumber,
                phase.SourceMix,
                phase.ProcessBatchSize,
                phase.EventsPerProcess,
                phase.AttemptedRecordsPerSecond,
                phase.CommittedRecordsPerSecond,
                phase.WriterPeakQueueDepth,
                phase.FailedBatches,
                phase.ThresholdReason));
        }

        return builder.ToString();
    }

    private static void DrainCompleted(
        List<Task<WriteBatchResult>> inFlight,
        ref long committed,
        ref long failedBatches,
        ref long failedRecords)
    {
        for (var index = inFlight.Count - 1; index >= 0; index--)
        {
            var task = inFlight[index];
            if (!task.IsCompleted)
            {
                continue;
            }

            inFlight.RemoveAt(index);
            ApplyBatchResult(task.GetAwaiter().GetResult(), ref committed, ref failedBatches, ref failedRecords);
        }
    }

    private static void ApplyBatchResult(
        WriteBatchResult result,
        ref long committed,
        ref long failedBatches,
        ref long failedRecords)
    {
        committed += result.CommittedRecords;
        failedBatches += result.FailedBatches;
        failedRecords += result.FailedRecords;
    }

    private static double CalculateRate(long records, TimeSpan elapsed)
    {
        return elapsed.TotalSeconds <= 0 ? 0 : records / elapsed.TotalSeconds;
    }

    private static string FormatRate(double value)
    {
        return $"{value:N0}/s";
    }

    private sealed record BenchmarkOptions(
        int PhaseDurationSeconds,
        int MaxPhaseCount,
        int InitialProcessBatchSize,
        int InitialEventsPerProcess,
        int MaxInFlightBatches,
        int MaxPendingWriterWorkItems,
        int ProgressIntervalMilliseconds)
    {
        public static BenchmarkOptions FromRequest(AgentJobRequest request)
        {
            var json = request.ToParametersJson();
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            return new BenchmarkOptions(
                ReadBounded(root, nameof(QueueSqliteBenchmarkCommand.PhaseDurationSeconds), 5, 1, 60),
                ReadBounded(root, nameof(QueueSqliteBenchmarkCommand.MaxPhaseCount), 4, 1, 8),
                ReadBounded(root, nameof(QueueSqliteBenchmarkCommand.InitialProcessBatchSize), 50, 1, 5000),
                ReadBounded(root, nameof(QueueSqliteBenchmarkCommand.InitialEventsPerProcess), 2, 0, 25),
                ReadBounded(root, nameof(QueueSqliteBenchmarkCommand.MaxInFlightBatches), 8, 1, 64),
                ReadBounded(root, nameof(QueueSqliteBenchmarkCommand.MaxPendingWriterWorkItems), 1024, 1, 4096),
                ReadBounded(root, nameof(QueueSqliteBenchmarkCommand.ProgressIntervalMilliseconds), 1000, 250, 10000));
        }

        private static int ReadBounded(JsonElement root, string name, int fallback, int min, int max)
        {
            if (!TryGetProperty(root, name, out var value) ||
                value.ValueKind != JsonValueKind.Number ||
                !value.TryGetInt32(out var number))
            {
                return fallback;
            }

            return Math.Clamp(number, min, max);
        }

        private static bool TryGetProperty(JsonElement root, string name, out JsonElement value)
        {
            if (root.TryGetProperty(name, out value))
            {
                return true;
            }

            if (string.IsNullOrWhiteSpace(name))
            {
                value = default;
                return false;
            }

            var camelName = char.ToLowerInvariant(name[0]) + name[1..];
            return root.TryGetProperty(camelName, out value);
        }
    }

    private sealed record BenchmarkPhase(
        int PhaseNumber,
        TimeSpan Duration,
        string SourceMix,
        int ProcessBatchSize,
        int EventsPerProcess,
        int MaxInFlightBatches)
    {
        public static BenchmarkPhase Create(int phaseNumber, BenchmarkOptions options)
        {
            var sourceMix = phaseNumber switch
            {
                1 => "Runtime process snapshots",
                2 => "Runtime process snapshots + Security events",
                3 => "Runtime + Security + PowerShell + ETW events",
                _ => "Runtime + Security + PowerShell + ETW + Sysmon/Windows events"
            };

            return new BenchmarkPhase(
                phaseNumber,
                TimeSpan.FromSeconds(options.PhaseDurationSeconds),
                sourceMix,
                options.InitialProcessBatchSize * phaseNumber,
                options.InitialEventsPerProcess * phaseNumber,
                Math.Min(options.MaxInFlightBatches, Math.Max(1, phaseNumber * 2)));
        }
    }

    private sealed record SyntheticBatch(
        IReadOnlyList<ProcessRecord> Processes,
        IReadOnlyList<TelemetryEventRecord> Events)
    {
        public int RecordCount => Processes.Count + Events.Count;

        public static SyntheticBatch Create(BenchmarkPhase phase, int batchNumber)
        {
            var now = DateTime.UtcNow;
            var processes = new List<ProcessRecord>(phase.ProcessBatchSize);
            var events = new List<TelemetryEventRecord>(phase.ProcessBatchSize * phase.EventsPerProcess);
            for (var index = 0; index < phase.ProcessBatchSize; index++)
            {
                var pid = 40000 + phase.PhaseNumber * 1000 + index;
                var startTime = now.AddMinutes(-index - phase.PhaseNumber);
                var processKey = $"{pid}_{startTime.Ticks}";
                var name = $"ProcInsiderBenchmark{phase.PhaseNumber}_{index % 16}.exe";
                processes.Add(new ProcessRecord
                {
                    CaseId = "benchmark-only",
                    EvidenceSessionId = "benchmark-only",
                    CaptureId = $"benchmark-phase-{phase.PhaseNumber}",
                    SourceIdentityId = $"Benchmark:{phase.SourceMix}",
                    HostId = Environment.MachineName,
                    ExecutionRootId = "benchmark-only",
                    ProcessKey = processKey,
                    ProcessId = pid,
                    ProcessGuid = Guid.NewGuid().ToString("N"),
                    StartTimeUtc = startTime,
                    Status = ProcessStatus.Running,
                    ParentProcessId = 4,
                    ParentProcessName = "System",
                    ProcessName = name,
                    ProcessPath = $@"C:\ProcInsiderBenchmark\{name}",
                    CommandLine = $@"{name} --benchmark-phase {phase.PhaseNumber} --batch {batchNumber}",
                    UserName = @"BENCHMARK\Synthetic",
                    SessionId = phase.PhaseNumber,
                    Architecture = "x64",
                    CpuUsage = index % 100,
                    MemoryUsageBytes = 10_000_000 + index * 4096,
                    CompanyName = "ProcInsider",
                    FileDescription = "Benchmark-only synthetic process",
                    Sha256Hash = "benchmark-only",
                    FirstObservedUtc = now,
                    LastObservedUtc = now,
                    LastSource = BenchmarkSource
                });

                for (var eventIndex = 0; eventIndex < phase.EventsPerProcess; eventIndex++)
                {
                    var source = SelectSource(phase.PhaseNumber, eventIndex);
                    events.Add(new TelemetryEventRecord
                    {
                        CaseId = "benchmark-only",
                        EvidenceSessionId = "benchmark-only",
                        CaptureId = $"benchmark-phase-{phase.PhaseNumber}",
                        SourceIdentityId = $"Benchmark:{source}",
                        HostId = Environment.MachineName,
                        ExecutionRootId = "benchmark-only",
                        TimestampUtc = now.AddMilliseconds(eventIndex),
                        Source = source,
                        ProcessKey = processKey,
                        ProcessId = pid,
                        ProcessStartTimeUtc = startTime,
                        ProcessName = name,
                        ParentProcessId = 4,
                        EventCode = 9000 + eventIndex,
                        Category = source switch
                        {
                            "Security" => ProcessEventCategory.Security,
                            "PowerShell" => ProcessEventCategory.PowerShell,
                            "ETW" => ProcessEventCategory.Etw,
                            _ => ProcessEventCategory.Windows
                        },
                        Action = source switch
                        {
                            "PowerShell" => ProcessEventAction.PowerShellScriptBlock,
                            "ETW" => ProcessEventAction.EtwEvent,
                            "Security" => ProcessEventAction.SecurityAudit,
                            _ => ProcessEventAction.WindowsEvent
                        },
                        Target = $"benchmark://phase/{phase.PhaseNumber}/batch/{batchNumber}/event/{eventIndex}",
                        Summary = "Benchmark-only synthetic telemetry event",
                        Details = $"Source mix {phase.SourceMix}; process {processKey}; batch {batchNumber}.",
                        RawProvider = "ProcInsider.Benchmark",
                        RawLogName = source,
                        RawRecordId = $"{phase.PhaseNumber}-{batchNumber}-{index}-{eventIndex}",
                        CorrelationMethod = "SyntheticBenchmark"
                    });
                }
            }

            return new SyntheticBatch(processes, events);
        }

        private static string SelectSource(int phaseNumber, int eventIndex)
        {
            var sources = phaseNumber switch
            {
                1 => new[] { "Runtime" },
                2 => new[] { "Runtime", "Security" },
                3 => new[] { "Runtime", "Security", "PowerShell", "ETW" },
                _ => new[] { "Runtime", "Security", "PowerShell", "ETW", "Sysmon", "WindowsOther" }
            };
            return sources[eventIndex % sources.Length];
        }
    }

    private sealed record WriteBatchResult(long CommittedRecords, long FailedBatches, long FailedRecords);
}
