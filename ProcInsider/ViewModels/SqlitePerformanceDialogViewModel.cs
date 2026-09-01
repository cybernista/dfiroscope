using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using ProcInsider.Models.Agent;

namespace ProcInsider.ViewModels;

public sealed class SqlitePerformanceDialogViewModel
{
    private SqlitePerformanceDialogViewModel(
        AgentRegistryEntryViewModel agent,
        string statusLine,
        string bottleneck,
        IReadOnlyList<SqlitePerformanceStageRowViewModel> stageRows,
        IReadOnlyList<SqlitePerformanceSourceRowViewModel> sourceRows,
        string diagnosticLogPath,
        long writerCompletedRows,
        DateTime observedUtc)
    {
        Agent = agent;
        StatusLine = statusLine;
        Bottleneck = bottleneck;
        StageRows = stageRows;
        SourceRows = sourceRows;
        DiagnosticLogPath = diagnosticLogPath;
        WriterCompletedRows = writerCompletedRows;
        ObservedUtc = observedUtc;
    }

    public AgentRegistryEntryViewModel Agent { get; }

    public string StatusLine { get; }

    public string Bottleneck { get; }

    public IReadOnlyList<SqlitePerformanceStageRowViewModel> StageRows { get; }

    public IReadOnlyList<SqlitePerformanceSourceRowViewModel> SourceRows { get; }

    public string DiagnosticLogPath { get; }

    public long WriterCompletedRows { get; }

    public DateTime ObservedUtc { get; }

    public static SqlitePerformanceDialogViewModel Create(
        AgentRegistryEntryViewModel agent,
        AgentIpcResponse response,
        SqlitePerformanceDialogViewModel? previous)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(response);

        var observedUtc = DateTime.UtcNow;
        if (!response.Success || response.Health == null)
        {
            var error = string.IsNullOrWhiteSpace(response.ErrorMessage)
                ? "The agent did not return a health snapshot."
                : response.ErrorMessage;
            return new SqlitePerformanceDialogViewModel(
                agent,
                "SQLite performance unavailable",
                error,
                new[] { new SqlitePerformanceStageRowViewModel("Agent health request", "Unavailable", "—", "—", error) },
                Array.Empty<SqlitePerformanceSourceRowViewModel>(),
                string.Empty,
                0,
                observedUtc);
        }

        var health = response.Health;
        var capture = health.CaptureHealth;
        var runtime = health.Runtime;
        var writerRowsPerSecond = CalculateRate(
            runtime.WriterCompletedRowCount,
            previous?.WriterCompletedRows,
            observedUtc,
            previous?.ObservedUtc);
        var sourceRows = capture.Sources
            .OrderBy(source => source.Source, StringComparer.OrdinalIgnoreCase)
            .Select(source => new SqlitePerformanceSourceRowViewModel(
                source.Source,
                source.Status,
                FormatRate(source.RecordsPerSecond),
                FormatCount(source.RecordsQueued),
                FormatCount(source.WriteFailures),
                FirstNonEmpty(source.Error, source.Detail)))
            .ToList();
        var inputRate = capture.Sources.Sum(source => Math.Max(0, source.RecordsPerSecond));
        var queuePressure = runtime.WriterQueueCapacity <= 0
            ? 0
            : (double)runtime.WriterPendingWorkItemCount / runtime.WriterQueueCapacity;
        var bottleneck = ClassifyBottleneck(capture, runtime, writerRowsPerSecond, inputRate, queuePressure);
        var database = runtime.LiveDatabaseDiagnostics;
        var transactionRate = runtime.WriterLastTransactionMilliseconds <= 0
            ? 0
            : runtime.WriterLastBatchRowCount / (runtime.WriterLastTransactionMilliseconds / 1000d);

        var stageRows = new List<SqlitePerformanceStageRowViewModel>
        {
            new(
                "Event ingress",
                capture.Health.ToString(),
                FormatRate(inputRate),
                $"{FormatCount(capture.LiveBufferPendingRecords)} events",
                $"Source rate; dropped {FormatCount(capture.TotalEventsDropped)} event(s)."),
            new(
                "Live event buffer",
                capture.LiveBufferDrainActive ? "Draining" : "Waiting",
                "—",
                $"{FormatCount(capture.LiveBufferPendingRecords)} events / {capture.LiveBufferPendingBatches:N0} batches",
                $"RAM {FormatBytes(capture.LiveBufferMemoryBytes)} of {FormatBytes(capture.LiveBufferMemoryLimitBytes)}; disk spill {FormatBytes(capture.LiveBufferDiskBytes)}; retries {capture.LiveBufferWriteRetries:N0}."),
            new(
                "SQLite writer queue",
                queuePressure >= 0.8 ? "Backpressure" : "Accepting",
                FormatRate(writerRowsPerSecond),
                $"{runtime.WriterPendingWorkItemCount:N0}/{runtime.WriterQueueCapacity:N0} work items",
                $"Last queue delay {FormatMilliseconds(runtime.WriterLastQueueDelayMilliseconds)}; max {FormatMilliseconds(runtime.WriterMaxQueueDelayMilliseconds)}."),
            new(
                "SQLite transaction",
                FirstNonEmpty(runtime.WriterLastOperation, "No completed write yet"),
                FormatRate(transactionRate),
                $"{runtime.WriterLastBatchRowCount:N0} rows",
                $"Last {FormatMilliseconds(runtime.WriterLastTransactionMilliseconds)}; max {FormatMilliseconds(runtime.WriterMaxTransactionMilliseconds)}; configured batch limit {runtime.WriterMaxRowsPerTransaction:N0}."),
            new(
                "SQLite database",
                database == null ? "Awaiting background sample" : FirstNonEmpty(database.JournalMode, "Sampled"),
                "—",
                database == null ? "—" : $"DB {FormatBytes(database.DatabaseSizeBytes)}; WAL {FormatBytes(database.WalSizeBytes)}",
                database == null
                    ? FirstNonEmpty(runtime.LiveDatabaseDiagnosticsCacheStatus, "SQLite diagnostics have not been sampled yet.")
                    : $"profile {database.Profile}; sync {database.SynchronousMode}; cache {database.CacheSizePages:N0}; indexes {database.LiveIndexCount:N0}/{database.LiveIndexExpectedCount:N0}.")
        };

        return new SqlitePerformanceDialogViewModel(
            agent,
            $"SQLite performance — writer {FormatRate(writerRowsPerSecond)}, source ingress {FormatRate(inputRate)}",
            bottleneck,
            stageRows,
            sourceRows,
            FirstNonEmpty(runtime.CaptureDiagnosticsLogPath, database?.DiagnosticsLogPath),
            runtime.WriterCompletedRowCount,
            observedUtc);
    }

    private static string ClassifyBottleneck(
        CaptureHealthReport capture,
        AgentRuntimeSnapshot runtime,
        double writerRowsPerSecond,
        double inputRate,
        double queuePressure)
    {
        if (runtime.WriterBusyOrLockedFailureCount > 0 || !string.IsNullOrWhiteSpace(runtime.WriterLastSqliteError))
        {
            return "SQLite contention or write error is limiting throughput. Check the transaction and database rows for the reported error.";
        }

        if (capture.LiveBufferDiskBytes > 0)
        {
            return "The live event buffer has spilled to disk; the writer cannot drain accepted events as fast as they arrive.";
        }

        if (queuePressure >= 0.8 || capture.LiveBufferPendingRecords > 0 && writerRowsPerSecond > 0 && writerRowsPerSecond < inputRate)
        {
            return "The serialized SQLite writer is the current bottleneck: its measured drain rate is below ingress, so backlog is growing.";
        }

        if (capture.LiveBufferPendingRecords > 0)
        {
            return "A prior burst is still draining. Compare the writer rows/s with ingress rows/s; the queue will shrink only when writer throughput stays higher.";
        }

        return "No active SQLite backlog is detected. The table will show a one-second writer rows/s measurement after the next refresh.";
    }

    private static double CalculateRate(long current, long? previous, DateTime currentUtc, DateTime? previousUtc)
    {
        if (!previous.HasValue || !previousUtc.HasValue)
        {
            return 0;
        }

        var elapsedSeconds = (currentUtc - previousUtc.Value).TotalSeconds;
        return elapsedSeconds <= 0 ? 0 : Math.Max(0, (current - previous.Value) / elapsedSeconds);
    }

    private static string FormatRate(double value)
        => value <= 0 ? "0 rows/s" : $"{value:N0} rows/s";

    private static string FormatCount(long value) => value.ToString("N0", CultureInfo.CurrentCulture);

    private static string FormatMilliseconds(double value)
        => value <= 0 ? "—" : $"{value:N1} ms";

    private static string FormatBytes(long value)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var size = Math.Max(0, value);
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }

        return unit == 0 ? $"{size:N0} {units[unit]}" : $"{size:N1} {units[unit]}";
    }

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
}

public sealed record SqlitePerformanceStageRowViewModel(
    string Stage,
    string Status,
    string Throughput,
    string Backlog,
    string Detail);

public sealed record SqlitePerformanceSourceRowViewModel(
    string Source,
    string Status,
    string Ingress,
    string Queued,
    string Failures,
    string Detail);
