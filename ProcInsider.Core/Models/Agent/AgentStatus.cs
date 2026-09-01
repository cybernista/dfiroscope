using System;
using System.Collections.Generic;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Portable discriminator for agent-to-viewer status message types.
/// Unknown = 0 is intentional for forward-compatibility.
/// </summary>
public enum AgentStatusKind
{
    Unknown = 0,

    /// <summary>Progress update for a specific job.</summary>
    JobProgress = 1,

    /// <summary>Snapshot of the agent's overall capture pipeline health.</summary>
    CaptureHealthReport = 2,

    /// <summary>
    /// Notification that new rows have been written to the SQLite staging database.
    /// The viewer should schedule a DB refresh to pick up changes.
    /// </summary>
    DatabaseChanged = 3,
}

/// <summary>
/// Base type for all agent-to-viewer status messages.
/// </summary>
public abstract record AgentStatusMessage
{
    /// <summary>Discriminator for JSON deserialization.</summary>
    public abstract AgentStatusKind Kind { get; }

    /// <summary>UTC timestamp when the agent emitted this message.</summary>
    public DateTime EmittedAtUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Reports progress and state changes for a single agent job.
/// </summary>
public sealed record JobProgress : AgentStatusMessage
{
    public override AgentStatusKind Kind => AgentStatusKind.JobProgress;

    /// <summary>Stable identifier for the job. Set by the agent when it accepts the command.</summary>
    public Guid JobId { get; init; }

    public string SourceRunId { get; init; } = string.Empty;

    /// <summary>
    /// The <see cref="CommandId"/> from the original <see cref="AgentCommand"/> that created this job.
    /// Null for jobs started internally by the agent.
    /// </summary>
    public Guid? OriginatingCommandId { get; init; }

    /// <summary>What kind of work this job performs.</summary>
    public JobKind JobKind { get; init; }

    /// <summary>Current lifecycle state of the job.</summary>
    public JobState State { get; init; }

    /// <summary>Short human-readable description of current progress, suitable for a status bar.</summary>
    public string ProgressMessage { get; init; } = string.Empty;

    /// <summary>Number of items processed so far (events, processes, modules, handles — depends on job kind).</summary>
    public long ProcessedCount { get; init; }

    /// <summary>Total items expected, or -1 when the total is not known.</summary>
    public long TotalCount { get; init; } = -1;

    /// <summary>UTC time the job was accepted by the agent.</summary>
    public DateTime? StartedAtUtc { get; init; }

    /// <summary>UTC time the job reached a terminal state (Completed, Cancelled, Failed).</summary>
    public DateTime? FinishedAtUtc { get; init; }

    /// <summary>Error detail when <see cref="State"/> is <see cref="JobState.Failed"/>. Empty otherwise.</summary>
    public string ErrorText { get; init; } = string.Empty;

    /// <summary>Structured progress or final result for SQLite benchmark jobs.</summary>
    public AgentSqliteBenchmarkResult? SqliteBenchmark { get; init; }

    /// <summary>Bounded structured progress or final result for memory-family jobs.</summary>
    public AgentMemoryActionResult? MemoryAction { get; init; }
}

public sealed record AgentMemoryActionResult
{
    public string Action { get; init; } = string.Empty;

    public string Status { get; init; } = string.Empty;

    public string ImageId { get; init; } = string.Empty;

    public IReadOnlyList<string> RunIds { get; init; } = Array.Empty<string>();

    public string Sha256Hash { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public string OutputDirectory { get; init; } = string.Empty;

    public long FileSizeBytes { get; init; }

    public string CleanupStatus { get; init; } = string.Empty;

    public string QuarantinedPath { get; init; } = string.Empty;

    public string Summary { get; init; } = string.Empty;
}

public sealed record AgentSqliteBenchmarkResult
{
    public bool IsBenchmarkOnly { get; init; } = true;

    public DateTime StartedAtUtc { get; init; }

    public DateTime? CompletedAtUtc { get; init; }

    public string Status { get; init; } = string.Empty;

    public string ThresholdReason { get; init; } = string.Empty;

    public string DatabasePath { get; init; } = string.Empty;

    public string ReportPath { get; init; } = string.Empty;

    public string JsonReportPath { get; init; } = string.Empty;

    public string PerformanceProfile { get; init; } = string.Empty;

    public string SourceMix { get; init; } = string.Empty;

    public double DurationSeconds { get; init; }

    public long AttemptedRecords { get; init; }

    public long CommittedRecords { get; init; }

    public double AttemptedRecordsPerSecond { get; init; }

    public double CommittedRecordsPerSecond { get; init; }

    public double MaxSustainedCommittedRecordsPerSecond { get; init; }

    public int WriterQueueDepth { get; init; }

    public int WriterPeakQueueDepth { get; init; }

    public int WriterQueueCapacity { get; init; }

    public long DroppedRecords { get; init; }

    public long FailedBatches { get; init; }

    public long FailedRecords { get; init; }

    public IReadOnlyList<AgentSqliteBenchmarkPhaseResult> Phases { get; init; } =
        Array.Empty<AgentSqliteBenchmarkPhaseResult>();
}

public sealed record AgentSqliteBenchmarkPhaseResult
{
    public int PhaseNumber { get; init; }

    public string SourceMix { get; init; } = string.Empty;

    public int ProcessBatchSize { get; init; }

    public int EventsPerProcess { get; init; }

    public int MaxInFlightBatches { get; init; }

    public double DurationSeconds { get; init; }

    public long AttemptedRecords { get; init; }

    public long CommittedRecords { get; init; }

    public double AttemptedRecordsPerSecond { get; init; }

    public double CommittedRecordsPerSecond { get; init; }

    public int WriterQueueDepth { get; init; }

    public int WriterPeakQueueDepth { get; init; }

    public long DroppedRecords { get; init; }

    public long FailedBatches { get; init; }

    public long FailedRecords { get; init; }

    public string ThresholdReason { get; init; } = string.Empty;
}

/// <summary>
/// Reports the current health of the agent's live capture pipeline.
/// </summary>
public sealed record CaptureHealthReport : AgentStatusMessage
{
    public override AgentStatusKind Kind => AgentStatusKind.CaptureHealthReport;

    /// <summary>Overall pipeline health.</summary>
    public CaptureHealth Health { get; init; }

    /// <summary>Human-readable detail about the health state (e.g., which provider is degraded).</summary>
    public string Detail { get; init; } = string.Empty;

    /// <summary>Cumulative event total for the current or most recently completed live-capture run.</summary>
    public long TotalEventsReceived { get; init; }

    /// <summary>Cumulative process-write total for the current or most recently completed live-capture run.</summary>
    public long TotalProcessRecordsWritten { get; init; }

    /// <summary>
    /// Indicates whether the current or most recently completed live-capture run
    /// has durably committed its first complete runtime process inventory.
    /// </summary>
    public InitialProcessInventoryState InitialProcessInventory { get; init; }

    /// <summary>Cumulative events dropped during the current or most recently completed run.</summary>
    public long TotalEventsDropped { get; init; }

    /// <summary>Cumulative process rows dropped during the current or most recently completed run.</summary>
    public long TotalProcessRecordsDropped { get; init; }

    /// <summary>Cumulative event batches dropped during the current or most recently completed run.</summary>
    public long EventBatchesDropped { get; init; }

    /// <summary>Cumulative process batches dropped during the current or most recently completed run.</summary>
    public long ProcessBatchesDropped { get; init; }

    /// <summary>Event write batches currently pending behind the serialized SQLite writer.</summary>
    public int PendingEventWriteBatches { get; init; }

    /// <summary>Process write batches currently pending behind the serialized SQLite writer.</summary>
    public int PendingProcessWriteBatches { get; init; }

    /// <summary>Configured cap for pending event write batches.</summary>
    public int MaxPendingEventWriteBatches { get; init; }

    /// <summary>Configured cap for pending process write batches.</summary>
    public int MaxPendingProcessWriteBatches { get; init; }

    /// <summary>Cumulative live event write failures during the current or most recently completed run.</summary>
    public long EventWriteFailures { get; init; }

    /// <summary>Cumulative live process write failures during the current or most recently completed run.</summary>
    public long ProcessWriteFailures { get; init; }

    /// <summary>Configured RAM budget for accepted live event batches before disk spill.</summary>
    public long LiveBufferMemoryLimitBytes { get; init; }

    /// <summary>Live event bytes currently buffered in RAM.</summary>
    public long LiveBufferMemoryBytes { get; init; }

    /// <summary>Peak live event bytes buffered in RAM for this capture.</summary>
    public long LiveBufferPeakMemoryBytes { get; init; }

    /// <summary>Live event bytes currently buffered on disk.</summary>
    public long LiveBufferDiskBytes { get; init; }

    /// <summary>Peak live event bytes buffered on disk for this capture.</summary>
    public long LiveBufferPeakDiskBytes { get; init; }

    /// <summary>Accepted live event batches waiting for SQLite.</summary>
    public int LiveBufferPendingBatches { get; init; }

    /// <summary>Accepted live event records waiting for SQLite.</summary>
    public long LiveBufferPendingRecords { get; init; }

    /// <summary>Total live event batches spilled to disk for this capture.</summary>
    public long LiveBufferSpilledBatches { get; init; }

    /// <summary>Total live event records spilled to disk for this capture.</summary>
    public long LiveBufferSpilledRecords { get; init; }

    /// <summary>Total live event batches drained from buffer into SQLite.</summary>
    public long LiveBufferCompletedBatches { get; init; }

    /// <summary>Total live event records drained from buffer into SQLite.</summary>
    public long LiveBufferCompletedRecords { get; init; }

    /// <summary>SQLite write retries performed by the live event buffer.</summary>
    public long LiveBufferWriteRetries { get; init; }

    /// <summary>True when capture has stopped but accepted live event records are still loading into SQLite.</summary>
    public bool LiveBufferDrainingAfterStop { get; init; }

    /// <summary>True when the live event buffer is actively draining a batch to SQLite.</summary>
    public bool LiveBufferDrainActive { get; init; }

    /// <summary>Directory used for append-only live event spill files.</summary>
    public string LiveBufferDirectory { get; init; } = string.Empty;

    /// <summary>Most recent live event buffer error or retry detail.</summary>
    public string LiveBufferLastError { get; init; } = string.Empty;

    /// <summary>UTC time for <see cref="LiveBufferLastError"/>.</summary>
    public DateTime? LiveBufferLastErrorUtc { get; init; }

    /// <summary>Per-source health and write statistics for the live capture pipeline.</summary>
    public IReadOnlyList<CaptureSourceHealthReport> Sources { get; init; } = Array.Empty<CaptureSourceHealthReport>();
}

public sealed record CaptureSourceHealthReport
{
    public string Source { get; init; } = string.Empty;

    public string Status { get; init; } = string.Empty;

    public string Detail { get; init; } = string.Empty;

    public bool IsEnabled { get; init; }

    public bool IsActive { get; init; }

    public DateTime UpdatedUtc { get; init; }

    public string Error { get; init; } = string.Empty;

    public int DedupKeyCount { get; init; }

    public int DedupKeyCapacity { get; init; }

    public long DedupKeysEvicted { get; init; }

    public long RecordsSeen { get; init; }

    public long RecordsMatched { get; init; }

    public long DuplicateRecords { get; init; }

    public long UnmatchedRecords { get; init; }

    public long MalformedRecords { get; init; }

    /// <summary>Cumulative records written during the current or most recently completed run.</summary>
    public long RecordsWritten { get; init; }

    /// <summary>Current write rate; always zero when the source is not active.</summary>
    public double RecordsPerSecond { get; init; }

    /// <summary>Records currently queued; always zero after terminal drain completes.</summary>
    public long RecordsQueued { get; init; }

    /// <summary>Cumulative records dropped during the current or most recently completed run.</summary>
    public long RecordsDropped { get; init; }

    /// <summary>Cumulative write failures during the current or most recently completed run.</summary>
    public long WriteFailures { get; init; }
}

/// <summary>
/// Notifies the viewer that new rows have been committed to the SQLite staging database.
/// The viewer should call <c>ScheduleDbRefresh()</c> to pick up the changes.
/// No row data is carried; the viewer queries SQLite directly.
/// </summary>
public sealed record DatabaseChangedNotification : AgentStatusMessage
{
    public override AgentStatusKind Kind => AgentStatusKind.DatabaseChanged;

    /// <summary>Random identity retained for one authoritative writer lifetime.</summary>
    public Guid WriterInstanceId { get; init; }

    /// <summary>Positive sequence advanced once for each cursor-eligible committed writer work item.</summary>
    public long CommitGeneration { get; init; }

    /// <summary>UTC time at which the writer completed the durable work item.</summary>
    public DateTime? LastCommittedAtUtc { get; init; }

    /// <summary>Cumulative cursor-eligible work items committed by this writer instance.</summary>
    public long CommittedWorkItemCount { get; init; }

    /// <summary>Cumulative rows attributed to cursor-eligible commits by this writer instance.</summary>
    public long CommittedRowCount { get; init; }

    /// <summary>
    /// Approximate count of new rows written across all tables since the last notification.
    /// 0 means unknown.
    /// </summary>
    public int ApproximateNewRowCount { get; init; }
}

/// <summary>Relationship between a current durable writer cursor and a viewer-acknowledged cursor.</summary>
public enum DatabaseChangeCursorRelation
{
    Unavailable = 0,
    Same = 1,
    Newer = 2,
    Older = 3,
    WriterInstanceChanged = 4
}

/// <summary>Portable comparison policy for additive database-change cursors.</summary>
public static class DatabaseChangeCursor
{
    public static bool IsAvailable(DatabaseChangedNotification? notification) =>
        notification is { CommitGeneration: > 0 } &&
        notification.WriterInstanceId != Guid.Empty;

    public static DatabaseChangeCursorRelation Compare(
        DatabaseChangedNotification? current,
        DatabaseChangedNotification? acknowledged)
    {
        if (!IsAvailable(current))
        {
            return DatabaseChangeCursorRelation.Unavailable;
        }

        if (!IsAvailable(acknowledged))
        {
            return DatabaseChangeCursorRelation.Newer;
        }

        if (current!.WriterInstanceId != acknowledged!.WriterInstanceId)
        {
            return DatabaseChangeCursorRelation.WriterInstanceChanged;
        }

        return current.CommitGeneration.CompareTo(acknowledged.CommitGeneration) switch
        {
            > 0 => DatabaseChangeCursorRelation.Newer,
            < 0 => DatabaseChangeCursorRelation.Older,
            _ => DatabaseChangeCursorRelation.Same
        };
    }
}
