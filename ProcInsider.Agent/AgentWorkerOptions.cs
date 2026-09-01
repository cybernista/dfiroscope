using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed record AgentWorkerOptions
{
    public const int DefaultQueueCapacity = 100;
    public const int DefaultMaxParallelEnrichmentJobs = 2;
    public const int DefaultMaxParallelImportJobs = 2;
    public const int DefaultMaxParallelProcessDumpJobs = 2;
    public const int DefaultMaxParallelZeekJobs = 1;
    public const int DefaultMaxParallelArtifactImportJobs = 2;
    public const int DefaultMaxParallelVolatilityJobs = 1;
    public const int DefaultPeAnalysisWorkers = PeAnalysisBatch.DefaultMaxConcurrency;
    public const int DefaultWriterQueueCapacity = 4096;
    public const int DefaultWriterMaxBatchRows = 1000;
    public const int DefaultWriterMaxBatchLatencyMilliseconds = 250;
    public const int DefaultWriterCheckpointWalMegabytes = 64;
    public const int DefaultWriterCheckpointMinIntervalSeconds = 30;
    public const int DefaultLiveBufferMemoryMegabytes = 500;

    public int WorkerCount { get; init; } = Math.Clamp(Environment.ProcessorCount / 2, 2, 4);

    public int QueueCapacity { get; init; } = DefaultQueueCapacity;

    public int MaxParallelEnrichmentJobs { get; init; } = DefaultMaxParallelEnrichmentJobs;

    public int MaxParallelImportJobs { get; init; } = DefaultMaxParallelImportJobs;

    public int MaxParallelProcessDumpJobs { get; init; } = DefaultMaxParallelProcessDumpJobs;

    public int MaxParallelZeekJobs { get; init; } = DefaultMaxParallelZeekJobs;

    public int MaxParallelArtifactImportJobs { get; init; } = DefaultMaxParallelArtifactImportJobs;

    public int MaxParallelVolatilityJobs { get; init; } = DefaultMaxParallelVolatilityJobs;

    public int PeAnalysisWorkers { get; init; } = DefaultPeAnalysisWorkers;

    public int WriterQueueCapacity { get; init; } = DefaultWriterQueueCapacity;

    public int WriterMaxBatchRows { get; init; } = DefaultWriterMaxBatchRows;

    public int WriterMaxBatchLatencyMilliseconds { get; init; } = DefaultWriterMaxBatchLatencyMilliseconds;

    public int WriterCheckpointWalMegabytes { get; init; } = DefaultWriterCheckpointWalMegabytes;

    public int WriterCheckpointMinIntervalSeconds { get; init; } = DefaultWriterCheckpointMinIntervalSeconds;

    public int LiveBufferMemoryMegabytes { get; init; } = DefaultLiveBufferMemoryMegabytes;

    public AgentWorkerOptions Normalize()
    {
        return this with
        {
            WorkerCount = Math.Clamp(WorkerCount, 1, 32),
            QueueCapacity = Math.Clamp(QueueCapacity, 1, 10000),
            MaxParallelEnrichmentJobs = Math.Clamp(MaxParallelEnrichmentJobs, 1, 32),
            MaxParallelImportJobs = Math.Clamp(MaxParallelImportJobs, 1, 32),
            MaxParallelProcessDumpJobs = Math.Clamp(MaxParallelProcessDumpJobs, 1, 32),
            MaxParallelZeekJobs = Math.Clamp(MaxParallelZeekJobs, 1, 32),
            MaxParallelArtifactImportJobs = Math.Clamp(MaxParallelArtifactImportJobs, 1, 32),
            MaxParallelVolatilityJobs = Math.Clamp(MaxParallelVolatilityJobs, 1, 32),
            PeAnalysisWorkers = Math.Clamp(PeAnalysisWorkers, 1, PeAnalysisBatch.MaximumConcurrency),
            WriterQueueCapacity = Math.Clamp(WriterQueueCapacity, 1, 100000),
            WriterMaxBatchRows = Math.Clamp(WriterMaxBatchRows, 1, 100000),
            WriterMaxBatchLatencyMilliseconds = Math.Clamp(WriterMaxBatchLatencyMilliseconds, 50, 60000),
            WriterCheckpointWalMegabytes = Math.Clamp(WriterCheckpointWalMegabytes, 1, 4096),
            WriterCheckpointMinIntervalSeconds = Math.Clamp(WriterCheckpointMinIntervalSeconds, 1, 3600),
            LiveBufferMemoryMegabytes = Math.Clamp(LiveBufferMemoryMegabytes, 500, 2048)
        };
    }
}
