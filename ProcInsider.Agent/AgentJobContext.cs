using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal sealed class AgentJobContext
{
    private readonly Func<long, long, string, AgentSqliteBenchmarkResult?, AgentMemoryActionResult?, CancellationToken, ValueTask> _reportProgress;

    public AgentJobContext(
        AgentJobRequest request,
        int sourceId,
        string sourceRunId,
        Func<long, long, string, AgentSqliteBenchmarkResult?, AgentMemoryActionResult?, CancellationToken, ValueTask> reportProgress,
        CancellationToken cancellationToken)
    {
        Request = request;
        SourceId = sourceId;
        SourceRunId = sourceRunId;
        _reportProgress = reportProgress;
        CancellationToken = cancellationToken;
    }

    public AgentJobRequest Request { get; }

    public int SourceId { get; }

    public string SourceRunId { get; }

    public CancellationToken CancellationToken { get; }

    public string SourceRunCompletionStatus { get; private set; } = "Completed";

    public string? SourceRunCompletionMetadataJson { get; private set; }

    public void SetSourceRunCompletion(string status, string? metadataJson = null)
    {
        if (string.IsNullOrWhiteSpace(status))
        {
            throw new ArgumentException("A source-run completion status is required.", nameof(status));
        }

        SourceRunCompletionStatus = status.Trim();
        SourceRunCompletionMetadataJson = metadataJson;
    }

    public ValueTask ReportProgressAsync(long current, long total, string message)
    {
        return _reportProgress(current, total, message, null, null, CancellationToken);
    }

    public ValueTask ReportProgressAsync(long current, long total, string message, CancellationToken cancellationToken)
    {
        return _reportProgress(current, total, message, null, null, cancellationToken);
    }

    public ValueTask ReportBenchmarkProgressAsync(
        long current,
        long total,
        string message,
        AgentSqliteBenchmarkResult benchmark,
        CancellationToken cancellationToken)
    {
        return _reportProgress(current, total, message, benchmark, null, cancellationToken);
    }

    public ValueTask ReportMemoryProgressAsync(
        long current,
        long total,
        string message,
        AgentMemoryActionResult memory,
        CancellationToken cancellationToken)
    {
        return _reportProgress(current, total, message, null, memory, cancellationToken);
    }

    public JobProgress CreateProgress(
        JobState state,
        long current,
        long total,
        string message,
        string errorText = "",
        AgentSqliteBenchmarkResult? benchmark = null,
        AgentMemoryActionResult? memory = null)
    {
        return new JobProgress
        {
            JobId = Request.JobId,
            SourceRunId = SourceRunId,
            OriginatingCommandId = Request.OriginatingCommandId,
            JobKind = Request.JobKind,
            State = state,
            ProgressMessage = message,
            ProcessedCount = current,
            TotalCount = total,
            ErrorText = errorText,
            FinishedAtUtc = state is JobState.Completed or JobState.Cancelled or JobState.Failed
                ? DateTime.UtcNow
                : null,
            SqliteBenchmark = benchmark,
            MemoryAction = memory
        };
    }
}
