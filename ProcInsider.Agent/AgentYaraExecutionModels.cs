using ProcInsider.Models;
using ProcInsider.Models.Analysis;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal enum YaraAgentExecutionOutcome
{
    Rejected = 0,
    Completed = 1,
    Unavailable = 2
}

internal sealed record YaraAgentExecutionResponse
{
    public YaraAgentExecutionOutcome Outcome { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public YaraScanResult? Result { get; init; }

    public YaraAnalysisPersistenceResult? Persistence { get; init; }
}

internal interface IYaraAnalysisResultPersistence
{
    ValueTask<YaraAnalysisPersistenceResult> PersistAsync(
        YaraAgentExecutionRequest request,
        YaraScanResult result,
        CancellationToken cancellationToken);
}

internal sealed class AgentStagingYaraAnalysisPersistence(AgentStagingWriter writer)
    : IYaraAnalysisResultPersistence
{
    private readonly AgentStagingWriter _writer =
        writer ?? throw new ArgumentNullException(nameof(writer));

    public ValueTask<YaraAnalysisPersistenceResult> PersistAsync(
        YaraAgentExecutionRequest request,
        YaraScanResult result,
        CancellationToken cancellationToken) =>
        _writer.PersistYaraAnalysisAsync(
            new YaraAnalysisPersistenceRequest
            {
                RequestId = request.RequestId,
                AdmissionProfile = request.AdmissionProfile,
                Result = result
            },
            cancellationToken);
}

internal sealed record YaraExecutionWorkspaceSnapshot
{
    public string GenerationId { get; init; } = string.Empty;

    public bool IsLive { get; init; }

    public bool IsSealed { get; init; }

    public bool IsCurrentAgentOwner { get; init; }
}

internal interface IYaraExecutionWorkspaceContext
{
    YaraExecutionWorkspaceSnapshot GetCurrent();
}

internal interface IYaraEvidenceTargetResolver
{
    Task<YaraEvidenceTargetResolution> ResolveAsync(
        YaraScanTarget target,
        CancellationToken cancellationToken);
}

internal sealed class SqliteYaraEvidenceTargetResolver : IYaraEvidenceTargetResolver
{
    private readonly string _databasePath;
    private readonly string _evidenceSessionId;

    public SqliteYaraEvidenceTargetResolver(string databasePath, string evidenceSessionId)
    {
        _databasePath = Path.GetFullPath(databasePath);
        _evidenceSessionId = evidenceSessionId;
    }

    public Task<YaraEvidenceTargetResolution> ResolveAsync(
        YaraScanTarget target,
        CancellationToken cancellationToken) => Task.Run(
        () =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            var query = new SqliteStagingQueryService(
                _databasePath,
                openContext: CaptureOpenContext.AgentWritableLive,
                expectedEvidenceSessionId: _evidenceSessionId);
            return query.YaraEvidenceQueries.ResolveExactTarget(target);
        },
        cancellationToken);
}

internal sealed record YaraExecutionAssetPaths
{
    public string ScannerRoot { get; init; } = string.Empty;

    public string ScannerPath { get; init; } = string.Empty;

    public string RulesetRoot { get; init; } = string.Empty;

    public string RulesetPath { get; init; } = string.Empty;

    public string RulesetManifestPath { get; init; } = string.Empty;

    public string SessionRoot { get; init; } = string.Empty;

    public string WorkingRoot { get; init; } = string.Empty;
}

internal enum YaraProcessRunOutcome
{
    Completed = 0,
    StartFailed = 1,
    ContainmentFailed = 2,
    TimedOut = 3,
    Canceled = 4,
    StdoutLimitExceeded = 5,
    StderrLimitExceeded = 6
}

internal sealed record YaraProcessRunRequest
{
    public string ExecutablePath { get; init; } = string.Empty;

    public string WorkingDirectory { get; init; } = string.Empty;

    public IReadOnlyList<string> Arguments { get; init; } = Array.Empty<string>();

    public TimeSpan Timeout { get; init; }

    public long ProcessMemoryLimitBytes { get; init; }

    public int MaximumStdoutBytes { get; init; }

    public int MaximumStderrBytes { get; init; }
}

internal sealed record YaraProcessRunResult
{
    public YaraProcessRunOutcome Outcome { get; init; }

    public int? ExitCode { get; init; }

    public byte[] StandardOutput { get; init; } = Array.Empty<byte>();

    public byte[] StandardError { get; init; } = Array.Empty<byte>();
}

internal interface IYaraProcessRunner
{
    Task<YaraProcessRunResult> RunAsync(
        YaraProcessRunRequest request,
        CancellationToken cancellationToken);
}
