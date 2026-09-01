using System.Globalization;
using System.IO;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public enum ViewerAgentToolActionKind
{
    Unknown = 0,
    StartNetworkCapture = 1,
    StopNetworkCapture = 2,
    RunZeek = 3,
    StartProcessMonitorCapture = 4,
    StopProcessMonitorCapture = 5,
    ImportProcessMonitor = 6,
    StartSqliteBenchmark = 7
}

public enum ViewerAgentToolActionOutcome
{
    Unknown = 0,
    Succeeded = 1,
    Rejected = 2,
    Unavailable = 3,
    AgentRejected = 4,
    TimedOut = 5,
    Canceled = 6,
    JobCanceled = 7,
    JobFailed = 8,
    Superseded = 9,
    Busy = 10,
    InternalFailure = 11
}

public sealed record ViewerZeekActionRequest(
    string CaptureId = "",
    string PcapPath = "",
    string ZeekPath = "",
    string WslDistributionName = "",
    string WslZeekCommand = "");

public sealed record ViewerProcessMonitorStartActionRequest(
    string ProcmonPath,
    bool AcceptEula,
    int MaxRows = AgentToolActionPolicy.MaximumProcessMonitorRows);

public sealed record ViewerProcessMonitorStopActionRequest(string ProcmonPath);

public sealed record ViewerProcessMonitorImportActionRequest(
    string InputPath,
    string ProcmonPath,
    int MaxRows = AgentToolActionPolicy.MaximumProcessMonitorRows);

public sealed record ViewerSqliteBenchmarkActionRequest(
    int? PhaseDurationSeconds = null,
    int? MaxPhaseCount = null,
    int? InitialProcessBatchSize = null,
    int? InitialEventsPerProcess = null,
    int? MaxInFlightBatches = null,
    int? MaxPendingWriterWorkItems = null);

public sealed record ViewerAgentToolActionResult
{
    public ViewerAgentToolActionKind Action { get; init; }

    public ViewerAgentToolActionOutcome Outcome { get; init; }

    public bool Succeeded => Outcome == ViewerAgentToolActionOutcome.Succeeded;

    public string ErrorCode { get; init; } = string.Empty;

    public string Diagnostic { get; init; } = string.Empty;

    public bool IsRetryable { get; init; }

    public bool Waited { get; init; }

    public bool RefreshNeeded { get; init; }

    public Guid? AcceptedJobId { get; init; }

    public AgentIpcResponse? Response { get; init; }

    public JobProgress? Job { get; init; }

    public IReadOnlyList<JobProgress> Jobs { get; init; } = Array.Empty<JobProgress>();
}

/// <summary>
/// Shared headless WPF/CLI owner for direct network capture, Zeek, Process Monitor,
/// and isolated SQLite benchmark actions. It builds only typed commands and composes
/// the generic job workflow; the elevated agent remains the tool/evidence owner.
/// </summary>
public sealed class ViewerAgentToolActionService : IDisposable
{
    private readonly IViewerAgentCaptureActionRuntime _runtime;
    private readonly ViewerAgentCaptureActionService _jobActions;
    private readonly Func<DateTime> _utcNow;
    private readonly CancellationTokenSource _disposeCts = new();
    private bool _disposed;

    public ViewerAgentToolActionService(
        IViewerAgentCaptureActionRuntime runtime,
        Func<DateTime>? utcNow = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
        _jobActions = new ViewerAgentCaptureActionService(runtime, _utcNow);
    }

    public async Task<ViewerAgentToolActionResult> StartNetworkCaptureAsync(
        ViewerAgentCaptureActionTarget target,
        bool wait = false,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var targetFailure = ValidateTarget(
            ViewerAgentToolActionKind.StartNetworkCapture,
            target,
            target.NetworkCapturesDirectory,
            "NetworkCaptures");
        if (targetFailure != null)
        {
            return targetFailure;
        }

        var current = await GetCurrentHealthAsync(
                ViewerAgentToolActionKind.StartNetworkCapture,
                target,
                cancellationToken)
            .ConfigureAwait(false);
        if (current.Failure != null)
        {
            return current.Failure;
        }

        if (HasActive(current.Health!, JobKind.NetworkCapture))
        {
            return Rejected(
                ViewerAgentToolActionKind.StartNetworkCapture,
                "NetworkCaptureAlreadyActive",
                "Fresh authoritative agent state already contains active or finalizing network capture work.");
        }

        if (HasActive(current.Health!, JobKind.SqliteBenchmark))
        {
            return Rejected(
                ViewerAgentToolActionKind.StartNetworkCapture,
                "SqliteBenchmarkActive",
                "Wait for the active SQLite benchmark before starting network capture.");
        }

        return await QueueAsync(
                ViewerAgentToolActionKind.StartNetworkCapture,
                target,
                new StartNetworkCaptureCommand
                {
                    OutputDirectory = Path.GetFullPath(target.NetworkCapturesDirectory)
                },
                "start direct network capture",
                wait,
                timeout,
                refreshNeeded: true,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ViewerAgentToolActionResult> StopNetworkCaptureAsync(
        ViewerAgentCaptureActionTarget target,
        bool wait = false,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var targetFailure = ValidateTarget(
            ViewerAgentToolActionKind.StopNetworkCapture,
            target,
            target.NetworkCapturesDirectory,
            "NetworkCaptures");
        if (targetFailure != null)
        {
            return targetFailure;
        }

        var current = await GetCurrentHealthAsync(
                ViewerAgentToolActionKind.StopNetworkCapture,
                target,
                cancellationToken)
            .ConfigureAwait(false);
        if (current.Failure != null)
        {
            return current.Failure;
        }

        if (CountActive(current.Health!, JobKind.NetworkCapture) != 1)
        {
            return Rejected(
                ViewerAgentToolActionKind.StopNetworkCapture,
                "AuthoritativeNetworkCaptureUnavailable",
                "Fresh authoritative agent state must identify exactly one active or finalizing network capture to stop.");
        }

        return await QueueAsync(
                ViewerAgentToolActionKind.StopNetworkCapture,
                target,
                new StopNetworkCaptureCommand(),
                "stop direct network capture",
                wait,
                timeout,
                refreshNeeded: true,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ViewerAgentToolActionResult> QueueZeekAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerZeekActionRequest request,
        bool wait = false,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(
            ViewerAgentToolActionKind.RunZeek,
            target,
            target.ZeekDirectory,
            "Zeek");
        if (targetFailure != null)
        {
            return targetFailure;
        }

        var hasCaptureId = !string.IsNullOrWhiteSpace(request.CaptureId);
        var hasPcapPath = !string.IsNullOrWhiteSpace(request.PcapPath);
        if (hasCaptureId == hasPcapPath)
        {
            return Rejected(
                ViewerAgentToolActionKind.RunZeek,
                "ZeekSourceInvalid",
                "Zeek analysis requires exactly one staged capture ID or explicit PCAP/PCAPNG path.");
        }

        var captureId = string.Empty;
        var pcapPath = string.Empty;
        if (hasCaptureId && !AgentToolActionPolicy.TryNormalizeCaptureId(request.CaptureId, out captureId))
        {
            return Rejected(
                ViewerAgentToolActionKind.RunZeek,
                "ZeekCaptureIdInvalid",
                "Zeek capture ID is malformed or exceeds the bounded identifier length.");
        }

        if (hasPcapPath &&
            (!TryNormalizeExistingFile(request.PcapPath, out pcapPath) ||
             !AgentToolActionPolicy.IsSupportedPcapPath(pcapPath)))
        {
            return Rejected(
                ViewerAgentToolActionKind.RunZeek,
                "ZeekPcapInvalid",
                "Zeek explicit input must be an existing readable absolute PCAP or PCAPNG file.");
        }

        if (!AgentToolActionPolicy.TryNormalizeZeekToolMode(
                request.ZeekPath,
                request.WslDistributionName,
                request.WslZeekCommand,
                out _,
                out var zeekPath,
                out var wslDistribution,
                out var wslCommand,
                out var modeError))
        {
            return Rejected(ViewerAgentToolActionKind.RunZeek, "ZeekToolModeInvalid", modeError);
        }

        if (zeekPath.Length > 0 && !File.Exists(zeekPath))
        {
            return Rejected(
                ViewerAgentToolActionKind.RunZeek,
                "ZeekExecutableUnavailable",
                "The explicit native Zeek executable does not exist or is inaccessible.");
        }

        var outputDirectory = Path.Combine(target.ZeekDirectory, CreateRunId("zeek"));
        return await QueueAsync(
                ViewerAgentToolActionKind.RunZeek,
                target,
                new QueueZeekAnalysisCommand
                {
                    CaptureId = captureId,
                    PcapPath = pcapPath,
                    ZeekPath = zeekPath,
                    WslDistributionName = wslDistribution,
                    WslZeekCommand = wslCommand,
                    OutputDirectory = outputDirectory
                },
                "queue Zeek analysis",
                wait,
                timeout,
                refreshNeeded: true,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ViewerAgentToolActionResult> StartProcessMonitorCaptureAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerProcessMonitorStartActionRequest request,
        bool wait = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(
            ViewerAgentToolActionKind.StartProcessMonitorCapture,
            target,
            target.ProcessMonitorDirectory,
            "ProcessMonitor");
        if (targetFailure != null)
        {
            return targetFailure;
        }

        if (!request.AcceptEula)
        {
            return Rejected(
                ViewerAgentToolActionKind.StartProcessMonitorCapture,
                "ProcessMonitorEulaRequired",
                "Process Monitor capture requires explicit EULA acceptance.");
        }

        if (request.MaxRows is < 1 or > AgentToolActionPolicy.MaximumProcessMonitorRows)
        {
            return ProcessMonitorRowsRejected(ViewerAgentToolActionKind.StartProcessMonitorCapture);
        }

        if (!TryNormalizeOptionalProcessMonitorExecutable(request.ProcmonPath, out var procmonPath))
        {
            return ProcessMonitorExecutableRejected(ViewerAgentToolActionKind.StartProcessMonitorCapture);
        }

        var current = await GetCurrentHealthAsync(
                ViewerAgentToolActionKind.StartProcessMonitorCapture,
                target,
                cancellationToken)
            .ConfigureAwait(false);
        if (current.Failure != null)
        {
            return current.Failure;
        }

        if (HasActive(current.Health!, JobKind.ProcessMonitorCapture))
        {
            return Rejected(
                ViewerAgentToolActionKind.StartProcessMonitorCapture,
                "ProcessMonitorCaptureAlreadyActive",
                "Fresh authoritative agent state already contains active Process Monitor capture work.");
        }

        if (HasActive(current.Health!, JobKind.SqliteBenchmark))
        {
            return Rejected(
                ViewerAgentToolActionKind.StartProcessMonitorCapture,
                "SqliteBenchmarkActive",
                "Wait for the active SQLite benchmark before starting Process Monitor capture.");
        }

        var captureId = CreateRunId("procmon-capture");
        var outputDirectory = Path.GetFullPath(target.ProcessMonitorDirectory);
        return await QueueAsync(
                ViewerAgentToolActionKind.StartProcessMonitorCapture,
                target,
                new StartProcessMonitorCaptureCommand
                {
                    ProcmonPath = procmonPath,
                    CaptureId = captureId,
                    OutputDirectory = outputDirectory,
                    BackingFilePath = Path.Combine(outputDirectory, captureId + ".pml"),
                    CsvOutputPath = Path.Combine(outputDirectory, captureId + ".csv"),
                    AcceptEula = true,
                    MaxRows = request.MaxRows
                },
                "start Process Monitor capture",
                wait,
                timeout: null,
                refreshNeeded: true,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ViewerAgentToolActionResult> StopProcessMonitorCaptureAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerProcessMonitorStopActionRequest request,
        bool wait = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(
            ViewerAgentToolActionKind.StopProcessMonitorCapture,
            target,
            target.ProcessMonitorDirectory,
            "ProcessMonitor");
        if (targetFailure != null)
        {
            return targetFailure;
        }

        if (!TryNormalizeOptionalProcessMonitorExecutable(request.ProcmonPath, out var procmonPath))
        {
            return ProcessMonitorExecutableRejected(ViewerAgentToolActionKind.StopProcessMonitorCapture);
        }

        var current = await GetCurrentHealthAsync(
                ViewerAgentToolActionKind.StopProcessMonitorCapture,
                target,
                cancellationToken)
            .ConfigureAwait(false);
        if (current.Failure != null)
        {
            return current.Failure;
        }

        if (CountActive(current.Health!, JobKind.ProcessMonitorCapture) != 1)
        {
            return Rejected(
                ViewerAgentToolActionKind.StopProcessMonitorCapture,
                "AuthoritativeProcessMonitorCaptureUnavailable",
                "Fresh authoritative agent state must identify exactly one active Process Monitor capture to stop.");
        }

        return await QueueAsync(
                ViewerAgentToolActionKind.StopProcessMonitorCapture,
                target,
                new StopProcessMonitorCaptureCommand { ProcmonPath = procmonPath },
                "stop Process Monitor capture",
                wait,
                timeout: null,
                refreshNeeded: true,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ViewerAgentToolActionResult> QueueProcessMonitorImportAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerProcessMonitorImportActionRequest request,
        bool wait = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(
            ViewerAgentToolActionKind.ImportProcessMonitor,
            target,
            target.ProcessMonitorDirectory,
            "ProcessMonitor");
        if (targetFailure != null)
        {
            return targetFailure;
        }

        if (!TryNormalizeExistingFile(request.InputPath, out var inputPath) ||
            !AgentToolActionPolicy.IsSupportedProcessMonitorInputPath(inputPath))
        {
            return Rejected(
                ViewerAgentToolActionKind.ImportProcessMonitor,
                "ProcessMonitorInputInvalid",
                "Process Monitor import requires one existing readable absolute CSV or PML file.");
        }

        if (!TryNormalizeOptionalProcessMonitorExecutable(request.ProcmonPath, out var procmonPath))
        {
            return ProcessMonitorExecutableRejected(ViewerAgentToolActionKind.ImportProcessMonitor);
        }

        if (request.MaxRows is < 1 or > AgentToolActionPolicy.MaximumProcessMonitorRows)
        {
            return ProcessMonitorRowsRejected(ViewerAgentToolActionKind.ImportProcessMonitor);
        }

        return await QueueAsync(
                ViewerAgentToolActionKind.ImportProcessMonitor,
                target,
                new QueueProcessMonitorImportCommand
                {
                    InputPath = inputPath,
                    ProcmonPath = procmonPath,
                    CaptureId = CreateRunId("procmon-import"),
                    OutputDirectory = Path.GetFullPath(target.ProcessMonitorDirectory),
                    MaxRows = request.MaxRows
                },
                "queue Process Monitor import",
                wait,
                timeout: null,
                refreshNeeded: true,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ViewerAgentToolActionResult> StartSqliteBenchmarkAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerSqliteBenchmarkActionRequest request,
        bool wait = false,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(
            ViewerAgentToolActionKind.StartSqliteBenchmark,
            target,
            target.BenchmarkDirectory,
            "Benchmarks");
        if (targetFailure != null)
        {
            return targetFailure;
        }

        var defaults = new QueueSqliteBenchmarkCommand();
        var command = defaults with
        {
            PhaseDurationSeconds = request.PhaseDurationSeconds ?? defaults.PhaseDurationSeconds,
            MaxPhaseCount = request.MaxPhaseCount ?? defaults.MaxPhaseCount,
            InitialProcessBatchSize = request.InitialProcessBatchSize ?? defaults.InitialProcessBatchSize,
            InitialEventsPerProcess = request.InitialEventsPerProcess ?? defaults.InitialEventsPerProcess,
            MaxInFlightBatches = request.MaxInFlightBatches ?? defaults.MaxInFlightBatches,
            MaxPendingWriterWorkItems = request.MaxPendingWriterWorkItems ?? defaults.MaxPendingWriterWorkItems
        };
        if (!AgentToolActionPolicy.TryValidateBenchmark(command, out var benchmarkError))
        {
            return Rejected(
                ViewerAgentToolActionKind.StartSqliteBenchmark,
                "SqliteBenchmarkOptionsInvalid",
                benchmarkError);
        }

        var current = await GetCurrentHealthAsync(
                ViewerAgentToolActionKind.StartSqliteBenchmark,
                target,
                cancellationToken)
            .ConfigureAwait(false);
        if (current.Failure != null)
        {
            return current.Failure;
        }

        if (HasActive(current.Health!, JobKind.SqliteBenchmark))
        {
            return Rejected(
                ViewerAgentToolActionKind.StartSqliteBenchmark,
                "SqliteBenchmarkAlreadyActive",
                "Fresh authoritative agent state already contains an active SQLite benchmark.");
        }

        var result = await QueueAsync(
                ViewerAgentToolActionKind.StartSqliteBenchmark,
                target,
                command,
                "start isolated SQLite benchmark",
                wait,
                timeout,
                refreshNeeded: false,
                cancellationToken)
            .ConfigureAwait(false);
        if (!result.Succeeded || result.Job?.SqliteBenchmark == null)
        {
            return result;
        }

        var benchmark = result.Job.SqliteBenchmark;
        if (!IsBenchmarkOutput(target.BenchmarkDirectory, benchmark.DatabasePath) ||
            !IsBenchmarkOutput(target.BenchmarkDirectory, benchmark.ReportPath) ||
            !IsBenchmarkOutput(target.BenchmarkDirectory, benchmark.JsonReportPath))
        {
            return result with
            {
                Outcome = ViewerAgentToolActionOutcome.Rejected,
                ErrorCode = "SqliteBenchmarkOutputRejected",
                Diagnostic = "The agent returned a benchmark output outside the active session Benchmarks directory."
            };
        }

        return result;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _disposeCts.Cancel();
        _jobActions.Dispose();
        _disposeCts.Dispose();
    }

    private async Task<ViewerAgentToolActionResult> QueueAsync(
        ViewerAgentToolActionKind action,
        ViewerAgentCaptureActionTarget target,
        AgentCommand command,
        string description,
        bool wait,
        TimeSpan? timeout,
        bool refreshNeeded,
        CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _disposeCts.Token);
        if (linked.IsCancellationRequested)
        {
            return Canceled(action);
        }

        AgentIpcResponse? response;
        try
        {
            response = await _runtime.ExecuteCommandAsync(
                    command,
                    description,
                    target.RequireViewerConnection,
                    linked.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            return Canceled(action);
        }
        catch
        {
            return InternalFailure(action, "The tool action failed internally before an accepted job was confirmed.");
        }

        if (!_runtime.IsCurrent(target))
        {
            return Superseded(action);
        }

        if (response == null)
        {
            return Unavailable(action, "AgentUnavailable", "The exact authenticated local agent was unavailable.");
        }

        if (!response.Success)
        {
            return new ViewerAgentToolActionResult
            {
                Action = action,
                Outcome = ViewerAgentToolActionOutcome.AgentRejected,
                ErrorCode = BoundCode(response.ErrorCode, "AgentRejected"),
                Diagnostic = Bound(response.ErrorMessage, "The agent rejected the typed tool action."),
                IsRetryable = response.IsRetryable,
                Response = response
            };
        }

        var jobId = response.AcceptedJobId ?? response.Job?.JobId;
        if (!jobId.HasValue || jobId.Value == Guid.Empty)
        {
            return new ViewerAgentToolActionResult
            {
                Action = action,
                Outcome = ViewerAgentToolActionOutcome.Rejected,
                ErrorCode = "AcceptedJobMissing",
                Diagnostic = "The agent accepted the action without returning an exact trackable job ID.",
                Response = response
            };
        }

        if (!wait)
        {
            return new ViewerAgentToolActionResult
            {
                Action = action,
                Outcome = ViewerAgentToolActionOutcome.Succeeded,
                Diagnostic = refreshNeeded
                    ? "The agent accepted the typed tool action. Durable evidence requires explicit Refresh from db."
                    : "The agent accepted the isolated benchmark action.",
                RefreshNeeded = refreshNeeded,
                AcceptedJobId = jobId,
                Response = response,
                Job = response.Job,
                Jobs = response.Job == null ? Array.Empty<JobProgress>() : [response.Job]
            };
        }

        var waited = await _jobActions.WaitForJobAsync(target, jobId.Value, timeout, linked.Token)
            .ConfigureAwait(false);
        return FromWait(action, response, jobId.Value, waited, refreshNeeded);
    }

    private async Task<CurrentHealthResult> GetCurrentHealthAsync(
        ViewerAgentToolActionKind action,
        ViewerAgentCaptureActionTarget target,
        CancellationToken cancellationToken)
    {
        var listed = await _jobActions.ListJobsAsync(target, cancellationToken).ConfigureAwait(false);
        if (listed.Succeeded && listed.Health != null)
        {
            return new CurrentHealthResult(listed.Health, null);
        }

        return new CurrentHealthResult(null, FromCaptureFailure(action, listed));
    }

    private ViewerAgentToolActionResult? ValidateTarget(
        ViewerAgentToolActionKind action,
        ViewerAgentCaptureActionTarget target,
        string ownedDirectory,
        string directoryName)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(target);
        if (string.IsNullOrWhiteSpace(target.AgentId) ||
            string.IsNullOrWhiteSpace(target.HostId) ||
            string.IsNullOrWhiteSpace(target.SessionId) ||
            string.IsNullOrWhiteSpace(target.SessionRoot) ||
            !Path.IsPathFullyQualified(target.SessionRoot) ||
            target.WorkspaceGeneration <= 0)
        {
            return Rejected(
                action,
                "InvalidToolActionTarget",
                "An exact agent, host, live-session root, session ID, and positive workspace generation are required.");
        }

        if (!_runtime.IsCurrent(target))
        {
            return Superseded(action);
        }

        if (string.IsNullOrWhiteSpace(ownedDirectory) ||
            !Path.IsPathFullyQualified(ownedDirectory) ||
            !AgentToolActionPolicy.IsStrictChildPath(target.SessionRoot, ownedDirectory) ||
            !AgentToolActionPolicy.PathsEqual(
                ownedDirectory,
                Path.Combine(target.SessionRoot, directoryName)))
        {
            return Rejected(
                action,
                "SessionToolDirectoryInvalid",
                $"The active SessionPathService {directoryName} directory must be the exact absolute {directoryName} child of the session root.");
        }

        return null;
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

    private string CreateRunId(string prefix) =>
        $"{prefix}-{_utcNow():yyyyMMdd-HHmmss}-{Guid.NewGuid():N}";

    private static bool HasActive(AgentHealthSnapshot health, JobKind kind) =>
        CountActive(health, kind) > 0;

    private static int CountActive(AgentHealthSnapshot health, JobKind kind) =>
        health.Control.ActiveWork.Count(job =>
            job.JobKind == kind &&
            (job.State is JobState.Queued or JobState.Running or JobState.Paused || job.StopRequested));

    private static bool IsBenchmarkOutput(string benchmarkDirectory, string? path) =>
        !string.IsNullOrWhiteSpace(path) &&
        AgentToolActionPolicy.IsStrictChildPath(benchmarkDirectory, path);

    private static ViewerAgentToolActionResult ProcessMonitorExecutableRejected(
        ViewerAgentToolActionKind action) =>
        Rejected(
            action,
            "ProcessMonitorExecutableInvalid",
            "An explicit Process Monitor executable must be an existing absolute Procmon.exe or Procmon64.exe path.");

    private static ViewerAgentToolActionResult ProcessMonitorRowsRejected(
        ViewerAgentToolActionKind action) =>
        Rejected(
            action,
            "ProcessMonitorMaxRowsOutOfRange",
            $"Process Monitor max rows must be from 1 through {AgentToolActionPolicy.MaximumProcessMonitorRows.ToString(CultureInfo.InvariantCulture)}.");

    private static ViewerAgentToolActionResult FromWait(
        ViewerAgentToolActionKind action,
        AgentIpcResponse acceptedResponse,
        Guid acceptedJobId,
        ViewerAgentCaptureActionResult waited,
        bool refreshNeeded)
    {
        var outcome = waited.Outcome switch
        {
            ViewerAgentCaptureActionOutcome.Succeeded => ViewerAgentToolActionOutcome.Succeeded,
            ViewerAgentCaptureActionOutcome.TimedOut => ViewerAgentToolActionOutcome.TimedOut,
            ViewerAgentCaptureActionOutcome.Canceled => ViewerAgentToolActionOutcome.Canceled,
            ViewerAgentCaptureActionOutcome.JobCanceled => ViewerAgentToolActionOutcome.JobCanceled,
            ViewerAgentCaptureActionOutcome.JobFailed => ViewerAgentToolActionOutcome.JobFailed,
            ViewerAgentCaptureActionOutcome.Superseded => ViewerAgentToolActionOutcome.Superseded,
            ViewerAgentCaptureActionOutcome.Busy => ViewerAgentToolActionOutcome.Busy,
            ViewerAgentCaptureActionOutcome.Unavailable => ViewerAgentToolActionOutcome.Unavailable,
            ViewerAgentCaptureActionOutcome.AgentRejected => ViewerAgentToolActionOutcome.AgentRejected,
            ViewerAgentCaptureActionOutcome.InternalFailure => ViewerAgentToolActionOutcome.InternalFailure,
            _ => ViewerAgentToolActionOutcome.Rejected
        };
        return new ViewerAgentToolActionResult
        {
            Action = action,
            Outcome = outcome,
            ErrorCode = waited.ErrorCode,
            Diagnostic = Bound(
                waited.Diagnostic,
                outcome == ViewerAgentToolActionOutcome.Succeeded
                    ? "The requested agent tool job completed."
                    : "The requested agent tool job did not complete successfully."),
            IsRetryable = waited.IsRetryable,
            Waited = true,
            RefreshNeeded = outcome == ViewerAgentToolActionOutcome.Succeeded && refreshNeeded,
            AcceptedJobId = acceptedJobId,
            Response = acceptedResponse,
            Job = waited.Job,
            Jobs = waited.Jobs
        };
    }

    private static ViewerAgentToolActionResult FromCaptureFailure(
        ViewerAgentToolActionKind action,
        ViewerAgentCaptureActionResult result) => new()
    {
        Action = action,
        Outcome = result.Outcome switch
        {
            ViewerAgentCaptureActionOutcome.Unavailable => ViewerAgentToolActionOutcome.Unavailable,
            ViewerAgentCaptureActionOutcome.AgentRejected => ViewerAgentToolActionOutcome.AgentRejected,
            ViewerAgentCaptureActionOutcome.TimedOut => ViewerAgentToolActionOutcome.TimedOut,
            ViewerAgentCaptureActionOutcome.Canceled => ViewerAgentToolActionOutcome.Canceled,
            ViewerAgentCaptureActionOutcome.Superseded => ViewerAgentToolActionOutcome.Superseded,
            ViewerAgentCaptureActionOutcome.Busy => ViewerAgentToolActionOutcome.Busy,
            ViewerAgentCaptureActionOutcome.InternalFailure => ViewerAgentToolActionOutcome.InternalFailure,
            _ => ViewerAgentToolActionOutcome.Rejected
        },
        ErrorCode = result.ErrorCode,
        Diagnostic = Bound(result.Diagnostic, "Fresh authoritative agent control is unavailable."),
        IsRetryable = result.IsRetryable,
        Response = result.Response
    };

    private static ViewerAgentToolActionResult Rejected(
        ViewerAgentToolActionKind action,
        string code,
        string message) => new()
    {
        Action = action,
        Outcome = ViewerAgentToolActionOutcome.Rejected,
        ErrorCode = code,
        Diagnostic = message
    };

    private static ViewerAgentToolActionResult Unavailable(
        ViewerAgentToolActionKind action,
        string code,
        string message) => new()
    {
        Action = action,
        Outcome = ViewerAgentToolActionOutcome.Unavailable,
        ErrorCode = code,
        Diagnostic = message,
        IsRetryable = true
    };

    private static ViewerAgentToolActionResult Canceled(ViewerAgentToolActionKind action) => new()
    {
        Action = action,
        Outcome = ViewerAgentToolActionOutcome.Canceled,
        ErrorCode = "Canceled",
        Diagnostic = "The tool action was canceled."
    };

    private static ViewerAgentToolActionResult Superseded(ViewerAgentToolActionKind action) => new()
    {
        Action = action,
        Outcome = ViewerAgentToolActionOutcome.Superseded,
        ErrorCode = "SessionSuperseded",
        Diagnostic = "The exact session binding was superseded before the tool action completed."
    };

    private static ViewerAgentToolActionResult InternalFailure(
        ViewerAgentToolActionKind action,
        string message) => new()
    {
        Action = action,
        Outcome = ViewerAgentToolActionOutcome.InternalFailure,
        ErrorCode = "InternalFailure",
        Diagnostic = message
    };

    private static string Bound(string? value, string fallback)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
        return normalized.Length <= ViewerAgentCommandResult.MaxDiagnosticLength
            ? normalized
            : normalized[..ViewerAgentCommandResult.MaxDiagnosticLength];
    }

    private static string BoundCode(string? value, string fallback)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
        return normalized.Length <= ViewerAgentCommandResult.MaxErrorCodeLength
            ? normalized
            : normalized[..ViewerAgentCommandResult.MaxErrorCodeLength];
    }

    private sealed record CurrentHealthResult(
        AgentHealthSnapshot? Health,
        ViewerAgentToolActionResult? Failure);
}
