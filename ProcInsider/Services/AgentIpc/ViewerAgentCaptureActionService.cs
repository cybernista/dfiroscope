using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services.AgentIpc;

namespace ProcInsider.Services.AgentIpc;

public enum ViewerAgentCaptureActionKind
{
    Unknown = 0,
    GetConfiguration = 1,
    CheckConfiguration = 2,
    SaveConfiguration = 3,
    StartConfiguredCapture = 4,
    StopConfiguredCapture = 5,
    StartSource = 6,
    StopSource = 7,
    ListJobs = 8,
    GetJobStatus = 9,
    WaitForJob = 10,
    CancelJob = 11,
    PauseConfiguredCapture = 12,
    ResumeConfiguredCapture = 13
}

public enum ViewerAgentCaptureActionOutcome
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

public sealed record ViewerAgentCaptureActionTarget(
    string AgentId,
    string HostId,
    string SessionId,
    string SessionRoot,
    long WorkspaceGeneration,
    bool RequireViewerConnection = false,
    string DumpsDirectory = "",
    string NetworkCapturesDirectory = "",
    string ZeekDirectory = "",
    string ProcessMonitorDirectory = "",
    string BenchmarkDirectory = "",
    string MemoryDirectory = "");

public sealed record ViewerAgentCaptureActionResult
{
    public ViewerAgentCaptureActionKind Action { get; init; }

    public ViewerAgentCaptureActionOutcome Outcome { get; init; }

    public bool Succeeded => Outcome == ViewerAgentCaptureActionOutcome.Succeeded;

    public string ErrorCode { get; init; } = string.Empty;

    public string Diagnostic { get; init; } = string.Empty;

    public bool IsRetryable { get; init; }

    public AgentIpcResponse? Response { get; init; }

    public AgentHealthSnapshot? Health { get; init; }

    public JobProgress? Job { get; init; }

    public IReadOnlyList<JobProgress> Jobs { get; init; } = Array.Empty<JobProgress>();

    public IReadOnlyList<AgentActiveWorkItem> ActiveJobs { get; init; } =
        Array.Empty<AgentActiveWorkItem>();
}

public interface IViewerAgentCaptureActionRuntime
{
    bool IsCurrent(ViewerAgentCaptureActionTarget target);

    Task<AgentIpcResponse?> ExecuteCommandAsync(
        AgentCommand command,
        string action,
        bool requireViewerConnection,
        CancellationToken cancellationToken);

    Task<AgentIpcResponse> GetHealthAsync(CancellationToken cancellationToken);

    Task<AgentIpcResponse> GetJobStatusAsync(Guid jobId, CancellationToken cancellationToken);

    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public sealed class DelegateViewerAgentCaptureActionRuntime(
    Func<ViewerAgentCaptureActionTarget, bool> isCurrent,
    Func<AgentCommand, string, bool, CancellationToken, Task<AgentIpcResponse?>> executeCommandAsync,
    Func<CancellationToken, Task<AgentIpcResponse>> getHealthAsync,
    Func<Guid, CancellationToken, Task<AgentIpcResponse>> getJobStatusAsync,
    Func<TimeSpan, CancellationToken, Task>? delayAsync = null) : IViewerAgentCaptureActionRuntime
{
    private readonly Func<ViewerAgentCaptureActionTarget, bool> _isCurrent =
        isCurrent ?? throw new ArgumentNullException(nameof(isCurrent));
    private readonly Func<AgentCommand, string, bool, CancellationToken, Task<AgentIpcResponse?>> _executeCommandAsync =
        executeCommandAsync ?? throw new ArgumentNullException(nameof(executeCommandAsync));
    private readonly Func<CancellationToken, Task<AgentIpcResponse>> _getHealthAsync =
        getHealthAsync ?? throw new ArgumentNullException(nameof(getHealthAsync));
    private readonly Func<Guid, CancellationToken, Task<AgentIpcResponse>> _getJobStatusAsync =
        getJobStatusAsync ?? throw new ArgumentNullException(nameof(getJobStatusAsync));
    private readonly Func<TimeSpan, CancellationToken, Task> _delayAsync =
        delayAsync ?? Task.Delay;

    public bool IsCurrent(ViewerAgentCaptureActionTarget target) => _isCurrent(target);

    public Task<AgentIpcResponse?> ExecuteCommandAsync(
        AgentCommand command,
        string action,
        bool requireViewerConnection,
        CancellationToken cancellationToken) =>
        _executeCommandAsync(command, action, requireViewerConnection, cancellationToken);

    public Task<AgentIpcResponse> GetHealthAsync(CancellationToken cancellationToken) =>
        _getHealthAsync(cancellationToken);

    public Task<AgentIpcResponse> GetJobStatusAsync(Guid jobId, CancellationToken cancellationToken) =>
        _getJobStatusAsync(jobId, cancellationToken);

    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        _delayAsync(delay, cancellationToken);
}

/// <summary>
/// Shared headless application owner for configured capture, live-source control,
/// and current job operations. Presentation adapters provide an already-bound,
/// exact-session runtime and render only the typed result.
/// </summary>
public sealed class ViewerAgentCaptureActionService : IDisposable
{
    public const int DefaultWaitTimeoutSeconds = 1800;
    public const int MaximumWaitTimeoutSeconds = 86400;
    public const long MaximumConfigurationFileBytes = 256 * 1024;
    public const int MaximumActiveJobCount = 128;

    private static readonly string[] SupportedSources =
    [
        "Runtime",
        "ETW",
        "Security",
        "PowerShell",
        "WindowsOther",
        "Sysmon"
    ];

    private readonly IViewerAgentCaptureActionRuntime _runtime;
    private readonly Func<DateTime> _utcNow;
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly object _waitSync = new();
    private readonly HashSet<Guid> _activeWaits = new();
    private bool _disposed;

    public ViewerAgentCaptureActionService(
        IViewerAgentCaptureActionRuntime runtime,
        Func<DateTime>? utcNow = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
    }

    public async Task<ViewerAgentCaptureActionResult> GetConfigurationAsync(
        ViewerAgentCaptureActionTarget target,
        CancellationToken cancellationToken = default)
    {
        var result = await ExecuteCommandAsync(
                ViewerAgentCaptureActionKind.GetConfiguration,
                target,
                new GetCaptureConfigurationCommand
                {
                    AgentId = target.AgentId,
                    HostId = target.HostId,
                    ConfigurationVersion = "cli-read-v1"
                },
                "get capture configuration",
                cancellationToken)
            .ConfigureAwait(false);
        return result.Succeeded && result.Response?.CaptureConfiguration == null
            ? MissingPayload(
                ViewerAgentCaptureActionKind.GetConfiguration,
                "CaptureConfigurationMissing",
                "The agent accepted the read but returned no capture configuration.",
                result.Response)
            : result;
    }

    public Task<ViewerAgentCaptureActionResult> CheckConfigurationAsync(
        ViewerAgentCaptureActionTarget target,
        AgentCaptureConfiguration? draftConfiguration,
        CancellationToken cancellationToken = default)
    {
        var validation = ValidateConfiguration(target, draftConfiguration, allowNull: true);
        if (validation != null)
        {
            return Task.FromResult(validation with
            {
                Action = ViewerAgentCaptureActionKind.CheckConfiguration
            });
        }

        return CheckConfigurationCoreAsync(target, draftConfiguration, cancellationToken);
    }

    public async Task<ViewerAgentCaptureActionResult> CheckConfigurationFileAsync(
        ViewerAgentCaptureActionTarget target,
        string configurationPath,
        CancellationToken cancellationToken = default)
    {
        var loaded = await LoadConfigurationFileAsync(target, configurationPath, cancellationToken)
            .ConfigureAwait(false);
        return loaded.Result ?? await CheckConfigurationAsync(
                target,
                loaded.Configuration,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<ViewerAgentCaptureActionResult> SaveConfigurationAsync(
        ViewerAgentCaptureActionTarget target,
        AgentCaptureConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        var validation = ValidateConfiguration(target, configuration, allowNull: false);
        if (validation != null)
        {
            return Task.FromResult(validation with
            {
                Action = ViewerAgentCaptureActionKind.SaveConfiguration
            });
        }

        return SaveConfigurationCoreAsync(target, configuration, cancellationToken);
    }

    private async Task<ViewerAgentCaptureActionResult> CheckConfigurationCoreAsync(
        ViewerAgentCaptureActionTarget target,
        AgentCaptureConfiguration? draftConfiguration,
        CancellationToken cancellationToken)
    {
        var result = await ExecuteCommandAsync(
                ViewerAgentCaptureActionKind.CheckConfiguration,
                target,
                new CheckCaptureConfigurationCommand
                {
                    AgentId = target.AgentId,
                    HostId = target.HostId,
                    ConfigurationVersion = draftConfiguration?.ConfigurationVersion ?? "viewer-current-capture",
                    ConfigurationHash = draftConfiguration?.ConfigurationHash ?? string.Empty,
                    DraftConfiguration = draftConfiguration
                },
                "check capture configuration",
                cancellationToken)
            .ConfigureAwait(false);
        return result.Succeeded && result.Response?.ConfigurationCheck == null
            ? MissingPayload(
                ViewerAgentCaptureActionKind.CheckConfiguration,
                "CaptureConfigurationCheckMissing",
                "The agent accepted the check but returned no typed check result.",
                result.Response)
            : result;
    }

    private async Task<ViewerAgentCaptureActionResult> SaveConfigurationCoreAsync(
        ViewerAgentCaptureActionTarget target,
        AgentCaptureConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var result = await ExecuteCommandAsync(
                ViewerAgentCaptureActionKind.SaveConfiguration,
                target,
                new SaveCaptureConfigurationCommand
                {
                    AgentId = target.AgentId,
                    HostId = target.HostId,
                    ConfigurationVersion = configuration.ConfigurationVersion,
                    ConfigurationHash = configuration.ConfigurationHash,
                    Configuration = configuration
                },
                "save capture configuration",
                cancellationToken)
            .ConfigureAwait(false);
        return result.Succeeded && result.Response?.CaptureConfiguration == null
            ? MissingPayload(
                ViewerAgentCaptureActionKind.SaveConfiguration,
                "CaptureConfigurationMissing",
                "The agent accepted the save but returned no typed capture configuration.",
                result.Response)
            : result;
    }

    public async Task<ViewerAgentCaptureActionResult> SaveConfigurationFileAsync(
        ViewerAgentCaptureActionTarget target,
        string configurationPath,
        CancellationToken cancellationToken = default)
    {
        var loaded = await LoadConfigurationFileAsync(target, configurationPath, cancellationToken)
            .ConfigureAwait(false);
        return loaded.Result ?? await SaveConfigurationAsync(
                target,
                loaded.Configuration!,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ViewerAgentCaptureActionResult> StartConfiguredCaptureAsync(
        ViewerAgentCaptureActionTarget target,
        bool waitForTerminal = false,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var health = await GetCurrentControlAsync(
                ViewerAgentCaptureActionKind.StartConfiguredCapture,
                target,
                cancellationToken)
            .ConfigureAwait(false);
        if (health.Result != null)
        {
            return health.Result;
        }

        var availability = EvaluateAvailability(health.Control!, health.Health!);
        if (!availability.CanStart)
        {
            return Rejected(
                ViewerAgentCaptureActionKind.StartConfiguredCapture,
                "CaptureStartUnavailable",
                availability.StartUnavailableReason);
        }

        var saved = await GetConfigurationAsync(target, cancellationToken).ConfigureAwait(false);
        if (!saved.Succeeded || saved.Response?.CaptureConfiguration == null)
        {
            return saved with { Action = ViewerAgentCaptureActionKind.StartConfiguredCapture };
        }

        var configuration = saved.Response.CaptureConfiguration;
        if (string.IsNullOrWhiteSpace(configuration.ConfigurationVersion) ||
            string.IsNullOrWhiteSpace(configuration.ConfigurationHash))
        {
            return Rejected(
                ViewerAgentCaptureActionKind.StartConfiguredCapture,
                "CaptureConfigurationUnavailable",
                "The saved capture configuration does not have an exact version and hash.");
        }

        var started = await ExecuteCommandAsync(
                ViewerAgentCaptureActionKind.StartConfiguredCapture,
                target,
                new StartConfiguredCaptureCommand
                {
                    AgentId = target.AgentId,
                    HostId = target.HostId,
                    ConfigurationVersion = configuration.ConfigurationVersion,
                    ConfigurationHash = configuration.ConfigurationHash,
                    RequireMatchingHash = true
                },
                "start configured capture",
                cancellationToken)
            .ConfigureAwait(false);
        if (started.Succeeded && started.Response?.CaptureLifecycle == null)
        {
            return MissingPayload(
                ViewerAgentCaptureActionKind.StartConfiguredCapture,
                "CaptureLifecycleMissing",
                "The agent accepted capture start but returned no typed lifecycle result.",
                started.Response);
        }

        return !started.Succeeded || !waitForTerminal
            ? started
            : await WaitForResponseJobsAsync(
                    target,
                    started,
                    affected: false,
                    timeout,
                    cancellationToken)
                .ConfigureAwait(false);
    }

    public async Task<ViewerAgentCaptureActionResult> StopConfiguredCaptureAsync(
        ViewerAgentCaptureActionTarget target,
        bool waitForTerminal = false,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var health = await GetCurrentControlAsync(
                ViewerAgentCaptureActionKind.StopConfiguredCapture,
                target,
                cancellationToken)
            .ConfigureAwait(false);
        if (health.Result != null)
        {
            return health.Result;
        }

        var availability = EvaluateAvailability(health.Control!, health.Health!);
        if (!availability.CanStop)
        {
            return Rejected(
                ViewerAgentCaptureActionKind.StopConfiguredCapture,
                "CaptureStopUnavailable",
                availability.StopUnavailableReason);
        }

        var configuredWork = AgentConfiguredCaptureWorkProjection.Select(
            health.Health!.Control.ActiveWork);
        var captureIds = configuredWork
            .Select(job => job.CaptureId)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (captureIds.Length != 1 ||
            !string.Equals(
                captureIds[0],
                health.Control!.ActiveCaptureId,
                StringComparison.Ordinal))
        {
            return Rejected(
                ViewerAgentCaptureActionKind.StopConfiguredCapture,
                "AuthoritativeCaptureUnavailable",
                "Fresh agent control does not identify exactly one matching configured capture to stop.");
        }

        var saved = await GetConfigurationAsync(target, cancellationToken).ConfigureAwait(false);
        if (!saved.Succeeded || saved.Response?.CaptureConfiguration == null)
        {
            return saved with { Action = ViewerAgentCaptureActionKind.StopConfiguredCapture };
        }

        var configuration = saved.Response.CaptureConfiguration;
        var stopped = await ExecuteCommandAsync(
                ViewerAgentCaptureActionKind.StopConfiguredCapture,
                target,
                new StopConfiguredCaptureCommand
                {
                    AgentId = target.AgentId,
                    HostId = target.HostId,
                    ConfigurationVersion = configuration.ConfigurationVersion,
                    ConfigurationHash = configuration.ConfigurationHash,
                    CaptureId = captureIds[0],
                    Reason = "Explicit viewer capture action"
                },
                "stop configured capture",
                cancellationToken)
            .ConfigureAwait(false);
        if (stopped.Succeeded && stopped.Response?.CaptureLifecycle == null)
        {
            return MissingPayload(
                ViewerAgentCaptureActionKind.StopConfiguredCapture,
                "CaptureLifecycleMissing",
                "The agent accepted capture stop but returned no typed lifecycle result.",
                stopped.Response);
        }

        return !stopped.Succeeded || !waitForTerminal
            ? stopped
            : await WaitForResponseJobsAsync(
                    target,
                    stopped,
                    affected: true,
                    timeout,
                    cancellationToken)
                .ConfigureAwait(false);
    }

    public Task<ViewerAgentCaptureActionResult> PauseConfiguredCaptureAsync(
        ViewerAgentCaptureActionTarget target,
        CancellationToken cancellationToken = default) =>
        TransitionConfiguredCaptureAsync(target, pause: true, cancellationToken);

    public Task<ViewerAgentCaptureActionResult> ResumeConfiguredCaptureAsync(
        ViewerAgentCaptureActionTarget target,
        CancellationToken cancellationToken = default) =>
        TransitionConfiguredCaptureAsync(target, pause: false, cancellationToken);

    private async Task<ViewerAgentCaptureActionResult> TransitionConfiguredCaptureAsync(
        ViewerAgentCaptureActionTarget target,
        bool pause,
        CancellationToken cancellationToken)
    {
        var action = pause
            ? ViewerAgentCaptureActionKind.PauseConfiguredCapture
            : ViewerAgentCaptureActionKind.ResumeConfiguredCapture;
        var health = await GetCurrentControlAsync(action, target, cancellationToken).ConfigureAwait(false);
        if (health.Result != null)
        {
            return health.Result;
        }

        var availability = EvaluateAvailability(health.Control!, health.Health!);
        var allowed = pause ? availability.CanPause : availability.CanResume;
        if (!allowed)
        {
            return Rejected(
                action,
                pause ? "CapturePauseUnavailable" : "CaptureResumeUnavailable",
                pause ? availability.PauseUnavailableReason : availability.ResumeUnavailableReason);
        }

        var configuredWork = AgentConfiguredCaptureWorkProjection.Select(health.Health!.Control.ActiveWork)
            .Where(job => job.IsLiveSource)
            .ToArray();
        var captureId = health.Control!.ActiveCaptureId;
        if (string.IsNullOrWhiteSpace(captureId) ||
            configuredWork.Length == 0 ||
            configuredWork.Any(job => !string.Equals(job.CaptureId, captureId, StringComparison.Ordinal)))
        {
            return Rejected(
                action,
                "AuthoritativeCaptureUnavailable",
                "Fresh agent control does not identify one exact configured live-source capture transition target.");
        }

        var anchor = configuredWork
            .OrderBy(job => job.JobKind == JobKind.LiveCapture ? 0 : 1)
            .ThenBy(job => job.AcceptedAtUtc)
            .First();
        AgentCommand command = pause
            ? new PauseJobCommand
            {
                JobId = anchor.JobId,
                CaptureId = captureId,
                Reason = "Explicit viewer pause action"
            }
            : new ResumeJobCommand
            {
                JobId = anchor.JobId,
                CaptureId = captureId
            };
        var transitioned = await ExecuteCommandAsync(
                action,
                target,
                command,
                pause ? "pause configured capture" : "resume configured capture",
                cancellationToken)
            .ConfigureAwait(false);
        var expectedAction = pause
            ? AgentCaptureLifecycleAction.Pause
            : AgentCaptureLifecycleAction.Resume;
        if (transitioned.Succeeded && transitioned.Response?.CaptureLifecycle?.Action != expectedAction)
        {
            return MissingPayload(
                action,
                "CaptureLifecycleMissing",
                $"The agent accepted capture {(pause ? "pause" : "resume")} but returned no matching typed lifecycle result.",
                transitioned.Response);
        }

        return transitioned;
    }

    public Task<ViewerAgentCaptureActionResult> StartSourceAsync(
        ViewerAgentCaptureActionTarget target,
        string source,
        CancellationToken cancellationToken = default) =>
        ExecuteSourceAsync(target, source, start: true, cancellationToken);

    public Task<ViewerAgentCaptureActionResult> StopSourceAsync(
        ViewerAgentCaptureActionTarget target,
        string source,
        CancellationToken cancellationToken = default) =>
        ExecuteSourceAsync(target, source, start: false, cancellationToken);

    public async Task<ViewerAgentCaptureActionResult> ListJobsAsync(
        ViewerAgentCaptureActionTarget target,
        CancellationToken cancellationToken = default)
    {
        var current = await GetCurrentControlAsync(
                ViewerAgentCaptureActionKind.ListJobs,
                target,
                cancellationToken)
            .ConfigureAwait(false);
        if (current.Result != null)
        {
            return current.Result;
        }

        var jobs = current.Health!.Control.ActiveWork
            .Where(job => job.JobId != Guid.Empty)
            .Where(job => job.State is JobState.Queued or JobState.Running)
            .OrderBy(job => job.AcceptedAtUtc)
            .ThenBy(job => job.JobId)
            .Take(MaximumActiveJobCount)
            .ToArray();
        return Succeeded(
            ViewerAgentCaptureActionKind.ListJobs,
            current.Response,
            current.Health,
            activeJobs: jobs,
            diagnostic: $"The agent reported {jobs.Length} bounded queued or running job(s).");
    }

    public Task<ViewerAgentCaptureActionResult> GetJobStatusAsync(
        ViewerAgentCaptureActionTarget target,
        Guid jobId,
        CancellationToken cancellationToken = default) =>
        GetJobStatusCoreAsync(
            ViewerAgentCaptureActionKind.GetJobStatus,
            target,
            jobId,
            cancellationToken);

    public async Task<ViewerAgentCaptureActionResult> WaitForJobAsync(
        ViewerAgentCaptureActionTarget target,
        Guid jobId,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        if (jobId == Guid.Empty)
        {
            return Rejected(
                ViewerAgentCaptureActionKind.WaitForJob,
                "InvalidJobId",
                "A non-empty job ID is required.");
        }

        if (!TryBeginWait(jobId))
        {
            return new ViewerAgentCaptureActionResult
            {
                Action = ViewerAgentCaptureActionKind.WaitForJob,
                Outcome = ViewerAgentCaptureActionOutcome.Busy,
                ErrorCode = "JobWaitBusy",
                Diagnostic = "A wait for this exact job is already active.",
                IsRetryable = true
            };
        }

        try
        {
            return await WaitForJobsCoreAsync(
                    ViewerAgentCaptureActionKind.WaitForJob,
                    target,
                    [jobId],
                    timeout,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            EndWait(jobId);
        }
    }

    public Task<ViewerAgentCaptureActionResult> CancelJobAsync(
        ViewerAgentCaptureActionTarget target,
        Guid jobId,
        CancellationToken cancellationToken = default)
    {
        if (jobId == Guid.Empty)
        {
            return Task.FromResult(Rejected(
                ViewerAgentCaptureActionKind.CancelJob,
                "InvalidJobId",
                "A non-empty job ID is required."));
        }

        return ExecuteCommandAsync(
            ViewerAgentCaptureActionKind.CancelJob,
            target,
            new CancelJobCommand { JobId = jobId },
            "cancel agent job",
            cancellationToken);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _disposeCts.Cancel();
        _disposeCts.Dispose();
    }

    private async Task<ViewerAgentCaptureActionResult> ExecuteSourceAsync(
        ViewerAgentCaptureActionTarget target,
        string source,
        bool start,
        CancellationToken cancellationToken)
    {
        var action = start
            ? ViewerAgentCaptureActionKind.StartSource
            : ViewerAgentCaptureActionKind.StopSource;
        if (!TryNormalizeSource(source, out var normalizedSource))
        {
            return Rejected(
                action,
                "CaptureSourceUnsupported",
                "Source must be Runtime, ETW, Security, PowerShell, WindowsOther, or Sysmon.");
        }

        var current = await GetCurrentControlAsync(action, target, cancellationToken)
            .ConfigureAwait(false);
        if (current.Result != null)
        {
            return current.Result;
        }

        var configured = AgentConfiguredCaptureWorkProjection.Select(
            current.Health!.Control.ActiveWork,
            current.Control!.ActiveCaptureId);
        var sourceControl = current.Control.GetLiveSource(normalizedSource);
        if (configured.Count == 0 ||
            string.IsNullOrWhiteSpace(current.Control.ActiveCaptureId) ||
            current.Control.State is not (AgentCaptureRunState.Starting or AgentCaptureRunState.Running) ||
            start && !sourceControl.CanStart ||
            !start && !sourceControl.CanStop)
        {
            return Rejected(
                action,
                start ? "CaptureSourceStartUnavailable" : "CaptureSourceStopUnavailable",
                "The fresh authoritative configured capture does not permit this source action.");
        }

        AgentCommand command = start
            ? new StartLiveCaptureSourceCommand { Source = normalizedSource }
            : new StopLiveCaptureSourceCommand { Source = normalizedSource };
        return await ExecuteCommandAsync(
                action,
                target,
                command,
                $"{(start ? "start" : "stop")} {normalizedSource} capture source",
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<ViewerAgentCaptureActionResult> ExecuteCommandAsync(
        ViewerAgentCaptureActionKind actionKind,
        ViewerAgentCaptureActionTarget target,
        AgentCommand command,
        string action,
        CancellationToken cancellationToken)
    {
        var targetFailure = ValidateTarget(actionKind, target);
        if (targetFailure != null)
        {
            return targetFailure;
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _disposeCts.Token);
        if (linked.IsCancellationRequested)
        {
            return Canceled(actionKind);
        }

        try
        {
            var response = await _runtime.ExecuteCommandAsync(
                    command,
                    action,
                    target.RequireViewerConnection,
                    linked.Token)
                .ConfigureAwait(false);
            if (!_runtime.IsCurrent(target))
            {
                return Superseded(actionKind);
            }

            if (response == null)
            {
                return Unavailable(
                    actionKind,
                    "AgentUnavailable",
                    $"The local agent was unavailable while trying to {action}.");
            }

            return response.Success
                ? Succeeded(
                    actionKind,
                    response,
                    response.Health,
                    response.Job,
                    diagnostic: $"The agent accepted the request to {action}.")
                : AgentRejected(actionKind, response);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            return cancellationToken.IsCancellationRequested || _disposeCts.IsCancellationRequested
                ? Canceled(actionKind)
                : Superseded(actionKind);
        }
        catch
        {
            return InternalFailure(actionKind, $"The action to {action} failed internally.");
        }
    }

    private async Task<ViewerAgentCaptureActionResult> GetJobStatusCoreAsync(
        ViewerAgentCaptureActionKind action,
        ViewerAgentCaptureActionTarget target,
        Guid jobId,
        CancellationToken cancellationToken)
    {
        var targetFailure = ValidateTarget(action, target);
        if (targetFailure != null)
        {
            return targetFailure;
        }

        if (jobId == Guid.Empty)
        {
            return Rejected(action, "InvalidJobId", "A non-empty job ID is required.");
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _disposeCts.Token);
        try
        {
            var response = await _runtime.GetJobStatusAsync(jobId, linked.Token)
                .ConfigureAwait(false);
            if (!_runtime.IsCurrent(target))
            {
                return Superseded(action);
            }

            if (!response.Success)
            {
                return AgentRejected(action, response);
            }

            if (response.Job == null || response.Job.JobId != jobId)
            {
                return Rejected(
                    action,
                    "JobStatusMismatch",
                    "The agent did not return status for the exact requested job.");
            }

            return Succeeded(
                action,
                response,
                response.Health,
                response.Job,
                jobs: [response.Job],
                diagnostic: $"Job {jobId:D} is {response.Job.State}.");
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            return Canceled(action);
        }
        catch
        {
            return InternalFailure(action, "The job-status request failed internally.");
        }
    }

    private async Task<ViewerAgentCaptureActionResult> WaitForResponseJobsAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerAgentCaptureActionResult commandResult,
        bool affected,
        TimeSpan? timeout,
        CancellationToken cancellationToken)
    {
        var response = commandResult.Response!;
        var jobs = affected
            ? AgentIpcResponseJobProjection.GetAffectedJobs(response)
            : AgentIpcResponseJobProjection.GetAcceptedJobs(response);
        var jobIds = jobs
            .Select(job => job.JobId)
            .Where(jobId => jobId != Guid.Empty)
            .Distinct()
            .ToArray();
        if (jobIds.Length == 0)
        {
            return Rejected(
                commandResult.Action,
                "AcceptedJobsMissing",
                "The accepted action did not return an exact job set to wait for.");
        }

        var waitsStarted = new List<Guid>();
        foreach (var jobId in jobIds)
        {
            if (!TryBeginWait(jobId))
            {
                foreach (var started in waitsStarted)
                {
                    EndWait(started);
                }

                return new ViewerAgentCaptureActionResult
                {
                    Action = commandResult.Action,
                    Outcome = ViewerAgentCaptureActionOutcome.Busy,
                    ErrorCode = "JobWaitBusy",
                    Diagnostic = "A wait for one of the accepted jobs is already active.",
                    IsRetryable = true,
                    Response = commandResult.Response
                };
            }

            waitsStarted.Add(jobId);
        }

        try
        {
            var waited = await WaitForJobsCoreAsync(
                    commandResult.Action,
                    target,
                    jobIds,
                    timeout,
                    cancellationToken)
                .ConfigureAwait(false);
            return waited with { Response = commandResult.Response };
        }
        finally
        {
            foreach (var jobId in waitsStarted)
            {
                EndWait(jobId);
            }
        }
    }

    private async Task<ViewerAgentCaptureActionResult> WaitForJobsCoreAsync(
        ViewerAgentCaptureActionKind action,
        ViewerAgentCaptureActionTarget target,
        IReadOnlyList<Guid> jobIds,
        TimeSpan? timeout,
        CancellationToken cancellationToken)
    {
        var effectiveTimeout = NormalizeTimeout(timeout);
        if (effectiveTimeout == null)
        {
            return Rejected(
                action,
                "InvalidTimeout",
                $"Timeout must be from 1 through {MaximumWaitTimeoutSeconds} seconds.");
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _disposeCts.Token);
        var deadline = _utcNow().Add(effectiveTimeout.Value);
        var delay = TimeSpan.FromMilliseconds(250);
        var terminal = new Dictionary<Guid, JobProgress>();
        while (true)
        {
            foreach (var jobId in jobIds)
            {
                if (terminal.ContainsKey(jobId))
                {
                    continue;
                }

                var status = await GetJobStatusCoreAsync(action, target, jobId, linked.Token)
                    .ConfigureAwait(false);
                if (!status.Succeeded)
                {
                    return status;
                }

                var job = status.Job!;
                if (job.State is JobState.Completed or JobState.Cancelled or JobState.Failed)
                {
                    terminal[jobId] = job;
                    if (job.State == JobState.Cancelled)
                    {
                        return TerminalFailure(
                            action,
                            ViewerAgentCaptureActionOutcome.JobCanceled,
                            "JobCanceled",
                            $"Job {jobId:D} was canceled.",
                            terminal.Values);
                    }

                    if (job.State == JobState.Failed)
                    {
                        return TerminalFailure(
                            action,
                            ViewerAgentCaptureActionOutcome.JobFailed,
                            "JobFailed",
                            FirstNonEmpty(job.ErrorText, $"Job {jobId:D} failed."),
                            terminal.Values);
                    }
                }
            }

            if (terminal.Count == jobIds.Count)
            {
                return new ViewerAgentCaptureActionResult
                {
                    Action = action,
                    Outcome = ViewerAgentCaptureActionOutcome.Succeeded,
                    Jobs = terminal.Values.OrderBy(job => job.JobId).ToArray(),
                    Job = terminal.Values.OrderBy(job => job.JobId).LastOrDefault(),
                    Diagnostic = $"All {terminal.Count} requested job(s) completed."
                };
            }

            if (_utcNow() >= deadline)
            {
                return new ViewerAgentCaptureActionResult
                {
                    Action = action,
                    Outcome = ViewerAgentCaptureActionOutcome.TimedOut,
                    ErrorCode = "JobWaitTimedOut",
                    Diagnostic = $"The job wait reached the {effectiveTimeout.Value.TotalSeconds:0}-second timeout.",
                    IsRetryable = true,
                    Jobs = terminal.Values.OrderBy(job => job.JobId).ToArray()
                };
            }

            try
            {
                await _runtime.DelayAsync(delay, linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (linked.IsCancellationRequested)
            {
                return Canceled(action);
            }

            delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 2000));
        }
    }

    private async Task<ControlResult> GetCurrentControlAsync(
        ViewerAgentCaptureActionKind action,
        ViewerAgentCaptureActionTarget target,
        CancellationToken cancellationToken)
    {
        var targetFailure = ValidateTarget(action, target);
        if (targetFailure != null)
        {
            return new ControlResult(null, null, null, targetFailure);
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _disposeCts.Token);
        try
        {
            var response = await _runtime.GetHealthAsync(linked.Token).ConfigureAwait(false);
            if (!_runtime.IsCurrent(target))
            {
                return new ControlResult(null, null, response, Superseded(action));
            }

            if (!response.Success || response.Health == null)
            {
                return new ControlResult(
                    null,
                    null,
                    response,
                    response.Success
                        ? Unavailable(action, "AgentHealthUnavailable", "Fresh agent health was unavailable.")
                        : AgentRejected(action, response));
            }

            var health = response.Health;
            var projection = new AgentCaptureControlProjectionService().ApplyHealth(
                health,
                string.Equals(health.SessionId, target.SessionId, StringComparison.Ordinal),
                _utcNow());
            if (projection.SnapshotStatus != AgentControlSnapshotStatus.Current ||
                !projection.SnapshotAccepted)
            {
                return new ControlResult(
                    health,
                    projection,
                    response,
                    Unavailable(
                        action,
                        "AuthoritativeControlUnavailable",
                        FirstNonEmpty(
                            projection.StatusDetail,
                            "A fresh authoritative matching-session agent control snapshot is required.")));
            }

            return new ControlResult(health, projection, response, null);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            return new ControlResult(null, null, null, Canceled(action));
        }
        catch
        {
            return new ControlResult(
                null,
                null,
                null,
                InternalFailure(action, "Fresh agent control validation failed internally."));
        }
    }

    private AgentConfiguredCaptureAvailability EvaluateAvailability(
        AgentCaptureControlViewState control,
        AgentHealthSnapshot health) =>
        AgentConfiguredCaptureAvailabilityPolicy.Evaluate(
            new AgentConfiguredCaptureAvailabilityContext
            {
                IsFeaturePublished = true,
                WorkspaceMode = health.WorkspaceMode,
                IsShutdownInProgress = false,
                HasSelectedLocalAgent = true,
                IsVerifiedAgentReachable = true,
                PairingState = AgentPairingState.Connected,
                HasActiveSqliteBenchmark = health.Control.ActiveWork.Any(job =>
                    job.JobKind == JobKind.SqliteBenchmark &&
                    job.State is JobState.Queued or JobState.Running),
                Control = control
            });

    private ViewerAgentCaptureActionResult? ValidateTarget(
        ViewerAgentCaptureActionKind action,
        ViewerAgentCaptureActionTarget target)
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
                "InvalidCaptureActionTarget",
                "An exact agent, host, live-session root, session ID, and positive workspace generation are required.");
        }

        return _runtime.IsCurrent(target)
            ? null
            : Superseded(action);
    }

    private static ViewerAgentCaptureActionResult? ValidateConfiguration(
        ViewerAgentCaptureActionTarget target,
        AgentCaptureConfiguration? configuration,
        bool allowNull)
    {
        if (configuration == null)
        {
            return allowNull
                ? null
                : Rejected(
                    ViewerAgentCaptureActionKind.SaveConfiguration,
                    "CaptureConfigurationMissing",
                    "A complete typed capture configuration is required.");
        }

        if (!string.Equals(configuration.AgentId, target.AgentId, StringComparison.Ordinal) ||
            !string.Equals(configuration.HostId, target.HostId, StringComparison.OrdinalIgnoreCase))
        {
            return Rejected(
                ViewerAgentCaptureActionKind.SaveConfiguration,
                "CaptureConfigurationTargetMismatch",
                "The configuration agent and host must match the exact authenticated target.");
        }

        if (string.IsNullOrWhiteSpace(configuration.ConfigurationVersion) ||
            configuration.ConfigurationVersion.Length > 128)
        {
            return Rejected(
                ViewerAgentCaptureActionKind.SaveConfiguration,
                "CaptureConfigurationVersionInvalid",
                "The configuration version is missing or exceeds 128 characters.");
        }

        if (configuration.RuntimeProcessSnapshots.Enabled &&
            configuration.RuntimeProcessSnapshots.RefreshIntervalSeconds is < 1 or > 3600)
        {
            return Rejected(
                ViewerAgentCaptureActionKind.SaveConfiguration,
                "CaptureIntervalOutOfRange",
                "Runtime process refresh interval must be from 1 through 3600 seconds.");
        }

        if (configuration.ArtifactCapture.RefreshIntervalSeconds is < 0 or > 86400 ||
            configuration.NetworkCapture.SegmentSeconds is < 0 or > 86400 ||
            configuration.NetworkCapture.MaxSegmentBytes is < 0 or > 1_099_511_627_776L ||
            configuration.SourceHealth.WarningAfterDroppedEvents is < 0 or > 1_000_000_000 ||
            configuration.SourceHealth.WarningAfterSourceSilenceSeconds is < 0 or > 86400 ||
            configuration.Guardrails.MaxEventsPerSecondWarning is < 0 or > 10_000_000 ||
            configuration.Guardrails.MaxLiveDatabaseBytesWarning is < 0 or > 1_099_511_627_776L ||
            configuration.Guardrails.RetentionDaysPlaceholder is < 0 or > 3650)
        {
            return Rejected(
                ViewerAgentCaptureActionKind.SaveConfiguration,
                "CaptureConfigurationBoundsInvalid",
                "One or more interval, size, warning, or retention values exceed supported bounds.");
        }

        var pathFailure = ValidateConfigurationPaths(target.SessionRoot, configuration);
        return pathFailure == null
            ? null
            : Rejected(
                ViewerAgentCaptureActionKind.SaveConfiguration,
                "CaptureConfigurationPathInvalid",
                pathFailure);
    }

    private static string? ValidateConfigurationPaths(
        string sessionRoot,
        AgentCaptureConfiguration configuration)
    {
        if (!ValidateOptionalAbsolutePath(configuration.Etw.ProfilePath, requireExisting: false) ||
            !ValidateOptionalAbsolutePath(configuration.Zeek.ZeekPath, requireExisting: false))
        {
            return "Configured ETW and Zeek paths must be bounded fully qualified paths.";
        }

        if (!ValidateSessionOutputPath(sessionRoot, configuration.NetworkCapture.OutputDirectory) ||
            !ValidateSessionOutputPath(sessionRoot, configuration.Zeek.OutputDirectory))
        {
            return "Network and Zeek output directories must remain bounded beneath the explicit session root.";
        }

        return null;
    }

    private static bool ValidateOptionalAbsolutePath(string? path, bool requireExisting)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        if (path.Length > 1024 || !Path.IsPathFullyQualified(path))
        {
            return false;
        }

        return !requireExisting || File.Exists(path);
    }

    private static bool ValidateSessionOutputPath(string sessionRoot, string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        try
        {
            if (path.Length > 1024 || !Path.IsPathFullyQualified(path))
            {
                return false;
            }

            var root = Path.GetFullPath(sessionRoot)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                Path.DirectorySeparatorChar;
            var candidate = Path.GetFullPath(path)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                Path.DirectorySeparatorChar;
            return candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase);
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

    private static async Task<ConfigurationFileLoadResult> LoadConfigurationFileAsync(
        ViewerAgentCaptureActionTarget target,
        string configurationPath,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(configurationPath) ||
            !Path.IsPathFullyQualified(configurationPath) ||
            !File.Exists(configurationPath))
        {
            return new ConfigurationFileLoadResult(
                null,
                Rejected(
                    ViewerAgentCaptureActionKind.SaveConfiguration,
                    "CaptureConfigurationFileUnavailable",
                    "--file must identify an existing absolute JSON file."));
        }

        try
        {
            var info = new FileInfo(configurationPath);
            if (info.Length <= 0 || info.Length > MaximumConfigurationFileBytes)
            {
                return new ConfigurationFileLoadResult(
                    null,
                    Rejected(
                        ViewerAgentCaptureActionKind.SaveConfiguration,
                        "CaptureConfigurationFileSizeInvalid",
                        $"Capture configuration JSON must be from 1 through {MaximumConfigurationFileBytes} bytes."));
            }

            var bytes = await File.ReadAllBytesAsync(configurationPath, cancellationToken)
                .ConfigureAwait(false);
            var json = new UTF8Encoding(false, true).GetString(bytes);
            var options = new JsonSerializerOptions(AgentIpcJson.JsonOptions)
            {
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
            };
            options.Converters.Insert(0, new JsonStringEnumConverter(allowIntegerValues: false));
            var configuration = JsonSerializer.Deserialize<AgentCaptureConfiguration>(json, options);
            var validation = ValidateConfiguration(target, configuration, allowNull: false);
            return validation == null
                ? new ConfigurationFileLoadResult(configuration, null)
                : new ConfigurationFileLoadResult(configuration, validation);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new ConfigurationFileLoadResult(
                null,
                Canceled(ViewerAgentCaptureActionKind.SaveConfiguration));
        }
        catch (Exception ex) when (ex is
            IOException or
            UnauthorizedAccessException or
            DecoderFallbackException or
            JsonException or
            NotSupportedException)
        {
            return new ConfigurationFileLoadResult(
                null,
                Rejected(
                    ViewerAgentCaptureActionKind.SaveConfiguration,
                    "CaptureConfigurationFileInvalid",
                    "The capture configuration file is not a current complete bounded UTF-8 JSON document."));
        }
    }

    private static bool TryNormalizeSource(string? source, out string normalized)
    {
        normalized = SupportedSources.FirstOrDefault(candidate =>
            string.Equals(candidate, source, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;
        return normalized.Length > 0;
    }

    private bool TryBeginWait(Guid jobId)
    {
        lock (_waitSync)
        {
            return _activeWaits.Add(jobId);
        }
    }

    private void EndWait(Guid jobId)
    {
        lock (_waitSync)
        {
            _activeWaits.Remove(jobId);
        }
    }

    private static TimeSpan? NormalizeTimeout(TimeSpan? timeout)
    {
        var effective = timeout ?? TimeSpan.FromSeconds(DefaultWaitTimeoutSeconds);
        return effective.TotalSeconds is >= 1 and <= MaximumWaitTimeoutSeconds
            ? effective
            : null;
    }

    private static ViewerAgentCaptureActionResult Succeeded(
        ViewerAgentCaptureActionKind action,
        AgentIpcResponse? response,
        AgentHealthSnapshot? health = null,
        JobProgress? job = null,
        IReadOnlyList<JobProgress>? jobs = null,
        IReadOnlyList<AgentActiveWorkItem>? activeJobs = null,
        string diagnostic = "") =>
        new()
        {
            Action = action,
            Outcome = ViewerAgentCaptureActionOutcome.Succeeded,
            Response = response,
            Health = health,
            Job = job,
            Jobs = jobs ?? Array.Empty<JobProgress>(),
            ActiveJobs = activeJobs ?? Array.Empty<AgentActiveWorkItem>(),
            Diagnostic = diagnostic
        };

    private static ViewerAgentCaptureActionResult Rejected(
        ViewerAgentCaptureActionKind action,
        string code,
        string diagnostic) =>
        new()
        {
            Action = action,
            Outcome = ViewerAgentCaptureActionOutcome.Rejected,
            ErrorCode = code,
            Diagnostic = diagnostic
        };

    private static ViewerAgentCaptureActionResult Unavailable(
        ViewerAgentCaptureActionKind action,
        string code,
        string diagnostic) =>
        new()
        {
            Action = action,
            Outcome = ViewerAgentCaptureActionOutcome.Unavailable,
            ErrorCode = code,
            Diagnostic = diagnostic,
            IsRetryable = true
        };

    private static ViewerAgentCaptureActionResult AgentRejected(
        ViewerAgentCaptureActionKind action,
        AgentIpcResponse response) =>
        new()
        {
            Action = action,
            Outcome = ViewerAgentCaptureActionOutcome.AgentRejected,
            ErrorCode = FirstNonEmpty(response.ErrorCode, "AgentRejected"),
            Diagnostic = FirstNonEmpty(response.ErrorMessage, "The agent rejected the request."),
            IsRetryable = response.IsRetryable,
            Response = response,
            Health = response.Health,
            Job = response.Job
        };

    private static ViewerAgentCaptureActionResult MissingPayload(
        ViewerAgentCaptureActionKind action,
        string code,
        string diagnostic,
        AgentIpcResponse? response) =>
        new()
        {
            Action = action,
            Outcome = ViewerAgentCaptureActionOutcome.AgentRejected,
            ErrorCode = code,
            Diagnostic = diagnostic,
            Response = response
        };

    private static ViewerAgentCaptureActionResult Canceled(ViewerAgentCaptureActionKind action) =>
        new()
        {
            Action = action,
            Outcome = ViewerAgentCaptureActionOutcome.Canceled,
            ErrorCode = "Canceled",
            Diagnostic = "The capture action was canceled."
        };

    private static ViewerAgentCaptureActionResult Superseded(ViewerAgentCaptureActionKind action) =>
        new()
        {
            Action = action,
            Outcome = ViewerAgentCaptureActionOutcome.Superseded,
            ErrorCode = "SessionSuperseded",
            Diagnostic = "The capture workspace changed before the action completed."
        };

    private static ViewerAgentCaptureActionResult InternalFailure(
        ViewerAgentCaptureActionKind action,
        string diagnostic) =>
        new()
        {
            Action = action,
            Outcome = ViewerAgentCaptureActionOutcome.InternalFailure,
            ErrorCode = "InternalFailure",
            Diagnostic = diagnostic
        };

    private static ViewerAgentCaptureActionResult TerminalFailure(
        ViewerAgentCaptureActionKind action,
        ViewerAgentCaptureActionOutcome outcome,
        string code,
        string diagnostic,
        IEnumerable<JobProgress> jobs) =>
        new()
        {
            Action = action,
            Outcome = outcome,
            ErrorCode = code,
            Diagnostic = diagnostic,
            Jobs = jobs.OrderBy(job => job.JobId).ToArray()
        };

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private sealed record ControlResult(
        AgentHealthSnapshot? Health,
        AgentCaptureControlViewState? Control,
        AgentIpcResponse? Response,
        ViewerAgentCaptureActionResult? Result);

    private sealed record ConfigurationFileLoadResult(
        AgentCaptureConfiguration? Configuration,
        ViewerAgentCaptureActionResult? Result);
}
