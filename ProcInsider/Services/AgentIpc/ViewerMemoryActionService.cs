using System.Globalization;
using System.IO;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public enum ViewerMemoryActionKind
{
    Unknown = 0,
    Acquire = 1,
    Import = 2,
    RunVolatility = 3
}

public enum ViewerMemoryActionOutcome
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

public sealed record ViewerMemoryAcquisitionRequest(
    bool Confirmed,
    string OutputFileName = "",
    int TimeoutSeconds = AgentMemoryActionPolicy.DefaultAcquisitionTimeoutSeconds);

public sealed record ViewerMemoryImageImportRequest(
    string ImagePath,
    string DisplayName = "",
    string HostName = "",
    string OsBuild = "",
    string AcquisitionTool = "Analyst import",
    string AcquisitionToolVersion = "",
    string AcquisitionCommandLine = "",
    string PrivilegeState = "");

public sealed record ViewerVolatilityActionRequest(
    string ImageId = "",
    string ImagePath = "",
    IReadOnlyList<string>? PluginNames = null,
    int PluginTimeoutSeconds = AgentMemoryActionPolicy.DefaultPluginTimeoutSeconds);

public sealed record ViewerMemoryActionResult
{
    public ViewerMemoryActionKind Action { get; init; }

    public ViewerMemoryActionOutcome Outcome { get; init; }

    public bool Succeeded => Outcome == ViewerMemoryActionOutcome.Succeeded;

    public string ErrorCode { get; init; } = string.Empty;

    public string Diagnostic { get; init; } = string.Empty;

    public bool IsRetryable { get; init; }

    public bool Waited { get; init; }

    public bool RefreshNeeded { get; init; }

    public Guid? AcceptedJobId { get; init; }

    public AgentIpcResponse? Response { get; init; }

    public JobProgress? Job { get; init; }

    public IReadOnlyList<JobProgress> Jobs { get; init; } = Array.Empty<JobProgress>();

    public AgentMemoryActionResult? Memory { get; init; }
}

/// <summary>
/// Shared headless WPF/CLI owner for system-memory acquisition, read-only image
/// import, and Volatility request construction. It composes the generic job wait;
/// the elevated agent remains the acquisition/tool/file/evidence authority.
/// </summary>
public sealed class ViewerMemoryActionService : IDisposable
{
    private readonly IViewerAgentCaptureActionRuntime _runtime;
    private readonly ViewerAgentCaptureActionService _jobActions;
    private readonly CancellationTokenSource _disposeCts = new();
    private bool _disposed;

    public ViewerMemoryActionService(
        IViewerAgentCaptureActionRuntime runtime,
        Func<DateTime>? utcNow = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _jobActions = new ViewerAgentCaptureActionService(runtime, utcNow);
    }

    public async Task<ViewerMemoryActionResult> AcquireAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerMemoryAcquisitionRequest request,
        bool wait = false,
        TimeSpan? waitTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(ViewerMemoryActionKind.Acquire, target);
        if (targetFailure != null)
        {
            return targetFailure;
        }

        if (!request.Confirmed)
        {
            return Rejected(
                ViewerMemoryActionKind.Acquire,
                "MemoryAcquisitionConfirmationRequired",
                "System-memory acquisition requires explicit confirmation.");
        }

        if (!AgentMemoryActionPolicy.TryNormalizeOptionalOutputFileName(
                request.OutputFileName,
                out var outputFileName))
        {
            return Rejected(
                ViewerMemoryActionKind.Acquire,
                "MemoryAcquisitionOutputFileInvalid",
                "The optional acquisition output must be one supported leaf file name without a directory.");
        }

        if (!AgentMemoryActionPolicy.IsValidAcquisitionTimeout(request.TimeoutSeconds))
        {
            return Rejected(
                ViewerMemoryActionKind.Acquire,
                "MemoryAcquisitionTimeoutOutOfRange",
                $"Acquisition timeout must be from {AgentMemoryActionPolicy.MinimumAcquisitionTimeoutSeconds.ToString(CultureInfo.InvariantCulture)} through {AgentMemoryActionPolicy.MaximumAcquisitionTimeoutSeconds.ToString(CultureInfo.InvariantCulture)} seconds.");
        }

        var listed = await _jobActions.ListJobsAsync(target, cancellationToken).ConfigureAwait(false);
        if (!listed.Succeeded || listed.Health == null)
        {
            return FromCaptureFailure(ViewerMemoryActionKind.Acquire, listed);
        }

        if (listed.Health.Control.ActiveWork.Any(work =>
                work.JobKind == JobKind.MemoryAcquisition &&
                (work.State is JobState.Queued or JobState.Running or JobState.Paused || work.StopRequested)))
        {
            return Rejected(
                ViewerMemoryActionKind.Acquire,
                "MemoryAcquisitionAlreadyActive",
                "Fresh authoritative agent state already contains active memory-acquisition work.");
        }

        return await QueueAsync(
                ViewerMemoryActionKind.Acquire,
                target,
                new QueueMemoryAcquisitionCommand
                {
                    RequestedOutputFileName = outputFileName,
                    TimeoutSeconds = request.TimeoutSeconds
                },
                "queue system-memory acquisition",
                wait,
                waitTimeout,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<ViewerMemoryActionResult> ImportAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerMemoryImageImportRequest request,
        bool wait = false,
        TimeSpan? waitTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(ViewerMemoryActionKind.Import, target);
        if (targetFailure != null)
        {
            return Task.FromResult(targetFailure);
        }

        if (!TryNormalizeExistingImage(request.ImagePath, out var imagePath))
        {
            return Task.FromResult(Rejected(
                ViewerMemoryActionKind.Import,
                "MemoryImageSourceInvalid",
                "Memory image import requires one existing readable non-empty absolute file with a supported extension."));
        }

        if (!TryNormalizeImportMetadata(request, out var normalized, out var metadataError))
        {
            return Task.FromResult(Rejected(
                ViewerMemoryActionKind.Import,
                "MemoryImageMetadataInvalid",
                metadataError));
        }

        return QueueAsync(
            ViewerMemoryActionKind.Import,
            target,
            new QueueMemoryImageImportCommand
            {
                ImagePath = imagePath,
                DisplayName = normalized.DisplayName,
                HostName = normalized.HostName,
                OsBuild = normalized.OsBuild,
                AcquisitionTool = normalized.AcquisitionTool,
                AcquisitionToolVersion = normalized.AcquisitionToolVersion,
                AcquisitionCommandLine = normalized.AcquisitionCommandLine,
                PrivilegeState = normalized.PrivilegeState
            },
            "queue memory-image import",
            wait,
            waitTimeout,
            cancellationToken);
    }

    public Task<ViewerMemoryActionResult> RunVolatilityAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerVolatilityActionRequest request,
        bool wait = false,
        TimeSpan? waitTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(ViewerMemoryActionKind.RunVolatility, target);
        if (targetFailure != null)
        {
            return Task.FromResult(targetFailure);
        }

        var hasImageId = !string.IsNullOrWhiteSpace(request.ImageId);
        var hasImagePath = !string.IsNullOrWhiteSpace(request.ImagePath);
        if (hasImageId == hasImagePath)
        {
            return Task.FromResult(Rejected(
                ViewerMemoryActionKind.RunVolatility,
                "VolatilityImageSelectorInvalid",
                "Volatility requires exactly one current staged image ID or explicit read-only image path."));
        }

        var imageId = string.Empty;
        var imagePath = string.Empty;
        if (hasImageId && !AgentMemoryActionPolicy.TryNormalizeImageId(request.ImageId, out imageId))
        {
            return Task.FromResult(Rejected(
                ViewerMemoryActionKind.RunVolatility,
                "VolatilityImageIdInvalid",
                "The staged memory image ID is malformed or exceeds the bounded identifier length."));
        }

        if (hasImagePath && !TryNormalizeExistingImage(request.ImagePath, out imagePath))
        {
            return Task.FromResult(Rejected(
                ViewerMemoryActionKind.RunVolatility,
                "VolatilityImagePathInvalid",
                "The explicit Volatility image must be an existing readable non-empty absolute file with a supported extension."));
        }

        if (!AgentMemoryActionPolicy.TryNormalizePlugins(
                request.PluginNames,
                out var plugins,
                out var pluginError))
        {
            return Task.FromResult(Rejected(
                ViewerMemoryActionKind.RunVolatility,
                "VolatilityPluginsInvalid",
                pluginError));
        }

        if (!AgentMemoryActionPolicy.IsValidPluginTimeout(request.PluginTimeoutSeconds))
        {
            return Task.FromResult(Rejected(
                ViewerMemoryActionKind.RunVolatility,
                "VolatilityTimeoutOutOfRange",
                $"Per-plugin timeout must be from {AgentMemoryActionPolicy.MinimumPluginTimeoutSeconds.ToString(CultureInfo.InvariantCulture)} through {AgentMemoryActionPolicy.MaximumPluginTimeoutSeconds.ToString(CultureInfo.InvariantCulture)} seconds."));
        }

        var outputDirectory = AgentMemoryActionPolicy.BuildVolatilityOutputDirectory(
            target.MemoryDirectory,
            imageId,
            imagePath);
        return QueueAsync(
            ViewerMemoryActionKind.RunVolatility,
            target,
            new QueueVolatilityAnalysisCommand
            {
                ImageId = imageId,
                ImagePath = imagePath,
                PluginNames = plugins.Length == 0 ? null : plugins,
                OutputDirectory = outputDirectory,
                TimeoutSeconds = request.PluginTimeoutSeconds
            },
            "queue Volatility analysis",
            wait,
            waitTimeout,
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
        _jobActions.Dispose();
        _disposeCts.Dispose();
    }

    private async Task<ViewerMemoryActionResult> QueueAsync(
        ViewerMemoryActionKind action,
        ViewerAgentCaptureActionTarget target,
        AgentCommand command,
        string description,
        bool wait,
        TimeSpan? timeout,
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
            return InternalFailure(action, "The memory action failed internally before an accepted job was confirmed.");
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
            return new ViewerMemoryActionResult
            {
                Action = action,
                Outcome = ViewerMemoryActionOutcome.AgentRejected,
                ErrorCode = BoundCode(response.ErrorCode, "AgentRejected"),
                Diagnostic = Bound(response.ErrorMessage, "The agent rejected the typed memory action."),
                IsRetryable = response.IsRetryable,
                Response = response
            };
        }

        var jobId = response.AcceptedJobId ?? response.Job?.JobId;
        if (!jobId.HasValue || jobId.Value == Guid.Empty)
        {
            return new ViewerMemoryActionResult
            {
                Action = action,
                Outcome = ViewerMemoryActionOutcome.Rejected,
                ErrorCode = "AcceptedJobMissing",
                Diagnostic = "The agent accepted the memory action without returning an exact trackable job ID.",
                Response = response
            };
        }

        if (!wait)
        {
            return new ViewerMemoryActionResult
            {
                Action = action,
                Outcome = ViewerMemoryActionOutcome.Succeeded,
                Diagnostic = "The agent accepted the typed memory action. Durable evidence requires explicit Refresh from db.",
                RefreshNeeded = true,
                AcceptedJobId = jobId,
                Response = response,
                Job = response.Job,
                Jobs = response.Job == null ? Array.Empty<JobProgress>() : [response.Job],
                Memory = response.Job?.MemoryAction
            };
        }

        var waited = await _jobActions.WaitForJobAsync(target, jobId.Value, timeout, linked.Token)
            .ConfigureAwait(false);
        return FromWait(action, response, jobId.Value, waited);
    }

    private ViewerMemoryActionResult? ValidateTarget(
        ViewerMemoryActionKind action,
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
                "InvalidMemoryActionTarget",
                "An exact agent, host, live-session root, session ID, and positive workspace generation are required.");
        }

        if (!_runtime.IsCurrent(target))
        {
            return Superseded(action);
        }

        if (string.IsNullOrWhiteSpace(target.MemoryDirectory) ||
            !Path.IsPathFullyQualified(target.MemoryDirectory) ||
            !AgentToolActionPolicy.IsStrictChildPath(target.SessionRoot, target.MemoryDirectory) ||
            !AgentToolActionPolicy.PathsEqual(
                target.MemoryDirectory,
                Path.Combine(target.SessionRoot, "Memory")))
        {
            return Rejected(
                action,
                "SessionMemoryDirectoryInvalid",
                "The active SessionPathService Memory directory must be the exact absolute Memory child of the session root.");
        }

        return null;
    }

    private static bool TryNormalizeExistingImage(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (!AgentToolActionPolicy.TryNormalizeAbsolutePath(value, out var candidate) ||
            !AgentMemoryActionPolicy.IsSupportedImagePath(candidate) ||
            !File.Exists(candidate))
        {
            return false;
        }

        try
        {
            var info = new FileInfo(candidate);
            if (info.Length <= 0)
            {
                return false;
            }

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

    private static bool TryNormalizeImportMetadata(
        ViewerMemoryImageImportRequest request,
        out ViewerMemoryImageImportRequest normalized,
        out string error)
    {
        normalized = request;
        error = string.Empty;
        var fields = new[]
        {
            ("display name", request.DisplayName, AgentMemoryActionPolicy.MaximumMetadataLength),
            ("host name", request.HostName, AgentMemoryActionPolicy.MaximumMetadataLength),
            ("OS build", request.OsBuild, AgentMemoryActionPolicy.MaximumMetadataLength),
            ("acquisition tool", request.AcquisitionTool, AgentMemoryActionPolicy.MaximumMetadataLength),
            ("acquisition tool version", request.AcquisitionToolVersion, AgentMemoryActionPolicy.MaximumMetadataLength),
            ("acquisition command line", request.AcquisitionCommandLine, AgentMemoryActionPolicy.MaximumCommandLineMetadataLength),
            ("privilege state", request.PrivilegeState, AgentMemoryActionPolicy.MaximumMetadataLength)
        };
        var values = new string[fields.Length];
        for (var index = 0; index < fields.Length; index++)
        {
            if (!AgentMemoryActionPolicy.TryNormalizeOptionalMetadata(
                    fields[index].Item2,
                    fields[index].Item3,
                    out values[index]))
            {
                error = $"Memory image {fields[index].Item1} is too long or contains control characters.";
                return false;
            }
        }

        normalized = request with
        {
            DisplayName = values[0],
            HostName = values[1],
            OsBuild = values[2],
            AcquisitionTool = values[3],
            AcquisitionToolVersion = values[4],
            AcquisitionCommandLine = values[5],
            PrivilegeState = values[6]
        };
        return true;
    }

    private static ViewerMemoryActionResult FromWait(
        ViewerMemoryActionKind action,
        AgentIpcResponse acceptedResponse,
        Guid acceptedJobId,
        ViewerAgentCaptureActionResult waited)
    {
        var outcome = waited.Outcome switch
        {
            ViewerAgentCaptureActionOutcome.Succeeded => ViewerMemoryActionOutcome.Succeeded,
            ViewerAgentCaptureActionOutcome.TimedOut => ViewerMemoryActionOutcome.TimedOut,
            ViewerAgentCaptureActionOutcome.Canceled => ViewerMemoryActionOutcome.Canceled,
            ViewerAgentCaptureActionOutcome.JobCanceled => ViewerMemoryActionOutcome.JobCanceled,
            ViewerAgentCaptureActionOutcome.JobFailed => ViewerMemoryActionOutcome.JobFailed,
            ViewerAgentCaptureActionOutcome.Superseded => ViewerMemoryActionOutcome.Superseded,
            ViewerAgentCaptureActionOutcome.Busy => ViewerMemoryActionOutcome.Busy,
            ViewerAgentCaptureActionOutcome.Unavailable => ViewerMemoryActionOutcome.Unavailable,
            ViewerAgentCaptureActionOutcome.AgentRejected => ViewerMemoryActionOutcome.AgentRejected,
            ViewerAgentCaptureActionOutcome.InternalFailure => ViewerMemoryActionOutcome.InternalFailure,
            _ => ViewerMemoryActionOutcome.Rejected
        };
        return new ViewerMemoryActionResult
        {
            Action = action,
            Outcome = outcome,
            ErrorCode = waited.ErrorCode,
            Diagnostic = Bound(
                waited.Diagnostic,
                outcome == ViewerMemoryActionOutcome.Succeeded
                    ? "The memory job completed. Refresh from db is required to project durable evidence."
                    : "The memory job did not complete successfully."),
            IsRetryable = waited.IsRetryable,
            Waited = true,
            RefreshNeeded = outcome == ViewerMemoryActionOutcome.Succeeded,
            AcceptedJobId = acceptedJobId,
            Response = acceptedResponse,
            Job = waited.Job,
            Jobs = waited.Jobs,
            Memory = waited.Job?.MemoryAction
        };
    }

    private static ViewerMemoryActionResult FromCaptureFailure(
        ViewerMemoryActionKind action,
        ViewerAgentCaptureActionResult result) => new()
    {
        Action = action,
        Outcome = result.Outcome switch
        {
            ViewerAgentCaptureActionOutcome.Unavailable => ViewerMemoryActionOutcome.Unavailable,
            ViewerAgentCaptureActionOutcome.AgentRejected => ViewerMemoryActionOutcome.AgentRejected,
            ViewerAgentCaptureActionOutcome.TimedOut => ViewerMemoryActionOutcome.TimedOut,
            ViewerAgentCaptureActionOutcome.Canceled => ViewerMemoryActionOutcome.Canceled,
            ViewerAgentCaptureActionOutcome.Superseded => ViewerMemoryActionOutcome.Superseded,
            ViewerAgentCaptureActionOutcome.Busy => ViewerMemoryActionOutcome.Busy,
            ViewerAgentCaptureActionOutcome.InternalFailure => ViewerMemoryActionOutcome.InternalFailure,
            _ => ViewerMemoryActionOutcome.Rejected
        },
        ErrorCode = result.ErrorCode,
        Diagnostic = Bound(result.Diagnostic, "Fresh authoritative agent control is unavailable."),
        IsRetryable = result.IsRetryable,
        Response = result.Response
    };

    private static ViewerMemoryActionResult Rejected(
        ViewerMemoryActionKind action,
        string code,
        string message) => new()
    {
        Action = action,
        Outcome = ViewerMemoryActionOutcome.Rejected,
        ErrorCode = code,
        Diagnostic = message
    };

    private static ViewerMemoryActionResult Unavailable(
        ViewerMemoryActionKind action,
        string code,
        string message) => new()
    {
        Action = action,
        Outcome = ViewerMemoryActionOutcome.Unavailable,
        ErrorCode = code,
        Diagnostic = message,
        IsRetryable = true
    };

    private static ViewerMemoryActionResult Canceled(ViewerMemoryActionKind action) => new()
    {
        Action = action,
        Outcome = ViewerMemoryActionOutcome.Canceled,
        ErrorCode = "Canceled",
        Diagnostic = "The memory action was canceled."
    };

    private static ViewerMemoryActionResult Superseded(ViewerMemoryActionKind action) => new()
    {
        Action = action,
        Outcome = ViewerMemoryActionOutcome.Superseded,
        ErrorCode = "SessionSuperseded",
        Diagnostic = "The exact session binding was superseded before the memory action completed."
    };

    private static ViewerMemoryActionResult InternalFailure(
        ViewerMemoryActionKind action,
        string message) => new()
    {
        Action = action,
        Outcome = ViewerMemoryActionOutcome.InternalFailure,
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
}
