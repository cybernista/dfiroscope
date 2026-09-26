using System.Globalization;
using System.IO;
using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public enum ViewerAgentEvidenceActionKind
{
    Unknown = 0,
    Enrichment = 1,
    ProcessDump = 2,
    FilesystemImport = 3
}

public enum ViewerAgentEvidenceActionOutcome
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

public sealed record ViewerProcessDumpActionRequest(
    string ProcessKey,
    MemoryDumpKind DumpKind,
    bool Confirmed);

public sealed record ViewerFilesystemImportActionRequest(
    string Path,
    bool Recurse,
    bool IncludeNtfs,
    bool IncludePrefetch,
    int MaxFiles = ViewerAgentEvidenceActionService.MaximumFilesystemImportFiles);

public sealed record ViewerAgentEvidenceActionResult
{
    public ViewerAgentEvidenceActionKind Action { get; init; }

    public ViewerAgentEvidenceActionOutcome Outcome { get; init; }

    public bool Succeeded => Outcome == ViewerAgentEvidenceActionOutcome.Succeeded;

    public string ErrorCode { get; init; } = string.Empty;

    public string Diagnostic { get; init; } = string.Empty;

    public bool IsRetryable { get; init; }

    public bool Waited { get; init; }

    public bool RefreshNeeded { get; init; }

    public Guid? AcceptedJobId { get; init; }

    public AgentIpcResponse? Response { get; init; }

    public JobProgress? Job { get; init; }

    public IReadOnlyList<JobProgress> Jobs { get; init; } = Array.Empty<JobProgress>();

    public ArtifactEnrichmentWorkflowResult? EnrichmentResult { get; init; }
}

/// <summary>
/// Shared headless owner for exact-process dump and bounded filesystem-import requests.
/// Presentation adapters supply an already-bound exact-session runtime; the elevated agent
/// remains the acquisition/import and durable-evidence owner.
/// </summary>
public sealed class ViewerAgentEvidenceActionService : IDisposable
{
    public const int MaximumEnrichmentTargetCount = AgentEvidenceActionPolicy.MaximumEnrichmentTargetCount;
    public const int MaximumProcessEntityIdLength = AgentEvidenceActionPolicy.MaximumProcessEntityIdLength;
    public const int MaximumProcessKeyLength = AgentEvidenceActionPolicy.MaximumProcessKeyLength;
    public const int MaximumFilesystemImportFiles = AgentEvidenceActionPolicy.MaximumFilesystemImportFiles;
    public const int MaximumSourcePathLength = 32_767;

    private readonly IViewerAgentCaptureActionRuntime _runtime;
    private readonly ViewerAgentCaptureActionService _jobActions;
    private readonly CancellationTokenSource _disposeCts = new();
    private bool _disposed;

    public ViewerAgentEvidenceActionService(
        IViewerAgentCaptureActionRuntime runtime,
        Func<DateTime>? utcNow = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _jobActions = new ViewerAgentCaptureActionService(runtime, utcNow);
    }

    public Task<ViewerAgentEvidenceActionResult> QueueProcessDumpAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerProcessDumpActionRequest request,
        bool wait = false,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(ViewerAgentEvidenceActionKind.ProcessDump, target, requireDumpsDirectory: true);
        if (targetFailure != null)
        {
            return Task.FromResult(targetFailure);
        }

        if (!request.Confirmed)
        {
            return Task.FromResult(Rejected(
                ViewerAgentEvidenceActionKind.ProcessDump,
                "ProcessDumpConfirmationRequired",
                "Process dump capture requires explicit confirmation."));
        }

        if (!TryNormalizeExactProcessKey(request.ProcessKey, out var processKey))
        {
            return Task.FromResult(Rejected(
                ViewerAgentEvidenceActionKind.ProcessDump,
                "ProcessKeyInvalid",
                "Process dump capture requires one exact ProcessKey in PID_StartTimeTicks form; PID-only targets are not accepted."));
        }

        if (!Enum.IsDefined(request.DumpKind))
        {
            return Task.FromResult(Rejected(
                ViewerAgentEvidenceActionKind.ProcessDump,
                "ProcessDumpKindInvalid",
                "Process dump kind must be Full or Mini."));
        }

        var dumpsDirectory = Path.GetFullPath(target.DumpsDirectory);
        return QueueAsync(
            ViewerAgentEvidenceActionKind.ProcessDump,
            target,
            new QueueProcessDumpCommand
            {
                ProcessKey = processKey,
                DumpKind = request.DumpKind,
                OutputDirectory = dumpsDirectory,
                OverwriteExisting = false
            },
            "queue exact-process dump",
            wait,
            timeout,
            cancellationToken);
    }

    public async Task<ViewerAgentEvidenceActionResult> QueueEnrichmentAsync(
        ViewerAgentCaptureActionTarget target,
        ArtifactEnrichmentWorkflowCoordinator coordinator,
        ArtifactEnrichmentQueueRequest request,
        bool wait = false,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(
            ViewerAgentEvidenceActionKind.Enrichment,
            target,
            requireDumpsDirectory: false);
        if (targetFailure != null)
        {
            return targetFailure;
        }

        ArtifactEnrichmentWorkflowResult enrichment;
        try
        {
            enrichment = await coordinator.QueueAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Canceled(ViewerAgentEvidenceActionKind.Enrichment);
        }
        catch (ArgumentException ex)
        {
            return Rejected(
                ViewerAgentEvidenceActionKind.Enrichment,
                "EnrichmentRequestInvalid",
                Bound(ex.Message, "The enrichment request was invalid."));
        }
        catch
        {
            return InternalFailure(
                ViewerAgentEvidenceActionKind.Enrichment,
                "The enrichment action failed internally before an accepted job was confirmed.");
        }

        if (!enrichment.Succeeded)
        {
            var response = enrichment.Response;
            var outcome = enrichment.Outcome switch
            {
                ArtifactEnrichmentWorkflowOutcome.Canceled => ViewerAgentEvidenceActionOutcome.Canceled,
                ArtifactEnrichmentWorkflowOutcome.Superseded => ViewerAgentEvidenceActionOutcome.Superseded,
                ArtifactEnrichmentWorkflowOutcome.Failed when response == null => ViewerAgentEvidenceActionOutcome.Unavailable,
                ArtifactEnrichmentWorkflowOutcome.Failed => ViewerAgentEvidenceActionOutcome.AgentRejected,
                _ => ViewerAgentEvidenceActionOutcome.Rejected
            };
            return new ViewerAgentEvidenceActionResult
            {
                Action = ViewerAgentEvidenceActionKind.Enrichment,
                Outcome = outcome,
                ErrorCode = BoundCode(response?.ErrorCode, enrichment.Outcome.ToString()),
                Diagnostic = Bound(enrichment.Detail, "The enrichment action was not accepted."),
                IsRetryable = response?.IsRetryable == true,
                Response = response,
                EnrichmentResult = enrichment
            };
        }

        var acceptedResponse = enrichment.Response;
        if (acceptedResponse?.AcceptedJobId is not { } jobId || jobId == Guid.Empty)
        {
            return new ViewerAgentEvidenceActionResult
            {
                Action = ViewerAgentEvidenceActionKind.Enrichment,
                Outcome = ViewerAgentEvidenceActionOutcome.Rejected,
                ErrorCode = "AcceptedJobMissing",
                Diagnostic = "The agent accepted enrichment without returning an exact trackable job ID.",
                Response = acceptedResponse,
                EnrichmentResult = enrichment
            };
        }

        if (!wait)
        {
            return new ViewerAgentEvidenceActionResult
            {
                Action = ViewerAgentEvidenceActionKind.Enrichment,
                Outcome = ViewerAgentEvidenceActionOutcome.Succeeded,
                Diagnostic = "The agent accepted typed enrichment. Results appear after Refresh from db.",
                RefreshNeeded = true,
                AcceptedJobId = jobId,
                Response = acceptedResponse,
                Job = acceptedResponse.Job,
                Jobs = acceptedResponse.Job == null ? Array.Empty<JobProgress>() : [acceptedResponse.Job],
                EnrichmentResult = enrichment
            };
        }

        var waited = await _jobActions.WaitForJobAsync(target, jobId, timeout, cancellationToken)
            .ConfigureAwait(false);
        return FromWait(
            ViewerAgentEvidenceActionKind.Enrichment,
            acceptedResponse,
            jobId,
            waited,
            enrichment);
    }

    public Task<ViewerAgentEvidenceActionResult> QueueFilesystemImportAsync(
        ViewerAgentCaptureActionTarget target,
        ViewerFilesystemImportActionRequest request,
        bool wait = false,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(ViewerAgentEvidenceActionKind.FilesystemImport, target, requireDumpsDirectory: false);
        if (targetFailure != null)
        {
            return Task.FromResult(targetFailure);
        }

        if (!request.IncludeNtfs && !request.IncludePrefetch)
        {
            return Task.FromResult(Rejected(
                ViewerAgentEvidenceActionKind.FilesystemImport,
                "FilesystemArtifactFamilyRequired",
                "Filesystem import requires NTFS, Prefetch, or both artifact families."));
        }

        if (request.MaxFiles is < 1 or > MaximumFilesystemImportFiles)
        {
            return Task.FromResult(Rejected(
                ViewerAgentEvidenceActionKind.FilesystemImport,
                "FilesystemMaxFilesOutOfRange",
                $"Filesystem import max files must be from 1 through {MaximumFilesystemImportFiles.ToString(CultureInfo.InvariantCulture)}."));
        }

        if (!TryNormalizeExistingSourcePath(request.Path, out var sourcePath, out var isFile))
        {
            return Task.FromResult(Rejected(
                ViewerAgentEvidenceActionKind.FilesystemImport,
                "FilesystemSourceInvalid",
                "Filesystem import requires an existing absolute regular file or directory."));
        }

        if (isFile && request.Recurse)
        {
            return Task.FromResult(Rejected(
                ViewerAgentEvidenceActionKind.FilesystemImport,
                "FilesystemRecurseInvalid",
                "Recursive import is valid only for a directory source."));
        }

        return QueueAsync(
            ViewerAgentEvidenceActionKind.FilesystemImport,
            target,
            new QueueArtifactImportCommand
            {
                Path = sourcePath,
                Recurse = request.Recurse,
                IncludeNtfs = request.IncludeNtfs,
                IncludePrefetch = request.IncludePrefetch,
                MaxFiles = request.MaxFiles
            },
            "queue bounded filesystem artifact import",
            wait,
            timeout,
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

    public static bool TryNormalizeExactProcessKey(string? value, out string normalized)
        => AgentEvidenceActionPolicy.TryNormalizeExactProcessKey(value, out normalized);

    public static bool TryNormalizeProcessEntityIds(
        IReadOnlyList<string>? values,
        out string[] normalized,
        out string error) =>
        AgentEvidenceActionPolicy.TryNormalizeProcessEntityIds(values, out normalized, out error);

    public static bool TryNormalizeProcessKeys(
        IReadOnlyList<string>? values,
        out string[] normalized,
        out string error) =>
        AgentEvidenceActionPolicy.TryNormalizeProcessKeys(values, out normalized, out error);

    private async Task<ViewerAgentEvidenceActionResult> QueueAsync(
        ViewerAgentEvidenceActionKind action,
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
            return InternalFailure(action, "The evidence action failed internally before an accepted job was confirmed.");
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
            return new ViewerAgentEvidenceActionResult
            {
                Action = action,
                Outcome = ViewerAgentEvidenceActionOutcome.AgentRejected,
                ErrorCode = BoundCode(response.ErrorCode, "AgentRejected"),
                Diagnostic = Bound(response.ErrorMessage, "The agent rejected the typed evidence action."),
                IsRetryable = response.IsRetryable,
                Response = response
            };
        }

        if (response.AcceptedJobId is not { } jobId || jobId == Guid.Empty)
        {
            return new ViewerAgentEvidenceActionResult
            {
                Action = action,
                Outcome = ViewerAgentEvidenceActionOutcome.Rejected,
                ErrorCode = "AcceptedJobMissing",
                Diagnostic = "The agent accepted the action without returning an exact trackable job ID.",
                Response = response
            };
        }

        if (!wait)
        {
            return new ViewerAgentEvidenceActionResult
            {
                Action = action,
                Outcome = ViewerAgentEvidenceActionOutcome.Succeeded,
                Diagnostic = "The agent accepted the typed evidence action. Results appear after Refresh from db.",
                RefreshNeeded = true,
                AcceptedJobId = jobId,
                Response = response,
                Job = response.Job,
                Jobs = response.Job == null ? Array.Empty<JobProgress>() : [response.Job]
            };
        }

        var waited = await _jobActions.WaitForJobAsync(target, jobId, timeout, linked.Token)
            .ConfigureAwait(false);
        return FromWait(action, response, jobId, waited);
    }

    private ViewerAgentEvidenceActionResult? ValidateTarget(
        ViewerAgentEvidenceActionKind action,
        ViewerAgentCaptureActionTarget target,
        bool requireDumpsDirectory)
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
                "InvalidEvidenceActionTarget",
                "An exact agent, host, live-session root, session ID, and positive workspace generation are required.");
        }

        if (!_runtime.IsCurrent(target))
        {
            return Superseded(action);
        }

        if (!requireDumpsDirectory)
        {
            return null;
        }

        try
        {
            if (string.IsNullOrWhiteSpace(target.DumpsDirectory) ||
                !Path.IsPathFullyQualified(target.DumpsDirectory) ||
                !IsStrictChildPath(target.SessionRoot, target.DumpsDirectory) ||
                !AgentToolActionPolicy.PathsEqual(
                    target.DumpsDirectory,
                    Path.Combine(target.SessionRoot, "Dumps")))
            {
                return Rejected(
                    action,
                    "SessionDumpDirectoryInvalid",
                    "The active SessionPathService dump directory must be the exact absolute Dumps child of the session root.");
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return Rejected(
                action,
                "SessionDumpDirectoryInvalid",
                "The active SessionPathService dump directory could not be normalized safely.");
        }

        return null;
    }

    private static bool TryNormalizeExistingSourcePath(
        string? value,
        out string normalized,
        out bool isFile)
    {
        normalized = string.Empty;
        isFile = false;
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > MaximumSourcePathLength ||
            !Path.IsPathFullyQualified(value))
        {
            return false;
        }

        try
        {
            normalized = Path.GetFullPath(value);
            isFile = File.Exists(normalized);
            return isFile || Directory.Exists(normalized);
        }
        catch (Exception ex) when (ex is
            ArgumentException or
            NotSupportedException or
            PathTooLongException or
            IOException or
            UnauthorizedAccessException)
        {
            normalized = string.Empty;
            return false;
        }
    }

    private static bool IsStrictChildPath(string parentPath, string childPath)
    {
        var parent = Path.GetFullPath(parentPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var child = Path.GetFullPath(childPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return child.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static ViewerAgentEvidenceActionResult FromWait(
        ViewerAgentEvidenceActionKind action,
        AgentIpcResponse acceptedResponse,
        Guid acceptedJobId,
        ViewerAgentCaptureActionResult waited,
        ArtifactEnrichmentWorkflowResult? enrichmentResult = null)
    {
        var outcome = waited.Outcome switch
        {
            ViewerAgentCaptureActionOutcome.Succeeded => ViewerAgentEvidenceActionOutcome.Succeeded,
            ViewerAgentCaptureActionOutcome.TimedOut => ViewerAgentEvidenceActionOutcome.TimedOut,
            ViewerAgentCaptureActionOutcome.Canceled => ViewerAgentEvidenceActionOutcome.Canceled,
            ViewerAgentCaptureActionOutcome.JobCanceled => ViewerAgentEvidenceActionOutcome.JobCanceled,
            ViewerAgentCaptureActionOutcome.JobFailed => ViewerAgentEvidenceActionOutcome.JobFailed,
            ViewerAgentCaptureActionOutcome.Superseded => ViewerAgentEvidenceActionOutcome.Superseded,
            ViewerAgentCaptureActionOutcome.Busy => ViewerAgentEvidenceActionOutcome.Busy,
            ViewerAgentCaptureActionOutcome.Unavailable => ViewerAgentEvidenceActionOutcome.Unavailable,
            ViewerAgentCaptureActionOutcome.AgentRejected => ViewerAgentEvidenceActionOutcome.AgentRejected,
            ViewerAgentCaptureActionOutcome.InternalFailure => ViewerAgentEvidenceActionOutcome.InternalFailure,
            _ => ViewerAgentEvidenceActionOutcome.Rejected
        };
        return new ViewerAgentEvidenceActionResult
        {
            Action = action,
            Outcome = outcome,
            ErrorCode = waited.ErrorCode,
            Diagnostic = Bound(
                waited.Diagnostic,
                outcome == ViewerAgentEvidenceActionOutcome.Succeeded
                    ? "The evidence job completed. Refresh from db is required to project durable evidence."
                    : "The evidence job did not complete successfully."),
            IsRetryable = waited.IsRetryable,
            Waited = true,
            RefreshNeeded = outcome == ViewerAgentEvidenceActionOutcome.Succeeded,
            AcceptedJobId = acceptedJobId,
            Response = acceptedResponse,
            Job = waited.Job,
            Jobs = waited.Jobs,
            EnrichmentResult = enrichmentResult
        };
    }

    private static ViewerAgentEvidenceActionResult Rejected(
        ViewerAgentEvidenceActionKind action,
        string code,
        string message) => new()
    {
        Action = action,
        Outcome = ViewerAgentEvidenceActionOutcome.Rejected,
        ErrorCode = code,
        Diagnostic = message
    };

    private static ViewerAgentEvidenceActionResult Unavailable(
        ViewerAgentEvidenceActionKind action,
        string code,
        string message) => new()
    {
        Action = action,
        Outcome = ViewerAgentEvidenceActionOutcome.Unavailable,
        ErrorCode = code,
        Diagnostic = message,
        IsRetryable = true
    };

    private static ViewerAgentEvidenceActionResult Canceled(ViewerAgentEvidenceActionKind action) => new()
    {
        Action = action,
        Outcome = ViewerAgentEvidenceActionOutcome.Canceled,
        ErrorCode = "Canceled",
        Diagnostic = "The evidence action was canceled."
    };

    private static ViewerAgentEvidenceActionResult Superseded(ViewerAgentEvidenceActionKind action) => new()
    {
        Action = action,
        Outcome = ViewerAgentEvidenceActionOutcome.Superseded,
        ErrorCode = "SessionSuperseded",
        Diagnostic = "The exact session binding was superseded before the evidence action completed."
    };

    private static ViewerAgentEvidenceActionResult InternalFailure(
        ViewerAgentEvidenceActionKind action,
        string message) => new()
    {
        Action = action,
        Outcome = ViewerAgentEvidenceActionOutcome.InternalFailure,
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
