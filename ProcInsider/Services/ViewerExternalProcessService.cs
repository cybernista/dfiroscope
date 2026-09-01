using System.Diagnostics;
using System.IO;

namespace ProcInsider.Services;

public enum ViewerExternalProcessOutcome
{
    Started,
    Completed,
    MissingExecutable,
    StartFailed,
    NonZeroExit,
    TimedOut,
    Canceled,
    MissingExpectedOutput,
    ExecutionFailed
}

public sealed record ViewerExternalProcessResult(
    ViewerExternalProcessOutcome Outcome,
    int? ExitCode,
    string StandardOutput,
    string StandardError,
    string Detail)
{
    public bool Succeeded => Outcome is ViewerExternalProcessOutcome.Started or ViewerExternalProcessOutcome.Completed;
}

public interface IViewerExternalProcessService
{
    ViewerExternalProcessResult OpenShellTarget(string targetPath);

    ViewerExternalProcessResult OpenWireshark(string executablePath, string capturePath);

    Task<ViewerExternalProcessResult> ExportTsharkFlowAsync(
        string executablePath,
        string capturePath,
        string displayFilter,
        string outputPath,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}

public sealed record ViewerExternalProcessStartRequest(
    string FileName,
    IReadOnlyList<string> ArgumentList,
    string? RawArguments,
    string? WorkingDirectory,
    bool UseShellExecute,
    bool CreateNoWindow,
    bool RedirectStandardOutput,
    bool RedirectStandardError);

public interface IViewerExternalProcessRuntime
{
    bool FileExists(string path);

    long GetFileLength(string path);

    IViewerExternalProcessHandle? Start(ViewerExternalProcessStartRequest request);
}

public interface IViewerExternalProcessHandle : IDisposable
{
    bool HasExited { get; }

    int ExitCode { get; }

    Task<string> ReadStandardOutputToEndAsync();

    Task<string> ReadStandardErrorToEndAsync();

    Task WaitForExitAsync(CancellationToken cancellationToken);

    void Kill(bool entireProcessTree);
}

public sealed class ViewerExternalProcessService : IViewerExternalProcessService
{
    private readonly IViewerExternalProcessRuntime _runtime;

    public ViewerExternalProcessService(IViewerExternalProcessRuntime? runtime = null)
    {
        _runtime = runtime ?? new SystemViewerExternalProcessRuntime();
    }

    public ViewerExternalProcessResult OpenShellTarget(string targetPath) =>
        StartDetached(
            new ViewerExternalProcessStartRequest(
                targetPath,
                [],
                RawArguments: null,
                WorkingDirectory: null,
                UseShellExecute: true,
                CreateNoWindow: false,
                RedirectStandardOutput: false,
                RedirectStandardError: false),
            requireExecutable: false,
            operationName: "shell target");

    public ViewerExternalProcessResult OpenWireshark(string executablePath, string capturePath) =>
        StartDetached(
            new ViewerExternalProcessStartRequest(
                executablePath,
                [capturePath],
                RawArguments: null,
                WorkingDirectory: null,
                UseShellExecute: false,
                CreateNoWindow: false,
                RedirectStandardOutput: false,
                RedirectStandardError: false),
            requireExecutable: true,
            operationName: "Wireshark");

    public Task<ViewerExternalProcessResult> ExportTsharkFlowAsync(
        string executablePath,
        string capturePath,
        string displayFilter,
        string outputPath,
        TimeSpan timeout,
        CancellationToken cancellationToken = default) =>
        RunAsync(
            new ViewerExternalProcessStartRequest(
                executablePath,
                ["-r", capturePath, "-Y", displayFilter, "-w", outputPath],
                RawArguments: null,
                WorkingDirectory: null,
                UseShellExecute: false,
                CreateNoWindow: true,
                RedirectStandardOutput: true,
                RedirectStandardError: true),
            operationName: "TShark",
            timeout,
            expectedOutputPath: outputPath,
            requireNonEmptyOutput: true,
            cancellationToken);

    private ViewerExternalProcessResult StartDetached(
        ViewerExternalProcessStartRequest request,
        bool requireExecutable,
        string operationName)
    {
        if (requireExecutable)
        {
            var validationFailure = ValidateExecutable(request.FileName, operationName);
            if (validationFailure != null)
            {
                return validationFailure;
            }
        }

        try
        {
            using var process = _runtime.Start(request);
            return process == null
                ? Result(
                    ViewerExternalProcessOutcome.StartFailed,
                    detail: $"The {operationName} process could not be started.")
                : Result(
                    ViewerExternalProcessOutcome.Started,
                    detail: $"The {operationName} process was started.");
        }
        catch (Exception ex)
        {
            return Result(
                ViewerExternalProcessOutcome.StartFailed,
                detail: $"The {operationName} process could not be started: {ex.Message}");
        }
    }

    private async Task<ViewerExternalProcessResult> RunAsync(
        ViewerExternalProcessStartRequest request,
        string operationName,
        TimeSpan? timeout,
        string expectedOutputPath,
        bool requireNonEmptyOutput,
        CancellationToken cancellationToken)
    {
        var validationFailure = ValidateExecutable(request.FileName, operationName);
        if (validationFailure != null)
        {
            return validationFailure;
        }

        IViewerExternalProcessHandle? startedProcess;
        try
        {
            startedProcess = _runtime.Start(request);
        }
        catch (Exception ex)
        {
            return Result(
                ViewerExternalProcessOutcome.StartFailed,
                detail: $"The {operationName} process could not be started: {ex.Message}");
        }

        if (startedProcess == null)
        {
            return Result(
                ViewerExternalProcessOutcome.StartFailed,
                detail: $"The {operationName} process could not be started.");
        }

        using var process = startedProcess;
        try
        {
            var stdoutTask = request.RedirectStandardOutput
                ? process.ReadStandardOutputToEndAsync()
                : Task.FromResult(string.Empty);
            var stderrTask = request.RedirectStandardError
                ? process.ReadStandardErrorToEndAsync()
                : Task.FromResult(string.Empty);

            using var timeoutCancellation = timeout.HasValue
                ? new CancellationTokenSource(timeout.Value)
                : null;
            using var linkedCancellation = timeoutCancellation == null
                ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken)
                : CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken,
                    timeoutCancellation.Token);

            try
            {
                await process.WaitForExitAsync(linkedCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                TryKillProcess(process);
                if (cancellationToken.IsCancellationRequested)
                {
                    const string canceledDetail = "The external process operation was canceled.";
                    return Result(
                        ViewerExternalProcessOutcome.Canceled,
                        standardError: canceledDetail,
                        detail: canceledDetail);
                }

                var timeoutDetail = $"Timed out after {timeout!.Value.TotalSeconds:F0} second(s).";
                return Result(
                    ViewerExternalProcessOutcome.TimedOut,
                    standardError: timeoutDetail,
                    detail: timeoutDetail);
            }

            var standardOutput = NormalizeProcessOutput(await stdoutTask.ConfigureAwait(false));
            var standardError = NormalizeProcessOutput(await stderrTask.ConfigureAwait(false));
            var exitCode = process.ExitCode;
            if (exitCode != 0)
            {
                return Result(
                    ViewerExternalProcessOutcome.NonZeroExit,
                    exitCode,
                    standardOutput,
                    standardError,
                    $"The {operationName} process exited with code {exitCode}.");
            }

            if (!HasExpectedOutput(expectedOutputPath, requireNonEmptyOutput))
            {
                return Result(
                    ViewerExternalProcessOutcome.MissingExpectedOutput,
                    exitCode,
                    standardOutput,
                    standardError,
                    $"The {operationName} process did not create the expected output: {expectedOutputPath}");
            }

            return Result(
                ViewerExternalProcessOutcome.Completed,
                exitCode,
                standardOutput,
                standardError,
                $"The {operationName} process completed successfully.");
        }
        catch (Exception ex)
        {
            return Result(
                ViewerExternalProcessOutcome.ExecutionFailed,
                detail: $"The {operationName} process failed: {ex.Message}");
        }
    }

    private ViewerExternalProcessResult? ValidateExecutable(string path, string operationName)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return Result(
                ViewerExternalProcessOutcome.MissingExecutable,
                detail: $"The {operationName} executable path is empty.");
        }

        try
        {
            return _runtime.FileExists(path)
                ? null
                : Result(
                    ViewerExternalProcessOutcome.MissingExecutable,
                    detail: $"The {operationName} executable was not found: {path}");
        }
        catch (Exception ex)
        {
            return Result(
                ViewerExternalProcessOutcome.ExecutionFailed,
                detail: $"The {operationName} executable could not be checked: {ex.Message}");
        }
    }

    private bool HasExpectedOutput(string path, bool requireNonEmptyOutput)
    {
        if (!_runtime.FileExists(path))
        {
            return false;
        }

        return !requireNonEmptyOutput || _runtime.GetFileLength(path) > 0;
    }

    private static string NormalizeProcessOutput(string value) =>
        string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Replace("\0", string.Empty, StringComparison.Ordinal).Trim();

    private static void TryKillProcess(IViewerExternalProcessHandle process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best-effort cleanup after cancellation or timeout.
        }
    }

    private static ViewerExternalProcessResult Result(
        ViewerExternalProcessOutcome outcome,
        int? exitCode = null,
        string standardOutput = "",
        string standardError = "",
        string detail = "") =>
        new(outcome, exitCode, standardOutput, standardError, detail);

    private sealed class SystemViewerExternalProcessRuntime : IViewerExternalProcessRuntime
    {
        public bool FileExists(string path) => File.Exists(path);

        public long GetFileLength(string path) => new FileInfo(path).Length;

        public IViewerExternalProcessHandle? Start(ViewerExternalProcessStartRequest request)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = request.FileName,
                UseShellExecute = request.UseShellExecute,
                CreateNoWindow = request.CreateNoWindow,
                RedirectStandardOutput = request.RedirectStandardOutput,
                RedirectStandardError = request.RedirectStandardError
            };
            if (!string.IsNullOrWhiteSpace(request.WorkingDirectory))
            {
                startInfo.WorkingDirectory = request.WorkingDirectory;
            }

            if (request.RawArguments != null)
            {
                startInfo.Arguments = request.RawArguments;
            }
            else
            {
                foreach (var argument in request.ArgumentList)
                {
                    startInfo.ArgumentList.Add(argument);
                }
            }

            var process = Process.Start(startInfo);
            return process == null ? null : new SystemViewerExternalProcessHandle(process);
        }
    }

    private sealed class SystemViewerExternalProcessHandle : IViewerExternalProcessHandle
    {
        private readonly Process _process;

        public SystemViewerExternalProcessHandle(Process process)
        {
            _process = process;
        }

        public bool HasExited => _process.HasExited;

        public int ExitCode => _process.ExitCode;

        public Task<string> ReadStandardOutputToEndAsync() =>
            _process.StandardOutput.ReadToEndAsync();

        public Task<string> ReadStandardErrorToEndAsync() =>
            _process.StandardError.ReadToEndAsync();

        public Task WaitForExitAsync(CancellationToken cancellationToken) =>
            _process.WaitForExitAsync(cancellationToken);

        public void Kill(bool entireProcessTree) =>
            _process.Kill(entireProcessTree);

        public void Dispose() => _process.Dispose();
    }
}
