using System.Diagnostics;
using System.Text;
using ProcInsider.Compatibility;
using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal enum AgentMemoryAcquisitionOutcome
{
    Completed,
    StartFailed,
    NonZeroExit,
    TimedOut,
    Canceled,
    MissingOutput,
    EmptyOutput,
    CleanupFailed,
    ExecutionFailed
}

internal sealed record AgentMemoryAcquisitionPlan
{
    public string ExecutablePath { get; init; } = string.Empty;

    public string Arguments { get; init; } = string.Empty;

    public string WorkingDirectory { get; init; } = string.Empty;

    public string OutputPath { get; init; } = string.Empty;

    public string ToolName { get; init; } = string.Empty;

    public string ToolVersion { get; init; } = string.Empty;

    public string ConfigurationDiagnostic { get; init; } = string.Empty;

    public int TimeoutSeconds { get; init; }
}

internal sealed record AgentMemoryAcquisitionPreflightResult(
    bool Success,
    string ErrorCode,
    string Detail,
    AgentMemoryAcquisitionPlan? Plan)
{
    public static AgentMemoryAcquisitionPreflightResult Accepted(AgentMemoryAcquisitionPlan plan) =>
        new(true, string.Empty, "Memory acquisition prerequisites are satisfied.", plan);

    public static AgentMemoryAcquisitionPreflightResult Rejected(string errorCode, string detail) =>
        new(false, errorCode, detail, null);
}

internal sealed record AgentMemoryAcquisitionResult
{
    public AgentMemoryAcquisitionOutcome Outcome { get; init; }

    public AgentMemoryAcquisitionPlan Plan { get; init; } = new();

    public DateTime StartedAtUtc { get; init; }

    public DateTime CompletedAtUtc { get; init; }

    public int? ExitCode { get; init; }

    public string StandardOutput { get; init; } = string.Empty;

    public string StandardError { get; init; } = string.Empty;

    public string Detail { get; init; } = string.Empty;

    public string CleanupDisposition { get; init; } = string.Empty;

    public string QuarantinedPath { get; init; } = string.Empty;

    public bool Succeeded => Outcome == AgentMemoryAcquisitionOutcome.Completed;
}

internal sealed record AgentMemoryAcquisitionProcessStartRequest(
    string FileName,
    string Arguments,
    string WorkingDirectory);

internal interface IAgentMemoryAcquisitionRuntime
{
    string? GetEnvironmentVariable(string name);

    string ExpandEnvironmentVariables(string value);

    bool DirectoryExists(string path);

    void CreateDirectory(string path);

    bool FileExists(string path);

    long GetFileLength(string path);

    void DeleteFile(string path);

    void MoveFile(string sourcePath, string destinationPath);

    string GetFileVersion(string path);

    IAgentMemoryAcquisitionProcessHandle? Start(AgentMemoryAcquisitionProcessStartRequest request);
}

internal interface IAgentMemoryAcquisitionProcessHandle : IDisposable
{
    int ExitCode { get; }

    Task<string> ReadStandardOutputAsync(int maxCharacters);

    Task<string> ReadStandardErrorAsync(int maxCharacters);

    Task WaitForExitAsync(CancellationToken cancellationToken);

    void Kill(bool entireProcessTree);
}

internal sealed class AgentMemoryAcquisitionService
{
    internal const int DefaultTimeoutSeconds = AgentMemoryActionPolicy.DefaultAcquisitionTimeoutSeconds;
    internal const int MaximumTimeoutSeconds = AgentMemoryActionPolicy.MaximumAcquisitionTimeoutSeconds;
    internal const int MaximumArgumentsLength = 8192;
    internal const int MaximumTranscriptCharacters = 32768;

    private readonly InvestigationSessionPaths _sessionPaths;
    private readonly IAgentMemoryAcquisitionRuntime _runtime;

    public AgentMemoryAcquisitionService(
        InvestigationSessionPaths sessionPaths,
        IAgentMemoryAcquisitionRuntime? runtime = null)
    {
        _sessionPaths = sessionPaths ?? throw new ArgumentNullException(nameof(sessionPaths));
        _runtime = runtime ?? new SystemAgentMemoryAcquisitionRuntime();
    }

    public AgentMemoryAcquisitionPreflightResult CreatePlan(
        Guid jobId,
        string requestedOutputFileName,
        int timeoutSeconds)
    {
        if (jobId == Guid.Empty)
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "InvalidMemoryAcquisitionJob",
                "Memory acquisition requires a non-empty job identity.");
        }

        if (!AgentMemoryActionPolicy.IsValidAcquisitionTimeout(timeoutSeconds))
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "InvalidMemoryAcquisitionTimeout",
                $"Memory acquisition timeout must be between 1 and {MaximumTimeoutSeconds} seconds.");
        }

        string sessionRoot;
        string memoryRoot;
        try
        {
            sessionRoot = Path.GetFullPath(_sessionPaths.SessionRoot);
            memoryRoot = Path.GetFullPath(_sessionPaths.MemoryDirectory);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "InvalidMemoryAcquisitionDestination",
                $"The active session memory path is invalid: {ex.Message}");
        }

        if (!IsContainedPath(sessionRoot, memoryRoot, allowEqual: false))
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "InvalidMemoryAcquisitionDestination",
                "The active memory directory is not contained by the agent's active session root.");
        }

        if (!_runtime.DirectoryExists(sessionRoot))
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "MemoryAcquisitionDestinationUnavailable",
                "The active SessionPathService session root is unavailable; acquisition was not queued.");
        }

        string outputFileName;
        string outputPath;
        try
        {
            outputFileName = string.IsNullOrWhiteSpace(requestedOutputFileName)
                ? $"system-memory-{DateTime.UtcNow:yyyyMMdd-HHmmssfff}-{jobId:N}.raw"
                : requestedOutputFileName.Trim();
            if (!AgentMemoryActionPolicy.TryNormalizeOptionalOutputFileName(
                    outputFileName,
                    out outputFileName) ||
                outputFileName.Length == 0)
            {
                return AgentMemoryAcquisitionPreflightResult.Rejected(
                    "InvalidMemoryAcquisitionDestination",
                    "The requested acquisition output must be one supported leaf file name without a directory.");
            }

            outputPath = Path.GetFullPath(Path.Combine(memoryRoot, outputFileName));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "InvalidMemoryAcquisitionDestination",
                $"The requested acquisition output is invalid: {ex.Message}");
        }

        if (!IsContainedPath(memoryRoot, outputPath, allowEqual: false))
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "InvalidMemoryAcquisitionDestination",
                "The requested acquisition output escapes the active session memory directory.");
        }

        if (_runtime.FileExists(outputPath))
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "MemoryAcquisitionOutputCollision",
                $"The requested memory image already exists and will not be replaced: {outputPath}");
        }

        var toolResolution = EnvironmentVariableCompatibility.Resolve(
            DfiroscopeEnvironmentVariables.MemoryAcquisitionTool,
            DfiroscopeEnvironmentVariables.LegacyMemoryAcquisitionTool,
            _runtime.GetEnvironmentVariable);
        if (!toolResolution.HasValue)
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "MemoryAcquisitionToolNotConfigured",
                $"Configure a trusted acquisition executable with {DfiroscopeEnvironmentVariables.MemoryAcquisitionTool}. " +
                $"{toolResolution.Diagnostic} No process or output was created.");
        }

        var expandedToolPath = _runtime.ExpandEnvironmentVariables(toolResolution.Value).Trim();
        if (!Path.IsPathFullyQualified(expandedToolPath))
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "MemoryAcquisitionToolNotTrusted",
                $"The configured acquisition tool must use a fully qualified path: {toolResolution.SourceName}.");
        }

        string executablePath;
        try
        {
            executablePath = Path.GetFullPath(expandedToolPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "MemoryAcquisitionToolNotTrusted",
                $"The configured acquisition tool path is invalid: {ex.Message}");
        }

        if (!_runtime.FileExists(executablePath))
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "MemoryAcquisitionToolMissing",
                $"The explicitly configured acquisition tool was not found: {executablePath}");
        }

        var argumentsResolution = EnvironmentVariableCompatibility.Resolve(
            DfiroscopeEnvironmentVariables.MemoryAcquisitionArguments,
            DfiroscopeEnvironmentVariables.LegacyMemoryAcquisitionArguments,
            _runtime.GetEnvironmentVariable);
        var argumentsTemplate = argumentsResolution.Value;
        if (!string.IsNullOrWhiteSpace(argumentsTemplate) &&
            !argumentsTemplate.Contains("{output}", StringComparison.OrdinalIgnoreCase) &&
            !argumentsTemplate.Contains("{outputPath}", StringComparison.OrdinalIgnoreCase))
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "MemoryAcquisitionArgumentsMissingOutput",
                $"Configured {argumentsResolution.SourceName} must contain an {{output}} or {{outputPath}} token.");
        }

        var quotedOutputPath = QuoteArgument(outputPath);
        var arguments = string.IsNullOrWhiteSpace(argumentsTemplate)
            ? quotedOutputPath
            : argumentsTemplate
                .Replace("{outputPath}", quotedOutputPath, StringComparison.OrdinalIgnoreCase)
                .Replace("{output}", quotedOutputPath, StringComparison.OrdinalIgnoreCase);
        if (arguments.Length > MaximumArgumentsLength)
        {
            return AgentMemoryAcquisitionPreflightResult.Rejected(
                "MemoryAcquisitionArgumentsTooLong",
                $"Configured memory acquisition arguments exceed {MaximumArgumentsLength} characters.");
        }

        string toolVersion;
        try
        {
            toolVersion = _runtime.GetFileVersion(executablePath);
        }
        catch
        {
            toolVersion = string.Empty;
        }

        return AgentMemoryAcquisitionPreflightResult.Accepted(
            new AgentMemoryAcquisitionPlan
            {
                ExecutablePath = executablePath,
                Arguments = arguments,
                WorkingDirectory = memoryRoot,
                OutputPath = outputPath,
                ToolName = Path.GetFileName(executablePath),
                ToolVersion = toolVersion,
                ConfigurationDiagnostic =
                    $"{toolResolution.Diagnostic} {argumentsResolution.Diagnostic}".Trim(),
                TimeoutSeconds = timeoutSeconds
            });
    }

    public async Task<AgentMemoryAcquisitionResult> ExecuteAsync(
        AgentMemoryAcquisitionPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var startedAtUtc = DateTime.UtcNow;
        var validation = ValidateAcceptedPlan(plan);
        if (validation != null)
        {
            return Failure(
                AgentMemoryAcquisitionOutcome.ExecutionFailed,
                plan,
                startedAtUtc,
                detail: validation);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return Failure(
                AgentMemoryAcquisitionOutcome.Canceled,
                plan,
                startedAtUtc,
                detail: "Memory acquisition was canceled before its output directory was materialized.");
        }

        try
        {
            _runtime.CreateDirectory(plan.WorkingDirectory);
        }
        catch (Exception ex)
        {
            return Failure(
                AgentMemoryAcquisitionOutcome.ExecutionFailed,
                plan,
                startedAtUtc,
                detail: $"The memory acquisition output directory could not be materialized: {ex.Message}");
        }

        if (!_runtime.DirectoryExists(plan.WorkingDirectory))
        {
            return Failure(
                AgentMemoryAcquisitionOutcome.ExecutionFailed,
                plan,
                startedAtUtc,
                detail: "The memory acquisition output directory could not be materialized.");
        }

        IAgentMemoryAcquisitionProcessHandle? process;
        try
        {
            process = _runtime.Start(
                new AgentMemoryAcquisitionProcessStartRequest(
                    plan.ExecutablePath,
                    plan.Arguments,
                    plan.WorkingDirectory));
        }
        catch (Exception ex)
        {
            return await FailureWithCleanupAsync(
                AgentMemoryAcquisitionOutcome.StartFailed,
                plan,
                startedAtUtc,
                detail: $"The memory acquisition process could not be started: {ex.Message}").ConfigureAwait(false);
        }

        if (process == null)
        {
            return await FailureWithCleanupAsync(
                AgentMemoryAcquisitionOutcome.StartFailed,
                plan,
                startedAtUtc,
                detail: "The memory acquisition process could not be started.").ConfigureAwait(false);
        }

        using (process)
        {
            var stdoutTask = process.ReadStandardOutputAsync(MaximumTranscriptCharacters);
            var stderrTask = process.ReadStandardErrorAsync(MaximumTranscriptCharacters);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(plan.TimeoutSeconds));
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await TryKillAndWaitAsync(process).ConfigureAwait(false);
                var diagnostics = await ReadDiagnosticsAsync(stdoutTask, stderrTask).ConfigureAwait(false);
                var canceled = cancellationToken.IsCancellationRequested;
                return await FailureWithCleanupAsync(
                    canceled
                        ? AgentMemoryAcquisitionOutcome.Canceled
                        : AgentMemoryAcquisitionOutcome.TimedOut,
                    plan,
                    startedAtUtc,
                    standardOutput: diagnostics.StandardOutput,
                    standardError: diagnostics.StandardError,
                    detail: canceled
                        ? "Memory acquisition was canceled and the process tree was terminated."
                        : $"Memory acquisition exceeded {plan.TimeoutSeconds} seconds and the process tree was terminated.")
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await TryKillAndWaitAsync(process).ConfigureAwait(false);
                var diagnostics = await ReadDiagnosticsAsync(stdoutTask, stderrTask).ConfigureAwait(false);
                return await FailureWithCleanupAsync(
                    AgentMemoryAcquisitionOutcome.ExecutionFailed,
                    plan,
                    startedAtUtc,
                    standardOutput: diagnostics.StandardOutput,
                    standardError: diagnostics.StandardError,
                    detail: $"Memory acquisition execution failed: {ex.Message}").ConfigureAwait(false);
            }

            var processDiagnostics = await ReadDiagnosticsAsync(stdoutTask, stderrTask).ConfigureAwait(false);
            int exitCode;
            try
            {
                exitCode = process.ExitCode;
            }
            catch (Exception ex)
            {
                return await FailureWithCleanupAsync(
                    AgentMemoryAcquisitionOutcome.ExecutionFailed,
                    plan,
                    startedAtUtc,
                    standardOutput: processDiagnostics.StandardOutput,
                    standardError: processDiagnostics.StandardError,
                    detail: $"Memory acquisition exit status could not be read: {ex.Message}").ConfigureAwait(false);
            }

            if (exitCode != 0)
            {
                return await FailureWithCleanupAsync(
                    AgentMemoryAcquisitionOutcome.NonZeroExit,
                    plan,
                    startedAtUtc,
                    exitCode,
                    processDiagnostics.StandardOutput,
                    processDiagnostics.StandardError,
                    $"Memory acquisition exited with code {exitCode}.").ConfigureAwait(false);
            }

            long outputLength;
            try
            {
                if (!_runtime.FileExists(plan.OutputPath))
                {
                    return await FailureWithCleanupAsync(
                        AgentMemoryAcquisitionOutcome.MissingOutput,
                        plan,
                        startedAtUtc,
                        exitCode,
                        processDiagnostics.StandardOutput,
                        processDiagnostics.StandardError,
                        "Memory acquisition exited successfully without creating the expected image.").ConfigureAwait(false);
                }

                outputLength = _runtime.GetFileLength(plan.OutputPath);
            }
            catch (Exception ex)
            {
                return await FailureWithCleanupAsync(
                    AgentMemoryAcquisitionOutcome.ExecutionFailed,
                    plan,
                    startedAtUtc,
                    exitCode,
                    processDiagnostics.StandardOutput,
                    processDiagnostics.StandardError,
                    $"Memory acquisition output could not be verified: {ex.Message}").ConfigureAwait(false);
            }

            if (outputLength <= 0)
            {
                return await FailureWithCleanupAsync(
                    AgentMemoryAcquisitionOutcome.EmptyOutput,
                    plan,
                    startedAtUtc,
                    exitCode,
                    processDiagnostics.StandardOutput,
                    processDiagnostics.StandardError,
                    "Memory acquisition created an empty image.").ConfigureAwait(false);
            }

            return new AgentMemoryAcquisitionResult
            {
                Outcome = AgentMemoryAcquisitionOutcome.Completed,
                Plan = plan,
                StartedAtUtc = startedAtUtc,
                CompletedAtUtc = DateTime.UtcNow,
                ExitCode = exitCode,
                StandardOutput = processDiagnostics.StandardOutput,
                StandardError = processDiagnostics.StandardError,
                Detail = $"Memory acquisition completed: {plan.OutputPath}",
                CleanupDisposition = "Retained verified output"
            };
        }
    }

    private string? ValidateAcceptedPlan(AgentMemoryAcquisitionPlan plan)
    {
        var sessionRoot = Path.GetFullPath(_sessionPaths.SessionRoot);
        var memoryRoot = Path.GetFullPath(_sessionPaths.MemoryDirectory);
        if (!_runtime.DirectoryExists(sessionRoot) ||
            !IsContainedPath(sessionRoot, memoryRoot, allowEqual: false))
        {
            return "The accepted memory acquisition destination no longer belongs to an available active session.";
        }

        if (!IsContainedPath(memoryRoot, Path.GetFullPath(plan.OutputPath), allowEqual: false))
        {
            return "The accepted memory acquisition destination no longer belongs to the active session.";
        }

        if (!string.Equals(memoryRoot, Path.GetFullPath(plan.WorkingDirectory), StringComparison.OrdinalIgnoreCase))
        {
            return "The accepted memory acquisition working directory no longer matches the active session.";
        }

        if (!_runtime.FileExists(plan.ExecutablePath))
        {
            return "The configured memory acquisition tool is no longer available.";
        }

        if (_runtime.FileExists(plan.OutputPath))
        {
            return "The accepted memory acquisition output now exists and will not be replaced.";
        }

        return null;
    }

    private async Task<AgentMemoryAcquisitionResult> FailureWithCleanupAsync(
        AgentMemoryAcquisitionOutcome outcome,
        AgentMemoryAcquisitionPlan plan,
        DateTime startedAtUtc,
        int? exitCode = null,
        string standardOutput = "",
        string standardError = "",
        string detail = "")
    {
        var cleanup = CleanupPartialOutput(plan.OutputPath);
        if (!cleanup.Succeeded)
        {
            outcome = AgentMemoryAcquisitionOutcome.CleanupFailed;
        }

        await Task.CompletedTask.ConfigureAwait(false);
        return Failure(
            outcome,
            plan,
            startedAtUtc,
            exitCode,
            standardOutput,
            standardError,
            string.IsNullOrWhiteSpace(cleanup.Detail)
                ? detail
                : $"{detail} {cleanup.Detail}".Trim(),
            cleanup.Disposition,
            cleanup.QuarantinedPath);
    }

    private AgentMemoryAcquisitionCleanupResult CleanupPartialOutput(string outputPath)
    {
        if (!_runtime.FileExists(outputPath))
        {
            return new AgentMemoryAcquisitionCleanupResult(true, "No partial output existed", string.Empty, string.Empty);
        }

        try
        {
            _runtime.DeleteFile(outputPath);
            return new AgentMemoryAcquisitionCleanupResult(true, "Deleted partial output", string.Empty, string.Empty);
        }
        catch (Exception deleteError)
        {
            var quarantinePath = $"{outputPath}.partial-{Guid.NewGuid():N}";
            try
            {
                _runtime.MoveFile(outputPath, quarantinePath);
                return new AgentMemoryAcquisitionCleanupResult(
                    true,
                    "Quarantined partial output",
                    $"Partial memory output could not be deleted and was quarantined: {quarantinePath}. Delete error: {deleteError.Message}",
                    quarantinePath);
            }
            catch (Exception quarantineError)
            {
                return new AgentMemoryAcquisitionCleanupResult(
                    false,
                    "Cleanup failed",
                    $"Partial memory output cleanup failed at '{outputPath}'. Delete: {deleteError.Message}; quarantine: {quarantineError.Message}",
                    string.Empty);
            }
        }
    }

    private static AgentMemoryAcquisitionResult Failure(
        AgentMemoryAcquisitionOutcome outcome,
        AgentMemoryAcquisitionPlan plan,
        DateTime startedAtUtc,
        int? exitCode = null,
        string standardOutput = "",
        string standardError = "",
        string detail = "",
        string cleanupDisposition = "",
        string quarantinedPath = "") =>
        new()
        {
            Outcome = outcome,
            Plan = plan,
            StartedAtUtc = startedAtUtc,
            CompletedAtUtc = DateTime.UtcNow,
            ExitCode = exitCode,
            StandardOutput = standardOutput,
            StandardError = standardError,
            Detail = detail,
            CleanupDisposition = cleanupDisposition,
            QuarantinedPath = quarantinedPath
        };

    private static async Task<(string StandardOutput, string StandardError)> ReadDiagnosticsAsync(
        Task<string> stdoutTask,
        Task<string> stderrTask)
    {
        try
        {
            await Task.WhenAll(stdoutTask, stderrTask)
                .WaitAsync(TimeSpan.FromSeconds(2))
                .ConfigureAwait(false);
        }
        catch
        {
            // Diagnostics are best-effort after a tool/process failure and remain bounded.
        }

        return (
            stdoutTask.IsCompletedSuccessfully ? stdoutTask.Result : string.Empty,
            stderrTask.IsCompletedSuccessfully ? stderrTask.Result : string.Empty);
    }

    private static bool IsContainedPath(string root, string candidate, bool allowEqual)
    {
        var normalizedRoot = Path.GetFullPath(root)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedCandidate = Path.GetFullPath(candidate)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.Equals(normalizedRoot, normalizedCandidate, StringComparison.OrdinalIgnoreCase))
        {
            return allowEqual;
        }

        return normalizedCandidate.StartsWith(
            normalizedRoot + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string QuoteArgument(string value) =>
        $"\"{value.Replace("\"", "\\\"", StringComparison.Ordinal)}\"";

    private static async Task TryKillAndWaitAsync(IAgentMemoryAcquisitionProcessHandle process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch
        {
            // Termination is best-effort; the bounded wait and cleanup still run.
        }

        try
        {
            await process.WaitForExitAsync(CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(2))
                .ConfigureAwait(false);
        }
        catch
        {
            // A tool that does not exit after forced termination is surfaced through cleanup disposition.
        }
    }

    private sealed record AgentMemoryAcquisitionCleanupResult(
        bool Succeeded,
        string Disposition,
        string Detail,
        string QuarantinedPath);

    private sealed class SystemAgentMemoryAcquisitionRuntime : IAgentMemoryAcquisitionRuntime
    {
        public string? GetEnvironmentVariable(string name) => Environment.GetEnvironmentVariable(name);

        public string ExpandEnvironmentVariables(string value) => Environment.ExpandEnvironmentVariables(value);

        public bool DirectoryExists(string path) => Directory.Exists(path);

        public void CreateDirectory(string path) => Directory.CreateDirectory(path);

        public bool FileExists(string path) => File.Exists(path);

        public long GetFileLength(string path) => new FileInfo(path).Length;

        public void DeleteFile(string path) => File.Delete(path);

        public void MoveFile(string sourcePath, string destinationPath) =>
            File.Move(sourcePath, destinationPath, overwrite: false);

        public string GetFileVersion(string path) =>
            FileVersionInfo.GetVersionInfo(path).FileVersion ?? string.Empty;

        public IAgentMemoryAcquisitionProcessHandle? Start(AgentMemoryAcquisitionProcessStartRequest request)
        {
            var process = Process.Start(
                new ProcessStartInfo
                {
                    FileName = request.FileName,
                    Arguments = request.Arguments,
                    WorkingDirectory = request.WorkingDirectory,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                });
            return process == null ? null : new SystemAgentMemoryAcquisitionProcessHandle(process);
        }
    }

    private sealed class SystemAgentMemoryAcquisitionProcessHandle : IAgentMemoryAcquisitionProcessHandle
    {
        private readonly Process _process;

        public SystemAgentMemoryAcquisitionProcessHandle(Process process)
        {
            _process = process;
        }

        public int ExitCode => _process.ExitCode;

        public Task<string> ReadStandardOutputAsync(int maxCharacters) =>
            ReadBoundedAsync(_process.StandardOutput, maxCharacters);

        public Task<string> ReadStandardErrorAsync(int maxCharacters) =>
            ReadBoundedAsync(_process.StandardError, maxCharacters);

        public Task WaitForExitAsync(CancellationToken cancellationToken) =>
            _process.WaitForExitAsync(cancellationToken);

        public void Kill(bool entireProcessTree) => _process.Kill(entireProcessTree);

        public void Dispose() => _process.Dispose();

        private static async Task<string> ReadBoundedAsync(StreamReader reader, int maxCharacters)
        {
            var buffer = new char[4096];
            var retained = new StringBuilder(Math.Min(maxCharacters, buffer.Length));
            while (true)
            {
                var read = await reader.ReadAsync(buffer.AsMemory(), CancellationToken.None).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                var remaining = maxCharacters - retained.Length;
                if (remaining > 0)
                {
                    retained.Append(buffer, 0, Math.Min(read, remaining));
                }
            }

            return retained.ToString().Replace("\0", string.Empty, StringComparison.Ordinal).Trim();
        }
    }
}
