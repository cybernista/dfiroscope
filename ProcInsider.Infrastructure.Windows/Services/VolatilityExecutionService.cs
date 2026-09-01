using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class VolatilityExecutionService
{
    public static readonly IReadOnlyList<string> DefaultPlugins =
    [
        "windows.pslist",
        "windows.psscan",
        "windows.pstree",
        "windows.cmdline"
    ];

    private readonly InvestigationSessionPaths? _sessionPaths;
    private readonly VolatilityOutputParser _parser;

    public VolatilityExecutionService(
        InvestigationSessionPaths? sessionPaths = null,
        VolatilityOutputParser? parser = null)
    {
        _sessionPaths = sessionPaths;
        _parser = parser ?? new VolatilityOutputParser();
    }

    public async Task<IReadOnlyList<VolatilityExecutionResult>> RunPluginsAsync(
        MemoryImageRecord image,
        Guid jobId,
        IReadOnlyList<string> plugins,
        string outputDirectory,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(image);
        var normalizedPlugins = plugins
            .Where(plugin => !string.IsNullOrWhiteSpace(plugin))
            .Select(plugin => plugin.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .DefaultIfEmpty("windows.pslist")
            .ToList();

        var resolvedOutputDirectory = ResolveOutputDirectory(image, outputDirectory, jobId);
        Directory.CreateDirectory(resolvedOutputDirectory);

        var runner = await TryResolveRunnerAsync(cancellationToken).ConfigureAwait(false);
        if (runner == null)
        {
            return normalizedPlugins
                .Select(plugin => CreatePrerequisiteFailure(image, jobId, plugin, resolvedOutputDirectory))
                .ToList();
        }

        var results = new List<VolatilityExecutionResult>();
        foreach (var plugin in normalizedPlugins)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await RunPluginAsync(
                runner,
                image,
                jobId,
                plugin,
                resolvedOutputDirectory,
                timeout,
                cancellationToken).ConfigureAwait(false));
        }

        return results;
    }

    private async Task<VolatilityExecutionResult> RunPluginAsync(
        IVolatilityRunner runner,
        MemoryImageRecord image,
        Guid jobId,
        string plugin,
        string outputDirectory,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var runId = CreateRunId(image.ImageId, jobId, plugin);
        var safePlugin = SanitizePathPart(plugin.Replace('.', '_'));
        var stdoutPath = Path.Combine(outputDirectory, $"{safePlugin}-{runId}-stdout.json");
        var stderrPath = Path.Combine(outputDirectory, $"{safePlugin}-{runId}-stderr.txt");
        var startedUtc = DateTime.UtcNow;
        var arguments = runner.BuildArguments(image.FilePath, plugin);
        var commandLine = BuildCommandLine(runner.DisplayName, arguments);

        try
        {
            var processResult = await RunProcessAsync(
                runner.FileName,
                arguments,
                outputDirectory,
                timeout,
                cancellationToken).ConfigureAwait(false);

            await File.WriteAllTextAsync(stdoutPath, processResult.StandardOutput, cancellationToken).ConfigureAwait(false);
            await File.WriteAllTextAsync(stderrPath, processResult.StandardError, cancellationToken).ConfigureAwait(false);
            var rawHash = Sha256(processResult.StandardOutput);
            var rows = processResult.ExitCode == 0
                ? _parser.ParseProcessPlugin(image.ImageId, runId, plugin, processResult.StandardOutput)
                : Array.Empty<MemoryProcessRecord>();
            var status = processResult.ExitCode == 0
                ? VolatilityPluginRunStatus.Completed
                : VolatilityPluginRunStatus.Failed;
            var error = processResult.ExitCode == 0
                ? string.Empty
                : $"Volatility exited with code {processResult.ExitCode}: {processResult.StandardError.Trim()}";

            return new VolatilityExecutionResult(
                CreateRunRecord(
                    image,
                    jobId,
                    runId,
                    plugin,
                    status,
                    startedUtc,
                    DateTime.UtcNow,
                    runner.DisplayName,
                    runner.Version,
                    commandLine,
                    outputDirectory,
                    stdoutPath,
                    stderrPath,
                    rawHash,
                    rows.Count,
                    error),
                rows);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            await File.WriteAllTextAsync(stderrPath, ex.Message, CancellationToken.None).ConfigureAwait(false);
            return new VolatilityExecutionResult(
                CreateRunRecord(
                    image,
                    jobId,
                    runId,
                    plugin,
                    VolatilityPluginRunStatus.Failed,
                    startedUtc,
                    DateTime.UtcNow,
                    runner.DisplayName,
                    runner.Version,
                    commandLine,
                    outputDirectory,
                    stdoutPath,
                    stderrPath,
                    string.Empty,
                    0,
                    ex.Message),
                Array.Empty<MemoryProcessRecord>());
        }
    }

    private VolatilityExecutionResult CreatePrerequisiteFailure(
        MemoryImageRecord image,
        Guid jobId,
        string plugin,
        string outputDirectory)
    {
        var runId = CreateRunId(image.ImageId, jobId, plugin);
        var safePlugin = SanitizePathPart(plugin.Replace('.', '_'));
        var stderrPath = Path.Combine(outputDirectory, $"{safePlugin}-{runId}-stderr.txt");
        var error = $"Volatility 3 was not found. Configure vol.exe/volatility3.exe/vol.py on PATH or install a local Python volatility3 module; {ProductIdentity.DisplayName} does not install it automatically.";
        Directory.CreateDirectory(outputDirectory);
        File.WriteAllText(stderrPath, error);
        return new VolatilityExecutionResult(
            CreateRunRecord(
                image,
                jobId,
                runId,
                plugin,
                VolatilityPluginRunStatus.Failed,
                DateTime.UtcNow,
                DateTime.UtcNow,
                string.Empty,
                string.Empty,
                string.Empty,
                outputDirectory,
                string.Empty,
                stderrPath,
                string.Empty,
                0,
                error),
            Array.Empty<MemoryProcessRecord>());
    }

    private async Task<IVolatilityRunner?> TryResolveRunnerAsync(CancellationToken cancellationToken)
    {
        foreach (var executable in new[] { "vol.exe", "volatility3.exe", "volatility.exe", "vol.py", "vol" })
        {
            var path = FindOnPath(executable);
            if (!string.IsNullOrWhiteSpace(path))
            {
                return new NativeVolatilityRunner(path, await ReadVersionAsync(path, ["--version"], cancellationToken).ConfigureAwait(false));
            }
        }

        var python = FindOnPath("python.exe") ?? FindOnPath("python");
        if (string.IsNullOrWhiteSpace(python))
        {
            return null;
        }

        var check = await RunProcessAsync(
            python,
            ["-m", "volatility3", "--help"],
            null,
            TimeSpan.FromSeconds(15),
            cancellationToken).ConfigureAwait(false);
        if (check.ExitCode != 0)
        {
            return null;
        }

        var version = await ReadVersionAsync(python, ["-m", "volatility3", "--version"], cancellationToken).ConfigureAwait(false);
        return new PythonModuleVolatilityRunner(python, version);
    }

    private static async Task<string> ReadVersionAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await RunProcessAsync(fileName, arguments, null, TimeSpan.FromSeconds(15), cancellationToken).ConfigureAwait(false);
            return (string.IsNullOrWhiteSpace(result.StandardOutput) ? result.StandardError : result.StandardOutput).Trim();
        }
        catch
        {
            return string.Empty;
        }
    }

    private string ResolveOutputDirectory(MemoryImageRecord image, string outputDirectory, Guid jobId)
    {
        if (!string.IsNullOrWhiteSpace(outputDirectory))
        {
            return Path.GetFullPath(outputDirectory);
        }

        var memoryRoot = _sessionPaths?.MemoryDirectory ?? SessionPathService.GetDefaultMemoryDirectory();
        var imageId = string.IsNullOrWhiteSpace(image.ImageId) ? jobId.ToString("N") : image.ImageId;
        return Path.Combine(memoryRoot, SanitizePathPart(imageId), "Volatility");
    }

    private static VolatilityPluginRunRecord CreateRunRecord(
        MemoryImageRecord image,
        Guid jobId,
        string runId,
        string plugin,
        VolatilityPluginRunStatus status,
        DateTime startedUtc,
        DateTime completedUtc,
        string volatilityPath,
        string volatilityVersion,
        string commandLine,
        string outputDirectory,
        string stdoutPath,
        string stderrPath,
        string rawOutputHash,
        int normalizedRows,
        string error)
    {
        return new VolatilityPluginRunRecord
        {
            RunId = runId,
            ImageId = image.ImageId,
            JobId = jobId,
            PluginName = plugin,
            Status = status,
            RequestedUtc = DateTime.UtcNow,
            StartedUtc = startedUtc,
            CompletedUtc = completedUtc,
            VolatilityPath = volatilityPath,
            VolatilityVersion = volatilityVersion,
            CommandLine = commandLine,
            OutputDirectory = outputDirectory,
            StdoutPath = stdoutPath,
            StderrPath = stderrPath,
            RawOutputHash = rawOutputHash,
            NormalizedRowCount = normalizedRows,
            ErrorMessage = error,
            Source = "AgentVolatility"
        };
    }

    private static async Task<ProcessRunResult> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? workingDirectory,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout <= TimeSpan.Zero ? TimeSpan.FromMinutes(10) : timeout);

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                WorkingDirectory = workingDirectory ?? string.Empty,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        process.Start();
        var stdoutTask = process.StandardOutput.ReadToEndAsync(timeoutSource.Token);
        var stderrTask = process.StandardError.ReadToEndAsync(timeoutSource.Token);
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
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
                // Best effort; the job still reports cancellation/timeout to the caller.
            }

            throw;
        }

        return new ProcessRunResult(
            process.ExitCode,
            await stdoutTask.ConfigureAwait(false),
            await stderrTask.ConfigureAwait(false));
    }

    private static string? FindOnPath(string fileName)
    {
        var paths = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var path in paths)
        {
            var candidate = Path.Combine(path, fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static string CreateRunId(string imageId, Guid jobId, string plugin)
        => Sha256($"{imageId}|{jobId:N}|{plugin}")[..32];

    private static string Sha256(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string BuildCommandLine(string fileName, IReadOnlyList<string> arguments)
        => string.Join(" ", new[] { Quote(fileName) }.Concat(arguments.Select(Quote)));

    private static string Quote(string value)
        => value.Contains(' ') || value.Contains('"')
            ? "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\""
            : value;

    private static string SanitizePathPart(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = value.ToCharArray();
        for (var index = 0; index < chars.Length; index++)
        {
            if (invalid.Contains(chars[index]))
            {
                chars[index] = '_';
            }
        }

        return new string(chars).Trim();
    }

    private interface IVolatilityRunner
    {
        string FileName { get; }
        string DisplayName { get; }
        string Version { get; }
        IReadOnlyList<string> BuildArguments(string imagePath, string pluginName);
    }

    private sealed class NativeVolatilityRunner : IVolatilityRunner
    {
        public NativeVolatilityRunner(string path, string version)
        {
            FileName = path;
            Version = version;
        }

        public string FileName { get; }
        public string DisplayName => FileName;
        public string Version { get; }

        public IReadOnlyList<string> BuildArguments(string imagePath, string pluginName)
            => ["-f", imagePath, "-r", "json", pluginName];
    }

    private sealed class PythonModuleVolatilityRunner : IVolatilityRunner
    {
        public PythonModuleVolatilityRunner(string pythonPath, string version)
        {
            FileName = pythonPath;
            Version = version;
        }

        public string FileName { get; }
        public string DisplayName => $"{FileName} -m volatility3";
        public string Version { get; }

        public IReadOnlyList<string> BuildArguments(string imagePath, string pluginName)
            => ["-m", "volatility3", "-f", imagePath, "-r", "json", pluginName];
    }

    private sealed record ProcessRunResult(int ExitCode, string StandardOutput, string StandardError);
}

public sealed record VolatilityExecutionResult(
    VolatilityPluginRunRecord Run,
    IReadOnlyList<MemoryProcessRecord> MemoryProcesses);
