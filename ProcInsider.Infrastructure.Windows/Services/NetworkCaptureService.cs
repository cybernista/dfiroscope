using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class NetworkCaptureService
{
    private const int CommandTimeoutSeconds = 30;
    private const int MaxStartAttempts = 10;
    private const int InitialStartRetryDelayMilliseconds = 500;
    private const int MaxStartRetryDelayMilliseconds = 2000;
    private readonly InvestigationSessionPaths? _sessionPaths;
    private readonly IPacketMonitorRunner _packetMonitorRunner;

    public NetworkCaptureService(InvestigationSessionPaths? sessionPaths = null)
        : this(sessionPaths, new PacketMonitorRunner())
    {
    }

    public NetworkCaptureService(
        InvestigationSessionPaths? sessionPaths,
        IPacketMonitorRunner packetMonitorRunner)
    {
        _sessionPaths = sessionPaths;
        _packetMonitorRunner = packetMonitorRunner ?? throw new ArgumentNullException(nameof(packetMonitorRunner));
    }

    public async Task<NetworkCaptureSession> StartCaptureAsync(
        Guid jobId,
        string outputDirectory,
        CancellationToken cancellationToken) =>
        await StartCaptureAsync(jobId, outputDirectory, 1, cancellationToken).ConfigureAwait(false);

    public async Task<NetworkCaptureSession> StartCaptureAsync(
        Guid jobId,
        string outputDirectory,
        int segmentIndex,
        CancellationToken cancellationToken)
    {
        if (segmentIndex < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(segmentIndex));
        }

        var directory = ResolveOutputDirectory(outputDirectory, _sessionPaths);
        Directory.CreateDirectory(directory);

        var diagnosticLog = CreateDiagnosticLog(jobId, directory);
        diagnosticLog.Write($"Starting Packet Monitor capture job {jobId}.");
        diagnosticLog.Write($"Requested output directory: {outputDirectory}");
        diagnosticLog.Write($"Resolved output directory: {directory}");

        var pktmonPath = _packetMonitorRunner.ResolvePktmonPath();
        diagnosticLog.Write(string.IsNullOrWhiteSpace(pktmonPath)
            ? "Resolved pktmon path: <not found>"
            : $"Resolved pktmon path: {pktmonPath}");

        if (string.IsNullOrWhiteSpace(pktmonPath))
        {
            throw new InvalidOperationException(WithDiagnosticLog(
                "pktmon.exe was not found. Network capture requires Windows Packet Monitor.",
                diagnosticLog.LogPath));
        }

        string lastFailure = "Packet Monitor capture did not start.";
        for (var attempt = 1; attempt <= MaxStartAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            diagnosticLog.Write($"Packet Monitor capture start attempt {attempt} of {MaxStartAttempts}.");

            var readinessFailure = await CheckPacketMonitorReadyAsync(pktmonPath, diagnosticLog, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(readinessFailure))
            {
                lastFailure = readinessFailure;
                await DelayBeforeStartRetryAsync(attempt, diagnosticLog, cancellationToken).ConfigureAwait(false);
                continue;
            }

            var baseName = BuildSegmentBaseName(jobId, segmentIndex, attempt);
            var etlPath = Path.Combine(directory, $"{baseName}.etl");
            var pcapPath = Path.Combine(directory, $"{baseName}.pcapng");
            diagnosticLog.Write($"ETL segment path: {etlPath}");
            diagnosticLog.Write($"PCAPNG segment path: {pcapPath}");

            var startArguments = new[] { "start", "--capture", "--pkt-size", "0", "--file-name", etlPath };
            PacketMonitorCommandResult result;
            try
            {
                result = await RunPacketMonitorCommandAsync(
                    pktmonPath,
                    startArguments,
                    diagnosticLog,
                    cancellationToken).ConfigureAwait(false);

                if (result.ExitCode != 0 && IsPacketMonitorAlreadyRunning(result.CombinedOutput))
                {
                    await StopStalePacketMonitorSessionAsync(pktmonPath, result.CombinedOutput, diagnosticLog, cancellationToken).ConfigureAwait(false);
                    result = await RunPacketMonitorCommandAsync(
                        pktmonPath,
                        startArguments,
                        diagnosticLog,
                        cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                if (IsAccessDeniedFailure(ex.Message))
                {
                    throw;
                }

                lastFailure = ex.Message;
                await DelayBeforeStartRetryAsync(attempt, diagnosticLog, cancellationToken).ConfigureAwait(false);
                continue;
            }

            if (result.ExitCode == 0)
            {
                diagnosticLog.Write($"Packet Monitor capture started on attempt {attempt} of {MaxStartAttempts}.");
                return new NetworkCaptureSession(pktmonPath, directory, etlPath, pcapPath, diagnosticLog.LogPath, DateTime.UtcNow);
            }

            lastFailure = $"pktmon start failed ({FormatArguments(startArguments)}): {DescribePktmonFailure(result)}";
            if (IsAccessDeniedFailure(result.CombinedOutput))
            {
                throw new InvalidOperationException(WithDiagnosticLog(
                    $"{lastFailure}. Run {ProductIdentity.DisplayName} and the local agent with administrator privileges.",
                    diagnosticLog.LogPath));
            }

            await DelayBeforeStartRetryAsync(attempt, diagnosticLog, cancellationToken).ConfigureAwait(false);
        }

        throw new InvalidOperationException(WithDiagnosticLog(
            $"Packet Monitor capture failed after {MaxStartAttempts} start attempts. Last failure: {lastFailure}",
            diagnosticLog.LogPath));
    }

    public async Task<NetworkCaptureResult> StopCaptureAsync(
        NetworkCaptureSession session,
        CancellationToken cancellationToken)
    {
        var diagnosticLog = NetworkCaptureDiagnosticLog.Open(session.LogFilePath);
        diagnosticLog.Write("Stopping Packet Monitor capture.");

        var stop = await RunPacketMonitorCommandAsync(session.PktmonPath, new[] { "stop" }, diagnosticLog, cancellationToken).ConfigureAwait(false);
        if (stop.ExitCode != 0 && !IsPacketMonitorNotRunning(stop.CombinedOutput))
        {
            throw new InvalidOperationException(WithDiagnosticLog(
                $"pktmon stop failed: {DescribePktmonFailure(stop)}",
                diagnosticLog.LogPath));
        }

        if (!File.Exists(session.EtlFilePath))
        {
            throw new FileNotFoundException(
                WithDiagnosticLog("pktmon stopped but did not produce an ETL segment.", diagnosticLog.LogPath),
                session.EtlFilePath);
        }

        var convertArguments = new[] { "etl2pcap", session.EtlFilePath, "--out", session.PcapFilePath };
        var convert = await RunPacketMonitorCommandAsync(
            session.PktmonPath,
            convertArguments,
            diagnosticLog,
            cancellationToken).ConfigureAwait(false);

        if (convert.ExitCode != 0)
        {
            throw new InvalidOperationException(WithDiagnosticLog(
                $"pktmon ETL-to-PCAP conversion failed ({FormatArguments(convertArguments)}): {DescribePktmonFailure(convert)}",
                diagnosticLog.LogPath));
        }

        if (!File.Exists(session.PcapFilePath))
        {
            throw new FileNotFoundException(
                WithDiagnosticLog("pktmon conversion completed but did not produce a PCAPNG segment.", diagnosticLog.LogPath),
                session.PcapFilePath);
        }

        var fileInfo = new FileInfo(session.PcapFilePath);
        diagnosticLog.Write($"PCAPNG segment produced: {session.PcapFilePath}");
        diagnosticLog.Write($"PCAPNG size: {fileInfo.Length:N0} bytes");
        return new NetworkCaptureResult(
            session.OutputDirectory,
            session.EtlFilePath,
            session.PcapFilePath,
            fileInfo.Length,
            await ComputeSha256Async(session.PcapFilePath, cancellationToken).ConfigureAwait(false),
            "pktmon",
            diagnosticLog.LogPath);
    }

    public async Task<NetworkCaptureResult> StopUntrackedCaptureAsync(
        Guid jobId,
        string outputDirectory,
        CancellationToken cancellationToken)
    {
        var directory = ResolveOutputDirectory(outputDirectory, _sessionPaths);
        Directory.CreateDirectory(directory);

        var diagnosticLog = CreateDiagnosticLog(jobId, directory);
        diagnosticLog.Write($"Stopping untracked Packet Monitor capture job {jobId}.");
        diagnosticLog.Write($"Requested output directory: {outputDirectory}");
        diagnosticLog.Write($"Resolved output directory: {directory}");

        var pktmonPath = _packetMonitorRunner.ResolvePktmonPath();
        diagnosticLog.Write(string.IsNullOrWhiteSpace(pktmonPath)
            ? "Resolved pktmon path: <not found>"
            : $"Resolved pktmon path: {pktmonPath}");

        if (string.IsNullOrWhiteSpace(pktmonPath))
        {
            throw new InvalidOperationException(WithDiagnosticLog(
                "pktmon.exe was not found. Network capture stop requires Windows Packet Monitor.",
                diagnosticLog.LogPath));
        }

        var status = await RunPacketMonitorCommandAsync(pktmonPath, new[] { "status" }, diagnosticLog, cancellationToken).ConfigureAwait(false);
        if (status.ExitCode != 0 && ContainsAny(status.CombinedOutput, "access is denied", "administrator", "elevated"))
        {
            throw new InvalidOperationException(WithDiagnosticLog(
                $"pktmon status failed before recovery stop: {DescribePktmonFailure(status)}. Run {ProductIdentity.DisplayName} and the local agent with administrator privileges.",
                diagnosticLog.LogPath));
        }

        var stop = await RunPacketMonitorCommandAsync(pktmonPath, new[] { "stop" }, diagnosticLog, cancellationToken).ConfigureAwait(false);
        if (stop.ExitCode != 0)
        {
            if (IsPacketMonitorNotRunning(stop.CombinedOutput))
            {
                throw new InvalidOperationException(WithDiagnosticLog(
                    "Packet Monitor is not running; no untracked network capture could be stopped.",
                    diagnosticLog.LogPath));
            }

            throw new InvalidOperationException(WithDiagnosticLog(
                $"pktmon recovery stop failed: {DescribePktmonFailure(stop)}",
                diagnosticLog.LogPath));
        }

        var etlPath = ResolveStoppedEtlPath(stop.CombinedOutput, directory);
        if (string.IsNullOrWhiteSpace(etlPath) || !File.Exists(etlPath))
        {
            throw new FileNotFoundException(
                WithDiagnosticLog("pktmon stopped an untracked capture but did not report an ETL segment path.", diagnosticLog.LogPath),
                string.IsNullOrWhiteSpace(etlPath) ? directory : etlPath);
        }

        var pcapPath = GetAvailablePcapPath(etlPath);
        var convertArguments = new[] { "etl2pcap", etlPath, "--out", pcapPath };
        var convert = await RunPacketMonitorCommandAsync(
            pktmonPath,
            convertArguments,
            diagnosticLog,
            cancellationToken).ConfigureAwait(false);

        if (convert.ExitCode != 0)
        {
            throw new InvalidOperationException(WithDiagnosticLog(
                $"pktmon recovery ETL-to-PCAP conversion failed ({FormatArguments(convertArguments)}): {DescribePktmonFailure(convert)}",
                diagnosticLog.LogPath));
        }

        if (!File.Exists(pcapPath))
        {
            throw new FileNotFoundException(
                WithDiagnosticLog("pktmon recovery conversion completed but did not produce a PCAPNG segment.", diagnosticLog.LogPath),
                pcapPath);
        }

        var fileInfo = new FileInfo(pcapPath);
        diagnosticLog.Write($"Recovered PCAPNG segment produced: {pcapPath}");
        diagnosticLog.Write($"Recovered PCAPNG size: {fileInfo.Length:N0} bytes");
        return new NetworkCaptureResult(
            Path.GetDirectoryName(etlPath) ?? directory,
            etlPath,
            pcapPath,
            fileInfo.Length,
            await ComputeSha256Async(pcapPath, cancellationToken).ConfigureAwait(false),
            "pktmon",
            diagnosticLog.LogPath);
    }

    private static string ResolveOutputDirectory(string outputDirectory, InvestigationSessionPaths? sessionPaths)
    {
        if (!string.IsNullOrWhiteSpace(outputDirectory))
        {
            return Path.GetFullPath(outputDirectory);
        }

        return sessionPaths?.NetworkCapturesDirectory ?? SessionPathService.GetDefaultNetworkCapturesDirectory();
    }

    private async Task<string> CheckPacketMonitorReadyAsync(
        string pktmonPath,
        NetworkCaptureDiagnosticLog diagnosticLog,
        CancellationToken cancellationToken)
    {
        var status = await RunPacketMonitorCommandAsync(pktmonPath, new[] { "status" }, diagnosticLog, cancellationToken).ConfigureAwait(false);
        if (status.ExitCode == 0)
        {
            diagnosticLog.Write("Packet Monitor status preflight passed.");
            return string.Empty;
        }

        var detail = DescribePktmonFailure(status);
        if (IsAccessDeniedFailure(status.CombinedOutput))
        {
            throw new InvalidOperationException(WithDiagnosticLog(
                $"pktmon status failed before capture: {detail}. Run {ProductIdentity.DisplayName} and the local agent with administrator privileges.",
                diagnosticLog.LogPath));
        }

        return $"pktmon status failed before capture: {detail}";
    }

    private async Task StopStalePacketMonitorSessionAsync(
        string pktmonPath,
        string startFailure,
        NetworkCaptureDiagnosticLog diagnosticLog,
        CancellationToken cancellationToken)
    {
        diagnosticLog.Write($"Packet Monitor reported an existing capture. Start failure: {NormalizeOutput(startFailure)}");
        var stop = await RunPacketMonitorCommandAsync(pktmonPath, new[] { "stop" }, diagnosticLog, cancellationToken).ConfigureAwait(false);
        if (stop.ExitCode != 0 && !IsPacketMonitorNotRunning(stop.CombinedOutput))
        {
            throw new InvalidOperationException(WithDiagnosticLog(
                $"pktmon reported an existing capture but the stale session could not be stopped. " +
                $"Start failure: {NormalizeOutput(startFailure)} Stop failure: {DescribePktmonFailure(stop)}",
                diagnosticLog.LogPath));
        }
    }

    private async Task<PacketMonitorCommandResult> RunPacketMonitorCommandAsync(
        string pktmonPath,
        IReadOnlyList<string> arguments,
        NetworkCaptureDiagnosticLog diagnosticLog,
        CancellationToken cancellationToken)
    {
        diagnosticLog.Write($"Running: {pktmonPath} {FormatArguments(arguments)}");

        try
        {
            var result = await _packetMonitorRunner.RunAsync(pktmonPath, arguments, cancellationToken).ConfigureAwait(false);
            diagnosticLog.Write($"Exit code: {result.ExitCode}");
            diagnosticLog.WriteBlock("Output", result.CombinedOutput);
            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            diagnosticLog.Write($"Command failed before exit code was available: {ex.GetType().Name}: {ex.Message}");
            throw new InvalidOperationException(WithDiagnosticLog(ex.Message, diagnosticLog.LogPath), ex);
        }
    }

    private NetworkCaptureDiagnosticLog CreateDiagnosticLog(Guid jobId, string outputDirectory)
    {
        var sessionLogsDirectory = _sessionPaths?.LogsDirectory;
        var logsDirectory = !string.IsNullOrWhiteSpace(sessionLogsDirectory)
            ? sessionLogsDirectory
            : Path.Combine(outputDirectory, "Logs");
        return NetworkCaptureDiagnosticLog.Open(Path.Combine(logsDirectory, $"NetworkCapture-{jobId:N}.log"));
    }

    private static string WithDiagnosticLog(string message, string logPath)
    {
        return string.IsNullOrWhiteSpace(logPath)
            ? message
            : $"{message} Diagnostic log: {logPath}";
    }

    private static bool IsPacketMonitorAlreadyRunning(string output)
        => ContainsAny(
            output,
            "already running",
            "already started",
            "data collection is already running",
            "data collection has already started",
            "collection is running");

    private static bool IsPacketMonitorNotRunning(string output)
        => ContainsAny(
            output,
            "not running",
            "not started",
            "data collection is not running",
            "no active");

    private static bool IsAccessDeniedFailure(string output)
        => ContainsAny(output, "access is denied", "administrator", "elevated");

    private static string BuildSegmentBaseName(Guid jobId, int segmentIndex, int attempt)
    {
        var suffix = attempt <= 1 ? string.Empty : $"-try{attempt:D2}";
        return $"network-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{jobId:N}-segment{segmentIndex:D3}{suffix}";
    }

    private static async Task DelayBeforeStartRetryAsync(
        int attempt,
        NetworkCaptureDiagnosticLog diagnosticLog,
        CancellationToken cancellationToken)
    {
        if (attempt >= MaxStartAttempts)
        {
            return;
        }

        var delay = TimeSpan.FromMilliseconds(Math.Min(
            InitialStartRetryDelayMilliseconds * attempt,
            MaxStartRetryDelayMilliseconds));
        diagnosticLog.Write($"Packet Monitor capture did not start; retrying in {delay.TotalMilliseconds:N0} ms.");
        await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
    }

    private static bool ContainsAny(string value, params string[] needles)
    {
        return needles.Any(needle => value.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }

    private static string DescribePktmonFailure(PacketMonitorCommandResult result)
    {
        var detail = NormalizeOutput(result.CombinedOutput);
        return string.IsNullOrWhiteSpace(detail)
            ? $"exit code {result.ExitCode} with no output"
            : $"exit code {result.ExitCode}: {detail}";
    }

    private static string NormalizeOutput(string output)
    {
        return string.IsNullOrWhiteSpace(output)
            ? string.Empty
            : output.ReplaceLineEndings(" ").Trim();
    }

    private static string ResolveStoppedEtlPath(string output, string outputDirectory)
    {
        var reportedPath = ExtractLogFilePath(output);
        if (!string.IsNullOrWhiteSpace(reportedPath))
        {
            return reportedPath;
        }

        try
        {
            return Directory
                .EnumerateFiles(outputDirectory, "*.etl", SearchOption.TopDirectoryOnly)
                .Select(path => new FileInfo(path))
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .Select(file => file.FullName)
                .FirstOrDefault() ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string ExtractLogFilePath(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return string.Empty;
        }

        const string marker = "Log file:";
        foreach (var rawLine in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            var markerIndex = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (markerIndex < 0)
            {
                continue;
            }

            var path = line[(markerIndex + marker.Length)..].Trim();
            var noteIndex = path.IndexOf(" (", StringComparison.Ordinal);
            if (noteIndex > 0)
            {
                path = path[..noteIndex].Trim();
            }

            return path;
        }

        return string.Empty;
    }

    private static string GetAvailablePcapPath(string etlPath)
    {
        var preferred = Path.ChangeExtension(etlPath, ".pcapng");
        if (!File.Exists(preferred))
        {
            return preferred;
        }

        var directory = Path.GetDirectoryName(preferred) ?? AppContext.BaseDirectory;
        var fileName = Path.GetFileNameWithoutExtension(preferred);
        return Path.Combine(directory, $"{fileName}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.pcapng");
    }

    private static string FormatArguments(IReadOnlyList<string> arguments)
    {
        return string.Join(" ", arguments.Select(QuoteArgument));
    }

    private static string QuoteArgument(string argument)
    {
        return argument.Any(char.IsWhiteSpace)
            ? $"\"{argument.Replace("\"", "\\\"")}\""
            : argument;
    }

    private sealed class NetworkCaptureDiagnosticLog
    {
        private NetworkCaptureDiagnosticLog(string logPath)
        {
            LogPath = logPath;
        }

        public string LogPath { get; }

        public static NetworkCaptureDiagnosticLog Open(string logPath)
        {
            return new NetworkCaptureDiagnosticLog(logPath);
        }

        public void Write(string message)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(LogPath) ?? AppContext.BaseDirectory);
                File.AppendAllText(
                    LogPath,
                    $"[{DateTimeOffset.Now:O}] {message}{Environment.NewLine}");
            }
            catch
            {
                // Packet capture diagnostics are best-effort and should not mask pktmon failures.
            }
        }

        public void WriteBlock(string title, string content)
        {
            if (string.IsNullOrWhiteSpace(content))
            {
                Write($"{title}: <none>");
                return;
            }

            Write($"{title}:{Environment.NewLine}{content.Trim()}");
        }
    }

    private sealed class PacketMonitorRunner : IPacketMonitorRunner
    {
        public string ResolvePktmonPath()
        {
            var systemPath = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var candidate = Path.Combine(systemPath, "pktmon.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    candidate = Path.Combine(directory.Trim(), "pktmon.exe");
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
                catch
                {
                    // Ignore malformed PATH entries.
                }
            }

            return string.Empty;
        }

        public async Task<PacketMonitorCommandResult> RunAsync(
            string pktmonPath,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken)
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = pktmonPath,
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

            var output = new StringBuilder();
            process.OutputDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                {
                    output.AppendLine(e.Data);
                }
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                {
                    output.AppendLine(e.Data);
                }
            };

            if (!process.Start())
            {
                throw new InvalidOperationException("Failed to start pktmon.exe.");
            }

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(CommandTimeoutSeconds));
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                TryKill(process);
                throw new TimeoutException($"pktmon command timed out after {CommandTimeoutSeconds} seconds: {FormatArguments(arguments)}");
            }

            return new PacketMonitorCommandResult(process.ExitCode, output.ToString().Trim());
        }
    }

    private static void TryKill(Process process)
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
            // The timeout error is more useful than a cleanup failure.
        }
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1024 * 128,
            useAsync: true);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }
}

public interface IPacketMonitorRunner
{
    string ResolvePktmonPath();

    Task<PacketMonitorCommandResult> RunAsync(
        string pktmonPath,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken);
}

public sealed record PacketMonitorCommandResult(int ExitCode, string CombinedOutput);

public sealed record NetworkCaptureSession(
    string PktmonPath,
    string OutputDirectory,
    string EtlFilePath,
    string PcapFilePath,
    string LogFilePath,
    DateTime StartedUtc);

public sealed record NetworkCaptureResult(
    string OutputDirectory,
    string EtlFilePath,
    string FilePath,
    long FileSizeBytes,
    string Sha256Hash,
    string ToolName,
    string LogFilePath);
