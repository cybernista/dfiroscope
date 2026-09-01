using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class ZeekProcessingService
{
    private static readonly string[] SupportedLogs = ["conn.log", "dns.log", "http.log", "ssl.log", "quic.log", "weird.log"];
    private readonly InvestigationSessionPaths? _sessionPaths;

    public ZeekProcessingService(InvestigationSessionPaths? sessionPaths = null)
    {
        _sessionPaths = sessionPaths;
    }

    public async Task<ZeekProcessingResult> ProcessCaptureAsync(
        string captureId,
        Guid jobId,
        string pcapPath,
        string outputDirectory,
        ZeekProcessingOptions? options,
        CancellationToken cancellationToken)
    {
        var resolvedOutputDirectory = ResolveOutputDirectory(outputDirectory, captureId, jobId, _sessionPaths);
        Directory.CreateDirectory(resolvedOutputDirectory);
        var diagnosticLog = CreateDiagnosticLog(jobId, resolvedOutputDirectory);
        diagnosticLog.Write($"Starting Zeek analysis job {jobId}.");
        diagnosticLog.Write($"CaptureId: {FirstNonEmpty(captureId, "<none>")}");
        diagnosticLog.Write($"PCAP path: {FirstNonEmpty(pcapPath, "<none>")}");
        diagnosticLog.Write($"Output directory: {resolvedOutputDirectory}");
        diagnosticLog.Write($"Diagnostic log path: {diagnosticLog.LogPath}");
        if (diagnosticLog.AllLogPaths.Count > 1)
        {
            diagnosticLog.Write($"Mirrored diagnostic log path(s): {string.Join("; ", diagnosticLog.AllLogPaths.Skip(1))}");
        }

        diagnosticLog.Write($"Configured native Zeek path: {FirstNonEmpty(options?.ZeekPath, "<none>")}");
        diagnosticLog.Write($"Configured WSL distro: {FirstNonEmpty(options?.WslDistributionName, "<default>")}");
        diagnosticLog.Write($"Configured WSL Zeek command: {FirstNonEmpty(options?.WslZeekCommand, "zeek")}");

        try
        {
            if (string.IsNullOrWhiteSpace(pcapPath))
            {
                throw new InvalidOperationException("Zeek analysis requires a PCAP or PCAPNG file path.");
            }

            if (!File.Exists(pcapPath))
            {
                throw new FileNotFoundException("The PCAP/PCAPNG file selected for Zeek analysis was not found.", pcapPath);
            }

            var runner = await ResolveRunnerAsync(options ?? new ZeekProcessingOptions(), diagnosticLog, cancellationToken).ConfigureAwait(false);
            diagnosticLog.Write($"Resolved Zeek runner: {runner.DisplayName}");
            await runner.RunAsync(pcapPath, resolvedOutputDirectory, diagnosticLog, cancellationToken).ConfigureAwait(false);

            var records = new List<ZeekNetworkRecord>();
            foreach (var logName in SupportedLogs)
            {
                var logPath = Path.Combine(resolvedOutputDirectory, logName);
                if (File.Exists(logPath))
                {
                    var parsed = ParseLog(captureId, jobId, logPath, cancellationToken);
                    records.AddRange(parsed);
                    diagnosticLog.Write($"Imported {parsed.Count} row(s) from {logPath}.");
                }
                else
                {
                    diagnosticLog.Write($"Expected supported Zeek log not found: {logPath}");
                }
            }

            diagnosticLog.Write($"Zeek analysis completed with {records.Count} imported row(s).");
            return new ZeekProcessingResult(resolvedOutputDirectory, runner.DisplayName, diagnosticLog.LogPathDisplay, records);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            diagnosticLog.Write($"Zeek analysis failed: {ex}");
            throw new ZeekProcessingException(
                WithDiagnosticLog(ex.Message, diagnosticLog.LogPathDisplay),
                diagnosticLog.LogPath,
                resolvedOutputDirectory,
                ex);
        }
    }

    private static string ResolveOutputDirectory(
        string outputDirectory,
        string captureId,
        Guid jobId,
        InvestigationSessionPaths? sessionPaths)
    {
        if (!string.IsNullOrWhiteSpace(outputDirectory))
        {
            return Path.GetFullPath(outputDirectory);
        }

        var id = string.IsNullOrWhiteSpace(captureId) ? jobId.ToString("N") : SanitizePathPart(captureId);
        return sessionPaths != null
            ? Path.Combine(sessionPaths.ZeekDirectory, id)
            : SessionPathService.GetDefaultZeekDirectory(captureId, jobId);
    }

    private static async Task<IZeekRunner> ResolveRunnerAsync(
        ZeekProcessingOptions options,
        ZeekDiagnosticLog diagnosticLog,
        CancellationToken cancellationToken)
    {
        var nativeZeek = !string.IsNullOrWhiteSpace(options.ZeekPath) && File.Exists(options.ZeekPath)
            ? options.ZeekPath
            : FindOnPath("zeek.exe") ?? FindOnPath("zeek");
        if (!string.IsNullOrWhiteSpace(nativeZeek))
        {
            diagnosticLog.Write($"Native Zeek candidate selected: {nativeZeek}");
            return new NativeZeekRunner(nativeZeek);
        }

        diagnosticLog.Write("Native Zeek was not found via configured path, PATH, or known Windows executable directories.");
        var wsl = FindOnPath("wsl.exe");
        if (!string.IsNullOrWhiteSpace(wsl))
        {
            diagnosticLog.Write($"WSL candidate found: {wsl}");
            await LogWslInventoryAsync(wsl, diagnosticLog, cancellationToken).ConfigureAwait(false);
            var zeekCommand = FirstNonEmpty(options.WslZeekCommand, "zeek");
            var configuredDistro = options.WslDistributionName?.Trim() ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(configuredDistro) &&
                await WslZeekIsAvailableAsync(wsl, configuredDistro, zeekCommand, diagnosticLog, cancellationToken).ConfigureAwait(false))
            {
                return new WslZeekRunner(wsl, configuredDistro, zeekCommand);
            }

            if (await WslZeekIsAvailableAsync(wsl, string.Empty, zeekCommand, diagnosticLog, cancellationToken).ConfigureAwait(false))
            {
                return new WslZeekRunner(wsl, string.Empty, zeekCommand);
            }
        }
        else
        {
            diagnosticLog.Write("wsl.exe was not found via PATH, System32, or Sysnative.");
        }

        throw new InvalidOperationException($"Zeek was not found. Configure a native Zeek path or a WSL distro and Zeek command in the Network tab, then run Zeek analysis again. {ProductIdentity.DisplayName} does not install Zeek or WSL automatically.");
    }

    private static async Task LogWslInventoryAsync(
        string wslPath,
        ZeekDiagnosticLog diagnosticLog,
        CancellationToken cancellationToken)
    {
        diagnosticLog.Write("Collecting WSL distro inventory.");
        await RunProcessAsync(
            wslPath,
            ["--list", "--verbose"],
            null,
            diagnosticLog,
            cancellationToken).ConfigureAwait(false);
    }

    private static string? FindOnPath(string fileName)
    {
        if (Path.IsPathRooted(fileName) && File.Exists(fileName))
        {
            return fileName;
        }

        var paths = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var path in paths.Concat(GetKnownExecutableDirectories()).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var candidate = Path.Combine(path, fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static IEnumerable<string> GetKnownExecutableDirectories()
    {
        var systemDirectory = Environment.SystemDirectory;
        if (!string.IsNullOrWhiteSpace(systemDirectory))
        {
            yield return systemDirectory;
        }

        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(windowsDirectory))
        {
            yield return Path.Combine(windowsDirectory, "System32");
            yield return Path.Combine(windowsDirectory, "Sysnative");
        }
    }

    private static async Task<bool> WslZeekIsAvailableAsync(
        string wslPath,
        string distributionName,
        string zeekCommand,
        ZeekDiagnosticLog diagnosticLog,
        CancellationToken cancellationToken)
    {
        var displayDistro = string.IsNullOrWhiteSpace(distributionName) ? "<default>" : distributionName;
        diagnosticLog.Write($"Checking WSL Zeek availability. Distro={displayDistro}; Command={FirstNonEmpty(zeekCommand, "zeek")}");
        var check = await RunProcessAsync(
            wslPath,
            BuildWslShellArguments(distributionName, $"command -v {ShellQuote(FirstNonEmpty(zeekCommand, "zeek"))}"),
            null,
            diagnosticLog,
            cancellationToken).ConfigureAwait(false);
        var available = check.ExitCode == 0 && !string.IsNullOrWhiteSpace(check.StandardOutput);
        diagnosticLog.Write(available
            ? $"WSL Zeek is available at {check.StandardOutput.Trim()}."
            : "WSL Zeek availability check failed.");
        return available;
    }

    private static IReadOnlyList<ZeekNetworkRecord> ParseLog(
        string captureId,
        Guid jobId,
        string logPath,
        CancellationToken cancellationToken)
    {
        var records = new List<ZeekNetworkRecord>();
        var logType = Path.GetFileNameWithoutExtension(logPath);
        var separator = '\t';
        var fields = Array.Empty<string>();
        var lineNumber = 0L;

        foreach (var line in File.ReadLines(logPath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            lineNumber++;
            if (line.StartsWith("#separator", StringComparison.Ordinal))
            {
                separator = ParseSeparator(line);
                continue;
            }

            if (line.StartsWith("#fields", StringComparison.Ordinal))
            {
                fields = line.Split(separator).Skip(1).ToArray();
                continue;
            }

            if (line.StartsWith('#') || fields.Length == 0 || string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var values = line.Split(separator);
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < Math.Min(fields.Length, values.Length); i++)
            {
                map[fields[i]] = NormalizeZeekValue(values[i]);
            }

            var record = CreateRecord(captureId, jobId, logPath, lineNumber, line, logType, map);
            records.Add(record);
        }

        return records;
    }

    private static ZeekNetworkRecord CreateRecord(
        string captureId,
        Guid jobId,
        string logPath,
        long lineNumber,
        string rawLine,
        string logType,
        IReadOnlyDictionary<string, string> map)
    {
        var sourceIp = Get(map, "id.orig_h");
        var sourcePort = GetInt(map, "id.orig_p");
        var destinationIp = Get(map, "id.resp_h");
        var destinationPort = GetInt(map, "id.resp_p");
        var protocol = FirstNonEmpty(Get(map, "proto"), InferProtocol(logType));
        var service = FirstNonEmpty(Get(map, "service"), InferService(logType));
        var dnsQuery = Get(map, "query");
        var httpHost = Get(map, "host");
        var httpUri = Get(map, "uri");
        var serverName = Get(map, "server_name");
        var clientProtocol = FirstNonEmpty(Get(map, "client_protocol"), Get(map, "next_protocol"));
        var weirdName = Get(map, "name");
        var weirdAdditional = Get(map, "addl");
        var summary = BuildSummary(
            logType,
            sourceIp,
            sourcePort,
            destinationIp,
            destinationPort,
            protocol,
            service,
            dnsQuery,
            httpHost,
            httpUri,
            serverName,
            clientProtocol,
            weirdName,
            weirdAdditional);
        var rawHash = Sha256(rawLine);

        return new ZeekNetworkRecord
        {
            ArtifactId = Sha256($"{captureId}|{logType}|{Get(map, "uid")}|{lineNumber}|{rawHash}")[..32],
            CaptureId = captureId,
            JobId = jobId,
            Status = ZeekArtifactStatus.Imported,
            TimestampUtc = GetTimestamp(map, "ts"),
            LogType = logType,
            ZeekUid = Get(map, "uid"),
            SourceIp = sourceIp,
            SourcePort = sourcePort,
            DestinationIp = destinationIp,
            DestinationPort = destinationPort,
            Protocol = protocol,
            Service = service,
            DnsQuery = dnsQuery,
            HttpMethod = Get(map, "method"),
            HttpHost = httpHost,
            HttpUri = httpUri,
            DurationSeconds = GetDouble(map, "duration"),
            OrigBytes = GetLong(map, "orig_bytes"),
            RespBytes = GetLong(map, "resp_bytes"),
            OrigPackets = GetLong(map, "orig_pkts"),
            RespPackets = GetLong(map, "resp_pkts"),
            OrigIpBytes = GetLong(map, "orig_ip_bytes"),
            RespIpBytes = GetLong(map, "resp_ip_bytes"),
            ConnectionState = Get(map, "conn_state"),
            History = Get(map, "history"),
            ServerName = serverName,
            ClientProtocol = clientProtocol,
            TlsVersion = Get(map, "version"),
            TlsCipher = Get(map, "cipher"),
            TlsEstablished = GetBool(map, "established"),
            WeirdName = weirdName,
            WeirdAdditional = weirdAdditional,
            Summary = summary,
            RawLogPath = logPath,
            RawLineNumber = lineNumber,
            RawLineHash = rawHash,
            RawText = rawLine,
            Source = "AgentZeek"
        };
    }

    private static string BuildSummary(
        string logType,
        string sourceIp,
        int sourcePort,
        string destinationIp,
        int destinationPort,
        string protocol,
        string service,
        string dnsQuery,
        string httpHost,
        string httpUri,
        string serverName,
        string clientProtocol,
        string weirdName,
        string weirdAdditional)
    {
        var endpoint = string.IsNullOrWhiteSpace(destinationIp)
            ? "<unknown>"
            : destinationPort > 0 ? $"{destinationIp}:{destinationPort}" : destinationIp;
        if (!string.IsNullOrWhiteSpace(dnsQuery))
        {
            return $"DNS {dnsQuery} via {endpoint}";
        }

        if (!string.IsNullOrWhiteSpace(httpHost) || !string.IsNullOrWhiteSpace(httpUri))
        {
            return $"HTTP {httpHost}{httpUri} via {endpoint}";
        }

        if (logType.Equals("ssl", StringComparison.OrdinalIgnoreCase))
        {
            var name = FirstNonEmpty(serverName, endpoint);
            return $"TLS {name} via {endpoint}";
        }

        if (logType.Equals("quic", StringComparison.OrdinalIgnoreCase))
        {
            var name = FirstNonEmpty(serverName, clientProtocol, endpoint);
            return $"QUIC {name} via {endpoint}";
        }

        if (logType.Equals("weird", StringComparison.OrdinalIgnoreCase))
        {
            var detail = string.IsNullOrWhiteSpace(weirdAdditional) ? string.Empty : $" ({weirdAdditional})";
            return $"Zeek weird {FirstNonEmpty(weirdName, "<unknown>")}{detail} via {endpoint}";
        }

        var origin = string.IsNullOrWhiteSpace(sourceIp)
            ? "<unknown>"
            : sourcePort > 0 ? $"{sourceIp}:{sourcePort}" : sourceIp;
        var displayProtocol = string.IsNullOrWhiteSpace(protocol) ? logType : protocol;
        var displayService = string.IsNullOrWhiteSpace(service) ? string.Empty : $" {service}";
        return $"{displayProtocol}{displayService} {origin} -> {endpoint}".Trim();
    }

    private static char ParseSeparator(string line)
    {
        var value = line["#separator".Length..].Trim();
        return value.Equals(@"\x09", StringComparison.OrdinalIgnoreCase) ? '\t' : value.FirstOrDefault('\t');
    }

    private static DateTime GetTimestamp(IReadOnlyDictionary<string, string> map, string key)
    {
        var value = Get(map, key);
        return double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds)
            ? DateTime.UnixEpoch.AddSeconds(seconds)
            : DateTime.UtcNow;
    }

    private static int GetInt(IReadOnlyDictionary<string, string> map, string key)
        => int.TryParse(Get(map, key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : 0;

    private static long GetLong(IReadOnlyDictionary<string, string> map, string key)
        => long.TryParse(Get(map, key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : 0;

    private static double GetDouble(IReadOnlyDictionary<string, string> map, string key)
        => double.TryParse(Get(map, key), NumberStyles.Float, CultureInfo.InvariantCulture, out var value) ? value : 0;

    private static bool GetBool(IReadOnlyDictionary<string, string> map, string key)
    {
        var value = Get(map, key);
        return value.Equals("T", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("1", StringComparison.OrdinalIgnoreCase);
    }

    private static string Get(IReadOnlyDictionary<string, string> map, string key)
        => map.TryGetValue(key, out var value) ? value : string.Empty;

    private static string InferService(string logType)
    {
        return logType.ToLowerInvariant() switch
        {
            "ssl" => "tls",
            "quic" => "quic",
            "dns" => "dns",
            "http" => "http",
            _ => string.Empty
        };
    }

    private static string InferProtocol(string logType)
    {
        return logType.ToLowerInvariant() switch
        {
            "quic" => "udp",
            "ssl" => "tcp",
            _ => string.Empty
        };
    }

    private static string NormalizeZeekValue(string value)
        => value is "-" or "(empty)" ? string.Empty : value;

    private static string Sha256(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string SanitizePathPart(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            builder.Append(invalid.Contains(ch) ? '_' : ch);
        }

        return builder.ToString();
    }

    private static async Task<ProcessRunResult> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? workingDirectory,
        ZeekDiagnosticLog diagnosticLog,
        CancellationToken cancellationToken)
    {
        diagnosticLog.Write($"Running: {fileName} {FormatArguments(arguments)}");
        diagnosticLog.Write($"Working directory: {FirstNonEmpty(workingDirectory, "<default>")}");
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
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        var result = new ProcessRunResult(
            process.ExitCode,
            NormalizeProcessOutput(await stdoutTask.ConfigureAwait(false)),
            NormalizeProcessOutput(await stderrTask.ConfigureAwait(false)));
        diagnosticLog.Write($"Exit code: {result.ExitCode}");
        diagnosticLog.WriteBlock("stdout", result.StandardOutput);
        diagnosticLog.WriteBlock("stderr", result.StandardError);
        return result;
    }

    private static string NormalizeProcessOutput(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var normalized = value.Replace("\0", string.Empty, StringComparison.Ordinal);
        return normalized.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();
    }

    private static IReadOnlyList<string> BuildWslShellArguments(string distributionName, string script)
    {
        var arguments = new List<string>();
        if (!string.IsNullOrWhiteSpace(distributionName))
        {
            arguments.Add("-d");
            arguments.Add(distributionName.Trim());
        }

        arguments.Add("sh");
        arguments.Add("-lc");
        arguments.Add(script);
        return arguments;
    }

    private static IReadOnlyList<string> BuildWslCommandArguments(string distributionName, params string[] commandArguments)
    {
        var arguments = new List<string>();
        if (!string.IsNullOrWhiteSpace(distributionName))
        {
            arguments.Add("-d");
            arguments.Add(distributionName.Trim());
        }

        arguments.AddRange(commandArguments);
        return arguments;
    }

    private static string NormalizeWindowsPathForWslPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return path;
        }

        var normalized = path.Trim();
        if (normalized.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        return normalized.Replace('\\', '/');
    }

    private interface IZeekRunner
    {
        string DisplayName { get; }
        Task RunAsync(string pcapPath, string outputDirectory, ZeekDiagnosticLog diagnosticLog, CancellationToken cancellationToken);
    }

    private sealed class NativeZeekRunner : IZeekRunner
    {
        private readonly string _zeekPath;

        public NativeZeekRunner(string zeekPath)
        {
            _zeekPath = zeekPath;
        }

        public string DisplayName => _zeekPath;

        public async Task RunAsync(
            string pcapPath,
            string outputDirectory,
            ZeekDiagnosticLog diagnosticLog,
            CancellationToken cancellationToken)
        {
            var result = await RunProcessAsync(_zeekPath, ["-r", pcapPath], outputDirectory, diagnosticLog, cancellationToken).ConfigureAwait(false);
            if (result.ExitCode != 0)
            {
                throw new InvalidOperationException($"Zeek failed with exit code {result.ExitCode}: {result.StandardError.Trim()}");
            }
        }
    }

    private sealed class WslZeekRunner : IZeekRunner
    {
        private readonly string _wslPath;
        private readonly string _distributionName;
        private readonly string _zeekCommand;

        public WslZeekRunner(string wslPath, string distributionName, string zeekCommand)
        {
            _wslPath = wslPath;
            _distributionName = distributionName.Trim();
            _zeekCommand = FirstNonEmpty(zeekCommand, "zeek");
        }

        public string DisplayName => string.IsNullOrWhiteSpace(_distributionName)
            ? $"WSL {_zeekCommand}"
            : $"WSL {_distributionName} {_zeekCommand}";

        public async Task RunAsync(
            string pcapPath,
            string outputDirectory,
            ZeekDiagnosticLog diagnosticLog,
            CancellationToken cancellationToken)
        {
            var wslPcap = (await RunProcessAsync(
                _wslPath,
                BuildWslCommandArguments(_distributionName, "wslpath", "-a", NormalizeWindowsPathForWslPath(pcapPath)),
                null,
                diagnosticLog,
                cancellationToken).ConfigureAwait(false)).StandardOutput.Trim();
            var wslOutput = (await RunProcessAsync(
                _wslPath,
                BuildWslCommandArguments(_distributionName, "wslpath", "-a", NormalizeWindowsPathForWslPath(outputDirectory)),
                null,
                diagnosticLog,
                cancellationToken).ConfigureAwait(false)).StandardOutput.Trim();
            if (string.IsNullOrWhiteSpace(wslPcap) || string.IsNullOrWhiteSpace(wslOutput))
            {
                throw new InvalidOperationException("WSL path conversion failed for Zeek analysis input or output paths.");
            }

            var script = $"cd {ShellQuote(wslOutput)} && {ShellQuote(_zeekCommand)} -r {ShellQuote(wslPcap)}";
            var result = await RunProcessAsync(
                _wslPath,
                BuildWslShellArguments(_distributionName, script),
                null,
                diagnosticLog,
                cancellationToken).ConfigureAwait(false);
            if (result.ExitCode != 0)
            {
                throw new InvalidOperationException($"WSL Zeek failed with exit code {result.ExitCode}: {result.StandardError.Trim()}");
            }
        }
    }

    private static string ShellQuote(string value)
        => "'" + value.Replace("'", "'\"'\"'", StringComparison.Ordinal) + "'";

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private static string FormatArguments(IEnumerable<string> arguments)
        => string.Join(" ", arguments.Select(QuoteArgument));

    private static string QuoteArgument(string argument)
    {
        return argument.Any(char.IsWhiteSpace)
            ? $"\"{argument.Replace("\"", "\\\"")}\""
            : argument;
    }

    private ZeekDiagnosticLog CreateDiagnosticLog(Guid jobId, string outputDirectory)
    {
        var fileName = $"ZeekAnalysis-{jobId:N}.log";
        var outputLogPath = Path.Combine(outputDirectory, fileName);
        var logPaths = new List<string> { outputLogPath };

        if (!string.IsNullOrWhiteSpace(_sessionPaths?.LogsDirectory))
        {
            logPaths.Add(Path.Combine(_sessionPaths.LogsDirectory, fileName));
        }

        return ZeekDiagnosticLog.Open(logPaths);
    }

    private static string WithDiagnosticLog(string message, string logPath)
        => string.IsNullOrWhiteSpace(logPath) ? message : $"{message} Diagnostic log: {logPath}";

    private sealed record ProcessRunResult(int ExitCode, string StandardOutput, string StandardError);

    private sealed class ZeekDiagnosticLog
    {
        private ZeekDiagnosticLog(IReadOnlyList<string> logPaths)
        {
            AllLogPaths = logPaths;
            LogPath = logPaths.FirstOrDefault() ?? string.Empty;
        }

        public string LogPath { get; }

        public IReadOnlyList<string> AllLogPaths { get; }

        public string LogPathDisplay => string.Join("; ", AllLogPaths);

        public static ZeekDiagnosticLog Open(IEnumerable<string> logPaths)
        {
            var distinctPaths = logPaths
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(Path.GetFullPath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            return new ZeekDiagnosticLog(distinctPaths);
        }

        public void Write(string message)
        {
            foreach (var logPath in AllLogPaths)
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? AppContext.BaseDirectory);
                    File.AppendAllText(
                        logPath,
                        $"[{DateTimeOffset.Now:O}] {message}{Environment.NewLine}");
                }
                catch
                {
                    // Zeek diagnostics are best-effort and should not mask analysis failures.
                }
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
}

public sealed class ZeekProcessingException : InvalidOperationException
{
    public ZeekProcessingException(
        string message,
        string diagnosticLogPath,
        string outputDirectory,
        Exception innerException)
        : base(message, innerException)
    {
        DiagnosticLogPath = diagnosticLogPath;
        OutputDirectory = outputDirectory;
    }

    public string DiagnosticLogPath { get; }

    public string OutputDirectory { get; }
}

public sealed record ZeekProcessingOptions(
    string ZeekPath = "",
    string WslDistributionName = "",
    string WslZeekCommand = "");

public sealed record ZeekProcessingResult(
    string OutputDirectory,
    string ToolName,
    string DiagnosticLogPath,
    IReadOnlyList<ZeekNetworkRecord> Records);
