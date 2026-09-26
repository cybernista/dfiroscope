using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed record SysmonCurrentConfigurationResult(
    bool Succeeded,
    string Detail,
    bool Truncated = false,
    bool NoRulesInstalled = false);

/// <summary>Reads the configuration of the installed Sysmon service without changing it.</summary>
internal static class SysmonCurrentConfigurationReader
{
    private const int MaximumCapturedBytes = 16 * 1024 * 1024;
    private const int MaximumDisplayedLines = 800;
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(20);

    internal static SysmonCurrentConfigurationResult Query(string executablePath)
        => QueryAsync(executablePath).GetAwaiter().GetResult();

    private static async Task<SysmonCurrentConfigurationResult> QueryAsync(string executablePath)
    {
        if (!Path.IsPathFullyQualified(executablePath) || !File.Exists(executablePath) ||
            !IsSysmonFileName(Path.GetFileName(executablePath)))
        {
            return new(false, "The registered Sysmon service executable is unavailable or has an unexpected name.");
        }

        try
        {
            using var trusted = TrustedSysmonExecutable.Create(executablePath);
            var start = new ProcessStartInfo
            {
                FileName = trusted.Path,
                WorkingDirectory = Path.GetDirectoryName(trusted.Path)!,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            // With no configuration-file argument, -c dumps the installed configuration.
            start.ArgumentList.Add("-c");
            using var process = Process.Start(start);
            if (process == null)
                return new(false, "The installed Sysmon executable could not be started for a read-only configuration query.");

            var outputTask = ReadBoundedAsync(process.StandardOutput.BaseStream);
            var errorTask = ReadBoundedAsync(process.StandardError.BaseStream);
            try
            {
                using var timeout = new CancellationTokenSource(QueryTimeout);
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                return new(false, "The installed Sysmon -c query exceeded 20 seconds and was stopped.");
            }

            var output = await outputTask.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            var error = await errorTask.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                var detail = string.IsNullOrWhiteSpace(error.Text) ? output.Text : error.Text;
                return new(false, $"Installed Sysmon -c exited with code {process.ExitCode}. " +
                    LimitLine(detail, 700));
            }

            var formatted = FormatOutput(output.Text, output.Truncated);
            return formatted;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or UnauthorizedAccessException or
                                   IOException or InvalidOperationException or TimeoutException)
        {
            return new(false, $"The installed Sysmon configuration could not be read: {ex.Message}");
        }
    }

    internal static SysmonCurrentConfigurationResult FormatOutput(string output, bool captureTruncated = false)
    {
        var lines = output.Replace("\r\r\n", "\n", StringComparison.Ordinal)
            .Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n')
            .Split('\n').Select(line => line.Trim()).ToArray();
        var firstConfiguration = Array.FindIndex(lines, line =>
            line.StartsWith("Current configuration", StringComparison.OrdinalIgnoreCase));
        if (firstConfiguration < 0)
            return new(false, "Installed Sysmon -c did not identify its current configuration in the returned output.");
        lines = lines[firstConfiguration..];

        var formatted = new List<string>();
        var displayOmitted = false;
        var noRulesInstalled = false;
        var hasConfigurationField = false;
        foreach (var line in lines)
        {
            if (line.Length == 0)
            {
                if (formatted.Count > 0 && formatted[^1].Length > 0) formatted.Add(string.Empty);
                continue;
            }
            if (line.StartsWith("Copyright (C)", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("By Mark Russinovich", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Sysmon v", StringComparison.OrdinalIgnoreCase)) continue;

            if (line.Equals("No rules installed", StringComparison.OrdinalIgnoreCase)) noRulesInstalled = true;

            if (formatted.Count >= MaximumDisplayedLines || line.Length > 500)
            {
                displayOmitted = true;
                if (formatted.Count >= MaximumDisplayedLines) continue;
            }
            var clean = LimitLine(new string(line.Where(c => !char.IsControl(c) || c == '\t').ToArray()), 500);
            if (clean.StartsWith("- ", StringComparison.Ordinal))
            {
                clean = clean[2..];
                var colon = clean.IndexOf(':');
                if (colon > 0 && colon < 100)
                {
                    hasConfigurationField = true;
                    clean = clean[..(colon + 1)] + " " + clean[(colon + 1)..].Trim();
                }
                clean = "• " + clean;
            }
            formatted.Add(clean);
        }
        while (formatted.Count > 0 && formatted[^1].Length == 0) formatted.RemoveAt(formatted.Count - 1);
        if (!hasConfigurationField && !noRulesInstalled)
            return new(false, "Installed Sysmon -c returned a header but no configuration settings or rules.");
        if (captureTruncated)
            formatted.Add("[Output was truncated. The complete active configuration was not confirmed by this check.]");
        else if (displayOmitted)
            formatted.Add("[Display shortened. The complete command output was checked.]");
        if (!captureTruncated)
        {
            // The display is bounded, but deployment drift comparisons must cover
            // every rule, including lines omitted after MaximumDisplayedLines.
            var fullDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', lines))));
            formatted.Add($"[Complete configuration output SHA-256: {fullDigest}]");
        }
        return new(true, string.Join(Environment.NewLine, formatted), captureTruncated, noRulesInstalled);
    }

    private static bool IsSysmonFileName(string name) =>
        name.Equals("Sysmon.exe", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Sysmon64.exe", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Sysmon64a.exe", StringComparison.OrdinalIgnoreCase);

    private static string LimitLine(string value, int limit) =>
        value.Length <= limit ? value.Trim() : value[..limit].Trim() + "…";

    internal static string DecodeOutput(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            return Encoding.Unicode.GetString(bytes[2..]);
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(bytes[2..]);
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            return Encoding.UTF8.GetString(bytes[3..]);
        var sample = Math.Min(bytes.Length, 128);
        var oddZeros = 0;
        var evenZeros = 0;
        for (var index = 0; index < sample; index++)
        {
            if (bytes[index] != 0) continue;
            if (index % 2 == 0) evenZeros++;
            else oddZeros++;
        }
        if (sample >= 8 && oddZeros > sample / 8 && oddZeros > evenZeros * 2)
            return Encoding.Unicode.GetString(bytes[..(bytes.Length & ~1)]);
        if (sample >= 8 && evenZeros > sample / 8 && evenZeros > oddZeros * 2)
            return Encoding.BigEndianUnicode.GetString(bytes[..(bytes.Length & ~1)]);
        return Encoding.UTF8.GetString(bytes);
    }

    private static async Task<(string Text, bool Truncated)> ReadBoundedAsync(Stream stream)
    {
        using var captured = new MemoryStream();
        var buffer = new byte[4096];
        var truncated = false;
        int read;
        while ((read = await stream.ReadAsync(buffer).ConfigureAwait(false)) > 0)
        {
            var remaining = MaximumCapturedBytes - (int)captured.Length;
            if (remaining > 0) captured.Write(buffer, 0, Math.Min(read, remaining));
            if (read > remaining) truncated = true;
        }
        return (DecodeOutput(captured.GetBuffer().AsSpan(0, (int)captured.Length)), truncated);
    }
}
