using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class ProcessDumpService
{
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessDuplicateHandle = 0x0040;
    private const uint ProcessDumpAccess = ProcessQueryInformation | ProcessVmRead | ProcessDuplicateHandle;
    private readonly InvestigationSessionPaths? _sessionPaths;

    public ProcessDumpService(InvestigationSessionPaths? sessionPaths = null)
    {
        _sessionPaths = sessionPaths;
    }

    public Task<ProcessDumpResult> CreateDumpAsync(
        ProcessRecord process,
        MemoryDumpKind dumpKind,
        string? outputDirectory,
        bool overwriteExisting,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(process);
        return Task.Run(
            () => CreateDump(process, dumpKind, outputDirectory, overwriteExisting, cancellationToken),
            cancellationToken);
    }

    private ProcessDumpResult CreateDump(
        ProcessRecord process,
        MemoryDumpKind dumpKind,
        string? outputDirectory,
        bool overwriteExisting,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var directory = ResolveOutputDirectory(outputDirectory, _sessionPaths);
        Directory.CreateDirectory(directory);
        var filePath = BuildDumpPath(directory, process, dumpKind, overwriteExisting);

        var processHandle = OpenProcess(ProcessDumpAccess, false, process.ProcessId);
        if (processHandle == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to open PID {process.ProcessId} for dump capture.");
        }

        try
        {
            using var fileStream = new FileStream(
                filePath,
                overwriteExisting ? FileMode.Create : FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.Read);
            var succeeded = MiniDumpWriteDump(
                processHandle,
                process.ProcessId,
                fileStream.SafeFileHandle,
                ToMiniDumpType(dumpKind),
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);
            if (!succeeded)
            {
                var error = Marshal.GetLastWin32Error();
                fileStream.Dispose();
                TryDelete(filePath);
                throw new Win32Exception(error, $"MiniDumpWriteDump failed for PID {process.ProcessId}.");
            }
        }
        finally
        {
            CloseHandle(processHandle);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var fileInfo = new FileInfo(filePath);
        return new ProcessDumpResult
        {
            FilePath = filePath,
            OutputDirectory = directory,
            FileSizeBytes = fileInfo.Length,
            Sha256Hash = ComputeSha256(filePath),
            ToolName = "MiniDumpWriteDump"
        };
    }

    private static string ResolveOutputDirectory(string? outputDirectory, InvestigationSessionPaths? sessionPaths)
    {
        if (!string.IsNullOrWhiteSpace(outputDirectory))
        {
            return Path.GetFullPath(Environment.ExpandEnvironmentVariables(outputDirectory));
        }

        return sessionPaths?.DumpsDirectory ?? SessionPathService.GetDefaultDumpsDirectory();
    }

    private static string BuildDumpPath(
        string outputDirectory,
        ProcessRecord process,
        MemoryDumpKind dumpKind,
        bool overwriteExisting)
    {
        var processName = SanitizeFileName(process.ProcessName);
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var baseName = $"{processName}_{process.ProcessId}_{timestamp}_{dumpKind.ToString().ToLowerInvariant()}";
        var path = Path.Combine(outputDirectory, $"{baseName}.dmp");
        if (overwriteExisting || !File.Exists(path))
        {
            return path;
        }

        for (var i = 1; i <= 999; i++)
        {
            var candidate = Path.Combine(outputDirectory, $"{baseName}_{i}.dmp");
            if (!File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException($"Unable to allocate a unique dump file path under {outputDirectory}.");
    }

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = string.IsNullOrWhiteSpace(value) ? "process".ToCharArray() : value.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            if (invalid.Contains(chars[i]))
            {
                chars[i] = '_';
            }
        }

        return new string(chars).Trim();
    }

    private static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = System.Security.Cryptography.SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static void TryDelete(string filePath)
    {
        try
        {
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }
        catch
        {
            // Best-effort cleanup of a failed dump file.
        }
    }

    private static MiniDumpType ToMiniDumpType(MemoryDumpKind dumpKind)
    {
        return dumpKind == MemoryDumpKind.Mini
            ? MiniDumpType.MiniDumpNormal
            : MiniDumpType.MiniDumpWithFullMemory |
              MiniDumpType.MiniDumpWithHandleData |
              MiniDumpType.MiniDumpWithUnloadedModules |
              MiniDumpType.MiniDumpWithFullMemoryInfo |
              MiniDumpType.MiniDumpWithThreadInfo;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MiniDumpWriteDump(
        IntPtr processHandle,
        int processId,
        SafeFileHandle fileHandle,
        MiniDumpType dumpType,
        IntPtr exceptionParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);

    [Flags]
    private enum MiniDumpType : uint
    {
        MiniDumpNormal = 0x00000000,
        MiniDumpWithFullMemory = 0x00000002,
        MiniDumpWithHandleData = 0x00000004,
        MiniDumpWithUnloadedModules = 0x00000020,
        MiniDumpWithFullMemoryInfo = 0x00000800,
        MiniDumpWithThreadInfo = 0x00001000
    }
}

public sealed class ProcessDumpResult
{
    public string FilePath { get; init; } = string.Empty;

    public string OutputDirectory { get; init; } = string.Empty;

    public long FileSizeBytes { get; init; }

    public string Sha256Hash { get; init; } = string.Empty;

    public string ToolName { get; init; } = string.Empty;
}
