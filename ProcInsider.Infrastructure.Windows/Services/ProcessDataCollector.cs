using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Collects process information from the system.
/// Handles access denied errors gracefully and caches file metadata.
/// </summary>
public class ProcessDataCollector
{
    // Cache for file hashes to avoid repeated computation
    private readonly Dictionary<string, string> _hashCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (string Company, string Description)> _metadataCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _cacheLock = new();

    // Cache for WMI command line data
    private Dictionary<int, string> _commandLineCache = new();
    private Dictionary<int, int> _parentPidCache = new();
    private DateTime _lastWmiRefresh = DateTime.MinValue;
    private readonly TimeSpan _wmiCacheExpiry = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Collects information about all running processes.
    /// </summary>
    public async Task<List<ProcessInfo>> CollectAllProcessesAsync(CancellationToken cancellationToken = default)
    {
        var processes = new List<ProcessInfo>();

        // Refresh WMI cache if needed
        await RefreshWmiCacheAsync(cancellationToken);

        Process[] systemProcesses;
        try
        {
            systemProcesses = Process.GetProcesses();
        }
        catch (Exception)
        {
            return processes;
        }

        foreach (var proc in systemProcesses)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var info = await CollectProcessInfoAsync(proc, cancellationToken);
                if (info != null)
                {
                    processes.Add(info);
                }
            }
            catch (Exception)
            {
                // Skip processes we can't access
            }
            finally
            {
                proc.Dispose();
            }
        }

        return processes;
    }

    /// <summary>
    /// Attempts to collect information about a single running process by PID.
    /// Returns null if the process cannot be accessed or has already exited.
    /// </summary>
    public async Task<ProcessInfo?> TryCollectProcessByIdAsync(int processId, CancellationToken cancellationToken = default)
    {
        await RefreshWmiCacheAsync(cancellationToken);

        try
        {
            using var proc = TryGetProcessById(processId);
            if (proc == null)
            {
                return null;
            }

            return await CollectProcessInfoAsync(proc, cancellationToken);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Collects information about a single process.
    /// </summary>
    private async Task<ProcessInfo?> CollectProcessInfoAsync(Process proc, CancellationToken cancellationToken)
    {
        var info = new ProcessInfo
        {
            ProcessId = proc.Id
        };

        // Process name (usually accessible)
        try
        {
            info.ProcessName = proc.ProcessName;
        }
        catch
        {
            info.ProcessName = "<access denied>";
        }

        // Session ID
        try
        {
            info.SessionId = proc.SessionId;
        }
        catch
        {
            info.SessionId = -1;
        }

        // Start time
        try
        {
            info.StartTime = proc.StartTime;
        }
        catch
        {
            // Some system processes don't allow access to start time
            info.StartTime = null;
        }

        // Memory usage
        try
        {
            info.MemoryUsageBytes = proc.WorkingSet64;
        }
        catch
        {
            info.MemoryUsageBytes = 0;
        }

        CollectProcessStatistics(proc, info);

        // Process path
        string? processPath = null;
        try
        {
            processPath = proc.MainModule?.FileName;
            info.ProcessPath = processPath ?? "<not available>";
        }
        catch (System.ComponentModel.Win32Exception)
        {
            info.ProcessPath = "<access denied>";
        }
        catch
        {
            info.ProcessPath = "<not available>";
        }

        // Architecture (32-bit or 64-bit)
        info.Architecture = GetProcessArchitecture(proc);

        // Parent PID from WMI cache
        lock (_cacheLock)
        {
            info.ParentProcessId = _parentPidCache.GetValueOrDefault(proc.Id, 0);
            info.CommandLine = _commandLineCache.GetValueOrDefault(proc.Id, "<not available>");
        }

        // User name
        info.UserName = GetProcessUserName(proc);

        // File metadata and hash (async, cached)
        if (!string.IsNullOrEmpty(processPath) && File.Exists(processPath))
        {
            await Task.Run(() =>
            {
                info.Sha256Hash = GetCachedHash(processPath);
                var metadata = GetCachedMetadata(processPath);
                info.CompanyName = metadata.Company;
                info.FileDescription = metadata.Description;
            }, cancellationToken);
        }

        return info;
    }

    private static Process? TryGetProcessById(int processId)
    {
        Process[] processes;
        try
        {
            processes = Process.GetProcesses();
        }
        catch
        {
            return null;
        }

        Process? match = null;
        foreach (var process in processes)
        {
            if (match == null && process.Id == processId)
            {
                match = process;
            }
            else
            {
                process.Dispose();
            }
        }

        return match;
    }

    /// <summary>
    /// Refreshes the WMI cache for command lines and parent PIDs.
    /// </summary>
    private async Task RefreshWmiCacheAsync(CancellationToken cancellationToken)
    {
        if (DateTime.Now - _lastWmiRefresh < _wmiCacheExpiry)
            return;

        await Task.Run(() =>
        {
            var newCommandLineCache = new Dictionary<int, string>();
            var newParentPidCache = new Dictionary<int, int>();

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, ParentProcessId, CommandLine FROM Win32_Process");

                foreach (ManagementObject obj in searcher.Get())
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        var pid = Convert.ToInt32(obj["ProcessId"]);
                        var ppid = Convert.ToInt32(obj["ParentProcessId"]);
                        var cmdLine = obj["CommandLine"]?.ToString() ?? "<not available>";

                        newCommandLineCache[pid] = cmdLine;
                        newParentPidCache[pid] = ppid;
                    }
                    catch
                    {
                        // Skip problematic entries
                    }
                }
            }
            catch
            {
                // WMI query failed, keep existing cache
                return;
            }

            lock (_cacheLock)
            {
                _commandLineCache = newCommandLineCache;
                _parentPidCache = newParentPidCache;
                _lastWmiRefresh = DateTime.Now;
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Gets the process architecture (32-bit or 64-bit).
    /// </summary>
    private string GetProcessArchitecture(Process proc)
    {
        if (!Environment.Is64BitOperatingSystem)
            return "x86";

        try
        {
            if (IsWow64Process(proc.Handle, out bool isWow64))
            {
                return isWow64 ? "x86" : "x64";
            }
        }
        catch
        {
            // Access denied or process exited
        }

        return "<not available>";
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

    private static void CollectProcessStatistics(Process proc, ProcessInfo info)
    {
        var errors = new List<string>();

        try
        {
            info.TotalProcessorTime = proc.TotalProcessorTime;
        }
        catch
        {
            errors.Add("CPU total unavailable");
        }

        try
        {
            info.UserProcessorTime = proc.UserProcessorTime;
        }
        catch
        {
            errors.Add("CPU user unavailable");
        }

        try
        {
            info.PrivilegedProcessorTime = proc.PrivilegedProcessorTime;
        }
        catch
        {
            errors.Add("CPU kernel unavailable");
        }

        try
        {
            if (GetProcessIoCounters(proc.Handle, out var counters))
            {
                info.ReadBytes = ToSignedByteCount(counters.ReadTransferCount);
                info.WrittenBytes = ToSignedByteCount(counters.WriteTransferCount);
            }
            else
            {
                errors.Add($"I/O counters unavailable ({Marshal.GetLastWin32Error()})");
            }
        }
        catch
        {
            errors.Add("I/O counters unavailable");
        }

        info.StatisticsCollectionError = string.Join("; ", errors.Distinct(StringComparer.Ordinal));
    }

    private static long ToSignedByteCount(ulong value)
    {
        return value > long.MaxValue ? long.MaxValue : (long)value;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessIoCounters(IntPtr hProcess, out IoCounters counters);

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    /// <summary>
    /// Gets the user name running the process.
    /// </summary>
    private string GetProcessUserName(Process proc)
    {
        try
        {
            var handle = proc.Handle;
            if (OpenProcessToken(handle, TOKEN_QUERY, out var tokenHandle))
            {
                try
                {
                    using var identity = new WindowsIdentity(tokenHandle);
                    return identity.Name;
                }
                finally
                {
                    CloseHandle(tokenHandle);
                }
            }
        }
        catch
        {
            // Access denied
        }

        return "<access denied>";
    }

    private const uint TOKEN_QUERY = 0x0008;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// Gets a cached SHA256 hash for a file path.
    /// </summary>
    private string GetCachedHash(string filePath)
    {
        lock (_cacheLock)
        {
            if (_hashCache.TryGetValue(filePath, out var cachedHash))
                return cachedHash;
        }

        string hash;
        try
        {
            using var stream = File.OpenRead(filePath);
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(stream);
            hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }
        catch
        {
            hash = "<access denied>";
        }

        lock (_cacheLock)
        {
            _hashCache[filePath] = hash;
        }

        return hash;
    }

    /// <summary>
    /// Gets cached file metadata (company name and description).
    /// </summary>
    private (string Company, string Description) GetCachedMetadata(string filePath)
    {
        lock (_cacheLock)
        {
            if (_metadataCache.TryGetValue(filePath, out var cached))
                return cached;
        }

        string company = "<not available>";
        string description = "<not available>";

        try
        {
            var versionInfo = FileVersionInfo.GetVersionInfo(filePath);
            company = versionInfo.CompanyName ?? "<not available>";
            description = versionInfo.FileDescription ?? "<not available>";
        }
        catch
        {
            company = "<access denied>";
            description = "<access denied>";
        }

        var result = (company, description);

        lock (_cacheLock)
        {
            _metadataCache[filePath] = result;
        }

        return result;
    }

    /// <summary>
    /// Clears all caches.
    /// </summary>
    public void ClearCaches()
    {
        lock (_cacheLock)
        {
            _hashCache.Clear();
            _metadataCache.Clear();
            _commandLineCache.Clear();
            _parentPidCache.Clear();
            _lastWmiRefresh = DateTime.MinValue;
        }
    }
}
