using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProcInsider.Agent;

internal sealed class WindowsJobYaraProcessRunner : IYaraProcessRunner
{
    public async Task<YaraProcessRunResult> RunAsync(
        YaraProcessRunRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!OperatingSystem.IsWindows())
        {
            return new YaraProcessRunResult { Outcome = YaraProcessRunOutcome.ContainmentFailed };
        }

        using var job = WindowsYaraJobObject.TryCreate(request.ProcessMemoryLimitBytes);
        if (job == null)
        {
            return new YaraProcessRunResult { Outcome = YaraProcessRunOutcome.ContainmentFailed };
        }

        using var process = new Process
        {
            StartInfo = CreateStartInfo(request),
            EnableRaisingEvents = true
        };

        try
        {
            if (!process.Start())
            {
                return new YaraProcessRunResult { Outcome = YaraProcessRunOutcome.StartFailed };
            }
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            return new YaraProcessRunResult { Outcome = YaraProcessRunOutcome.StartFailed };
        }

        if (!job.TryAssign(process))
        {
            TryKillProcessTree(process);
            return new YaraProcessRunResult { Outcome = YaraProcessRunOutcome.ContainmentFailed };
        }

        var stdoutTask = ReadBoundedAsync(
            process.StandardOutput.BaseStream,
            request.MaximumStdoutBytes);
        var stderrTask = ReadBoundedAsync(
            process.StandardError.BaseStream,
            request.MaximumStderrBytes);
        var exitTask = process.WaitForExitAsync();
        var timeoutTask = Task.Delay(request.Timeout);
        var cancellationTask = Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        var neverTask = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously).Task;
        var stdoutObserved = false;
        var stderrObserved = false;

        try
        {
            while (true)
            {
                var completed = await Task.WhenAny(
                    exitTask,
                    stdoutObserved ? neverTask : stdoutTask,
                    stderrObserved ? neverTask : stderrTask,
                    timeoutTask,
                    cancellationTask).ConfigureAwait(false);

                if (completed == cancellationTask)
                {
                    job.Terminate();
                    await AwaitExitAsync(process).ConfigureAwait(false);
                    return new YaraProcessRunResult { Outcome = YaraProcessRunOutcome.Canceled };
                }

                if (completed == timeoutTask)
                {
                    job.Terminate();
                    await AwaitExitAsync(process).ConfigureAwait(false);
                    return new YaraProcessRunResult { Outcome = YaraProcessRunOutcome.TimedOut };
                }

                if (completed == stdoutTask && stdoutTask.IsCompletedSuccessfully &&
                    stdoutTask.Result.LimitExceeded)
                {
                    job.Terminate();
                    await AwaitExitAsync(process).ConfigureAwait(false);
                    return new YaraProcessRunResult
                    {
                        Outcome = YaraProcessRunOutcome.StdoutLimitExceeded
                    };
                }

                if (completed == stdoutTask)
                {
                    stdoutObserved = true;
                    continue;
                }

                if (completed == stderrTask && stderrTask.IsCompletedSuccessfully &&
                    stderrTask.Result.LimitExceeded)
                {
                    job.Terminate();
                    await AwaitExitAsync(process).ConfigureAwait(false);
                    return new YaraProcessRunResult
                    {
                        Outcome = YaraProcessRunOutcome.StderrLimitExceeded
                    };
                }

                if (completed == stderrTask)
                {
                    stderrObserved = true;
                    continue;
                }

                if (completed != exitTask)
                {
                    // One stream can close before the process exits. Wait for the
                    // remaining process/stream/deadline signals.
                    await Task.Yield();
                    continue;
                }

                var stdout = await stdoutTask.ConfigureAwait(false);
                var stderr = await stderrTask.ConfigureAwait(false);
                if (stdout.LimitExceeded)
                {
                    return new YaraProcessRunResult
                    {
                        Outcome = YaraProcessRunOutcome.StdoutLimitExceeded
                    };
                }

                if (stderr.LimitExceeded)
                {
                    return new YaraProcessRunResult
                    {
                        Outcome = YaraProcessRunOutcome.StderrLimitExceeded
                    };
                }

                return new YaraProcessRunResult
                {
                    Outcome = YaraProcessRunOutcome.Completed,
                    ExitCode = process.ExitCode,
                    StandardOutput = stdout.Bytes,
                    StandardError = stderr.Bytes
                };
            }
        }
        finally
        {
            if (!process.HasExited)
            {
                job.Terminate();
                await AwaitExitAsync(process).ConfigureAwait(false);
            }
        }
    }

    private static ProcessStartInfo CreateStartInfo(YaraProcessRunRequest request)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = request.ExecutablePath,
            WorkingDirectory = request.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = false,
            StandardOutputEncoding = new System.Text.UTF8Encoding(false, true),
            StandardErrorEncoding = new System.Text.UTF8Encoding(false, true)
        };
        foreach (var argument in request.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        var systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        startInfo.Environment.Clear();
        startInfo.Environment["SystemRoot"] = systemRoot;
        startInfo.Environment["WINDIR"] = systemRoot;
        startInfo.Environment["TEMP"] = request.WorkingDirectory;
        startInfo.Environment["TMP"] = request.WorkingDirectory;
        return startInfo;
    }

    private static async Task<BoundedReadResult> ReadBoundedAsync(Stream stream, int maximumBytes)
    {
        using var output = new MemoryStream(Math.Min(maximumBytes, 64 * 1024));
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer).ConfigureAwait(false);
            if (read == 0)
            {
                return new BoundedReadResult(false, output.ToArray());
            }

            if (output.Length + read > maximumBytes)
            {
                return new BoundedReadResult(true, Array.Empty<byte>());
            }

            output.Write(buffer, 0, read);
        }
    }

    private static async Task AwaitExitAsync(Process process)
    {
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidOperationException or TimeoutException)
        {
            TryKillProcessTree(process);
        }
    }

    private static void TryKillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            // Best effort after the Job Object fail-closed path.
        }
    }

    private sealed record BoundedReadResult(bool LimitExceeded, byte[] Bytes);
}

internal sealed class WindowsYaraJobObject : IDisposable
{
    internal const uint KillOnJobCloseFlag = 0x00002000;
    internal const uint ProcessMemoryLimitFlag = 0x00000100;
    private const int JobObjectExtendedLimitInformation = 9;
    private readonly SafeJobHandle _handle;

    private WindowsYaraJobObject(SafeJobHandle handle)
    {
        _handle = handle;
    }

    public static WindowsYaraJobObject? TryCreate(long processMemoryLimitBytes)
    {
        if (processMemoryLimitBytes <= 0 || !OperatingSystem.IsWindows())
        {
            return null;
        }

        var handle = NativeMethods.CreateJobObject(IntPtr.Zero, null);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            return null;
        }

        var limits = CreateLimits(processMemoryLimitBytes);
        var size = Marshal.SizeOf<NativeMethods.JobObjectExtendedLimitInformation>();
        var pointer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(limits, pointer, false);
            if (!NativeMethods.SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    pointer,
                    (uint)size))
            {
                handle.Dispose();
                return null;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }

        return new WindowsYaraJobObject(handle);
    }

    internal static NativeMethods.JobObjectExtendedLimitInformation CreateLimits(
        long processMemoryLimitBytes) => new()
    {
        BasicLimitInformation = new NativeMethods.JobObjectBasicLimitInformation
        {
            LimitFlags = KillOnJobCloseFlag | ProcessMemoryLimitFlag
        },
        ProcessMemoryLimit = (nuint)processMemoryLimitBytes
    };

    public bool TryAssign(Process process)
    {
        try
        {
            return NativeMethods.AssignProcessToJobObject(_handle, process.SafeHandle);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            return false;
        }
    }

    public void Terminate()
    {
        NativeMethods.TerminateJobObject(_handle, 1);
    }

    public void Dispose()
    {
        _handle.Dispose();
    }

    internal static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct JobObjectBasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public nuint MinimumWorkingSetSize;
            public nuint MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public nuint Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JobObjectExtendedLimitInformation
        {
            public JobObjectBasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public nuint ProcessMemoryLimit;
            public nuint JobMemoryLimit;
            public nuint PeakProcessMemoryUsed;
            public nuint PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeJobHandle CreateJobObject(IntPtr jobAttributes, string? name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetInformationJobObject(
            SafeJobHandle job,
            int informationClass,
            IntPtr information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AssignProcessToJobObject(
            SafeJobHandle job,
            SafeProcessHandle process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateJobObject(SafeJobHandle job, uint exitCode);
    }

    internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeJobHandle()
            : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
