using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace ProcInsider.Services.AgentIpc;

public sealed record LocalAgentNativeProcessIdentity(
    string ExecutablePath,
    string ExecutableName,
    DateTime StartedAtUtc,
    string OwnerSid,
    bool? IsElevated);

public sealed record LocalAgentIdentityVerificationResult(
    bool Verified,
    LocalAgentNativeProcessIdentity? Identity,
    string Detail);

/// <summary>Shared query-limited verifier for the Viewer and unelevated Telemetrios client.</summary>
public static class LocalAgentProcessIdentityVerifier
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenElevationClass = 20;
    private static readonly TimeSpan StartTolerance = TimeSpan.FromSeconds(1);

    public static LocalAgentIdentityVerificationResult Verify(
        int processId,
        DateTime expectedStartedAtUtc,
        string expectedExecutableName,
        IReadOnlyList<string> allowedExecutablePaths)
    {
        if (processId <= 0 || expectedStartedAtUtc == default ||
            !IsSupportedAgentName(expectedExecutableName) ||
            allowedExecutablePaths.Count == 0)
        {
            return new LocalAgentIdentityVerificationResult(false, null, "The expected local-Agent identity is incomplete or unsupported.");
        }

        try
        {
            var identity = Inspect(processId);
            using var current = WindowsIdentity.GetCurrent();
            var currentSid = current.User?.Value ?? string.Empty;
            var failures = new List<string>();
            if (!IsSupportedAgentName(identity.ExecutableName) ||
                !NamesEqual(identity.ExecutableName, expectedExecutableName))
                failures.Add("the executable name is outside the current/former Agent allowlist or differs from discovery");
            if (!allowedExecutablePaths.Any(path => PathsEqual(identity.ExecutablePath, path)))
                failures.Add("the executable path differs from the exact allowlisted discovery path");
            if ((identity.StartedAtUtc - expectedStartedAtUtc).Duration() > StartTolerance)
                failures.Add("the process start time differs from discovery");
            if (string.IsNullOrWhiteSpace(currentSid) || string.IsNullOrWhiteSpace(identity.OwnerSid) ||
                !string.Equals(currentSid, identity.OwnerSid, StringComparison.OrdinalIgnoreCase))
                failures.Add("the process owner differs from the current user");
            if (identity.IsElevated != true)
                failures.Add("the process elevation state is not verified elevated");
            return failures.Count == 0
                ? new LocalAgentIdentityVerificationResult(true, identity,
                    "The Agent PID, start time, current/former name, exact path, current-user owner, and elevated token were verified with query-limited access.")
                : new LocalAgentIdentityVerificationResult(false, identity, string.Join("; ", failures));
        }
        catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException or InvalidOperationException or SecurityException)
        {
            return new LocalAgentIdentityVerificationResult(false, null, "Query-limited Agent identity inspection failed: " + ex.Message);
        }
    }

    public static LocalAgentNativeProcessIdentity Inspect(int processId)
    {
        var processHandle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (processHandle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"The local-Agent PID {processId} could not be opened with query-only access.");
        try
        {
            var path = GetExecutablePath(processHandle);
            var started = GetStartedAtUtc(processHandle);
            var (owner, elevated) = GetTokenIdentityOrUnavailable(processHandle);
            return new LocalAgentNativeProcessIdentity(path, Path.GetFileName(path), started, owner, elevated);
        }
        finally
        {
            _ = CloseHandle(processHandle);
        }
    }

    public static bool IsSameProcessRunning(int processId, DateTime expectedStartedAtUtc)
    {
        var processHandle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (processHandle == IntPtr.Zero)
        {
            var error = Marshal.GetLastWin32Error();
            if (error is 87 or 1168) return false;
            throw new Win32Exception(error, $"The local-Agent PID {processId} could not be polled with query-only access.");
        }
        try
        {
            if (!GetProcessTimes(processHandle, out var creation, out _, out _, out _))
            {
                var error = Marshal.GetLastWin32Error();
                if (error is 6 or 87 or 1168) return false;
                throw new Win32Exception(error, "The local-Agent process start time could not be polled.");
            }
            if ((DateTime.FromFileTimeUtc(creation.ToLong()) - expectedStartedAtUtc).Duration() > StartTolerance) return false;
            if (!GetExitCodeProcess(processHandle, out var exitCode))
            {
                var error = Marshal.GetLastWin32Error();
                if (error is 6 or 87 or 1168) return false;
                throw new Win32Exception(error, "The local-Agent process exit state could not be polled.");
            }
            return exitCode == 259;
        }
        finally
        {
            _ = CloseHandle(processHandle);
        }
    }

    public static bool PathsEqual(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right)) return false;
        try
        {
            return string.Equals(ResolvePath(left), ResolvePath(right), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string ResolvePath(string path)
    {
        var full = NormalizePrefix(Path.GetFullPath(path));
        try
        {
            using var handle = File.OpenHandle(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var capacity = 512;
            while (capacity <= 32768)
            {
                var buffer = new StringBuilder(capacity);
                var length = GetFinalPathNameByHandle(handle.DangerousGetHandle(), buffer, (uint)capacity, 0);
                if (length == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
                if (length < capacity) return NormalizePrefix(Path.GetFullPath(buffer.ToString()));
                capacity = checked((int)length + 1);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or NotSupportedException)
        {
        }
        return full;
    }

    private static string NormalizePrefix(string path) =>
        path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ? @"\\" + path[8..] :
        path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ? path[4..] : path;

    private static bool IsSupportedAgentName(string value)
    {
        var name = Path.GetFileName(value.Trim());
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
        return name.Equals("DFIRoscope.Agent", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("ProcInsider.Agent", StringComparison.OrdinalIgnoreCase);
    }

    private static bool NamesEqual(string left, string right)
    {
        static string Normalize(string value)
        {
            var name = Path.GetFileName(value.Trim());
            return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        }
        return string.Equals(Normalize(left), Normalize(right), StringComparison.OrdinalIgnoreCase);
    }

    private static string GetExecutablePath(IntPtr handle)
    {
        var size = 32768;
        var buffer = new StringBuilder(size);
        if (!QueryFullProcessImageName(handle, 0, buffer, ref size))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "The local-Agent executable path could not be queried.");
        return buffer.ToString();
    }

    private static DateTime GetStartedAtUtc(IntPtr handle)
    {
        if (!GetProcessTimes(handle, out var creation, out _, out _, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "The local-Agent process start time could not be queried.");
        return DateTime.FromFileTimeUtc(creation.ToLong());
    }

    private static (string OwnerSid, bool? IsElevated) GetTokenIdentityOrUnavailable(IntPtr processHandle)
    {
        if (!OpenProcessToken(processHandle, TokenQuery, out var token))
        {
            var error = Marshal.GetLastWin32Error();
            if (IsExpectedUnavailable(error)) return (string.Empty, null);
            throw new Win32Exception(error, "The local-Agent process token could not be queried.");
        }
        try
        {
            var owner = string.Empty;
            try
            {
                using var identity = new WindowsIdentity(token);
                owner = identity.User?.Value ?? string.Empty;
            }
            catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException or SecurityException)
            {
            }
            bool? elevated;
            if (GetTokenInformation(token, TokenElevationClass, out var elevation, Marshal.SizeOf<TokenElevation>(), out _))
                elevated = elevation.TokenIsElevated != 0;
            else
            {
                var error = Marshal.GetLastWin32Error();
                if (!IsExpectedUnavailable(error)) throw new Win32Exception(error, "The local-Agent elevation state could not be queried.");
                elevated = null;
            }
            return (owner, elevated);
        }
        finally
        {
            _ = CloseHandle(token);
        }
    }

    private static bool IsExpectedUnavailable(int error) => error is 5 or 6 or 87 or 1008 or 1168 or 1314;

    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder path, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(IntPtr process, out NativeFileTime creation, out NativeFileTime exit, out NativeFileTime kernel, out NativeFileTime user);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(IntPtr file, StringBuilder path, uint length, uint flags);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr token, int informationClass, out TokenElevation information, int length, out int returnLength);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)] private struct NativeFileTime
    {
        private uint _low;
        private uint _high;
        public long ToLong() => ((long)_high << 32) | _low;
    }

    [StructLayout(LayoutKind.Sequential)] private struct TokenElevation { public int TokenIsElevated; }
}
