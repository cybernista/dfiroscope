using System.ComponentModel;
using System.Runtime.InteropServices;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal sealed record AgentInstanceGuardFailure(
    string ErrorCode,
    string GuardName,
    string Message);

/// <summary>
/// Acquires both current and former machine-global host identities on one dedicated
/// thread. The explicit SDDL allows only LocalSystem and elevated Administrators, so
/// Interactive and service hosts arbitrate the same objects across Windows sessions.
/// </summary>
internal sealed class AgentInstanceGuard : IDisposable
{
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitAbandoned = 0x00000080;
    private const uint WaitTimeout = 0x00000102;
    private const uint Infinite = 0xFFFFFFFF;
    private const uint SddlRevision1 = 1;
    private const string GuardSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

    private readonly EventWaitHandle _acquired = new(initialState: false, EventResetMode.ManualReset);
    private readonly EventWaitHandle _release = new(initialState: false, EventResetMode.ManualReset);
    private readonly Thread _ownerThread;
    private readonly List<nint> _ownedMutexes = [];
    private bool _ownsMutexes;
    private bool _disposed;

    private AgentInstanceGuard()
    {
        _ownerThread = new Thread(AcquireAndHold)
        {
            IsBackground = true,
            Name = AgentRuntimeIdentity.InstanceGuardThreadName
        };
    }

    public AgentInstanceGuardFailure? Failure { get; private set; }

    public static bool TryAcquire(
        out AgentInstanceGuard? guard,
        out AgentInstanceGuardFailure? failure)
    {
        var candidate = new AgentInstanceGuard();
        candidate._ownerThread.Start();
        candidate._acquired.WaitOne();
        if (candidate._ownsMutexes)
        {
            guard = candidate;
            failure = null;
            return true;
        }

        failure = candidate.Failure ?? new AgentInstanceGuardFailure(
            "InstanceGuardUnavailable",
            string.Empty,
            "The machine-global Agent host guard could not be acquired.");
        candidate.Dispose();
        guard = null;
        return false;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _release.Set();
        _ownerThread.Join();
        _release.Dispose();
        _acquired.Dispose();
    }

    private void AcquireAndHold()
    {
        try
        {
            foreach (var mutexName in AgentRuntimeIdentity.CompatibleInstanceMutexNames)
            {
                var handle = CreateProtectedMutex(mutexName);
                if (handle == 0)
                {
                    var error = Marshal.GetLastWin32Error();
                    Failure = new AgentInstanceGuardFailure(
                        error == 5 ? "InstanceGuardAccessDenied" : "InstanceGuardCreateFailed",
                        mutexName,
                        $"The Agent host guard '{mutexName}' could not be opened ({new Win32Exception(error).Message}).");
                    ReleaseOwnedMutexes();
                    return;
                }

                var wait = WaitForSingleObject(handle, 0);
                if (wait is not (WaitObject0 or WaitAbandoned))
                {
                    CloseHandle(handle);
                    Failure = wait == WaitTimeout
                        ? new AgentInstanceGuardFailure(
                            "AgentHostAlreadyRunning",
                            mutexName,
                            $"Another Interactive or LocalSystem Agent host owns '{mutexName}'.")
                        : new AgentInstanceGuardFailure(
                            "InstanceGuardWaitFailed",
                            mutexName,
                            $"The Agent host guard '{mutexName}' wait failed ({new Win32Exception(Marshal.GetLastWin32Error()).Message}).");
                    ReleaseOwnedMutexes();
                    return;
                }

                _ownedMutexes.Add(handle);
            }

            _ownsMutexes = true;
        }
        finally
        {
            _acquired.Set();
        }

        if (!_ownsMutexes)
        {
            return;
        }

        WaitForSingleObject(_release.SafeWaitHandle.DangerousGetHandle(), Infinite);
        ReleaseOwnedMutexes();
    }

    private static nint CreateProtectedMutex(string name)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                GuardSddl,
                SddlRevision1,
                out var descriptor,
                out _))
        {
            return 0;
        }

        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor,
                InheritHandle = false
            };
            return CreateMutex(ref attributes, initialOwner: false, name);
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    private void ReleaseOwnedMutexes()
    {
        for (var index = _ownedMutexes.Count - 1; index >= 0; index--)
        {
            ReleaseMutex(_ownedMutexes[index]);
            CloseHandle(_ownedMutexes[index]);
        }

        _ownedMutexes.Clear();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public nint SecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSdRevision,
        out nint securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("kernel32.dll", EntryPoint = "CreateMutexW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint CreateMutex(
        ref SecurityAttributes mutexAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool initialOwner,
        string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(nint handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReleaseMutex(nint mutex);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);

    [DllImport("kernel32.dll")]
    private static extern nint LocalFree(nint memory);
}
