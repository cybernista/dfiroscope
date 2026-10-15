using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>Cycle-scoped native observations. The budget admits sequential calls; a native syscall cannot be forcibly cancelled.</summary>
internal sealed class NetworkEndpointProcessReader(NetworkEndpointProcessReader.QueryProcess? queryOverride = null, TimeSpan? budget = null,
    NetworkEndpointProcessReader.WaitProcess? waitOverride = null) : IDisposable
{
    private sealed record Owner(SafeProcessHandle Handle, DateTime StartUtc, NetworkEndpointProcessMetadata Metadata);
    private readonly Dictionary<int, Owner?> _owners = [];
    private readonly Dictionary<int, NetworkEndpointProcessMetadata> _failures = [];
    private readonly Stopwatch _budget = Stopwatch.StartNew();
    private readonly TimeSpan _limit = budget ?? TimeSpan.FromSeconds(2);
    private const string Method = "WaitForSingleObject(0) / GetProcessTimes / QueryFullProcessImageNameW / NtQueryInformationProcess(60)";
    internal NetworkEndpointNative Read(NetworkEndpointNative row, EvidenceIdentity scope, DateTime tableStartUtc, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!_owners.TryGetValue(row.ProcessId, out var owner))
        {
            owner = ReadOwner(row.ProcessId, token);
            _owners[row.ProcessId] = owner;
        }
        if (owner == null) return row with { Metadata = _failures.GetValueOrDefault(row.ProcessId) };
        var liveness = Liveness(owner.Handle);
        var verified = row.VerifyOwner(scope, owner.StartUtc, tableStartUtc, liveness == EndpointMetadataState.Available);
        return verified.Ownership == EndpointOwnership.VerifiedLifetime ? verified with { Metadata = owner.Metadata } :
            verified with { Metadata = Failure(liveness == EndpointMetadataState.Available ? EndpointMetadataState.Unavailable : liveness, DateTime.UtcNow) };
    }
    private Owner? ReadOwner(int pid, CancellationToken token)
    {
        var start = DateTime.UtcNow;
        if (pid <= 0 || _budget.Elapsed >= _limit) { _failures[pid] = Failure(pid <= 0 ? EndpointMetadataState.Unavailable : EndpointMetadataState.Timeout, start); return null; }
        var handle = OpenProcess(0x1000 | 0x00100000, false, pid);
        if (handle.IsInvalid) { var error = Marshal.GetLastWin32Error(); handle.Dispose(); _failures[pid] = Failure(error == 5 ? EndpointMetadataState.AccessDenied : EndpointMetadataState.Unavailable, start); return null; }
        try
        {
            var liveness = Liveness(handle);
            if (liveness != EndpointMetadataState.Available) { _failures[pid] = Failure(liveness, start); return null; }
            if (!GetProcessTimes(handle, out var creation, out _, out _, out _))
            { _failures[pid] = Failure(Marshal.GetLastWin32Error() == 5 ? EndpointMetadataState.AccessDenied : EndpointMetadataState.Unavailable, start); return null; }
            var nativeStart = DateTime.FromFileTimeUtc(creation);
            token.ThrowIfCancellationRequested();
            var path = new StringBuilder(32768); uint length = (uint)path.Capacity;
            var imageState = EndpointMetadataState.Timeout;
            string? image = null;
            if (_budget.Elapsed < _limit)
            {
                if (QueryFullProcessImageNameW(handle, 0, path, ref length)) { image = path.ToString(); imageState = EndpointMetadataState.Available; }
                else imageState = Marshal.GetLastWin32Error() == 5 ? EndpointMetadataState.AccessDenied : EndpointMetadataState.Unavailable;
            }
            var (command, commandState) = CommandLine(handle, token);
            token.ThrowIfCancellationRequested();
            var metadata = new NetworkEndpointProcessMetadata(image == null ? null : Path.GetFileName(image), image, command,
                imageState, imageState, commandState, start, DateTime.UtcNow, Method);
            var result = new Owner(handle, nativeStart, metadata);
            handle = null!;
            return result;
        }
        finally { handle?.Dispose(); }
    }
    private static NetworkEndpointProcessMetadata Failure(EndpointMetadataState state, DateTime start) =>
        new(null, null, null, state, state, state, start, DateTime.UtcNow, Method);
    private EndpointMetadataState Liveness(SafeProcessHandle handle)
    {
        var result = waitOverride == null ? WaitForSingleObject(handle, 0) : waitOverride(handle, 0);
        return result switch
        {
            0x102 => EndpointMetadataState.Available,
            0 => EndpointMetadataState.Exited,
            uint.MaxValue => Marshal.GetLastWin32Error() == 5 ? EndpointMetadataState.AccessDenied : EndpointMetadataState.Unavailable,
            _ => EndpointMetadataState.Unavailable
        };
    }
    private (string?, EndpointMetadataState) CommandLine(SafeProcessHandle handle, CancellationToken token)
    {
        if (_budget.Elapsed >= _limit) return (null, EndpointMetadataState.Timeout);
        // This native information class is optional and can change across Windows versions.
        if (!NativeLibrary.TryLoad("ntdll.dll", out var library)) return (null, EndpointMetadataState.Unsupported);
        try
        {
            if (!NativeLibrary.TryGetExport(library, "NtQueryInformationProcess", out var address)) return (null, EndpointMetadataState.Unsupported);
            var query = queryOverride ?? Marshal.GetDelegateForFunctionPointer<QueryProcess>(address);
            uint capacity = 4096;
            for (var attempt = 0; attempt < 3; attempt++)
            {
                token.ThrowIfCancellationRequested();
                if (_budget.Elapsed >= _limit) return (null, EndpointMetadataState.Timeout);
                if (capacity > 131072 || capacity < Marshal.SizeOf<UnicodeString>()) return (null, EndpointMetadataState.Unavailable);
                var buffer = Marshal.AllocHGlobal((int)capacity);
                try
                {
                    var status = query(handle, 60, buffer, capacity, out var needed);
                    token.ThrowIfCancellationRequested();
                    if (_budget.Elapsed >= _limit) return (null, EndpointMetadataState.Timeout);
                    if (status is unchecked((int)0xC0000004) or unchecked((int)0xC0000023)) { capacity = needed > capacity ? needed : capacity * 2; continue; }
                    if (status < 0) return (null, status == unchecked((int)0xC0000022) ? EndpointMetadataState.AccessDenied :
                        status is unchecked((int)0xC0000003) or unchecked((int)0xC0000002) ? EndpointMetadataState.Unsupported :
                        status == unchecked((int)0xC000010A) ? EndpointMetadataState.Exited : EndpointMetadataState.Unavailable);
                    var value = Marshal.PtrToStructure<UnicodeString>(buffer);
                    var offset = value.Buffer.ToInt64() - buffer.ToInt64();
                    if ((value.Length & 1) != 0 || value.Length > value.MaximumLength || offset < Marshal.SizeOf<UnicodeString>() ||
                        offset > capacity || value.Length > capacity - offset) return (null, EndpointMetadataState.Unavailable);
                    return (Marshal.PtrToStringUni(value.Buffer, value.Length / 2), EndpointMetadataState.Available);
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            return (null, EndpointMetadataState.Unavailable);
        }
        finally { NativeLibrary.Free(library); }
    }
    public void Dispose() { foreach (var owner in _owners.Values) owner?.Handle.Dispose(); _owners.Clear(); }
    [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate int QueryProcess(SafeProcessHandle process, int informationClass, IntPtr buffer, uint size, out uint needed);
    internal delegate uint WaitProcess(SafeProcessHandle process, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, StringBuilder image, ref uint size);
}
