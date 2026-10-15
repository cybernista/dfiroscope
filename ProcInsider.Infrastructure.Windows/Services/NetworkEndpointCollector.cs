using System.ComponentModel;

using System.Net;
using System.Runtime.InteropServices;
using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>Agent-invoked read-only IP Helper inventory. Each native family is independently complete or failed.</summary>
public sealed class NetworkEndpointCollector(TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private NetworkEndpointProcessReader? _cycle;
    public IDisposable BeginCycle()
    {
        if (_cycle != null) throw new InvalidOperationException("Endpoint collection cycles cannot overlap.");
        _cycle = new NetworkEndpointProcessReader();
        return new Cycle(this);
    }
    private sealed class Cycle(NetworkEndpointCollector collector) : IDisposable
    {
        public void Dispose() { collector._cycle?.Dispose(); collector._cycle = null; }
    }
    public NetworkEndpointFamilyResult Collect(EndpointFamily family, bool connections, EvidenceIdentity scope,
        CancellationToken cancellationToken)
    {
        var start = _clock.GetUtcNow().UtcDateTime;
        using var localReader = _cycle == null ? new NetworkEndpointProcessReader() : null;
        var reader = _cycle ?? localReader!;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var tcp = family is EndpointFamily.TcpV4 or EndpointFamily.TcpV6;
            var v6 = family is EndpointFamily.TcpV6 or EndpointFamily.UdpV6;
            var af = v6 ? 23u : 2u;
            uint size = 0;
            uint Call(IntPtr p) => tcp ? GetExtendedTcpTable(p, ref size, false, af, connections ? 8 : 6, 0)
                : GetExtendedUdpTable(p, ref size, false, af, 2, 0);
            var code = Call(IntPtr.Zero);
            if (code != 122 && code != 0) throw new Win32Exception((int)code);
            for (var attempt = 0; attempt < 4; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (size < 4 || size > 64 * 1024 * 1024) throw new InvalidOperationException("Invalid or excessive native table size.");
                var capacity = size;
                var buffer = Marshal.AllocHGlobal(checked((int)capacity));
                try
                {
                    code = Call(buffer);
                    if (code == 122) continue;
                    if (code != 0) throw new Win32Exception((int)code);
                    // OWNER_MODULE tables align their first row to eight bytes (LARGE_INTEGER).
                    var stride = tcp ? v6 ? 192 : 160 : v6 ? 176 : 160;
                    var count = Marshal.ReadInt32(buffer);
                    if (count < 0 || count > 0 && 8L + (long)count * stride > capacity) throw new InvalidOperationException("Truncated native endpoint table.");
                    var rows = new List<NetworkEndpointNative>(count);
                    for (var i = 0; i < count; i++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var p = IntPtr.Add(buffer, checked(8 + i * stride));
                        uint U(int offset) => unchecked((uint)Marshal.ReadInt32(p, offset));
                        string Address(int offset) { var bytes = new byte[v6 ? 16 : 4]; Marshal.Copy(IntPtr.Add(p, offset), bytes, 0, bytes.Length); return new IPAddress(bytes).ToString(); }
                        int Port(int offset) => (int)(((U(offset) & 255) << 8) | ((U(offset) >> 8) & 255));
                        var state = tcp ? (int?)U(v6 ? 48 : 0) : null;
                        var pid = checked((int)U(tcp ? v6 ? 52 : 20 : v6 ? 24 : 8));
                        var nativeTime = Marshal.ReadInt64(p, tcp ? v6 ? 56 : 24 : v6 ? 32 : 16);
                        DateTime? created = null;
                        try { if (nativeTime > 0) created = DateTime.FromFileTimeUtc(nativeTime); } catch (ArgumentOutOfRangeException) { }
                        var row = new NetworkEndpointNative(family, Address(tcp && !v6 ? 4 : 0), v6 ? U(16) : 0,
                            Port(v6 ? 20 : tcp ? 8 : 4), tcp && state != 2 ? Address(v6 ? 24 : 12) : null,
                            tcp && v6 && state != 2 ? U(40) : null, tcp && state != 2 ? Port(v6 ? 44 : 16) : null,
                            state, pid, created);
                        row = reader.Read(row, scope, start, cancellationToken);
                        rows.Add(row);
                    }
                    return new(family, start, _clock.GetUtcNow().UtcDateTime, EndpointPollOutcome.Complete, rows, FreshOwners: rows.Where(r => r.Ownership == EndpointOwnership.VerifiedLifetime && r.Metadata != null).DistinctBy(r => r.ProcessEntityId).ToArray());
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            throw new InvalidOperationException("Native endpoint table changed size repeatedly; coverage is unknown.");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or OverflowException)
        { return new(family, start, _clock.GetUtcNow().UtcDateTime, EndpointPollOutcome.Failed, [], ex.Message); }
    }
    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedTcpTable(IntPtr table, ref uint size,
        [MarshalAs(UnmanagedType.Bool)] bool order, uint af, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedUdpTable(IntPtr table, ref uint size,
        [MarshalAs(UnmanagedType.Bool)] bool order, uint af, int tableClass, uint reserved);
}
