using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text.Json;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed record RegistryAuditIdentityChain(string Path, string Current, string[] Previous);
internal sealed record RegistryAuditIdentityHistory(int Version, RegistryAuditIdentityChain[] Chains);

/// <summary>Agent-owned proof of successful handle-bound writes; portable files cannot add aliases.</summary>
internal abstract class RegistryAuditIdentityHistoryStore
{
    private const int MaxAliases = 256;
    private static readonly ConditionalWeakTable<IObjectAuditJournalStore, Memory> Fixtures = new();
    internal static RegistryAuditIdentityHistoryStore ForFixture(IObjectAuditJournalStore store) => Fixtures.GetValue(store, _ => new());
    internal abstract IDisposable Enter();
    protected abstract RegistryAuditIdentityHistory? ReadCore();
    protected abstract void WriteCore(RegistryAuditIdentityHistory history);

    private RegistryAuditIdentityHistory Read()
    {
        var history = ReadCore() ?? new(1, []);
        if (history.Version != 1 || history.Chains == null || history.Chains.Length > AgentObjectAccessAuditingService.MaxTargets ||
            history.Chains.Any(c => c == null || string.IsNullOrWhiteSpace(c.Path) || c.Path.Length > 4096 ||
                string.IsNullOrEmpty(c.Current) || c.Current.Length > 4096 || c.Previous == null || c.Previous.Length > MaxAliases ||
                c.Previous.Any(p => string.IsNullOrEmpty(p) || p.Length > 4096) || c.Previous.Distinct().Count() != c.Previous.Length) ||
            history.Chains.Select(c => c.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != history.Chains.Length)
            throw new InvalidOperationException("Registry audit identity history is malformed; identity aliases were not accepted.");
        return history;
    }

    internal bool Matches(string path, string saved, string current)
    {
        if (saved == current) return true;
        var chain = Read().Chains.SingleOrDefault(c => c.Path.Equals(path, StringComparison.OrdinalIgnoreCase));
        return chain != null && chain.Current == current && chain.Previous.Contains(saved);
    }

    internal void CheckCapacity(string path, string before)
    {
        var history = Read();
        var prior = history.Chains.SingleOrDefault(c => c.Path.Equals(path, StringComparison.OrdinalIgnoreCase));
        if ((prior == null && history.Chains.Length == AgentObjectAccessAuditingService.MaxTargets) ||
            (prior?.Current == before && prior.Previous.Length >= MaxAliases) ||
            JsonSerializer.SerializeToUtf8Bytes(history).Length > 24 * 1024 * 1024 - 32768)
            throw new InvalidOperationException("Registry audit identity history capacity reached; no registry write attempted.");
    }

    internal void Record(string path, string before, string after)
    {
        if (before == after) return;
        CheckCapacity(path, before);
        var history = Read();
        var prior = history.Chains.SingleOrDefault(c => c.Path.Equals(path, StringComparison.OrdinalIgnoreCase));
        // A fresh independently authorized baseline after outside drift starts a new chain.
        // Never connect old aliases across a gap in Agent-observed identity continuity.
        var aliases = (prior?.Current == before ? prior.Previous : []).Append(before).Distinct().ToArray();
        WriteCore(new(1, history.Chains.Where(c => !c.Path.Equals(path, StringComparison.OrdinalIgnoreCase))
            .Append(new(path, after, aliases)).ToArray()));
    }

    private sealed class Memory : RegistryAuditIdentityHistoryStore
    {
        private RegistryAuditIdentityHistory? _value;
        internal override IDisposable Enter() { Monitor.Enter(this); return new Lease(() => Monitor.Exit(this)); }
        protected override RegistryAuditIdentityHistory? ReadCore() => _value;
        protected override void WriteCore(RegistryAuditIdentityHistory history) => _value = history;
    }
    internal sealed class Lease(Action release) : IDisposable
    {
        private Action? _release = release;
        public void Dispose() => Interlocked.Exchange(ref _release, null)?.Invoke();
    }
}

internal sealed class RegistryAuditIdentityHistoryFile(MonitoringConfigurationStore store) : RegistryAuditIdentityHistoryStore
{
    private const string Slot = "registry-audit-identity-history-v1";
    internal override IDisposable Enter()
    {
        // Coarse per-user/host serialization also covers different capture sessions and installations.
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value ?? throw new InvalidOperationException("Registry history owner unavailable.");
        var mutex = new Mutex(false, @"Global\DFIRoscope.RegistryAuditIdentityHistory." + sid);
        try
        {
            try { if (!mutex.WaitOne(TimeSpan.FromSeconds(30))) throw new IOException("Registry recovery is busy in another Agent."); }
            catch (AbandonedMutexException) { /* Durable pending writes still fail closed below. */ }
            return new Lease(() => { mutex.ReleaseMutex(); mutex.Dispose(); });
        }
        catch { mutex.Dispose(); throw; }
    }
    protected override RegistryAuditIdentityHistory? ReadCore() => store.Read<RegistryAuditIdentityHistory>(Slot);
    protected override void WriteCore(RegistryAuditIdentityHistory history) => store.Write(Slot, history);
}
