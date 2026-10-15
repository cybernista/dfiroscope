using System.Collections.Concurrent;

namespace ProcInsider.Agent;

/// <summary>Process-lifetime admission for one explicit Prefetch command ID; durable receipts remain the replay authority after restart.</summary>
internal sealed class PrefetchCommandAdmissionCache : IDisposable
{
    private readonly ConcurrentDictionary<Guid, Lazy<Task<Guid>>> _admissions = new();
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<Guid> AdmitAsync(Guid commandId, Func<CancellationToken, Task<Guid>> enqueue, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(enqueue);
        var candidate = new Lazy<Task<Guid>>(
            () => EnqueueUnderGateAsync(enqueue, cancellationToken),
            LazyThreadSafetyMode.ExecutionAndPublication);
        var admission = _admissions.GetOrAdd(commandId, candidate);
        try { return await admission.Value.ConfigureAwait(false); }
        catch
        {
            TryRemoveExact(commandId, admission);
            throw;
        }
    }

    internal bool TryRemoveExact(Guid commandId, Lazy<Task<Guid>> admission)
        => ((ICollection<KeyValuePair<Guid, Lazy<Task<Guid>>>>)_admissions).Remove(new(commandId, admission));

    private async Task<Guid> EnqueueUnderGateAsync(Func<CancellationToken, Task<Guid>> enqueue, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return await enqueue(cancellationToken).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    public void Dispose() => _gate.Dispose();
}
