namespace ProcInsider.Agent;

/// <summary>
/// Serializes Agent-owned host-monitoring reads and mutations so configuration,
/// deployment, reversal, and effective-state checks observe one ordered timeline.
/// </summary>
internal sealed class AgentHostMonitoringOperationGate
{
    private readonly object _sync = new();

    public T Execute<T>(Func<T> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        lock (_sync)
        {
            return operation();
        }
    }
}
