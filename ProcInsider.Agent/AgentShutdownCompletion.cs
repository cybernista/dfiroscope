using ProcInsider.Services.AgentIpc;

namespace ProcInsider.Agent;

/// <summary>Reports completed timed shutdown only after the host resource scope returns successfully.</summary>
internal sealed class AgentShutdownCompletion : IDisposable
{
    private readonly object _gate = new();
    private int _shutdownReason;
    internal bool ScheduledShutdownRequested { get { lock (_gate) return _shutdownReason == 1; } }

    internal void RequestShutdown(bool scheduledDuration, Action requestShutdown)
    {
        lock (_gate)
        {
            if (_shutdownReason != 0) return;
            _shutdownReason = scheduledDuration ? 1 : 2;
        }
        requestShutdown();
    }

    internal AgentPairingRuntime? Pairing { get; set; }
    internal Func<bool> DurationExpired { get; set; } = () => false;
    internal Func<bool> DrainSucceeded { get; set; } = () => false;

    internal void Complete(bool successful)
    {
        if (successful && ScheduledShutdownRequested && DurationExpired() && DrainSucceeded())
            Pairing?.RecordScheduledShutdownCompletion();
    }

    public void Dispose() => Pairing?.Dispose();
}
