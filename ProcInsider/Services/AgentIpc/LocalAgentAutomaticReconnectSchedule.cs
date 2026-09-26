namespace ProcInsider.Services.AgentIpc;

/// <summary>
/// Schedules full, authenticated local-agent recovery after a lost Viewer connection.
/// The caller owns the recovery operation and reports its completion before another begins.
/// </summary>
public sealed class LocalAgentAutomaticReconnectSchedule
{
    private static readonly TimeSpan FastWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FastInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan SlowInterval = TimeSpan.FromSeconds(15);

    private DateTime? _disconnectedSinceUtc;
    private DateTime _nextAttemptUtc;
    private long _version;
    private long? _activeAttempt;

    public DateTime? DisconnectedSinceUtc => _disconnectedSinceUtc;

    public DateTime NextAttemptUtc => _nextAttemptUtc;

    public bool TryBegin(DateTime nowUtc, out long attemptId)
    {
        attemptId = 0;
        if (_activeAttempt.HasValue)
        {
            return false;
        }

        _disconnectedSinceUtc ??= nowUtc;
        if (nowUtc < _nextAttemptUtc)
        {
            return false;
        }

        attemptId = ++_version;
        _activeAttempt = attemptId;
        return true;
    }

    public void Complete(long attemptId, DateTime nowUtc, bool connected)
    {
        if (_activeAttempt != attemptId)
        {
            return;
        }

        _activeAttempt = null;
        if (connected)
        {
            Reset();
            return;
        }

        var interval = nowUtc - _disconnectedSinceUtc.GetValueOrDefault(nowUtc) < FastWindow
            ? FastInterval
            : SlowInterval;
        _nextAttemptUtc = nowUtc.Add(interval);
    }

    public void Reset()
    {
        _disconnectedSinceUtc = null;
        _nextAttemptUtc = DateTime.MinValue;
        _activeAttempt = null;
        _version++;
    }
}
