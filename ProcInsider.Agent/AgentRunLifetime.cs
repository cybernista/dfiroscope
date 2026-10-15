namespace ProcInsider.Agent;

/// <summary>Foreground process lifetime, including idle time. Only explicit authenticated setup changes it.</summary>
internal sealed class AgentRunLifetime : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly SemaphoreSlim _changed = new(0, 1);
    private readonly CancellationTokenSource _stop = new();
    private readonly Action _requestShutdown;
    private readonly TimeProvider _clock;
    private readonly Func<TimeSpan, CancellationToken, Task<bool>> _wait;
    private readonly Task _worker;
    private int? _minutes;
    private long _started;
    private long _revision;
    private bool _expired;
    private bool _disposed;

    internal AgentRunLifetime(Action requestShutdown, TimeProvider? clock = null,
        Func<TimeSpan, CancellationToken, Task<bool>>? wait = null)
    {
        _requestShutdown = requestShutdown;
        _clock = clock ?? TimeProvider.System;
        _wait = wait ?? ((timeout, token) => _changed.WaitAsync(timeout, token));
        _worker = Task.Run(RunAsync);
    }

    internal bool HasExpired { get { lock (_gate) return _expired; } }

    internal bool TryConfigure(int? minutes)
    {
        if (minutes is <= 0) return false;
        lock (_gate)
        {
            if (_disposed || _expired) return false;
            _minutes = minutes;
            _started = _clock.GetTimestamp();
            _revision++;
            if (_changed.CurrentCount == 0) _changed.Release();
            return true;
        }
    }

    private async Task RunAsync()
    {
        try
        {
            while (true)
            {
                int? minutes;
                long started, revision;
                lock (_gate)
                {
                    if (_disposed || _expired) return;
                    minutes = _minutes; started = _started; revision = _revision;
                }
                if (minutes is null)
                {
                    await _wait(Timeout.InfiniteTimeSpan, _stop.Token).ConfigureAwait(false);
                    continue;
                }
                var remaining = TimeSpan.FromMinutes(minutes.Value) - _clock.GetElapsedTime(started);
                if (remaining <= TimeSpan.Zero)
                {
                    lock (_gate)
                    {
                        if (_disposed) return;
                        if (_revision != revision) continue;
                        _expired = true;
                        _requestShutdown();
                    }
                    return;
                }
                // Positive Int32 minute values exceed timer limits. Recheck monotonic elapsed time in bounded chunks.
                await _wait(remaining > TimeSpan.FromDays(1) ? TimeSpan.FromDays(1) : remaining,
                    _stop.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
    }

    public async ValueTask DisposeAsync()
    {
        lock (_gate) _disposed = true;
        _stop.Cancel();
        await _worker.ConfigureAwait(false);
        _stop.Dispose();
        _changed.Dispose();
    }
}
