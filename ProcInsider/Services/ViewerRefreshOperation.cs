namespace ProcInsider.Services;

/// <summary>Owns one user-cancellable refresh lifetime; cancellation never stops Agent capture.</summary>
public sealed class ViewerRefreshOperation : IDisposable
{
    private readonly CancellationTokenSource _cancellation;
    private readonly object _gate = new();
    private bool _disposed;
    private bool _publishing;

    public ViewerRefreshOperation(CancellationToken callerToken) =>
        _cancellation = CancellationTokenSource.CreateLinkedTokenSource(callerToken);

    public CancellationToken Token => _cancellation.Token;
    public bool IsCancellationRequested => _cancellation.IsCancellationRequested;
    public bool CanCancel { get { lock (_gate) return !_disposed && !_publishing && !IsCancellationRequested; } }

    // Called inside the atomic dispatcher publication callback. A click received before
    // this point cancels; afterwards publication is already committing and must finish.
    public void BeginPublication()
    {
        lock (_gate)
        {
            _cancellation.Token.ThrowIfCancellationRequested();
            _publishing = true;
        }
    }

    public void Cancel()
    {
        lock (_gate)
        {
            if (!_disposed && !_publishing) _cancellation.Cancel();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _cancellation.Dispose();
        }
    }
}
