namespace ProcInsider.Cli;

internal interface ICliInterruptSource : IDisposable
{
    event EventHandler? InterruptRequested;
}

internal sealed class SystemCliInterruptSource : ICliInterruptSource
{
    private bool _disposed;

    public SystemCliInterruptSource()
    {
        Console.CancelKeyPress += OnCancelKeyPress;
    }

    public event EventHandler? InterruptRequested;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Console.CancelKeyPress -= OnCancelKeyPress;
    }

    private void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs eventArgs)
    {
        eventArgs.Cancel = true;
        InterruptRequested?.Invoke(this, EventArgs.Empty);
    }
}

internal sealed class NullCliInterruptSource : ICliInterruptSource
{
    public event EventHandler? InterruptRequested
    {
        add { }
        remove { }
    }

    public void Dispose()
    {
    }
}
