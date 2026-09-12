using System.Diagnostics;
using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace ProcInsider.Services;

public sealed record SqliteWorkProgress(
    long StageId, string Stage, long Completed, long? Total, string Unit,
    long DatabaseOperations, TimeSpan Elapsed);

/// <summary>
/// Operation-local progress and cancellation propagated through background query calls.
/// No timer estimates completion. SQLite's progress callback counts executed VM instructions
/// and interrupts on its own execution thread; SqliteCommand.Cancel is a no-op in our provider.
/// Connections installed here are unpooled and close with their owning query.
/// </summary>
public sealed class SqliteWorkScope : IDisposable
{
    private static readonly AsyncLocal<SqliteWorkScope?> Ambient = new();
    private static long _nextStageId;
    private readonly SqliteWorkScope? _previous;
    private readonly IProgress<SqliteWorkProgress>? _progress;
    private readonly Stopwatch _timer = Stopwatch.StartNew();
    private readonly long _id = Interlocked.Increment(ref _nextStageId);
    private long _operations;
    private long _lastReport;
    private long _completed;
    private long? _total;
    private string _unit;
    private bool _disposed;

    public SqliteWorkScope(CancellationToken cancellationToken,
        IProgress<SqliteWorkProgress>? progress = null, string stage = "Preparing refresh",
        long? total = null, string unit = "items")
    {
        _previous = Ambient.Value;
        CancellationToken = cancellationToken.CanBeCanceled ? cancellationToken :
            _previous?.CancellationToken ?? cancellationToken;
        _progress = progress ?? _previous?._progress;
        Stage = stage;
        _total = total;
        _unit = unit;
        Ambient.Value = this;
        Report(force: true);
    }

    public string Stage { get; }
    public CancellationToken CancellationToken { get; }
    public static SqliteWorkScope? Current => Ambient.Value;
    internal bool HasProgressObserver => _progress != null;

    public static SqliteWorkScope Begin(string stage, long? total = null, string unit = "items") =>
        new(Current?.CancellationToken ?? CancellationToken.None, stage: stage, total: total, unit: unit);

    /// <summary>Recovery must reopen the previous binding even when the failed operation was canceled.</summary>
    public static IDisposable Suppress()
    {
        var previous = Ambient.Value;
        Ambient.Value = null;
        return new RestoreScope(previous);
    }

    private sealed class RestoreScope(SqliteWorkScope? previous) : IDisposable
    {
        public void Dispose() => Ambient.Value = previous;
    }

    public void Advance(long completed, long? total = null, string? unit = null)
    {
        var firstMeasuredWork = _completed == 0 && completed > 0;
        _completed = completed;
        _total = total ?? _total;
        _unit = unit ?? _unit;
        Report(force: firstMeasuredWork || (_total.HasValue && _completed == _total.Value));
    }

    internal static void Install(SqliteConnection connection)
    {
        var scope = Current;
        if (scope == null || (!scope.CancellationToken.CanBeCanceled && !scope.HasProgressObserver)) return;
        scope.CancellationToken.ThrowIfCancellationRequested();
        // The provider retains this callback until the unpooled native connection closes.
        raw.sqlite3_progress_handler(connection.Handle!, 10000, _ =>
        {
            if (scope.CancellationToken.IsCancellationRequested) return 1;
            var stage = Current ?? scope;
            stage._operations += 10000;
            stage.Report();
            return scope.CancellationToken.IsCancellationRequested ? 1 : 0;
        }, null);
    }

    private void Report(bool force = false)
    {
        var elapsed = _timer.ElapsedMilliseconds;
        if (!force && elapsed - _lastReport < 200) return;
        _lastReport = elapsed;
        // Progress is diagnostic; never let a UI callback throw across a native SQLite frame.
        try
        {
            _progress?.Report(new(_id, Stage, _completed, _total, _unit, _operations, _timer.Elapsed));
        }
        catch { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Report(force: true);
        Ambient.Value = _previous;
    }
}
