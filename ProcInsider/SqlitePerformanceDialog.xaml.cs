using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using ProcInsider.ViewModels;

namespace ProcInsider;

public partial class SqlitePerformanceDialog : Window
{
    private readonly Func<CancellationToken, Task<SqlitePerformanceDialogViewModel>> _refreshAsync;
    private readonly DispatcherTimer _refreshTimer;
    private readonly CancellationTokenSource _refreshCancellation = new();
    private bool _isRefreshing;

    public SqlitePerformanceDialog(
        SqlitePerformanceDialogViewModel viewModel,
        Func<CancellationToken, Task<SqlitePerformanceDialogViewModel>> refreshAsync)
    {
        _refreshAsync = refreshAsync ?? throw new ArgumentNullException(nameof(refreshAsync));
        DataContext = viewModel;
        InitializeComponent();

        _refreshTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _refreshTimer.Tick += RefreshTimer_Tick;
        Loaded += (_, _) => _refreshTimer.Start();
        Closed += SqlitePerformanceDialog_Closed;
    }

    private void SqlitePerformanceDialog_Closed(object? sender, EventArgs e)
    {
        _refreshTimer.Stop();
        _refreshTimer.Tick -= RefreshTimer_Tick;
        _refreshCancellation.Cancel();
        _refreshCancellation.Dispose();
    }

    private async void RefreshTimer_Tick(object? sender, EventArgs e)
    {
        if (_isRefreshing || _refreshCancellation.IsCancellationRequested)
        {
            return;
        }

        _isRefreshing = true;
        try
        {
            var refreshedViewModel = await _refreshAsync(_refreshCancellation.Token);
            if (!_refreshCancellation.IsCancellationRequested && IsLoaded)
            {
                DataContext = refreshedViewModel;
            }
        }
        catch (OperationCanceledException) when (_refreshCancellation.IsCancellationRequested)
        {
        }
        finally
        {
            _isRefreshing = false;
        }
    }
}
