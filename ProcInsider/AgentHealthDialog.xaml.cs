using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using ProcInsider.ViewModels;

namespace ProcInsider;

public partial class AgentHealthDialog : Window
{
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private CancellationTokenSource? _refreshCancellation;

    public AgentHealthDialog(
        AgentHealthDialogViewModel viewModel,
        MainViewModel commands)
    {
        Commands = commands;
        DataContext = viewModel;
        InitializeComponent();
        _refreshTimer.Tick += OnRefreshTimerTick;
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    public MainViewModel Commands { get; }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        _refreshCancellation = new CancellationTokenSource();
        if (DataContext is AgentHealthDialogViewModel { CanRefresh: true })
        {
            _refreshTimer.Start();
        }
    }

    private async void OnRefreshTimerTick(object? sender, EventArgs e)
    {
        await RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        if (_refreshCancellation == null ||
            DataContext is not AgentHealthDialogViewModel viewModel)
        {
            return;
        }

        await viewModel.RefreshAsync(_refreshCancellation.Token);
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        _refreshTimer.Stop();
        _refreshCancellation?.Cancel();
        _refreshCancellation?.Dispose();
        _refreshCancellation = null;
    }
}
