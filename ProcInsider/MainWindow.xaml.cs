using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using ProcInsider.Models;
using ProcInsider.Services;
using ProcInsider.ViewModels;

namespace ProcInsider;

/// <summary>
/// Main window for the desktop process investigation tool.
/// </summary>
public partial class MainWindow : Window
{
    private MainViewModel? _viewModel;
    private bool _closeConfirmed;
    private bool _closeWorkflowInProgress;

    public MainWindow()
        : this(null)
    {
    }

    internal MainWindow(
        Features.Infrastructure.InfrastructureCaseWorkspaceFeatureDependencies?
            infrastructureCaseWorkspaceDependencies)
    {
        InitializeComponent();

        // Create and set the view model
        _viewModel = new MainViewModel(
            infrastructureCaseWorkspaceDependencies: infrastructureCaseWorkspaceDependencies);
        DataContext = _viewModel;
    }

    /// <summary>
    /// Handles window loaded event - starts process monitoring.
    /// </summary>
    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        if (_viewModel != null)
        {
            await _viewModel.InitializeAsync();
        }
    }

    /// <summary>
    /// Handles window closing event - stops process monitoring.
    /// </summary>
    private void Window_Closing(object sender, CancelEventArgs e)
    {
        if (_closeConfirmed)
        {
            _viewModel?.Shutdown();
            return;
        }

        // A Window is still in its closing transition while this event is executing.
        // Cancel first, then move the asynchronous prompt to the next dispatcher turn;
        // otherwise WPF can reject MessageBox.Show with "while a Window is closing".
        e.Cancel = true;
        if (_closeWorkflowInProgress)
        {
            return;
        }

        _closeWorkflowInProgress = true;
        Dispatcher.BeginInvoke(
            DispatcherPriority.Background,
            new Action(() => _ = ConfirmCloseAsync()));
    }

    private async Task ConfirmCloseAsync()
    {
        try
        {
            var viewModel = _viewModel;
            if (viewModel == null)
            {
                ConfirmAndClose();
                return;
            }

            var prompt = await viewModel.GetAgentShutdownPromptAsync();
            if (!string.IsNullOrWhiteSpace(prompt))
            {
                var result = AgentShutdownConfirmationDialog.ShowForViewerClose(
                    this,
                    prompt);

                if (result == AgentShutdownConfirmationChoice.Cancel)
                {
                    return;
                }

                if (result == AgentShutdownConfirmationChoice.Terminate)
                {
                    var stopped = await viewModel.ShutdownAgentForActiveSessionAsync();
                    if (!stopped)
                    {
                        var guidance = viewModel.IsAgentLateExitObservationActive
                            ? "The bounded close-time grace period ended, but the viewer is still observing only the exact verified process. Shutdown controls remain disabled during that observation; if the process exits, stopped/disconnected state will reconcile automatically."
                            : "You can retry Terminate Agent, wait for current work to finish, or choose Leave Agent Running on close.";
                        MessageBox.Show(
                            this,
                            $"{ProductIdentity.AgentDisplayName} did not stop within the verified shutdown waits. {ProductIdentity.DisplayName} will stay open. {guidance}",
                            "Agent Still Running",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                        return;
                    }
                }

                ConfirmAndClose();
                return;
            }

            ConfirmAndClose();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                $"{ProductIdentity.DisplayName} could not prepare the agent shutdown prompt. The application will remain open.\n\n{ex.Message}",
                $"Close {ProductIdentity.DisplayName}",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            _closeWorkflowInProgress = false;
        }
    }

    private void ConfirmAndClose()
    {
        _closeConfirmed = true;
        Close();
    }

    internal CrashDiagnosticContext CreateCrashDiagnosticContext(string lifecycleState)
        => _viewModel?.CreateCrashDiagnosticContext(lifecycleState) ??
           new CrashDiagnosticContext { ViewerLifecycleState = lifecycleState };

    internal void PrepareForFatalShutdown()
    {
        // Bypass the asynchronous agent prompt. Fatal shutdown must not submit
        // agent stop/cancel/write commands from a fragile exception path.
        _closeConfirmed = true;
        _closeWorkflowInProgress = false;
    }

    internal static void SynchronizeProcessSortIndicators(DataGrid grid, Func<string, ListSortDirection?> getDirection)
        => Views.Presentation.ProcessInvestigationView.SynchronizeProcessSortIndicators(grid, getDirection);

    internal static void ApplyProcessSortIndicators(DataGrid grid, DataGridColumn activeColumn, ListSortDirection? direction)
        => Views.Presentation.ProcessInvestigationView.ApplyProcessSortIndicators(grid, activeColumn, direction);
}
