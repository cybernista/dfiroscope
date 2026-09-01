using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
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
    private bool _isRestoringProcessViewport;

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
        _viewModel.ProcessRowNavigationRequested += row =>
            Dispatcher.BeginInvoke(
                DispatcherPriority.Background,
                new Action(() => ProcessDataGrid.ScrollIntoView(row)));
        _viewModel.ProcessViewportAnchorCaptureRequested += CaptureProcessViewportAnchor;
        _viewModel.ProcessViewportAnchorRestoreRequested += RestoreProcessViewportAnchor;
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

    /// <summary>
    /// Handles DataGrid sorting to use custom tree-aware sorting for ProcessName.
    /// </summary>
    private void ProcessDataGrid_Sorting(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true; // We handle sorting ourselves

        if (_viewModel == null || e.Column.SortMemberPath == null)
            return;

        // Get column name for sorting
        var columnName = e.Column.SortMemberPath;

        ListSortDirection? direction;
        if (string.Equals(columnName, "Tree", System.StringComparison.OrdinalIgnoreCase))
        {
            _viewModel.ResetTreeSort();
            direction = null;
        }
        else
        {
            _viewModel.SortVisibleProcessRows(columnName);
            direction = _viewModel.GetSortDirection(columnName);
        }

        e.Column.SortDirection = direction;

        // Clear sort direction on other columns
        foreach (var column in ProcessDataGrid.Columns)
        {
            if (column != e.Column)
            {
                column.SortDirection = null;
            }
        }
    }

    private void ProcessDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is DataGrid grid && grid.SelectedItem is ProcessListingPlaceholder)
        {
            grid.UnselectAll();
        }
    }

    private void ProcessDataGrid_LoadingRow(object sender, DataGridRowEventArgs e)
    {
        _viewModel?.RequestProcessListingRange(e.Row.GetIndex(), 1);
    }

    private void ProcessDataGrid_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (!_isRestoringProcessViewport &&
            (Math.Abs(e.VerticalChange) > double.Epsilon ||
             Math.Abs(e.ViewportHeightChange) > double.Epsilon))
        {
            _viewModel?.NotifyProcessViewportChanged();
        }
    }

    private ViewerProcessViewportAnchor? CaptureProcessViewportAnchor()
    {
        var row = FindVisualChildren<DataGridRow>(ProcessDataGrid)
            .Select(candidate => new
            {
                Row = candidate,
                Top = candidate.TranslatePoint(new Point(0, 0), ProcessDataGrid).Y
            })
            .Where(candidate =>
                candidate.Row.DataContext is ProcessRowViewModel &&
                candidate.Top + candidate.Row.ActualHeight > 0 &&
                candidate.Top < ProcessDataGrid.ActualHeight)
            .OrderBy(candidate => candidate.Top)
            .FirstOrDefault();
        if (row?.Row.DataContext is not ProcessRowViewModel process)
        {
            return null;
        }

        return new ViewerProcessViewportAnchor(
            process.ProcessInfo.ProcessEntityId ?? string.Empty,
            process.ProcessKey,
            row.Top);
    }

    private void RestoreProcessViewportAnchor(ProcessRowViewModel row, double relativeOffset)
    {
        _isRestoringProcessViewport = true;
        ProcessDataGrid.ScrollIntoView(row);
        Dispatcher.BeginInvoke(
            DispatcherPriority.Loaded,
            new Action(() =>
            {
                try
                {
                    ProcessDataGrid.UpdateLayout();
                    if (ProcessDataGrid.ItemContainerGenerator.ContainerFromItem(row) is not DataGridRow container ||
                        FindVisualChild<ScrollViewer>(ProcessDataGrid) is not { } scrollViewer)
                    {
                        return;
                    }

                    var currentOffset = container.TranslatePoint(
                        new Point(0, 0),
                        ProcessDataGrid).Y;
                    scrollViewer.ScrollToVerticalOffset(
                        Math.Max(0, scrollViewer.VerticalOffset + currentOffset - relativeOffset));
                }
                finally
                {
                    _isRestoringProcessViewport = false;
                }
            }));
    }

    private static T? FindVisualChild<T>(DependencyObject parent)
        where T : DependencyObject
        => FindVisualChildren<T>(parent).FirstOrDefault();

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject parent)
        where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match)
            {
                yield return match;
            }

            foreach (var descendant in FindVisualChildren<T>(child))
            {
                yield return descendant;
            }
        }
    }

}
