using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

public sealed class WorkspaceContentTemplateSelector : DataTemplateSelector
{
    public DataTemplate? Processes { get; set; }
    public DataTemplate? Events { get; set; }
    public override DataTemplate? SelectTemplate(object item, DependencyObject container) => item switch
    {
        ProcessesWorkspaceViewModel => Processes,
        EventsWorkspaceViewModel => Events,
        _ => null
    };
}

public partial class WorkspaceShellView : UserControl
{
    public WorkspaceShellView()
    {
        InitializeComponent();
        WorkspaceTabs.ContentTemplateSelector = new WorkspaceContentTemplateSelector
        {
            Processes = (DataTemplate)Resources["ProcessesTemplate"], Events = (DataTemplate)Resources["EventsTemplate"]
        };
        WorkspaceTabs.SelectionChanged += WorkspaceSelectionChanged;
        AddHandler(Button.ClickEvent, new RoutedEventHandler(CloseWorkspace));
        PreviewMouseDown += (_, _) => CaptureLayout();
        PreviewKeyDown += (_, _) => CaptureLayout();
        Loaded += (_, _) => RestoreLayout();
        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is WorkspaceManager oldManager)
            {
                oldManager.ActiveContextChanging -= CaptureLayout;
                oldManager.ActiveContextChanged -= RestoreLayout;
            }
            if (e.NewValue is WorkspaceManager newManager)
            {
                newManager.ActiveContextChanging += CaptureLayout;
                newManager.ActiveContextChanged += RestoreLayout;
            }
        };
    }
    private IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) yield return match;
            foreach (var nested in Descendants<T>(child)) yield return nested;
        }
    }
    private void CaptureLayout()
    {
        var view = Descendants<ProcInsider.Views.Presentation.ProcessInvestigationView>(WorkspaceTabs).FirstOrDefault();
        if (view != null) PresentationUnloaded(view, new RoutedEventArgs());
    }
    private void RestoreLayout() => Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
    {
        var view = Descendants<ProcInsider.Views.Presentation.ProcessInvestigationView>(WorkspaceTabs).FirstOrDefault();
        if (view != null) PresentationLoaded(view, new RoutedEventArgs());
    }));
    private async void WorkspaceSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ReferenceEquals(e.OriginalSource, sender) && sender is TabControl tabs && DataContext is WorkspaceManager manager &&
            !manager.IsChangingInstances && tabs.SelectedItem is WorkspaceInstanceViewModel instance)
        {
            await manager.ActivateAsync(instance);
        }
    }
    private async void CloseWorkspace(object sender, RoutedEventArgs e)
    {
        if (DataContext is WorkspaceManager manager && e.OriginalSource is Button { Tag: "CloseWorkspace", DataContext: WorkspaceInstanceViewModel instance })
        {
            e.Handled = true;
            await manager.CloseAsync(instance);
        }
    }
    private ProcessesWorkspaceViewModel? Owner(object sender) =>
        sender is FrameworkElement { DataContext: ProcessPresentationViewModel p } && DataContext is WorkspaceManager manager
            ? manager.Instances.OfType<ProcessesWorkspaceViewModel>().FirstOrDefault(x => ReferenceEquals(x.Presentation, p)) : null;
    private void PresentationUnloaded(object sender, RoutedEventArgs e)
    {
        if (Owner(sender) is not { } instance || sender is not UserControl { Content: Grid grid }) return;
        instance.CapturePosition();
        instance.Layout = instance.Layout with { ListingWeight = grid.RowDefinitions[0].ActualHeight, DataWeight = grid.RowDefinitions[2].ActualHeight };
        var bottom = grid.Children.OfType<Grid>().Single(x => Grid.GetRow(x) == 2);
        instance.Layout = instance.Layout with { DataWidth = bottom.ColumnDefinitions[0].ActualWidth, DetailsWidth = bottom.ColumnDefinitions[2].ActualWidth };
    }
    private void PresentationLoaded(object sender, RoutedEventArgs e)
    {
        if (Owner(sender) is not { } instance || sender is not UserControl { Content: Grid grid } control) return;
        var layout = instance.Layout;
        if (layout.ListingWeight > 0 && layout.DataWeight > 0)
        {
            grid.RowDefinitions[0].Height = new GridLength(layout.ListingWeight, GridUnitType.Star);
            grid.RowDefinitions[2].Height = new GridLength(layout.DataWeight, GridUnitType.Star);
        }
        var bottom = grid.Children.OfType<Grid>().Single(x => Grid.GetRow(x) == 2);
        if (layout.DataWidth > 0 && layout.DetailsWidth > 0)
        {
            bottom.ColumnDefinitions[0].Width = new GridLength(layout.DataWidth, GridUnitType.Star);
            bottom.ColumnDefinitions[2].Width = new GridLength(layout.DetailsWidth, GridUnitType.Star);
        }
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
        {
            if (!control.IsLoaded || instance.IsDisposed || !ReferenceEquals(control.DataContext, instance.Presentation)) return;
            if (instance.Viewport is { } anchor && instance.Presentation._virtualizedProcessListing is { } rows)
            {
                var row = rows.GetLoadedRows().FirstOrDefault(x => !string.IsNullOrEmpty(anchor.ProcessEntityId)
                    ? x.ProcessInfo.ProcessEntityId == anchor.ProcessEntityId : x.ProcessKey == anchor.ProcessKey);
                if (row != null) instance.Presentation.RestoreViewport(row, anchor.RelativeOffset);
            }
        }));
    }
}
