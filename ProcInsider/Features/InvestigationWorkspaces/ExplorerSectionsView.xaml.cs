using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

public partial class ExplorerSectionsView : UserControl
{
    private bool _selecting;
    public ExplorerSectionsView()
    {
        InitializeComponent();
        AddHandler(TreeView.SelectedItemChangedEvent, new RoutedPropertyChangedEventHandler<object>(NodeSelected));
        AddHandler(TreeViewItem.ExpandedEvent, new RoutedEventHandler(NodeExpanded));
        PreviewMouseLeftButtonDown += NodeMouseDown;
    }
    private async void NodeSelected(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (!_selecting && e.NewValue is EventsPivot pivot && DataContext is ExplorerSectionsViewModel { Events: { } events })
            await events.SelectCommand.ExecuteAsync(pivot);
        if (!_selecting && e.NewValue is SysmonExplorerNode sysmon && DataContext is ExplorerSectionsViewModel { Events: { } sysmonEvents })
            await sysmonEvents.SelectSysmonCommand.ExecuteAsync(sysmon);
        if (!_selecting && e.NewValue is ExplorerNodeViewModel node && DataContext is ExplorerSectionsViewModel model)
            await model.NavigateAsync(node);
    }
    private async void NodeMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (Ancestor<ButtonBase>(e.OriginalSource as DependencyObject) != null ||
            Ancestor<TreeViewItem>(e.OriginalSource as DependencyObject) is not { DataContext: ExplorerNodeViewModel node } item ||
            DataContext is not ExplorerSectionsViewModel model) return;
        _selecting = true;
        try { item.IsSelected = true; item.Focus(); }
        finally { _selecting = false; }
        e.Handled = true;
        await model.NavigateAsync(node, gesture: Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) ? ExplorerSelectionGesture.Range :
            Keyboard.Modifiers.HasFlag(ModifierKeys.Control) ? ExplorerSelectionGesture.Toggle : ExplorerSelectionGesture.Replace);
    }
    private async void NodeExpanded(object sender, RoutedEventArgs e)
    {
        if (e.OriginalSource is TreeViewItem { DataContext: ExplorerNodeViewModel node } &&
            DataContext is ExplorerSectionsViewModel model) await model.Explorer.ExpandNodeAsync(node);
    }
    private static T? Ancestor<T>(DependencyObject? node) where T : DependencyObject
    {
        while (node != null) { if (node is T match) return match; node = VisualTreeHelper.GetParent(node); }
        return null;
    }
}

public sealed class ExplorerTreeItemStyleSelector : StyleSelector
{
    public override Style SelectStyle(object item, DependencyObject container) =>
        (Style)((FrameworkElement)container).FindResource(item switch
        {
            EventsExplorerViewModel => "EventsRootStyle", EventsPivot => "EventPivotStyle", SysmonExplorerNode => "SysmonNodeStyle",
            EventsExplorerSection { Dimension: EventAggregateDimension.Identity } => "IdentityCategoryStyle",
            EventsExplorerSection => "EventCategoryStyle",
            EventsCategoryPlaceholder => "EventPlaceholderStyle", _ => "ProcessNodeStyle"
        });
}
