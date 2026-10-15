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
        if (!_selecting && e.NewValue is AiExplorerNode ai && DataContext is ExplorerSectionsViewModel { IsUpdatingAiInventory: false } aiModel)
            await aiModel.NavigateAiCommand.ExecuteAsync(ai);
        if (!_selecting && e.NewValue is ArtifactsExplorerViewModel artifactsRootModel) await artifactsRootModel.SelectCommand.ExecuteAsync(artifactsRootModel.Root);
        if (!_selecting && e.NewValue is PersistenceExplorerNode persistence && DataContext is ExplorerSectionsViewModel { Persistence: { } persistenceRoot }) await persistenceRoot.SelectCommand.ExecuteAsync(persistence);
        if (!_selecting && e.NewValue is ArtifactsExplorerNode artifacts && DataContext is ExplorerSectionsViewModel { Artifacts: { } artifactsRoot }) await artifactsRoot.SelectCommand.ExecuteAsync(artifacts);
        if(!_selecting && IsKeyboardFocusWithin && e.NewValue is NetworkExplorerNode network && DataContext is ExplorerSectionsViewModel {Network:{ } root} && !root.IsRecalculating)await root.SelectCommand.ExecuteAsync(network);
        if (!_selecting && e.NewValue is EventsPivot pivot && DataContext is ExplorerSectionsViewModel { Events: { } events })
            await events.SelectCommand.ExecuteAsync(pivot);
        if (!_selecting && e.NewValue is SysmonExplorerNode sysmon && DataContext is ExplorerSectionsViewModel { Events: { } sysmonEvents })
            await sysmonEvents.SelectSysmonCommand.ExecuteAsync(sysmon);
        if (!_selecting && e.NewValue is ExplorerNodeViewModel node && DataContext is ExplorerSectionsViewModel model)
            await model.NavigateAsync(node);
    }
    private async void NodeMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (Ancestor<ButtonBase>(e.OriginalSource as DependencyObject) == null &&
            Ancestor<TreeViewItem>(e.OriginalSource as DependencyObject) is { } aiItem &&
            aiItem.DataContext is AiExplorerNode &&
            DataContext is ExplorerSectionsViewModel aiModel)
        {
            _selecting = true;
            try { aiItem.IsSelected = true; aiItem.Focus(); }
            finally { _selecting = false; }
            e.Handled = true;
            await aiModel.NavigateAiCommand.ExecuteAsync((AiExplorerNode)aiItem.DataContext);
            return;
        }
        if (Ancestor<ButtonBase>(e.OriginalSource as DependencyObject) == null &&
            Ancestor<TreeViewItem>(e.OriginalSource as DependencyObject) is { } artifactsItem &&
            artifactsItem.DataContext is ArtifactsExplorerNode or ArtifactsExplorerViewModel &&
            DataContext is ExplorerSectionsViewModel { Artifacts: { } artifactsRoot })
        {
            var artifacts = artifactsItem.DataContext is ArtifactsExplorerNode artifactsNode ? artifactsNode : artifactsRoot.Root;
            _selecting = true;
            try { artifactsItem.IsSelected = true; artifactsItem.Focus(); }
            finally { _selecting = false; }
            e.Handled = true;
            await artifactsRoot.SelectCommand.ExecuteAsync(artifacts);
            return;
        }
        if (Ancestor<ButtonBase>(e.OriginalSource as DependencyObject) == null &&
            Ancestor<TreeViewItem>(e.OriginalSource as DependencyObject) is { DataContext: NetworkExplorerNode network } networkItem &&
            DataContext is ExplorerSectionsViewModel { Network: { } networkRoot })
        {
            _selecting = true;
            try { networkItem.IsSelected = true; networkItem.Focus(); }
            finally { _selecting = false; }
            e.Handled = true;
            await networkRoot.SelectCommand.ExecuteAsync(network);
            return;
        }
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
    public Style AiNodeStyle { get; set; } = null!;
    public Style ProcessNodeStyle { get; set; } = null!;
    public Style PersistenceNodeStyle { get; set; } = null!;
    public Style ArtifactsRootStyle { get; set; } = null!;
    public Style ArtifactsNodeStyle { get; set; } = null!;
    public Style EventCategoryStyle { get; set; } = null!;
    public Style NetworkDirectoryStyle { get; set; } = null!;
    public Style NetworkNodeStyle { get; set; } = null!;
    public Style NetworkPagingStyle { get; set; } = null!;
    public Style EventsRootStyle { get; set; } = null!;
    public Style EventPivotStyle { get; set; } = null!;
    public Style SysmonNodeStyle { get; set; } = null!;
    public Style IdentityCategoryStyle { get; set; } = null!;
    public Style EventPlaceholderStyle { get; set; } = null!;

    // Local styles are supplied by the view; generated containers may be detached during rebuilding.
    public override Style SelectStyle(object item, DependencyObject container) => item switch
    {
        AiExplorerNode => AiNodeStyle,
        AiExplorerMore => NetworkPagingStyle,
        PersistenceExplorerViewModel => EventCategoryStyle,
        PersistenceExplorerNode => PersistenceNodeStyle,
        ArtifactsExplorerViewModel => ArtifactsRootStyle,
        ArtifactsExplorerNode => ArtifactsNodeStyle,
        NetworkExplorerViewModel => EventCategoryStyle,
        NetworkEndpointDirectory => NetworkDirectoryStyle,
        NetworkProcessDirectory => NetworkDirectoryStyle,
        NetworkExplorerNode => NetworkNodeStyle,
        NetworkDirectoryMore => NetworkPagingStyle,
        EventsExplorerViewModel => EventsRootStyle, EventsPivot => EventPivotStyle, SysmonExplorerNode => SysmonNodeStyle,
        EventsExplorerSection { Dimension: EventAggregateDimension.Identity } => IdentityCategoryStyle,
        EventsExplorerSection => EventCategoryStyle,
        EventsCategoryPlaceholder => EventPlaceholderStyle, _ => ProcessNodeStyle
    };
}
