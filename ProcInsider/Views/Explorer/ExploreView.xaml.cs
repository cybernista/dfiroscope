using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using ProcInsider.ViewModels;

namespace ProcInsider.Views.Explorer;

public partial class ExploreView : UserControl
{
    private bool _suppressSelectionChanged;

    public ExploreView()
    {
        InitializeComponent();
    }

    private void ExplorerTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (_suppressSelectionChanged ||
            e.NewValue is not ExplorerNodeViewModel node ||
            DataContext is not ExplorerViewModel explorer)
        {
            return;
        }

        explorer.SelectNode(node, GetSelectionGesture());
    }

    private void ExplorerTree_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (FindAncestor<ButtonBase>(e.OriginalSource as DependencyObject) != null ||
            FindAncestor<TreeViewItem>(e.OriginalSource as DependencyObject) is not
                { DataContext: ExplorerNodeViewModel node } item ||
            DataContext is not ExplorerViewModel explorer)
        {
            return;
        }

        _suppressSelectionChanged = true;
        try
        {
            item.IsSelected = true;
            item.Focus();
        }
        finally
        {
            _suppressSelectionChanged = false;
        }

        explorer.SelectNode(node, GetSelectionGesture());
        e.Handled = true;
    }

    private async void ExplorerTreeItem_Expanded(object sender, RoutedEventArgs e)
    {
        if (!ReferenceEquals(sender, e.OriginalSource))
        {
            return;
        }

        if (sender is TreeViewItem { DataContext: ExplorerNodeViewModel node } &&
            DataContext is ExplorerViewModel explorer)
        {
            await explorer.ExpandNodeAsync(node);
        }
    }

    private static ExplorerSelectionGesture GetSelectionGesture()
    {
        var modifiers = Keyboard.Modifiers;
        if (modifiers.HasFlag(ModifierKeys.Shift))
        {
            return ExplorerSelectionGesture.Range;
        }

        return modifiers.HasFlag(ModifierKeys.Control)
            ? ExplorerSelectionGesture.Toggle
            : ExplorerSelectionGesture.Replace;
    }

    private static T? FindAncestor<T>(DependencyObject? current)
        where T : DependencyObject
    {
        while (current != null)
        {
            if (current is T match)
            {
                return match;
            }

            try
            {
                current = VisualTreeHelper.GetParent(current);
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }

        return null;
    }
}
