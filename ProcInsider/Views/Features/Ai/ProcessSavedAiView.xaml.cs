using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using ProcInsider.Features.InvestigationWorkspaces;
using ProcInsider.ViewModels;

namespace ProcInsider.Views.Features.Ai;

public partial class ProcessSavedAiView : UserControl
{
    public ProcessSavedAiView() => InitializeComponent();

    private async void SavedItemSelected(object sender, SelectionChangedEventArgs e)
    {
        if (ProcessSavedAiItems.DataContext is ProcessSavedAiNavigationViewModel { IsUpdating: false } navigation &&
            e.AddedItems.Count > 0 && e.AddedItems[0] is ConversationExplorerEntry or InvestigationExplorerEntry)
            await navigation.OpenCommand.ExecuteAsync(e.AddedItems[0]);
    }

    private async void SavedItemMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (ProcessSavedAiItems.DataContext is not ProcessSavedAiNavigationViewModel { IsUpdating: false } navigation)
            return;
        var source = e.OriginalSource as DependencyObject;
        if (Ancestor<ButtonBase>(source) != null || Ancestor<ListBoxItem>(source) is not { IsSelected: true } item)
            return;
        if (item.DataContext is not (ConversationExplorerEntry or InvestigationExplorerEntry)) return;
        e.Handled = true;
        item.Focus();
        await navigation.OpenCommand.ExecuteAsync(item.DataContext);
    }

    private static T? Ancestor<T>(DependencyObject? source) where T : DependencyObject
    {
        while (source != null)
        {
            if (source is T match) return match;
            source = VisualTreeHelper.GetParent(source);
        }
        return null;
    }
}
