using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace ProcInsider.Features.InvestigationWorkspaces;
public partial class AiWorkspaceView : UserControl
{
    public AiWorkspaceView() => InitializeComponent();
    private async void SavedItemSelected(object sender, SelectionChangedEventArgs e)
    {
        if (DataContext is AiWorkspaceViewModel { IsUpdatingSavedItems: false } model &&
            e.AddedItems.Count > 0 && e.AddedItems[0] is ConversationExplorerEntry or InvestigationExplorerEntry)
            await model.OpenSavedAiCommand.ExecuteAsync(e.AddedItems[0]);
    }
    private async void SavedItemMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is not AiWorkspaceViewModel { IsUpdatingSavedItems: false } model) return;
        var source = e.OriginalSource as DependencyObject;
        if (Ancestor<ButtonBase>(source) != null || Ancestor<ListBoxItem>(source) is not { IsSelected: true } item) return;
        if (item.DataContext is not (ConversationExplorerEntry or InvestigationExplorerEntry)) return;
        e.Handled = true;
        item.Focus();
        await model.OpenSavedAiCommand.ExecuteAsync(item.DataContext);
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
