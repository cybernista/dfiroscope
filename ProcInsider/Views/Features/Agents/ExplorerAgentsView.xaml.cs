using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace ProcInsider.Views.Features.Agents;

public partial class ExplorerAgentsView : UserControl
{
    public ExplorerAgentsView()
    {
        InitializeComponent();
    }

    private void OnAgentsGridPreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGrid agentsGrid ||
            e.OriginalSource is not DependencyObject source ||
            ItemsControl.ContainerFromElement(agentsGrid, source) is not DataGridRow row)
        {
            return;
        }

        agentsGrid.SelectedItem = row.Item;
        row.Focus();
    }
}
