using System.Windows;
using System.Windows.Controls;
using ProcInsider.ViewModels;

namespace ProcInsider.Views.Features.Events;

public partial class DataEventListView : UserControl
{
    public DataEventListView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    // DataGridColumn is outside the visual tree, so it cannot inherit the view's DataContext.
    // Keep the generic list neutral for Windows Other while exposing profile projections to Sysmon/PowerShell.
    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        var visibility = e.NewValue is EventsViewModel { HasNativeProfileDetails: true }
            ? Visibility.Visible
            : Visibility.Collapsed;
        DescriptionColumn.Visibility = visibility;
        HighFieldsColumn.Visibility = visibility;
    }
}
