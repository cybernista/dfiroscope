using System.ComponentModel;
using System.Windows;

namespace ProcInsider.Features.WindowsSecurityDetails;

public partial class SecurityDetailsEditorWindow : Window
{
    public SecurityDetailsEditorWindow() => InitializeComponent();
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (DataContext is SecurityDetailsEditorViewModel vm) e.Cancel = !vm.CanClose();
    }
}
