using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using ProcInsider.ViewModels;

namespace ProcInsider;

public partial class CaptureConfigurationDialog : Window
{
    public CaptureConfigurationDialog(
        IEnumerable<AgentCaptureOptionViewModel> options,
        string primaryButtonContent)
    {
        CaptureOptions = new ObservableCollection<AgentCaptureOptionViewModel>(
            AgentCaptureOptionViewModel.CloneOptions(options)
                .Where(option => option.IsPublished));
        PrimaryButtonContent = primaryButtonContent;
        InitializeComponent();
    }

    public ObservableCollection<AgentCaptureOptionViewModel> CaptureOptions { get; }

    public string PrimaryButtonContent { get; }

    public IReadOnlyList<AgentCaptureOptionViewModel> GetCaptureOptions()
        => CaptureOptions.Select(option => option.Clone()).ToList();

    private void AcceptButton_Click(object sender, RoutedEventArgs e)
    {
        if (CaptureOptions.Any(option => option.Kind == AgentCaptureOptionKind.Persistence && option.PersistenceIntervalMinutes is < 1 or > 1440) || HasValidationError(this))
        {
            MessageBox.Show(this, "Persistence cadence must be a whole number between 1 and 1440 minutes.", "Capture configuration", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        DialogResult = true;
    }
    private static bool HasValidationError(DependencyObject node)
    {
        if (System.Windows.Controls.Validation.GetHasError(node)) return true;
        for (var i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(node); i++) if (HasValidationError(System.Windows.Media.VisualTreeHelper.GetChild(node, i))) return true;
        return false;
    }
}
