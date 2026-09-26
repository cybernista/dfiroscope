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
        DialogResult = true;
    }
}
