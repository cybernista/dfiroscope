using System.Windows;
using ProcInsider.ViewModels;

namespace ProcInsider;

public partial class HostMonitoringConfigurationDialog : Window
{
    public HostMonitoringConfigurationDialog(
        HostMonitoringConfigurationViewModel monitoringConfiguration,
        string primaryButtonContent,
        bool requiresComputerChangeAcknowledgement)
    {
        MonitoringConfiguration = monitoringConfiguration;
        PrimaryButtonContent = primaryButtonContent;
        RequiresComputerChangeAcknowledgement = requiresComputerChangeAcknowledgement;
        InitializeComponent();
    }

    public HostMonitoringConfigurationViewModel MonitoringConfiguration { get; }

    public string PrimaryButtonContent { get; }

    public bool RequiresComputerChangeAcknowledgement { get; }

    private void AcceptButton_Click(object sender, RoutedEventArgs e)
    {
        if (RequiresComputerChangeAcknowledgement && ComputerChangeAcknowledgement.IsChecked != true)
        {
            return;
        }
        DialogResult = true;
    }
}
