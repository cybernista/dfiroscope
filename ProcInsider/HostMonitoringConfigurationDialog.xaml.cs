using System.Windows;
using ProcInsider.ViewModels;

namespace ProcInsider;

public partial class HostMonitoringConfigurationDialog : Window
{
    public HostMonitoringConfigurationDialog(
        HostMonitoringConfigurationViewModel monitoringConfiguration,
        string primaryButtonContent)
    {
        MonitoringConfiguration = monitoringConfiguration;
        PrimaryButtonContent = primaryButtonContent;
        InitializeComponent();
    }

    public HostMonitoringConfigurationViewModel MonitoringConfiguration { get; }

    public string PrimaryButtonContent { get; }

    private void AcceptButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
    }
}
