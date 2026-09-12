using System.Windows;
using ProcInsider.ViewModels;

namespace ProcInsider;

public partial class AgentMonitoringStatusDialog : Window
{
    public AgentMonitoringStatusDialog(
        AgentRegistryEntryViewModel agent)
    {
        DataContext = agent;
        InitializeComponent();
    }
}
