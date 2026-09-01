using System.Windows;
using ProcInsider.ViewModels;

namespace ProcInsider;

public partial class AgentMonitoringStatusDialog : Window
{
    public AgentMonitoringStatusDialog(
        AgentRegistryEntryViewModel agent,
        MainViewModel commands)
    {
        Commands = commands;
        DataContext = agent;
        InitializeComponent();
    }

    public MainViewModel Commands { get; }
}
