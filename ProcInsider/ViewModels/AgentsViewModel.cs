using System;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.AgentIpc;

namespace ProcInsider.ViewModels;

public partial class AgentsViewModel : ViewModelBase
{
    public const string LocalAgentId = "local";

    public AgentsViewModel()
    {
        Agents.CollectionChanged += OnAgentsCollectionChanged;
    }

    public ObservableCollection<AgentRegistryEntryViewModel> Agents { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelectedAgent))]
    private AgentRegistryEntryViewModel? selectedAgent;

    [ObservableProperty]
    private bool isInfrastructureProjectionActive;

    [ObservableProperty]
    private int infrastructureConnectedAgentCount;

    [ObservableProperty]
    private string statusMessage = "No agents configured.";

    public bool HasAgents => Agents.Count > 0;

    public bool HasSelectedAgent => SelectedAgent != null;

    public bool HasLocalAgent => Agents.Any(IsLocalAgentRegistryEntry);

    public AgentRegistryEntryViewModel AddOrUpdateLocalAgent()
    {
        var entry = AgentRegistryEntry.CreateLocal();
        var existing = Agents.FirstOrDefault(IsLocalAgentRegistryEntry);

        if (existing != null)
        {
            SelectedAgent = existing;
            StatusMessage = "Local agent already exists.";
            return existing;
        }

        var viewModel = new AgentRegistryEntryViewModel(entry);
        viewModel.HealthSummary = "Local agent registered. Add or Start Agent starts it for the active session.";
        viewModel.CaptureStatusSummary = "Agent is registered but not started.";
        Agents.Add(viewModel);
        SelectedAgent = viewModel;
        StatusMessage = "Local agent added. Starting agent for the active session.";
        return viewModel;
    }

    public void ApplyLocalHealth(AgentIpcResponse response, bool isActiveSession)
    {
        var local = Agents.FirstOrDefault(IsLocalAgentRegistryEntry);
        if (local == null)
        {
            return;
        }

        local.ApplyHealth(response, isActiveSession);
        StatusMessage = local.HealthSummary;
    }

    public void ApplyLocalPairing(AgentPairingStoreResult status, bool authenticated = false)
    {
        var local = Agents.FirstOrDefault(IsLocalAgentRegistryEntry);
        if (local == null)
        {
            return;
        }

        local.ApplyPairingStatus(status, authenticated);
        StatusMessage = status.Status;
    }

    public void MarkLocalAgentDeployedIdle(string message)
    {
        var local = Agents.FirstOrDefault(IsLocalAgentRegistryEntry);
        if (local == null)
        {
            return;
        }

        local.DeploymentState = AgentDeploymentState.Deployed;
        local.CaptureState = AgentCaptureState.Idle;
        local.LastCheckUtc = DateTime.UtcNow;
        local.LastError = string.Empty;
        local.HealthSummary = message;
        local.CaptureStatusSummary = "Agent process is deployed and idle.";
        local.IsViewerConnected = false;
        StatusMessage = message;
    }

    public void MarkAgentViewerConnected(AgentRegistryEntryViewModel agent, AgentIpcResponse response)
    {
        foreach (var entry in Agents)
        {
            entry.IsViewerConnected = ReferenceEquals(entry, agent);
        }

        agent.ApplyHealth(response, isActiveSession: true);
        StatusMessage = $"Viewer connected to {agent.DisplayName}.";
    }

    public void MarkAgentViewerDisconnected(AgentRegistryEntryViewModel? agent, string message)
    {
        if (agent == null)
        {
            foreach (var entry in Agents)
            {
                entry.IsViewerConnected = false;
            }
        }
        else
        {
            agent.IsViewerConnected = false;
        }

        StatusMessage = message;
    }

    public void MarkLocalAgentUnavailable(string message)
    {
        var local = Agents.FirstOrDefault(IsLocalAgentRegistryEntry);
        if (local == null)
        {
            return;
        }

        local.DeploymentState = AgentDeploymentState.Unavailable;
        local.CaptureState = AgentCaptureState.Unknown;
        local.LastCheckUtc = DateTime.UtcNow;
        local.LastError = message;
        local.HealthSummary = message;
        local.IsViewerConnected = false;
        StatusMessage = message;
    }

    public void RemoveLocalAgentAfterConfirmedStop(string message)
    {
        var local = Agents.FirstOrDefault(IsLocalAgentRegistryEntry);
        if (local == null)
        {
            StatusMessage = message;
            return;
        }

        if (ReferenceEquals(SelectedAgent, local))
        {
            SelectedAgent = null;
        }

        Agents.Remove(local);
        StatusMessage = message;
    }

    public void ApplyConfigurationCheck(AgentRegistryEntryViewModel agent, AgentConfigurationCheckResult result)
    {
        agent.ApplyConfigurationCheck(result);
        StatusMessage = agent.LastConfigurationCheckSummary;
    }

    public void ApplyHostMonitoringConfiguration(AgentRegistryEntryViewModel agent, AgentHostMonitoringConfiguration configuration)
    {
        agent.ApplyHostMonitoringConfiguration(configuration);
        StatusMessage = agent.LastConfigurationCheckSummary;
    }

    public void ApplyMonitoringDeployment(AgentRegistryEntryViewModel agent, AgentMonitoringDeploymentResult result)
    {
        agent.ApplyMonitoringDeployment(result);
        StatusMessage = agent.LastConfigurationCheckSummary;
    }

    public void ApplyCaptureConfiguration(AgentRegistryEntryViewModel agent, AgentCaptureConfiguration configuration)
    {
        agent.ApplyCaptureConfiguration(configuration);
        StatusMessage = agent.CaptureStatusSummary;
    }

    public void ApplyCaptureLifecycle(AgentRegistryEntryViewModel agent, AgentCaptureLifecycleResult result)
    {
        agent.ApplyCaptureLifecycle(result);
        StatusMessage = agent.CaptureStatusSummary;
    }

    public void ApplyTelemetryStats(TelemetryStoreStats stats)
    {
        foreach (var agent in Agents)
        {
            agent.ApplyTelemetryStats(stats);
        }
    }

    public void ResetSessionState(string message)
    {
        foreach (var agent in Agents)
        {
            agent.ResetSessionState(message);
        }

        StatusMessage = message;
    }

    public void ApplyInfrastructureProjection(InfrastructureAgentProjectionResponse projection)
    {
        ArgumentNullException.ThrowIfNull(projection);
        IsInfrastructureProjectionActive = true;
        InfrastructureConnectedAgentCount = projection.Allowed
            ? projection.ConnectedAgentCount
            : 0;
        var selectedIdentity = SelectedAgent is { IsInfrastructureProjection: true } selected
            ? (selected.AgentId, selected.HostId)
            : default;
        var existingRemote = Agents
            .Where(agent => agent.IsInfrastructureProjection)
            .ToDictionary(agent => (agent.AgentId, agent.HostId));
        var incoming = projection.Allowed
            ? projection.Agents.ToDictionary(agent => (agent.AgentId, agent.HostId))
            : new Dictionary<(string AgentId, string HostId), InfrastructureAgentProjectionRow>();

        foreach (var removed in existingRemote.Keys.Where(key => !incoming.ContainsKey(key)).ToArray())
        {
            Agents.Remove(existingRemote[removed]);
        }

        foreach (var pair in incoming)
        {
            if (!existingRemote.TryGetValue(pair.Key, out var viewModel))
            {
                viewModel = new AgentRegistryEntryViewModel(new AgentRegistryEntry
                {
                    AgentId = pair.Value.AgentId,
                    HostId = pair.Value.HostId,
                    DisplayName = pair.Value.DisplayName,
                    TransportKind = AgentTransportKind.RemoteHttp,
                    Endpoint = "DFIRoscope Server"
                });
                Agents.Add(viewModel);
            }

            viewModel.ApplyInfrastructureProjection(pair.Value);
        }

        if (selectedIdentity != default)
        {
            SelectedAgent = Agents.FirstOrDefault(agent =>
                agent.IsInfrastructureProjection &&
                string.Equals(agent.AgentId, selectedIdentity.AgentId, StringComparison.Ordinal) &&
                string.Equals(agent.HostId, selectedIdentity.HostId, StringComparison.Ordinal));
        }

        StatusMessage = projection.Allowed
            ? $"Infrastructure Mode: {projection.Agents.Count:N0} authorized Agent(s); " +
              $"{projection.ConnectedAgentCount:N0} freshly authenticated."
            : $"Infrastructure Agent projection unavailable: {projection.Message}";
    }

    public void ClearInfrastructureProjection(string message)
    {
        var selectedInfrastructure = SelectedAgent?.IsInfrastructureProjection == true;
        foreach (var remote in Agents.Where(agent => agent.IsInfrastructureProjection).ToArray())
        {
            Agents.Remove(remote);
        }

        if (selectedInfrastructure)
        {
            SelectedAgent = null;
        }

        InfrastructureConnectedAgentCount = 0;
        IsInfrastructureProjectionActive = false;
        StatusMessage = message;
    }

    public void MarkConfigurationCheckUnavailable(
        AgentRegistryEntryViewModel agent,
        AgentConfigurationTargetKind targetKind,
        string message)
    {
        agent.ApplyConfigurationCheckUnavailable(targetKind, message);
        StatusMessage = agent.LastConfigurationCheckSummary;
    }

    private void OnAgentsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        OnPropertyChanged(nameof(HasAgents));
        OnPropertyChanged(nameof(HasLocalAgent));
    }

    private static bool IsLocalAgentRegistryEntry(AgentRegistryEntryViewModel agent) =>
        !agent.IsInfrastructureProjection &&
        agent.TransportKind == AgentTransportKind.LocalNamedPipe &&
        string.Equals(agent.AgentId, LocalAgentId, StringComparison.Ordinal);
}
