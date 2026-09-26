using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.Features;

namespace ProcInsider.Agent;

/// <summary>
/// Validates the already publication-fenced machine configuration before the service resolves a
/// session or creates SQLite, protected-store, endpoint, credential, or network state.
/// </summary>
internal static class AgentInfrastructureConfigurationStartupPolicy
{
    public static InfrastructureConfigurationContracts.InfrastructureAgentConfiguration ValidateEnabledOrThrow(
        AgentOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var store = options.InfrastructureConfigurationStore ??
            throw new InvalidOperationException(
                "Agent Service configuration access was not authorized by the Infrastructure publication fence.");
        var read = store.ReadAgent();
        if (!read.IsSuccess || read.Configuration == null)
        {
            var codes = read.Diagnostics.Count == 0
                ? read.Outcome.ToString()
                : string.Join(",", read.Diagnostics.Select(diagnostic => diagnostic.ErrorCode));
            throw new InvalidDataException(
                $"Agent Service machine configuration failed closed ({codes}); no runtime side effect was started.");
        }

        var configuration = read.Configuration;
        if (!configuration.Enabled)
        {
            throw new InvalidOperationException(
                "Agent Service machine configuration is disabled; no runtime side effect was started.");
        }

        var definition = CurrentInfrastructureModeProfile.Definition;
        if (!string.Equals(
                configuration.PublicationGroupId,
                definition.Id.Value,
                StringComparison.Ordinal) ||
            !string.Equals(
                configuration.DeploymentProfileId,
                definition.ProfileId.Value,
                StringComparison.Ordinal) ||
            !string.Equals(configuration.ReleaseId, definition.ReleaseId, StringComparison.Ordinal) ||
            configuration.ProtocolGeneration != definition.ProtocolGeneration)
        {
            throw new InvalidDataException(
                "Agent Service machine configuration does not match the compiled publication, deployment, release, and protocol identity.");
        }

        return configuration;
    }
}
