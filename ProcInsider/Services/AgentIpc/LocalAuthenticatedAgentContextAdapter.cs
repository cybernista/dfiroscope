using System.IO;
using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

/// <summary>
/// Converts the already verified local named-pipe boundary into the common
/// transport-neutral identity. It deliberately has no discovery, pairing,
/// process-inspection, transport, authorization-grant, or evidence authority.
/// </summary>
public static class LocalAuthenticatedAgentContextAdapter
{
    public const string LocalAgentId = "local";

    public static AgentAuthenticationDecision Authenticate(
        ViewerAgentCommandExecutionContext executionContext,
        AgentHealthSnapshot health,
        AgentPairingStoreResult pairing,
        string authenticatedEndpoint,
        LocalAgentProcessResult processVerification,
        DateTime authenticatedAtUtc,
        Guid connectionGeneration)
    {
        ArgumentNullException.ThrowIfNull(executionContext);
        ArgumentNullException.ThrowIfNull(health);
        ArgumentNullException.ThrowIfNull(pairing);
        ArgumentNullException.ThrowIfNull(processVerification);

        var lease = pairing.Lease;
        var leaseEndpoints = lease?.Endpoints;
        var releaseProfile = health.ReleaseProfile;
        var commandCapabilityInventory = releaseProfile?.PublishedCommandCapabilities;
        var control = health.Control;
        var supportedExecutablePaths = executionContext.Target.SupportedExecutablePaths;
        var expectedEndpoints = AgentContracts.CompatiblePipeNames
            .Concat(AgentContracts.CompatibleShutdownControlPipeNames)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var endpointInventoryMatches = leaseEndpoints != null &&
            leaseEndpoints.Count == expectedEndpoints.Length &&
            leaseEndpoints.All(endpoint => !string.IsNullOrWhiteSpace(endpoint)) &&
            leaseEndpoints.Distinct(StringComparer.Ordinal).Count() == expectedEndpoints.Length &&
            !leaseEndpoints.Except(expectedEndpoints, StringComparer.Ordinal).Any() &&
            !expectedEndpoints.Except(leaseEndpoints, StringComparer.Ordinal).Any();
        var leaseExecutablePath = lease?.ExecutablePath ?? string.Empty;
        var executableMatches = lease != null &&
            supportedExecutablePaths != null &&
            !string.IsNullOrWhiteSpace(lease.ExecutableName) &&
            ExecutableIdentity.IsSupportedAgentProcessName(lease.ExecutableName) &&
            LocalAgentProcessLifecycleService.IsSupportedAgentExecutablePath(
                leaseExecutablePath,
                supportedExecutablePaths);
        if (authenticatedAtUtc.Kind != DateTimeKind.Utc ||
            connectionGeneration == Guid.Empty ||
            string.IsNullOrWhiteSpace(health.MachineName) ||
            health.ProcessId <= 0 ||
            health.StartedAtUtc.Kind != DateTimeKind.Utc ||
            health.ContractVersion != AgentContracts.ContractVersion ||
            control == null ||
            !control.IsAuthoritative ||
            control.Generation <= 0 ||
            control.EmittedAtUtc.Kind != DateTimeKind.Utc ||
            releaseProfile == null ||
            commandCapabilityInventory == null ||
            commandCapabilityInventory.Any(capability => capability == null) ||
            releaseProfile.Match is not
                (AgentReleaseProfileMatch.Match or AgentReleaseProfileMatch.Mismatch) ||
            string.IsNullOrWhiteSpace(releaseProfile.ReleaseId) ||
            !string.Equals(
                releaseProfile.ViewerReleaseId,
                executionContext.ViewerReleaseId,
                StringComparison.Ordinal) ||
            (releaseProfile.Match == AgentReleaseProfileMatch.Match) !=
                string.Equals(
                    releaseProfile.ReleaseId,
                    executionContext.ViewerReleaseId,
                    StringComparison.Ordinal) ||
            pairing.State is not (AgentPairingState.Ready or AgentPairingState.Connected) ||
            pairing.PairingGeneration <= 0 ||
            !pairing.ExpiresAtUtc.HasValue ||
            pairing.ExpiresAtUtc.Value <= authenticatedAtUtc ||
            lease == null ||
            lease.State is not (AgentPairingState.Ready or AgentPairingState.Connected) ||
            lease.PairingGeneration != pairing.PairingGeneration ||
            lease.PairingContractVersion != AgentContracts.PairingContractVersion ||
            lease.IpcContractVersion != AgentContracts.ContractVersion ||
            lease.ExpiresAtUtc <= authenticatedAtUtc ||
            !string.Equals(lease.SessionId, executionContext.Target.SessionId, StringComparison.Ordinal) ||
            !SamePath(lease.DatabaseIdentity, executionContext.Target.DatabasePath) ||
            !string.Equals(
                lease.ReleaseId,
                releaseProfile.ReleaseId,
                StringComparison.Ordinal) ||
            lease.WorkspaceMode != executionContext.Target.WorkspaceMode ||
            lease.CaptureSealed != executionContext.Target.IsSealed ||
            lease.AgentProcessId != health.ProcessId ||
            lease.AgentStartedAtUtc != health.StartedAtUtc ||
            !string.Equals(health.SessionId, executionContext.Target.SessionId, StringComparison.Ordinal) ||
            !SamePath(health.DatabasePath, executionContext.Target.DatabasePath) ||
            health.WorkspaceMode != executionContext.Target.WorkspaceMode ||
            health.CaptureSealed != executionContext.Target.IsSealed ||
            !endpointInventoryMatches ||
            !executableMatches ||
            string.IsNullOrWhiteSpace(authenticatedEndpoint) ||
            !AgentContracts.CompatiblePipeNames.Contains(
                authenticatedEndpoint,
                StringComparer.Ordinal) ||
            !leaseEndpoints!.Contains(authenticatedEndpoint, StringComparer.Ordinal) ||
            processVerification.Outcome != LocalAgentProcessOutcome.VerifiedRunning ||
            processVerification.ProcessId != health.ProcessId ||
            !processVerification.IsRunning ||
            processVerification.IsStopped ||
            processVerification.Forced)
        {
            return new AgentAuthenticationDecision
            {
                Failure = AgentAuthenticationFailure.InvalidContext,
                Diagnostic = "The local pairing, endpoint, release, target, freshness, or exact process verification was incomplete."
            };
        }

        var commandCapabilities = commandCapabilityInventory
            .Where(capability =>
                capability != null &&
                capability.OperationalAvailability == AgentCommandOperationalAvailability.Supported &&
                capability.CommandKind != AgentCommandKind.Unknown)
            .Select(capability => capability.CommandKind)
            .Distinct()
            .OrderBy(kind => kind)
            .ToArray();

        var context = new AuthenticatedAgentContext
        {
            AgentId = LocalAgentId,
            HostId = health.MachineName,
            AuthenticationKind = AgentAuthenticationKind.LocalInteractiveNamedPipe,
            EnrollmentState = AgentEnrollmentState.NotApplicableLocal,
            CredentialEpoch = pairing.PairingGeneration,
            ConnectionGeneration = connectionGeneration,
            ProtocolContractVersion = health.ContractVersion,
            ReleaseId = releaseProfile.ReleaseId,
            ReleaseMatch = releaseProfile.Match,
            AuthenticatedAtUtc = authenticatedAtUtc,
            FreshUntilUtc = control.EmittedAtUtc +
                            AgentCaptureControlProjectionService.DefaultFreshnessWindow,
            CommandCapabilities = Array.AsReadOnly(commandCapabilities),
            Scope = new AgentAuthorizationScope
            {
                SessionId = executionContext.Target.SessionId,
                CaptureId = control.ActiveCaptureId ?? string.Empty,
                DatabaseIdentity = Path.GetFullPath(executionContext.Target.DatabasePath),
                WorkspaceMode = executionContext.Target.WorkspaceMode,
                CaptureSealed = executionContext.Target.IsSealed
            },
            IsAuthoritativeEvidenceWriter = true
        };

        return AgentAuthenticationPolicy.Evaluate(
            new AgentAuthenticationCandidate
            {
                Context = context,
                CredentialStatus = AgentCredentialStatus.Active,
                ConnectionStatus = AgentConnectionStatus.Current,
                CredentialProofVerified = true,
                HostBindingVerified = true,
                ProtocolCompatible = true
            },
            authenticatedAtUtc);
    }

    private static bool SamePath(string first, string second)
    {
        try
        {
            return Path.IsPathFullyQualified(first) &&
                   Path.IsPathFullyQualified(second) &&
                   string.Equals(
                       Path.GetFullPath(first),
                       Path.GetFullPath(second),
                       StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (
            ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }
}
