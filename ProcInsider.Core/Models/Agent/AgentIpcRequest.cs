using System;
using System.Text.Json;

namespace ProcInsider.Models.Agent;

public sealed record AgentIpcRequest
{
    public int ContractVersion { get; init; } = AgentContracts.ContractVersion;

    public Guid RequestId { get; init; } = Guid.NewGuid();

    /// <summary>
    /// Stable compiled educational-release identity of the requesting viewer.
    /// Command submission fails closed when it is absent or differs from the
    /// agent's compiled profile; health requests use it for diagnostics.
    /// </summary>
    public string ViewerReleaseId { get; init; } = string.Empty;

    public AgentIpcRequestKind Kind { get; init; }

    public AgentCommandKind CommandKind { get; init; }

    public JsonElement? Payload { get; init; }

    public Guid? JobId { get; init; }

    /// <summary>
    /// Present only on an unauthenticated challenge request. The agent validates
    /// every context field before returning a nonce and discloses no health.
    /// </summary>
    public AgentPairingChallengeRequest? PairingChallenge { get; init; }

    /// <summary>
    /// One-time challenge response for every request other than
    /// <see cref="AgentIpcRequestKind.PairingChallenge"/>. It never contains the
    /// reusable pairing secret.
    /// </summary>
    public AgentPairingProof? PairingProof { get; init; }

    public static AgentIpcRequest CreateHealthRequest(string viewerReleaseId = "")
        => new()
        {
            Kind = AgentIpcRequestKind.Health,
            ViewerReleaseId = viewerReleaseId
        };

    public static AgentIpcRequest CreateCommandRequest(
        AgentCommand command,
        JsonElement payload,
        string viewerReleaseId = "")
        => new()
        {
            Kind = AgentIpcRequestKind.SubmitCommand,
            CommandKind = command.Kind,
            Payload = payload,
            ViewerReleaseId = viewerReleaseId
        };

    public static AgentIpcRequest CreateJobStatusRequest(Guid jobId, string viewerReleaseId = "")
        => new()
        {
            Kind = AgentIpcRequestKind.GetJobStatus,
            JobId = jobId,
            ViewerReleaseId = viewerReleaseId
        };

    public static AgentIpcRequest CreatePairingChallengeRequest(
        AgentPairingContext context,
        Guid protectedRequestId)
        => new()
        {
            Kind = AgentIpcRequestKind.PairingChallenge,
            ViewerReleaseId = context.ReleaseId,
            PairingChallenge = new AgentPairingChallengeRequest
            {
                Context = context,
                ProtectedRequestId = protectedRequestId
            }
        };
}
