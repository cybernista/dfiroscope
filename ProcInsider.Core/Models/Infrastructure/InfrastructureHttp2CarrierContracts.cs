using ProcInsider.Models.Agent;

namespace ProcInsider.Models.Infrastructure;

/// <summary>
/// Generation-1 HTTP/2 carrier vocabulary. Authentication messages are bounded setup
/// records; application messages continue to use the existing five-byte gRPC frame codec.
/// </summary>
public static class InfrastructureHttp2CarrierProtocol
{
    public const string ChallengePath = "/infrastructure/g1/agent/challenge";
    public const string AuthenticationPath = "/infrastructure/g1/agent/authenticate";
    public const string ControlPath = "/infrastructure/g1/agent/control";
    public const string EvidencePath = "/infrastructure/g1/agent/evidence";
    public const string AuthenticationContentType = "application/vnd.dfiroscope.infrastructure-auth+json";
    public const string GrpcContentType = "application/grpc";
    public const string CarrierIdHeader = "x-dfiroscope-carrier-id";
    public const string ConnectionGenerationHeader = "x-dfiroscope-connection-generation";
    public const string GrpcStatusTrailer = "grpc-status";
    public const int MaximumAuthenticationDocumentBytes = 64 * 1024;
    public const int MaximumProofBytes = 1024;
    public static readonly TimeSpan CarrierSetupLifetime = TimeSpan.FromSeconds(30);

    public static bool IsExactHttp2(Version version) =>
        version.Major == 2 && version.Minor == 0;
}

public sealed record InfrastructureHttp2ChallengeRequest
{
    public string IdentityId { get; init; } = string.Empty;

    public Guid ConnectionGeneration { get; init; }
}

public sealed record InfrastructureHttp2ChallengeResponse
{
    public bool Accepted { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public InfrastructureAuthenticationChallenge? Challenge { get; init; }
}

public sealed record InfrastructureHttp2AuthenticationRequest
{
    public InfrastructureMutualAuthenticationRequest Authentication { get; init; } = new();

    public byte[] ProofSignature { get; init; } = Array.Empty<byte>();

    public string CorrelationId { get; init; } = string.Empty;
}

public sealed record InfrastructureHttp2AuthenticationResponse
{
    public bool Accepted { get; init; }

    public InfrastructureAuthenticationFailure Failure { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public Guid CarrierId { get; init; }

    public DateTime ExpiresAtUtc { get; init; }

    public AuthenticatedAgentContext? AuthenticatedAgent { get; init; }

    public AuthenticatedInfrastructureViewerContext? AuthenticatedViewer { get; init; }
}
