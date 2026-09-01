using ProcInsider.Models.Agent;

namespace ProcInsider.Models.Infrastructure;

public enum InfrastructureSessionPlane
{
    Unknown = 0,
    Control = 1,
    Evidence = 2
}

public enum InfrastructureSessionPeerRole
{
    Unknown = 0,
    Agent = 1,
    Server = 2
}

public enum InfrastructureSessionMessageKind
{
    Unknown = 0,
    HealthSnapshot = 1,
    CommandRequest = 2,
    CommandResult = 3,
    EvidenceStreamOffer = 4,
    EvidenceStreamAccepted = 5,
    KeepAlivePing = 6,
    KeepAlivePong = 7,
    DrainRequest = 8,
    DrainAcknowledged = 9,
    Error = 10,
    EvidenceBatchManifest = 11,
    EvidenceArtifactManifest = 12,
    EvidenceContentChunk = 13,
    EvidenceCommit = 14,
    EvidenceAcknowledgement = 15
}

public enum InfrastructureSessionIdempotency
{
    Unknown = 0,
    Idempotent = 1,
    NonIdempotent = 2
}

public enum InfrastructureSessionCompression
{
    None = 0,
    Gzip = 1
}

public enum InfrastructureSessionCommandOutcome
{
    Unknown = 0,
    Accepted = 1,
    Rejected = 2,
    Completed = 3,
    Failed = 4,
    Canceled = 5
}

public enum InfrastructureSessionDrainReason
{
    Unknown = 0,
    AgentShutdown = 1,
    ServerShutdown = 2,
    SessionReplacement = 3,
    CredentialInvalidated = 4,
    ProtocolFailure = 5
}

public enum InfrastructureSessionFailure
{
    None = 0,
    InvalidRequest = 1,
    AuthenticationStale = 2,
    BindingMismatch = 3,
    EndpointMismatch = 4,
    ReleaseIncompatible = 5,
    ProtocolIncompatible = 6,
    CapabilityIncompatible = 7,
    DowngradeRejected = 8,
    SessionLimitReached = 9,
    SessionDuplicate = 10,
    SessionReplayed = 11,
    SessionStale = 12,
    SessionClosed = 13,
    PlaneMismatch = 14,
    MessageKindRejected = 15,
    MessageTooLarge = 16,
    MessageMalformed = 17,
    MessageDuplicate = 18,
    MessageOutOfOrder = 19,
    MessageExpired = 20,
    RequestLimitReached = 21,
    RequestUnknown = 22,
    RetryRejected = 23,
    QueueSaturated = 24,
    MemoryBudgetExceeded = 25,
    KeepAliveTimedOut = 26,
    CompressionRejected = 27,
    Canceled = 28,
    RateLimitReached = 29,
    EvidenceInvalid = 30,
    EvidenceRouteRejected = 31,
    EvidenceConflict = 32,
    EvidenceIncomplete = 33,
    EvidenceCommitFailed = 34,
    EvidenceQuotaBlocked = 35
}

public enum InfrastructureSessionLifecycleState
{
    Negotiating = 0,
    Active = 1,
    Draining = 2,
    Closed = 3,
    Failed = 4
}

public static class InfrastructureSessionCapabilities
{
    public const string KeepAliveV1 = "session.keepalive/v1";
    public const string GracefulDrainV1 = "session.graceful-drain/v1";
    public const string HealthProjectionV1 = "health.projection/v1";
    public const string CommandRequestResultV1 = "command.request-result/v1";
    public const string EvidenceNegotiationV1 = "evidence.negotiation/v1";
    public const string EvidenceTransferV1 = "evidence.immutable-transfer/v1";

    public static IReadOnlyList<string> Baseline { get; } =
        Array.AsReadOnly([KeepAliveV1, GracefulDrainV1]);

    public static IReadOnlyList<string> Known { get; } =
        Array.AsReadOnly(
        [
            KeepAliveV1,
            GracefulDrainV1,
            HealthProjectionV1,
            CommandRequestResultV1,
            EvidenceNegotiationV1,
            EvidenceTransferV1
        ]);

    public static bool IsValid(string? capability) =>
        !string.IsNullOrWhiteSpace(capability) &&
        capability.Length <= 128 &&
        capability.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '/' or '_');
}

public sealed record InfrastructureSessionLimits
{
    public const int CompiledMaximumControlEnvelopeBytes = 1024 * 1024;
    public const int CompiledMaximumEvidenceChunkBytes = 4 * 1024 * 1024;
    public const int CompiledMaximumEvidenceBatchBytes = 64 * 1024 * 1024;
    public const int CompiledMaximumDecompressionRatio = 100;
    public const int CompiledMaximumConcurrentRequests = 64;
    public const int CompiledMaximumControlMessagesPerSecond = 256;
    public const int CompiledMaximumEvidenceMessagesPerSecond = 64;
    public const int CompiledMaximumControlQueueEntries = 256;
    public const int CompiledMaximumEvidenceQueueEntries = 32;
    public const int CompiledMaximumSessionMemoryBytes = 32 * 1024 * 1024;
    public static readonly TimeSpan CompiledRequestDeadline = TimeSpan.FromSeconds(30);

    public int MaximumControlEnvelopeBytes { get; init; } = CompiledMaximumControlEnvelopeBytes;

    public int MaximumEvidenceChunkBytes { get; init; } = CompiledMaximumEvidenceChunkBytes;

    public int MaximumEvidenceBatchBytes { get; init; } = CompiledMaximumEvidenceBatchBytes;

    public int MaximumDecompressionRatio { get; init; } = CompiledMaximumDecompressionRatio;

    public int MaximumConcurrentRequests { get; init; } = CompiledMaximumConcurrentRequests;

    public int MaximumControlMessagesPerSecond { get; init; } = CompiledMaximumControlMessagesPerSecond;

    public int MaximumEvidenceMessagesPerSecond { get; init; } = CompiledMaximumEvidenceMessagesPerSecond;

    public int ControlQueueCapacity { get; init; } = CompiledMaximumControlQueueEntries;

    public int EvidenceQueueCapacity { get; init; } = CompiledMaximumEvidenceQueueEntries;

    public int MaximumSessionMemoryBytes { get; init; } = CompiledMaximumSessionMemoryBytes;

    public TimeSpan RequestDeadline { get; init; } = CompiledRequestDeadline;

    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan StaleTimeout { get; init; } = TimeSpan.FromSeconds(90);

    public TimeSpan DrainTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public bool IsValid =>
        MaximumControlEnvelopeBytes is > 0 and <= CompiledMaximumControlEnvelopeBytes &&
        MaximumEvidenceChunkBytes is > 0 and <= CompiledMaximumEvidenceChunkBytes &&
        MaximumEvidenceBatchBytes is > 0 and <= CompiledMaximumEvidenceBatchBytes &&
        MaximumEvidenceBatchBytes >= MaximumEvidenceChunkBytes &&
        MaximumDecompressionRatio is > 0 and <= CompiledMaximumDecompressionRatio &&
        MaximumConcurrentRequests is > 0 and <= CompiledMaximumConcurrentRequests &&
        MaximumControlMessagesPerSecond is > 0 and <= CompiledMaximumControlMessagesPerSecond &&
        MaximumEvidenceMessagesPerSecond is > 0 and <= CompiledMaximumEvidenceMessagesPerSecond &&
        ControlQueueCapacity is > 0 and <= CompiledMaximumControlQueueEntries &&
        EvidenceQueueCapacity is > 0 and <= CompiledMaximumEvidenceQueueEntries &&
        MaximumSessionMemoryBytes is > 0 and <= CompiledMaximumSessionMemoryBytes &&
        RequestDeadline is { TotalSeconds: > 0 and <= 30 } &&
        HandshakeTimeout is { TotalSeconds: > 0 and <= 30 } &&
        KeepAliveInterval is { TotalSeconds: >= 5 and <= 30 } &&
        StaleTimeout >= KeepAliveInterval + KeepAliveInterval &&
        StaleTimeout <= TimeSpan.FromSeconds(90) &&
        DrainTimeout is { TotalSeconds: > 0 and <= 30 };
}

public sealed record InfrastructureSessionNegotiationRequest
{
    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public string ServerEndpoint { get; init; } = string.Empty;

    public string ReleaseId { get; init; } = string.Empty;

    public IReadOnlyList<int> SupportedProtocolGenerations { get; init; } = Array.Empty<int>();

    public IReadOnlyList<string> Capabilities { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> RequiredCapabilities { get; init; } = Array.Empty<string>();

    public byte[] ClientNonce { get; init; } = Array.Empty<byte>();

    public int RequestedControlQueueCapacity { get; init; }

    public int RequestedEvidenceQueueCapacity { get; init; }

    public int RequestedMaximumConcurrentRequests { get; init; }

    public DateTime CreatedAtUtc { get; init; }

    public override string ToString() =>
        $"InfrastructureSessionNegotiationRequest {{ AgentId = {AgentId}, HostId = {HostId}, " +
        $"CredentialEpoch = {CredentialEpoch}, ConnectionGeneration = {ConnectionGeneration}, " +
        $"ServerEndpoint = {ServerEndpoint}, ReleaseId = {ReleaseId}, ClientNonce = <redacted>, " +
        $"CreatedAtUtc = {CreatedAtUtc:O} }}";
}

public sealed record InfrastructureSessionBinding
{
    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public long ServerSessionGeneration { get; init; }

    public Guid SessionId { get; init; }

    public string ServerEndpoint { get; init; } = string.Empty;

    public int ProtocolGeneration { get; init; }

    public string ReleaseId { get; init; } = string.Empty;
}

public sealed record InfrastructureSessionNegotiationResponse
{
    public bool Accepted { get; init; }

    public InfrastructureSessionFailure Failure { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public InfrastructureSessionBinding? Binding { get; init; }

    public IReadOnlyList<string> NegotiatedCapabilities { get; init; } = Array.Empty<string>();

    public InfrastructureSessionLimits? Limits { get; init; }

    public byte[] ServerNonce { get; init; } = Array.Empty<byte>();

    public DateTime AcceptedAtUtc { get; init; }

    public override string ToString() =>
        $"InfrastructureSessionNegotiationResponse {{ Accepted = {Accepted}, Failure = {Failure}, " +
        $"ErrorCode = {ErrorCode}, SessionId = {Binding?.SessionId}, ServerNonce = <redacted>, " +
        $"AcceptedAtUtc = {AcceptedAtUtc:O} }}";
}

public sealed record InfrastructureSessionHealthPayload
{
    public long HealthRevision { get; init; }

    public DateTime ObservedAtUtc { get; init; }

    public string AvailabilityCode { get; init; } = string.Empty;

    public long ControlGeneration { get; init; }

    public AgentCaptureRunState CaptureState { get; init; }

    public int ActiveWorkCount { get; init; }

    public int PendingOutboxEntries { get; init; }

    public int SpooledOutboxEntries { get; init; }

    public int CleanupPendingOutboxEntries { get; init; }

    public int PendingSpoolPackages { get; init; }

    public long PendingSpoolBytes { get; init; }
}

public sealed record InfrastructureSessionCommandRequestPayload
{
    public Guid RequestId { get; init; }

    public AgentCommandKind CommandKind { get; init; }

    public InfrastructureSessionIdempotency Idempotency { get; init; }

    public int Attempt { get; init; }

    public DateTime DeadlineUtc { get; init; }

    public string ViewerUserId { get; init; } = string.Empty;

    public string GrantId { get; init; } = string.Empty;

    public long AuthorizationRevision { get; init; }

    public AgentAuthorizationGrant AuthorizationGrant { get; init; } = new();

    public InfrastructureCommandTarget Target { get; init; } = new();

    public CaptureWriteCategory WriteCategory { get; init; }

    public string CommandPayloadJson { get; init; } = string.Empty;
}

public sealed record InfrastructureSessionCommandResultPayload
{
    public Guid RequestId { get; init; }

    public InfrastructureSessionCommandOutcome Outcome { get; init; }

    public string JobId { get; init; } = string.Empty;

    public string ErrorCode { get; init; } = string.Empty;

    public DateTime CompletedAtUtc { get; init; }
}

public sealed record InfrastructureSessionEvidenceNegotiationPayload
{
    public Guid TransferId { get; init; }

    public InfrastructureSessionCompression Compression { get; init; }

    public long DeclaredBatchBytes { get; init; }

    public int DeclaredMaximumChunkBytes { get; init; }

    public int DeclaredDecompressionRatio { get; init; }
}

public sealed record InfrastructureSessionKeepAlivePayload
{
    public Guid PingId { get; init; }

    public DateTime ObservedAtUtc { get; init; }

    public long LastControlSequence { get; init; }

    public long LastEvidenceSequence { get; init; }
}

public sealed record InfrastructureSessionDrainPayload
{
    public InfrastructureSessionDrainReason Reason { get; init; }

    public DateTime DeadlineUtc { get; init; }
}

public sealed record InfrastructureSessionErrorPayload
{
    public InfrastructureSessionFailure Failure { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public Guid CorrelationId { get; init; }
}

public sealed record InfrastructureSessionEnvelope
{
    public InfrastructureSessionBinding Binding { get; init; } = new();

    public InfrastructureSessionPlane Plane { get; init; }

    public InfrastructureSessionMessageKind Kind { get; init; }

    public Guid MessageId { get; init; }

    public long Sequence { get; init; }

    public DateTime SentAtUtc { get; init; }

    public InfrastructureSessionHealthPayload? Health { get; init; }

    public InfrastructureSessionCommandRequestPayload? CommandRequest { get; init; }

    public InfrastructureSessionCommandResultPayload? CommandResult { get; init; }

    public InfrastructureSessionEvidenceNegotiationPayload? EvidenceNegotiation { get; init; }

    public InfrastructureSessionKeepAlivePayload? KeepAlive { get; init; }

    public InfrastructureSessionDrainPayload? Drain { get; init; }

    public InfrastructureSessionErrorPayload? Error { get; init; }

    public InfrastructureEvidenceTransferMessage? EvidenceTransfer { get; init; }
}

public sealed record InfrastructureSessionDecision(
    bool Allowed,
    InfrastructureSessionFailure Failure,
    string ErrorCode,
    string Message)
{
    public static InfrastructureSessionDecision Permit(string message) =>
        new(true, InfrastructureSessionFailure.None, string.Empty, message);

    public static InfrastructureSessionDecision Deny(
        InfrastructureSessionFailure failure,
        string errorCode,
        string message) =>
        new(false, failure, errorCode, message);
}

public static class InfrastructureSessionNegotiationPolicy
{
    public const int MaximumProtocolGenerations = 2;
    public const int NonceBytes = 32;

    public static InfrastructureSessionNegotiationResponse Negotiate(
        InfrastructureSessionNegotiationRequest request,
        AuthenticatedAgentContext authenticated,
        string expectedEndpoint,
        string expectedReleaseId,
        IReadOnlyList<int> serverProtocolGenerations,
        IReadOnlyList<string> serverCapabilities,
        InfrastructureSessionLimits serverLimits,
        long serverSessionGeneration,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authenticated);
        ArgumentNullException.ThrowIfNull(serverProtocolGenerations);
        ArgumentNullException.ThrowIfNull(serverCapabilities);
        ArgumentNullException.ThrowIfNull(serverLimits);

        var failure = ValidateRequest(
            request,
            authenticated,
            expectedEndpoint,
            expectedReleaseId,
            serverProtocolGenerations,
            serverCapabilities,
            serverLimits,
            serverSessionGeneration,
            nowUtc);
        if (failure != null)
        {
            return Rejected(failure.Failure, failure.ErrorCode, failure.Message, nowUtc);
        }

        var commonGenerations = request.SupportedProtocolGenerations
            .Intersect(serverProtocolGenerations)
            .OrderByDescending(generation => generation)
            .ToArray();
        if (commonGenerations.Length == 0)
        {
            return Rejected(
                InfrastructureSessionFailure.ProtocolIncompatible,
                "ProtocolGenerationUnavailable",
                "The Agent and Server have no supported protocol generation in common.",
                nowUtc);
        }

        var selectedGeneration = commonGenerations[0];
        if (!request.SupportedProtocolGenerations.Contains(authenticated.ProtocolContractVersion) ||
            selectedGeneration != authenticated.ProtocolContractVersion)
        {
            return Rejected(
                InfrastructureSessionFailure.DowngradeRejected,
                "ProtocolDowngradeRejected",
                "The session cannot select an older mutually supported generation.",
                nowUtc);
        }

        var negotiatedCapabilities = request.Capabilities
            .Intersect(serverCapabilities, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var required = InfrastructureSessionCapabilities.Baseline
            .Concat(request.RequiredCapabilities)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (required.Except(negotiatedCapabilities, StringComparer.Ordinal).Any())
        {
            return Rejected(
                InfrastructureSessionFailure.CapabilityIncompatible,
                "RequiredCapabilityUnavailable",
                "At least one required session capability was not negotiated.",
                nowUtc);
        }

        var limits = serverLimits with
        {
            ControlQueueCapacity = Math.Min(
                request.RequestedControlQueueCapacity,
                serverLimits.ControlQueueCapacity),
            EvidenceQueueCapacity = Math.Min(
                request.RequestedEvidenceQueueCapacity,
                serverLimits.EvidenceQueueCapacity),
            MaximumConcurrentRequests = Math.Min(
                request.RequestedMaximumConcurrentRequests,
                serverLimits.MaximumConcurrentRequests)
        };
        return new InfrastructureSessionNegotiationResponse
        {
            Accepted = true,
            Binding = new InfrastructureSessionBinding
            {
                AgentId = request.AgentId,
                HostId = request.HostId,
                CredentialEpoch = request.CredentialEpoch,
                ConnectionGeneration = request.ConnectionGeneration,
                ServerSessionGeneration = serverSessionGeneration,
                SessionId = Guid.NewGuid(),
                ServerEndpoint = request.ServerEndpoint,
                ProtocolGeneration = selectedGeneration,
                ReleaseId = request.ReleaseId
            },
            NegotiatedCapabilities = Array.AsReadOnly(negotiatedCapabilities),
            Limits = limits,
            ServerNonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(NonceBytes),
            AcceptedAtUtc = nowUtc
        };
    }

    private static InfrastructureSessionDecision? ValidateRequest(
        InfrastructureSessionNegotiationRequest request,
        AuthenticatedAgentContext authenticated,
        string expectedEndpoint,
        string expectedReleaseId,
        IReadOnlyList<int> serverProtocolGenerations,
        IReadOnlyList<string> serverCapabilities,
        InfrastructureSessionLimits serverLimits,
        long serverSessionGeneration,
        DateTime nowUtc)
    {
        if (nowUtc.Kind != DateTimeKind.Utc ||
            !AgentAuthenticationPolicy.IsValidContext(authenticated) ||
            request.CreatedAtUtc.Kind != DateTimeKind.Utc ||
            request.ClientNonce?.Length != NonceBytes ||
            serverSessionGeneration <= 0 ||
            !serverLimits.IsValid ||
            request.SupportedProtocolGenerations is not { Count: > 0 and <= MaximumProtocolGenerations } ||
            request.SupportedProtocolGenerations.Any(generation => generation <= 0) ||
            request.SupportedProtocolGenerations.Distinct().Count() != request.SupportedProtocolGenerations.Count ||
            serverProtocolGenerations is not { Count: > 0 and <= MaximumProtocolGenerations } ||
            serverProtocolGenerations.Any(generation => generation <= 0) ||
            serverProtocolGenerations.Distinct().Count() != serverProtocolGenerations.Count ||
            !IsCapabilities(request.Capabilities) ||
            !IsCapabilities(request.RequiredCapabilities) ||
            !IsCapabilities(serverCapabilities) ||
            request.RequestedControlQueueCapacity <= 0 ||
            request.RequestedEvidenceQueueCapacity <= 0 ||
            request.RequestedMaximumConcurrentRequests <= 0)
        {
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.InvalidRequest,
                "NegotiationRequestInvalid",
                "The session negotiation request or compiled policy is malformed.");
        }

        if (nowUtc - request.CreatedAtUtc < TimeSpan.Zero ||
            nowUtc - request.CreatedAtUtc > serverLimits.HandshakeTimeout ||
            authenticated.FreshUntilUtc.Kind != DateTimeKind.Utc ||
            authenticated.FreshUntilUtc < nowUtc)
        {
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.AuthenticationStale,
                "AuthenticationFreshnessExpired",
                "The authenticated identity is no longer fresh enough to open a session.");
        }

        if (!Equal(request.AgentId, authenticated.AgentId) ||
            !Equal(request.HostId, authenticated.HostId) ||
            request.CredentialEpoch != authenticated.CredentialEpoch ||
            request.ConnectionGeneration != authenticated.ConnectionGeneration)
        {
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.BindingMismatch,
                "AuthenticatedBindingMismatch",
                "The negotiation request does not match the authenticated Agent and generation.");
        }

        if (!UriEquals(request.ServerEndpoint, expectedEndpoint))
        {
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.EndpointMismatch,
                "ServerEndpointMismatch",
                "The negotiation request is not bound to the authenticated Server endpoint.");
        }

        if (!Equal(request.ReleaseId, expectedReleaseId) ||
            !Equal(request.ReleaseId, authenticated.ReleaseId))
        {
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.ReleaseIncompatible,
                "ReleaseIdentityMismatch",
                "The Agent and Server release identities do not match.");
        }

        return null;
    }

    private static bool IsCapabilities(IReadOnlyList<string>? capabilities) =>
        capabilities is { Count: <= InfrastructureConfigurationContracts.MaximumCapabilities } &&
        capabilities.Distinct(StringComparer.Ordinal).Count() == capabilities.Count &&
        capabilities.All(InfrastructureSessionCapabilities.IsValid);

    private static InfrastructureSessionNegotiationResponse Rejected(
        InfrastructureSessionFailure failure,
        string errorCode,
        string message,
        DateTime nowUtc) =>
        new()
        {
            Failure = failure,
            ErrorCode = errorCode,
            Message = message,
            AcceptedAtUtc = nowUtc
        };

    private static bool Equal(string left, string right) =>
        string.Equals(left, right, StringComparison.Ordinal);

    private static bool UriEquals(string left, string right) =>
        Uri.TryCreate(left, UriKind.Absolute, out var leftUri) &&
        Uri.TryCreate(right, UriKind.Absolute, out var rightUri) &&
        Uri.Compare(
            leftUri,
            rightUri,
            UriComponents.AbsoluteUri,
            UriFormat.SafeUnescaped,
            StringComparison.OrdinalIgnoreCase) == 0;
}

public static class InfrastructureSessionEnvelopePolicy
{
    public static InfrastructureSessionDecision Validate(
        InfrastructureSessionEnvelope envelope,
        InfrastructureSessionBinding expectedBinding,
        InfrastructureSessionLimits limits,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(expectedBinding);
        ArgumentNullException.ThrowIfNull(limits);
        if (!limits.IsValid || nowUtc.Kind != DateTimeKind.Utc ||
            envelope.MessageId == Guid.Empty || envelope.Sequence <= 0 ||
            envelope.SentAtUtc.Kind != DateTimeKind.Utc || envelope.SentAtUtc > nowUtc + TimeSpan.FromMinutes(5))
        {
            return Deny(InfrastructureSessionFailure.MessageMalformed, "EnvelopeMalformed");
        }

        if (!Equals(envelope.Binding, expectedBinding))
        {
            return Deny(InfrastructureSessionFailure.BindingMismatch, "EnvelopeBindingMismatch");
        }

        var plane = ExpectedPlane(envelope.Kind);
        if (plane == InfrastructureSessionPlane.Unknown || plane != envelope.Plane)
        {
            return Deny(InfrastructureSessionFailure.PlaneMismatch, "EnvelopePlaneMismatch");
        }

        var payloadCount = new object?[]
        {
            envelope.Health,
            envelope.CommandRequest,
            envelope.CommandResult,
            envelope.EvidenceNegotiation,
            envelope.KeepAlive,
            envelope.Drain,
            envelope.Error,
            envelope.EvidenceTransfer
        }.Count(payload => payload != null);
        if (payloadCount != 1 || !PayloadMatchesKind(envelope))
        {
            return Deny(InfrastructureSessionFailure.MessageMalformed, "EnvelopePayloadMismatch");
        }

        return ValidatePayload(envelope, limits, nowUtc);
    }

    public static bool IsAllowedInboundKind(
        InfrastructureSessionPeerRole receiver,
        InfrastructureSessionMessageKind kind) => receiver switch
    {
        InfrastructureSessionPeerRole.Server => kind is
            InfrastructureSessionMessageKind.HealthSnapshot or
            InfrastructureSessionMessageKind.CommandResult or
            InfrastructureSessionMessageKind.EvidenceStreamOffer or
            InfrastructureSessionMessageKind.EvidenceBatchManifest or
            InfrastructureSessionMessageKind.EvidenceArtifactManifest or
            InfrastructureSessionMessageKind.EvidenceContentChunk or
            InfrastructureSessionMessageKind.EvidenceCommit or
            InfrastructureSessionMessageKind.KeepAlivePing or
            InfrastructureSessionMessageKind.KeepAlivePong or
            InfrastructureSessionMessageKind.DrainRequest or
            InfrastructureSessionMessageKind.DrainAcknowledged or
            InfrastructureSessionMessageKind.Error,
        InfrastructureSessionPeerRole.Agent => kind is
            InfrastructureSessionMessageKind.CommandRequest or
            InfrastructureSessionMessageKind.EvidenceStreamAccepted or
            InfrastructureSessionMessageKind.EvidenceAcknowledgement or
            InfrastructureSessionMessageKind.KeepAlivePing or
            InfrastructureSessionMessageKind.KeepAlivePong or
            InfrastructureSessionMessageKind.DrainRequest or
            InfrastructureSessionMessageKind.DrainAcknowledged or
            InfrastructureSessionMessageKind.Error,
        _ => false
    };

    private static InfrastructureSessionDecision ValidatePayload(
        InfrastructureSessionEnvelope envelope,
        InfrastructureSessionLimits limits,
        DateTime nowUtc)
    {
        if (envelope.Health is { } health &&
            (health.HealthRevision <= 0 || health.ObservedAtUtc.Kind != DateTimeKind.Utc ||
             !IsCode(health.AvailabilityCode) || health.ControlGeneration < 0 ||
             !Enum.IsDefined(health.CaptureState) ||
             health.ActiveWorkCount is < 0 or > 1_000_000 ||
             health.PendingOutboxEntries is < 0 or > 1_000_000 ||
             health.SpooledOutboxEntries is < 0 or > 1_000_000 ||
             health.CleanupPendingOutboxEntries is < 0 or > 1_000_000 ||
             health.PendingSpoolPackages is < 0 or > 1_000_000 ||
             health.PendingSpoolBytes is < 0 or > InfrastructureEvidenceInterchange.DefaultMaximumSpoolBytes))
        {
            return Deny(InfrastructureSessionFailure.MessageMalformed, "HealthPayloadInvalid");
        }

        if (envelope.CommandRequest is { } request)
        {
            if (request.RequestId == Guid.Empty || request.CommandKind == AgentCommandKind.Unknown ||
                !Enum.IsDefined(request.CommandKind) || request.Idempotency == InfrastructureSessionIdempotency.Unknown ||
                !Enum.IsDefined(request.Idempotency) || request.Attempt <= 0 ||
                request.DeadlineUtc.Kind != DateTimeKind.Utc || request.DeadlineUtc <= nowUtc ||
                request.DeadlineUtc - nowUtc > limits.RequestDeadline ||
                string.IsNullOrWhiteSpace(request.ViewerUserId) || request.ViewerUserId.Length > 512 ||
                string.IsNullOrWhiteSpace(request.GrantId) || request.GrantId.Length > 512 ||
                request.AuthorizationRevision <= 0 ||
                request.AuthorizationGrant == null ||
                request.AuthorizationGrant.GrantId != request.GrantId ||
                request.AuthorizationGrant.ConnectionGeneration != envelope.Binding.ConnectionGeneration ||
                !InfrastructureCommandPolicy.IsValidTarget(request.Target) ||
                request.Target.AgentId != envelope.Binding.AgentId ||
                request.Target.HostId != envelope.Binding.HostId ||
                request.Target.CredentialEpoch != envelope.Binding.CredentialEpoch ||
                request.Target.ConnectionGeneration != envelope.Binding.ConnectionGeneration ||
                request.Target.ServerSessionGeneration != envelope.Binding.ServerSessionGeneration ||
                request.Target.SessionId != envelope.Binding.SessionId ||
                request.WriteCategory == CaptureWriteCategory.Unspecified ||
                !Enum.IsDefined(request.WriteCategory) ||
                string.IsNullOrWhiteSpace(request.CommandPayloadJson) ||
                request.CommandPayloadJson.Length > InfrastructureCommandPolicy.MaximumCommandPayloadBytes)
            {
                return Deny(InfrastructureSessionFailure.MessageMalformed, "CommandRequestInvalid");
            }

            if (request.Idempotency == InfrastructureSessionIdempotency.NonIdempotent && request.Attempt != 1)
            {
                return Deny(InfrastructureSessionFailure.RetryRejected, "NonIdempotentRetryRejected");
            }
        }

        if (envelope.CommandResult is { } result &&
            (result.RequestId == Guid.Empty || result.Outcome == InfrastructureSessionCommandOutcome.Unknown ||
             !Enum.IsDefined(result.Outcome) || result.CompletedAtUtc.Kind != DateTimeKind.Utc ||
             result.CompletedAtUtc > nowUtc + TimeSpan.FromMinutes(5) ||
             (!string.IsNullOrEmpty(result.JobId) && !IsCode(result.JobId)) ||
             (!string.IsNullOrEmpty(result.ErrorCode) && !IsCode(result.ErrorCode))))
        {
            return Deny(InfrastructureSessionFailure.MessageMalformed, "CommandResultInvalid");
        }

        if (envelope.EvidenceNegotiation is { } evidence &&
            (evidence.TransferId == Guid.Empty ||
             !Enum.IsDefined(evidence.Compression) ||
             evidence.DeclaredBatchBytes is < 0 || evidence.DeclaredBatchBytes > limits.MaximumEvidenceBatchBytes ||
             evidence.DeclaredMaximumChunkBytes is <= 0 ||
             evidence.DeclaredMaximumChunkBytes > limits.MaximumEvidenceChunkBytes ||
             evidence.DeclaredDecompressionRatio is <= 0 ||
             evidence.DeclaredDecompressionRatio > limits.MaximumDecompressionRatio))
        {
            return Deny(InfrastructureSessionFailure.MessageMalformed, "EvidenceNegotiationInvalid");
        }

        if (envelope.EvidenceTransfer is { } transfer)
        {
            var validation = InfrastructureEvidenceTransferMessagePolicy.Validate(
                transfer,
                envelope.Binding,
                limits,
                nowUtc);
            if (!validation.Valid)
            {
                return Deny(InfrastructureSessionFailure.EvidenceInvalid, validation.ErrorCode);
            }
        }

        if (envelope.KeepAlive is { } keepAlive &&
            (keepAlive.PingId == Guid.Empty || keepAlive.ObservedAtUtc.Kind != DateTimeKind.Utc ||
             keepAlive.LastControlSequence < 0 || keepAlive.LastEvidenceSequence < 0))
        {
            return Deny(InfrastructureSessionFailure.MessageMalformed, "KeepAliveInvalid");
        }

        if (envelope.Drain is { } drain &&
            (drain.Reason == InfrastructureSessionDrainReason.Unknown || !Enum.IsDefined(drain.Reason) ||
             drain.DeadlineUtc.Kind != DateTimeKind.Utc || drain.DeadlineUtc <= nowUtc ||
             drain.DeadlineUtc - nowUtc > limits.DrainTimeout))
        {
            return Deny(InfrastructureSessionFailure.MessageMalformed, "DrainInvalid");
        }

        if (envelope.Error is { } error &&
            (error.Failure == InfrastructureSessionFailure.None || !Enum.IsDefined(error.Failure) ||
             !IsCode(error.ErrorCode)))
        {
            return Deny(InfrastructureSessionFailure.MessageMalformed, "ErrorPayloadInvalid");
        }

        return InfrastructureSessionDecision.Permit("The typed session envelope is valid.");
    }

    private static InfrastructureSessionPlane ExpectedPlane(InfrastructureSessionMessageKind kind) => kind switch
    {
        InfrastructureSessionMessageKind.EvidenceStreamOffer or
        InfrastructureSessionMessageKind.EvidenceStreamAccepted or
        InfrastructureSessionMessageKind.EvidenceBatchManifest or
        InfrastructureSessionMessageKind.EvidenceArtifactManifest or
        InfrastructureSessionMessageKind.EvidenceContentChunk or
        InfrastructureSessionMessageKind.EvidenceCommit or
        InfrastructureSessionMessageKind.EvidenceAcknowledgement => InfrastructureSessionPlane.Evidence,
        InfrastructureSessionMessageKind.HealthSnapshot or
        InfrastructureSessionMessageKind.CommandRequest or
        InfrastructureSessionMessageKind.CommandResult or
        InfrastructureSessionMessageKind.KeepAlivePing or
        InfrastructureSessionMessageKind.KeepAlivePong or
        InfrastructureSessionMessageKind.DrainRequest or
        InfrastructureSessionMessageKind.DrainAcknowledged or
        InfrastructureSessionMessageKind.Error => InfrastructureSessionPlane.Control,
        _ => InfrastructureSessionPlane.Unknown
    };

    private static bool PayloadMatchesKind(InfrastructureSessionEnvelope envelope) => envelope.Kind switch
    {
        InfrastructureSessionMessageKind.HealthSnapshot => envelope.Health != null,
        InfrastructureSessionMessageKind.CommandRequest => envelope.CommandRequest != null,
        InfrastructureSessionMessageKind.CommandResult => envelope.CommandResult != null,
        InfrastructureSessionMessageKind.EvidenceStreamOffer or
        InfrastructureSessionMessageKind.EvidenceStreamAccepted => envelope.EvidenceNegotiation != null,
        InfrastructureSessionMessageKind.EvidenceBatchManifest or
        InfrastructureSessionMessageKind.EvidenceArtifactManifest or
        InfrastructureSessionMessageKind.EvidenceContentChunk or
        InfrastructureSessionMessageKind.EvidenceCommit or
        InfrastructureSessionMessageKind.EvidenceAcknowledgement => envelope.EvidenceTransfer?.Kind == envelope.Kind,
        InfrastructureSessionMessageKind.KeepAlivePing or
        InfrastructureSessionMessageKind.KeepAlivePong => envelope.KeepAlive != null,
        InfrastructureSessionMessageKind.DrainRequest or
        InfrastructureSessionMessageKind.DrainAcknowledged => envelope.Drain != null,
        InfrastructureSessionMessageKind.Error => envelope.Error != null,
        _ => false
    };

    private static bool IsCode(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 128 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or ':');

    private static InfrastructureSessionDecision Deny(
        InfrastructureSessionFailure failure,
        string errorCode) =>
        InfrastructureSessionDecision.Deny(
            failure,
            errorCode,
            "The session envelope failed a bounded protocol check.");
}

public sealed class InfrastructureSessionMessageWindow
{
    private const int MaximumRememberedMessageIds = 4096;
    private readonly object _gate = new();
    private readonly InfrastructureSessionBinding _binding;
    private readonly InfrastructureSessionPeerRole _receiver;
    private readonly InfrastructureSessionLimits _limits;
    private readonly HashSet<Guid> _messageIds = new();
    private readonly HashSet<Guid> _outboundMessageIds = new();
    private readonly Dictionary<Guid, InfrastructureSessionCommandRequestPayload> _pendingRequests = new();
    private readonly Dictionary<Guid, InfrastructureSessionCommandRequestPayload> _inboundRequests = new();
    private readonly Queue<DateTime> _inboundControlRate = new();
    private readonly Queue<DateTime> _inboundEvidenceRate = new();
    private readonly Queue<DateTime> _outboundControlRate = new();
    private readonly Queue<DateTime> _outboundEvidenceRate = new();
    private long _controlSequence;
    private long _evidenceSequence;
    private long _outboundControlSequence;
    private long _outboundEvidenceSequence;

    public InfrastructureSessionMessageWindow(
        InfrastructureSessionBinding binding,
        InfrastructureSessionPeerRole receiver,
        InfrastructureSessionLimits limits)
    {
        _binding = binding ?? throw new ArgumentNullException(nameof(binding));
        _receiver = receiver;
        _limits = limits ?? throw new ArgumentNullException(nameof(limits));
        if (receiver == InfrastructureSessionPeerRole.Unknown || !limits.IsValid)
        {
            throw new ArgumentException("A valid peer role and bounded limits are required.");
        }
    }

    public DateTime LastActivityUtc { get; private set; }

    public InfrastructureSessionDecision AcceptInbound(
        InfrastructureSessionEnvelope envelope,
        DateTime nowUtc)
    {
        var validation = InfrastructureSessionEnvelopePolicy.Validate(envelope, _binding, _limits, nowUtc);
        if (!validation.Allowed)
        {
            return validation;
        }

        if (!InfrastructureSessionEnvelopePolicy.IsAllowedInboundKind(_receiver, envelope.Kind))
        {
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.MessageKindRejected,
                "MessageDirectionRejected",
                "The message kind is not accepted from this authenticated peer.");
        }

        lock (_gate)
        {
            if (!TryConsumeRate(envelope.Plane, nowUtc, outbound: false))
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.RateLimitReached,
                    "InboundMessageRateLimitReached",
                    "The bounded per-plane inbound message rate was exceeded.");
            }

            if (_messageIds.Contains(envelope.MessageId))
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.MessageDuplicate,
                    "MessageReplayRejected",
                    "The message identifier was already accepted in this session.");
            }

            if (_messageIds.Count >= MaximumRememberedMessageIds)
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.MemoryBudgetExceeded,
                    "ReplayWindowExhausted",
                    "The bounded replay window is exhausted; reconnect is required.");
            }

            ref var sequence = ref envelope.Plane == InfrastructureSessionPlane.Control
                ? ref _controlSequence
                : ref _evidenceSequence;
            if (envelope.Sequence != sequence + 1)
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.MessageOutOfOrder,
                    "MessageSequenceRejected",
                    "The message sequence is duplicate, missing, or out of order.");
            }

            if (envelope.CommandResult is { } result && !_pendingRequests.Remove(result.RequestId))
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.RequestUnknown,
                    "CommandResultUnknown",
                    "The command result does not correlate to one current request.");
            }

            if (envelope.CommandRequest is { } request)
            {
                if (_inboundRequests.Count >= _limits.MaximumConcurrentRequests)
                {
                    return InfrastructureSessionDecision.Deny(
                        InfrastructureSessionFailure.RequestLimitReached,
                        "ConcurrentInboundRequestLimitReached",
                        "The bounded inbound request limit is saturated.");
                }

                if (!_inboundRequests.TryAdd(request.RequestId, request))
                {
                    return InfrastructureSessionDecision.Deny(
                        InfrastructureSessionFailure.MessageDuplicate,
                        "InboundCommandRequestDuplicate",
                        "The inbound command request identifier is already in flight.");
                }
            }

            sequence = envelope.Sequence;
            _messageIds.Add(envelope.MessageId);
            LastActivityUtc = nowUtc;
            return InfrastructureSessionDecision.Permit("The ordered session message was accepted.");
        }
    }

    public InfrastructureSessionDecision RegisterOutbound(
        InfrastructureSessionEnvelope envelope,
        DateTime nowUtc)
    {
        var validation = InfrastructureSessionEnvelopePolicy.Validate(envelope, _binding, _limits, nowUtc);
        if (!validation.Allowed)
        {
            return validation;
        }

        var remoteRole = _receiver == InfrastructureSessionPeerRole.Server
            ? InfrastructureSessionPeerRole.Agent
            : InfrastructureSessionPeerRole.Server;
        if (!InfrastructureSessionEnvelopePolicy.IsAllowedInboundKind(remoteRole, envelope.Kind))
        {
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.MessageKindRejected,
                "OutboundMessageDirectionRejected",
                "The remote peer does not accept this message kind.");
        }

        lock (_gate)
        {
            if (!TryConsumeRate(envelope.Plane, nowUtc, outbound: true))
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.RateLimitReached,
                    "OutboundMessageRateLimitReached",
                    "The bounded per-plane outbound message rate was exceeded.");
            }

            if (_outboundMessageIds.Contains(envelope.MessageId))
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.MessageDuplicate,
                    "OutboundMessageReplayRejected",
                    "The outbound message identifier was already registered in this session.");
            }

            if (_outboundMessageIds.Count >= MaximumRememberedMessageIds)
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.MemoryBudgetExceeded,
                    "OutboundReplayWindowExhausted",
                    "The bounded outbound replay window is exhausted; reconnect is required.");
            }

            ref var sequence = ref envelope.Plane == InfrastructureSessionPlane.Control
                ? ref _outboundControlSequence
                : ref _outboundEvidenceSequence;
            if (envelope.Sequence != sequence + 1)
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.MessageOutOfOrder,
                    "OutboundMessageSequenceRejected",
                    "The outbound message sequence is duplicate, missing, or out of order.");
            }

            if (envelope.CommandRequest is { } request)
            {
                if (_pendingRequests.Count >= _limits.MaximumConcurrentRequests)
                {
                    return InfrastructureSessionDecision.Deny(
                        InfrastructureSessionFailure.RequestLimitReached,
                        "ConcurrentRequestLimitReached",
                        "The bounded in-flight request limit is saturated.");
                }

                if (!_pendingRequests.TryAdd(request.RequestId, request))
                {
                    return InfrastructureSessionDecision.Deny(
                        InfrastructureSessionFailure.MessageDuplicate,
                        "CommandRequestDuplicate",
                        "The command request identifier is already in flight.");
                }
            }

            if (envelope.CommandResult is { } result && !_inboundRequests.Remove(result.RequestId))
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.RequestUnknown,
                    "OutboundCommandResultUnknown",
                    "The outbound command result does not correlate to one current inbound request.");
            }

            sequence = envelope.Sequence;
            _outboundMessageIds.Add(envelope.MessageId);
            LastActivityUtc = nowUtc;
            return InfrastructureSessionDecision.Permit("The outbound message is registered for correlation.");
        }
    }

    public bool IsStale(DateTime nowUtc) =>
        LastActivityUtc.Kind == DateTimeKind.Utc &&
        nowUtc.Kind == DateTimeKind.Utc &&
        nowUtc - LastActivityUtc > _limits.StaleTimeout;

    private bool TryConsumeRate(
        InfrastructureSessionPlane plane,
        DateTime nowUtc,
        bool outbound)
    {
        var queue = (outbound, plane) switch
        {
            (false, InfrastructureSessionPlane.Control) => _inboundControlRate,
            (false, InfrastructureSessionPlane.Evidence) => _inboundEvidenceRate,
            (true, InfrastructureSessionPlane.Control) => _outboundControlRate,
            (true, InfrastructureSessionPlane.Evidence) => _outboundEvidenceRate,
            _ => throw new ArgumentOutOfRangeException(nameof(plane))
        };
        var maximum = plane == InfrastructureSessionPlane.Control
            ? _limits.MaximumControlMessagesPerSecond
            : _limits.MaximumEvidenceMessagesPerSecond;
        var cutoff = nowUtc - TimeSpan.FromSeconds(1);
        while (queue.TryPeek(out var acceptedAtUtc) && acceptedAtUtc <= cutoff)
        {
            queue.Dequeue();
        }

        if (queue.Count >= maximum)
        {
            return false;
        }

        queue.Enqueue(nowUtc);
        return true;
    }
}
