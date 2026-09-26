using System.Security.Cryptography;
using System.Security.Authentication;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.Infrastructure;
using Contracts = ProcInsider.Models.Infrastructure.InfrastructureConfigurationContracts;

namespace ProcInsider.Agent;

internal interface IAgentInfrastructureGrpcConnector
{
    /// <summary>
    /// Initiates the outbound mTLS HTTP/2 connection, completes #335 mutual proof, and
    /// returns the two separately typed gRPC message streams. Implementations never listen.
    /// </summary>
    Task<AgentInfrastructureAuthenticatedTransport> ConnectAsync(
        Contracts.InfrastructureAgentConfiguration configuration,
        Guid connectionGeneration,
        CancellationToken cancellationToken);
}

internal sealed class AgentInfrastructureAuthenticatedTransport : IAsyncDisposable
{
    private readonly IAsyncDisposable? _lifetime;

    public AgentInfrastructureAuthenticatedTransport(
        AuthenticatedAgentContext authenticated,
        Stream controlStream,
        Stream evidenceStream,
        IAsyncDisposable? lifetime = null)
    {
        Authenticated = authenticated ?? throw new ArgumentNullException(nameof(authenticated));
        ControlStream = controlStream ?? throw new ArgumentNullException(nameof(controlStream));
        EvidenceStream = evidenceStream ?? throw new ArgumentNullException(nameof(evidenceStream));
        _lifetime = lifetime;
    }

    public AuthenticatedAgentContext Authenticated { get; }

    public Stream ControlStream { get; }

    public Stream EvidenceStream { get; }

    public async ValueTask DisposeAsync()
    {
        await ControlStream.DisposeAsync().ConfigureAwait(false);
        await EvidenceStream.DisposeAsync().ConfigureAwait(false);
        if (_lifetime != null)
        {
            await _lifetime.DisposeAsync().ConfigureAwait(false);
        }
    }
}

internal sealed record AgentInfrastructureSessionOpenResult(
    bool Succeeded,
    InfrastructureSessionFailure Failure,
    string ErrorCode,
    string Message,
    AgentInfrastructureSessionConnection? Connection = null,
    AgentInfrastructureSessionOpenFailureClass FailureClass = AgentInfrastructureSessionOpenFailureClass.None)
{
    public bool Retryable => FailureClass == AgentInfrastructureSessionOpenFailureClass.TransientTransport;
}

internal enum AgentInfrastructureSessionOpenFailureClass
{
    None = 0,
    Canceled = 1,
    TransientTransport = 2,
    Configuration = 3,
    Security = 4,
    Protocol = 5
}

internal enum AgentInfrastructureSessionOpenPhase
{
    Connecting = 0,
    AuthenticatingAndNegotiating = 1
}

internal sealed class AgentInfrastructureSessionClient
{
    private readonly IAgentInfrastructureGrpcConnector _connector;

    public AgentInfrastructureSessionClient(IAgentInfrastructureGrpcConnector connector)
    {
        _connector = connector ?? throw new ArgumentNullException(nameof(connector));
    }

    public async Task<AgentInfrastructureSessionOpenResult> OpenAsync(
        Contracts.InfrastructureAgentConfiguration configuration,
        CancellationToken cancellationToken,
        Action<AgentInfrastructureSessionOpenPhase>? reportPhase = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (!IsValidConfiguration(configuration))
        {
            return new(false, InfrastructureSessionFailure.InvalidRequest, "AgentSessionConfigurationInvalid",
                "The Agent session configuration failed before any network client was created.",
                FailureClass: AgentInfrastructureSessionOpenFailureClass.Configuration);
        }

        var connectionGeneration = Guid.NewGuid();
        AgentInfrastructureAuthenticatedTransport transport;
        try
        {
            reportPhase?.Invoke(AgentInfrastructureSessionOpenPhase.Connecting);
            transport = await _connector.ConnectAsync(configuration, connectionGeneration, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new(false, InfrastructureSessionFailure.Canceled, "OutboundConnectCanceled",
                "The outbound session connection was canceled.",
                FailureClass: AgentInfrastructureSessionOpenFailureClass.Canceled);
        }
        catch (Exception ex) when (ex is AuthenticationException or UnauthorizedAccessException)
        {
            return new(false, InfrastructureSessionFailure.AuthenticationStale, "OutboundAuthenticationRejected",
                "The outbound credential or Server trust binding was rejected.",
                FailureClass: AgentInfrastructureSessionOpenFailureClass.Security);
        }
        catch (InvalidOperationException)
        {
            return new(false, InfrastructureSessionFailure.InvalidRequest, "OutboundProtectedBindingInvalid",
                "The protected Agent credential, trust, or endpoint binding was invalid.",
                FailureClass: AgentInfrastructureSessionOpenFailureClass.Configuration);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            return new(false, InfrastructureSessionFailure.SessionClosed, "OutboundConnectFailed",
                "The outbound authenticated session carrier could not be established.",
                FailureClass: AgentInfrastructureSessionOpenFailureClass.TransientTransport);
        }

        reportPhase?.Invoke(AgentInfrastructureSessionOpenPhase.AuthenticatingAndNegotiating);
        var authenticated = transport.Authenticated;
        if (!AgentAuthenticationPolicy.IsValidContext(authenticated) ||
            !string.Equals(authenticated.AgentId, configuration.AgentId, StringComparison.Ordinal) ||
            !string.Equals(authenticated.HostId, configuration.HostId, StringComparison.Ordinal) ||
            authenticated.ConnectionGeneration != connectionGeneration ||
            authenticated.ProtocolContractVersion != configuration.ProtocolGeneration ||
            !string.Equals(authenticated.ReleaseId, configuration.ReleaseId, StringComparison.Ordinal) ||
            authenticated.FreshUntilUtc.Kind != DateTimeKind.Utc || authenticated.FreshUntilUtc < DateTime.UtcNow)
        {
            await DisposeTransportAsync(transport).ConfigureAwait(false);
            return new(false, InfrastructureSessionFailure.BindingMismatch, "AuthenticatedTransportMismatch",
                "The outbound carrier did not return the exact authenticated Agent identity.",
                FailureClass: AgentInfrastructureSessionOpenFailureClass.Security);
        }

        var endpoint = configuration.ServerEndpoints[0].Uri;
        var capabilities = InfrastructureSessionCapabilities.Known
            .Concat(configuration.RequiredCapabilities)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var request = new InfrastructureSessionNegotiationRequest
        {
            AgentId = configuration.AgentId,
            HostId = configuration.HostId,
            CredentialEpoch = authenticated.CredentialEpoch,
            ConnectionGeneration = connectionGeneration,
            ServerEndpoint = endpoint,
            ReleaseId = configuration.ReleaseId,
            SupportedProtocolGenerations = configuration.ProtocolGeneration > 1
                ? Array.AsReadOnly([configuration.ProtocolGeneration, configuration.ProtocolGeneration - 1])
                : Array.AsReadOnly([configuration.ProtocolGeneration]),
            Capabilities = Array.AsReadOnly(capabilities),
            RequiredCapabilities = Array.AsReadOnly(
                InfrastructureSessionCapabilities.Baseline
                    .Concat(configuration.RequiredCapabilities)
                    .Distinct(StringComparer.Ordinal)
                    .Order(StringComparer.Ordinal)
                    .ToArray()),
            ClientNonce = RandomNumberGenerator.GetBytes(InfrastructureSessionNegotiationPolicy.NonceBytes),
            RequestedControlQueueCapacity = InfrastructureSessionLimits.CompiledMaximumControlQueueEntries,
            RequestedEvidenceQueueCapacity = InfrastructureSessionLimits.CompiledMaximumEvidenceQueueEntries,
            RequestedMaximumConcurrentRequests = InfrastructureSessionLimits.CompiledMaximumConcurrentRequests,
            CreatedAtUtc = DateTime.UtcNow
        };

        using var handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshake.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            await InfrastructureSessionFrameCodec.WriteNegotiationRequestAsync(
                    transport.ControlStream,
                    request,
                    handshake.Token)
                .ConfigureAwait(false);
            var responseFrame = await InfrastructureSessionFrameCodec.ReadNegotiationResponseAsync(
                    transport.ControlStream,
                    handshake.Token)
                .ConfigureAwait(false);
            if (responseFrame.Outcome != InfrastructureSessionFrameOutcome.Success || responseFrame.Value == null)
            {
                await DisposeTransportAsync(transport).ConfigureAwait(false);
                return new(false, InfrastructureSessionFailure.MessageMalformed, responseFrame.ErrorCode,
                    "The Server session negotiation response was malformed or incomplete.",
                    FailureClass: AgentInfrastructureSessionOpenFailureClass.Protocol);
            }

            var response = responseFrame.Value;
            if (!response.Accepted || response.Binding == null || response.Limits == null ||
                !BindingMatches(request, response.Binding) || !response.Limits.IsValid ||
                response.ServerNonce?.Length != InfrastructureSessionNegotiationPolicy.NonceBytes ||
                InfrastructureSessionCapabilities.Baseline
                    .Except(response.NegotiatedCapabilities, StringComparer.Ordinal)
                    .Any())
            {
                await DisposeTransportAsync(transport).ConfigureAwait(false);
                return new(false,
                    response.Failure == InfrastructureSessionFailure.None
                        ? InfrastructureSessionFailure.MessageMalformed
                        : response.Failure,
                    string.IsNullOrWhiteSpace(response.ErrorCode) ? "NegotiationResponseRejected" : response.ErrorCode,
                    "The Server did not return one exact bounded session binding.",
                    FailureClass: ClassifyNegotiationFailure(response.Failure));
            }

            return new(true, InfrastructureSessionFailure.None, string.Empty,
                "The outbound authenticated Agent session is active.",
                new AgentInfrastructureSessionConnection(transport, response));
        }
        catch (OperationCanceledException)
        {
            await DisposeTransportAsync(transport).ConfigureAwait(false);
            return new(false,
                cancellationToken.IsCancellationRequested
                    ? InfrastructureSessionFailure.Canceled
                    : InfrastructureSessionFailure.SessionStale,
                cancellationToken.IsCancellationRequested ? "NegotiationCanceled" : "NegotiationTimedOut",
                "The bounded session negotiation did not complete.",
                FailureClass: cancellationToken.IsCancellationRequested
                    ? AgentInfrastructureSessionOpenFailureClass.Canceled
                    : AgentInfrastructureSessionOpenFailureClass.TransientTransport);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
        {
            await DisposeTransportAsync(transport).ConfigureAwait(false);
            return new(false,
                InfrastructureSessionFailure.SessionClosed,
                "NegotiationTransportClosed",
                "The authenticated carrier disconnected during bounded session negotiation.",
                FailureClass: AgentInfrastructureSessionOpenFailureClass.TransientTransport);
        }
    }

    private static AgentInfrastructureSessionOpenFailureClass ClassifyNegotiationFailure(
        InfrastructureSessionFailure failure) => failure switch
        {
            InfrastructureSessionFailure.SessionLimitReached or
            InfrastructureSessionFailure.SessionDuplicate or
            InfrastructureSessionFailure.SessionClosed or
            InfrastructureSessionFailure.SessionStale or
            InfrastructureSessionFailure.KeepAliveTimedOut or
            InfrastructureSessionFailure.RateLimitReached =>
                AgentInfrastructureSessionOpenFailureClass.TransientTransport,
            InfrastructureSessionFailure.AuthenticationStale or
            InfrastructureSessionFailure.BindingMismatch or
            InfrastructureSessionFailure.EndpointMismatch or
            InfrastructureSessionFailure.SessionReplayed =>
                AgentInfrastructureSessionOpenFailureClass.Security,
            InfrastructureSessionFailure.InvalidRequest =>
                AgentInfrastructureSessionOpenFailureClass.Configuration,
            _ => AgentInfrastructureSessionOpenFailureClass.Protocol
        };

    private static bool BindingMatches(
        InfrastructureSessionNegotiationRequest request,
        InfrastructureSessionBinding binding) =>
        binding.SessionId != Guid.Empty && binding.ServerSessionGeneration > 0 &&
        string.Equals(binding.AgentId, request.AgentId, StringComparison.Ordinal) &&
        string.Equals(binding.HostId, request.HostId, StringComparison.Ordinal) &&
        binding.CredentialEpoch == request.CredentialEpoch &&
        binding.ConnectionGeneration == request.ConnectionGeneration &&
        string.Equals(binding.ServerEndpoint, request.ServerEndpoint, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(binding.ReleaseId, request.ReleaseId, StringComparison.Ordinal) &&
        request.SupportedProtocolGenerations.Contains(binding.ProtocolGeneration);

    private static async ValueTask DisposeTransportAsync(AgentInfrastructureAuthenticatedTransport transport)
    {
        try
        {
            await transport.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or TimeoutException)
        {
        }
    }

    private static bool IsValidConfiguration(Contracts.InfrastructureAgentConfiguration configuration) =>
        configuration.Enabled &&
        !string.IsNullOrWhiteSpace(configuration.AgentId) && configuration.AgentId.Length <= 512 &&
        !string.IsNullOrWhiteSpace(configuration.HostId) && configuration.HostId.Length <= 512 &&
        !string.IsNullOrWhiteSpace(configuration.ReleaseId) && configuration.ReleaseId.Length <= 512 &&
        configuration.ProtocolGeneration > 0 &&
        configuration.ServerEndpoints is { Count: > 0 and <= Contracts.MaximumEndpoints } &&
        configuration.ServerEndpoints.All(endpoint =>
            Uri.TryCreate(endpoint.Uri, UriKind.Absolute, out var uri) &&
            string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(endpoint.ExpectedServerIdentity)) &&
        configuration.RequiredCapabilities is { Count: <= Contracts.MaximumCapabilities } &&
        configuration.RequiredCapabilities.All(InfrastructureSessionCapabilities.IsValid) &&
        configuration.RequiredCapabilities.Distinct(StringComparer.Ordinal).Count() ==
        configuration.RequiredCapabilities.Count;
}

internal sealed class AgentInfrastructureSessionConnection : IAsyncDisposable
{
    private readonly AgentInfrastructureAuthenticatedTransport _transport;
    private readonly InfrastructureSessionMessageWindow _messages;
    private readonly SemaphoreSlim _controlWriteGate = new(1, 1);
    private readonly SemaphoreSlim _evidenceWriteGate = new(1, 1);
    private long _controlSequence;
    private long _evidenceSequence;

    public AgentInfrastructureSessionConnection(
        AgentInfrastructureAuthenticatedTransport transport,
        InfrastructureSessionNegotiationResponse negotiation)
    {
        _transport = transport;
        Negotiation = negotiation;
        _messages = new InfrastructureSessionMessageWindow(
            negotiation.Binding!,
            InfrastructureSessionPeerRole.Agent,
            negotiation.Limits!);
    }

    public InfrastructureSessionNegotiationResponse Negotiation { get; }

    public AuthenticatedAgentContext Authenticated => _transport.Authenticated;

    public InfrastructureSessionLifecycleState State { get; private set; } = InfrastructureSessionLifecycleState.Active;

    public async Task<InfrastructureSessionDecision> SendKeepAliveAsync(CancellationToken cancellationToken)
    {
        return await SendControlAsync(
                InfrastructureSessionMessageKind.KeepAlivePing,
                (sequence, nowUtc) => new InfrastructureSessionEnvelope
                {
                    KeepAlive = new InfrastructureSessionKeepAlivePayload
                    {
                        PingId = Guid.NewGuid(),
                        ObservedAtUtc = nowUtc,
                        LastControlSequence = sequence - 1,
                        LastEvidenceSequence = Interlocked.Read(ref _evidenceSequence)
                    }
                },
                Negotiation.Limits!.RequestDeadline,
                InfrastructureSessionFailure.KeepAliveTimedOut,
                "KeepAliveWriteTimedOut",
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<InfrastructureSessionDecision> SendHealthAsync(
        InfrastructureSessionHealthPayload health,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(health);
        return await SendControlAsync(
                InfrastructureSessionMessageKind.HealthSnapshot,
                (_, _) => new InfrastructureSessionEnvelope { Health = health },
                Negotiation.Limits!.RequestDeadline,
                InfrastructureSessionFailure.SessionStale,
                "HealthWriteTimedOut",
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<InfrastructureSessionDecision> ReadControlAsync(CancellationToken cancellationToken)
    {
        var read = await ReadControlEnvelopeAsync(cancellationToken).ConfigureAwait(false);
        return read.Decision;
    }

    public async Task<InfrastructureSessionDecision> ReadAndDispatchControlAsync(
        AgentInfrastructureCommandDispatcher commandDispatcher,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commandDispatcher);
        var read = await ReadControlEnvelopeAsync(cancellationToken).ConfigureAwait(false);
        if (!read.Decision.Allowed || read.Envelope?.CommandRequest == null)
        {
            return read.Decision;
        }

        var result = await commandDispatcher.ExecuteAsync(
                _transport.Authenticated,
                Negotiation.Binding!,
                read.Envelope.CommandRequest,
                cancellationToken)
            .ConfigureAwait(false);
        return await SendControlAsync(
                InfrastructureSessionMessageKind.CommandResult,
                (_, _) => new InfrastructureSessionEnvelope { CommandResult = result },
                Negotiation.Limits!.RequestDeadline,
                InfrastructureSessionFailure.SessionStale,
                "CommandResultWriteTimedOut",
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<ControlEnvelopeReadResult> ReadControlEnvelopeAsync(
        CancellationToken cancellationToken)
    {
        InfrastructureSessionFrameReadResult<InfrastructureSessionEnvelope> frame;
        using var read = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        read.CancelAfter(Negotiation.Limits!.StaleTimeout);
        try
        {
            frame = await InfrastructureSessionFrameCodec.ReadEnvelopeAsync(
                    _transport.ControlStream,
                    Negotiation.Limits.MaximumControlEnvelopeBytes,
                    read.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            State = InfrastructureSessionLifecycleState.Failed;
            return new ControlEnvelopeReadResult(InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.KeepAliveTimedOut,
                "ControlStreamStale",
                "The control stream exceeded its bounded stale timeout."), null);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            State = InfrastructureSessionLifecycleState.Failed;
            return new ControlEnvelopeReadResult(InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.SessionClosed,
                "ControlStreamClosed",
                "The control stream disconnected."), null);
        }
        if (frame.Outcome != InfrastructureSessionFrameOutcome.Success || frame.Value == null)
        {
            State = InfrastructureSessionLifecycleState.Failed;
            return new ControlEnvelopeReadResult(InfrastructureSessionDecision.Deny(
                frame.Outcome switch
                {
                    InfrastructureSessionFrameOutcome.EndOfStream => InfrastructureSessionFailure.SessionClosed,
                    InfrastructureSessionFrameOutcome.TooLarge => InfrastructureSessionFailure.MessageTooLarge,
                    _ => InfrastructureSessionFailure.MessageMalformed
                },
                frame.ErrorCode,
                "The inbound control frame failed closed."), null);
        }

        var decision = _messages.AcceptInbound(frame.Value, DateTime.UtcNow);
        if (!decision.Allowed)
        {
            State = InfrastructureSessionLifecycleState.Failed;
        }
        else if (frame.Value.Kind == InfrastructureSessionMessageKind.DrainRequest)
        {
            State = InfrastructureSessionLifecycleState.Draining;
        }

        return new ControlEnvelopeReadResult(decision, frame.Value);
    }

    public async Task<InfrastructureSessionDecision> BeginDrainAsync(
        InfrastructureSessionDrainReason reason,
        CancellationToken cancellationToken)
    {
        if (reason == InfrastructureSessionDrainReason.Unknown)
        {
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.SessionClosed,
                "SessionNotActive",
                "The session cannot enter drain from its current state.");
        }

        var written = await SendControlAsync(
                InfrastructureSessionMessageKind.DrainRequest,
                (_, nowUtc) => new InfrastructureSessionEnvelope
                {
                    Drain = new InfrastructureSessionDrainPayload
                    {
                        Reason = reason,
                        DeadlineUtc = nowUtc + Negotiation.Limits!.DrainTimeout
                    }
                },
                Negotiation.Limits!.DrainTimeout,
                InfrastructureSessionFailure.SessionStale,
                "DrainWriteTimedOut",
                cancellationToken)
            .ConfigureAwait(false);
        if (written.Allowed)
        {
            State = InfrastructureSessionLifecycleState.Draining;
        }

        return written;
    }

    private async Task<InfrastructureSessionDecision> SendControlAsync(
        InfrastructureSessionMessageKind kind,
        Func<long, DateTime, InfrastructureSessionEnvelope> createPayload,
        TimeSpan timeout,
        InfrastructureSessionFailure timeoutFailure,
        string timeoutCode,
        CancellationToken cancellationToken)
    {
        using var write = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        write.CancelAfter(timeout);
        var entered = false;
        try
        {
            await _controlWriteGate.WaitAsync(write.Token).ConfigureAwait(false);
            entered = true;
            if (State != InfrastructureSessionLifecycleState.Active)
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.SessionClosed,
                    "SessionNotActive",
                    "Control publication is unavailable after drain or close.");
            }

            var nowUtc = DateTime.UtcNow;
            var sequence = ++_controlSequence;
            var envelope = createPayload(sequence, nowUtc) with
            {
                Binding = Negotiation.Binding!,
                Plane = InfrastructureSessionPlane.Control,
                Kind = kind,
                MessageId = Guid.NewGuid(),
                Sequence = sequence,
                SentAtUtc = nowUtc
            };
            var decision = _messages.RegisterOutbound(envelope, nowUtc);
            if (!decision.Allowed)
            {
                State = InfrastructureSessionLifecycleState.Failed;
                return decision;
            }

            await InfrastructureSessionFrameCodec.WriteEnvelopeAsync(
                    _transport.ControlStream,
                    envelope,
                    Negotiation.Limits!.MaximumControlEnvelopeBytes,
                    write.Token)
                .ConfigureAwait(false);
            return InfrastructureSessionDecision.Permit("The bounded control message was written.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            State = InfrastructureSessionLifecycleState.Failed;
            return InfrastructureSessionDecision.Deny(
                timeoutFailure,
                timeoutCode,
                "The control stream write exceeded its compiled deadline.");
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            State = InfrastructureSessionLifecycleState.Failed;
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.SessionClosed,
                "ControlStreamClosed",
                "The control stream disconnected.");
        }
        finally
        {
            if (entered)
            {
                _controlWriteGate.Release();
            }
        }
    }

    public async Task<InfrastructureSessionDecision> SendEvidenceAsync(
        InfrastructureEvidenceTransferMessage message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);

        using var write = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        write.CancelAfter(Negotiation.Limits!.RequestDeadline);
        var entered = false;
        try
        {
            await _evidenceWriteGate.WaitAsync(write.Token).ConfigureAwait(false);
            entered = true;
            if (State != InfrastructureSessionLifecycleState.Active)
            {
                return InfrastructureSessionDecision.Deny(
                    InfrastructureSessionFailure.SessionClosed,
                    "SessionNotActive",
                    "Evidence transfer is unavailable after drain or close.");
            }

            var nowUtc = DateTime.UtcNow;
            var sequence = ++_evidenceSequence;
            var envelope = new InfrastructureSessionEnvelope
            {
                Binding = Negotiation.Binding!,
                Plane = InfrastructureSessionPlane.Evidence,
                Kind = message.Kind,
                MessageId = Guid.NewGuid(),
                Sequence = sequence,
                SentAtUtc = nowUtc,
                EvidenceTransfer = message
            };
            var decision = _messages.RegisterOutbound(envelope, nowUtc);
            if (!decision.Allowed)
            {
                State = InfrastructureSessionLifecycleState.Failed;
                return decision;
            }

            await InfrastructureSessionFrameCodec.WriteEnvelopeAsync(
                    _transport.EvidenceStream,
                    envelope,
                    Negotiation.Limits.MaximumEvidenceChunkBytes,
                    write.Token)
                .ConfigureAwait(false);
            return InfrastructureSessionDecision.Permit("The bounded evidence message was written.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            State = InfrastructureSessionLifecycleState.Failed;
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.SessionStale,
                "EvidenceWriteTimedOut",
                "The evidence stream write exceeded its compiled deadline.");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
        {
            State = InfrastructureSessionLifecycleState.Failed;
            return InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.SessionClosed,
                "EvidenceStreamClosed",
                "The evidence stream disconnected.");
        }
        finally
        {
            if (entered)
            {
                _evidenceWriteGate.Release();
            }
        }
    }

    public async Task<AgentInfrastructureEvidenceReadResult> ReadEvidenceAsync(
        CancellationToken cancellationToken)
    {
        using var read = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        read.CancelAfter(Negotiation.Limits!.StaleTimeout);
        try
        {
            var frame = await InfrastructureSessionFrameCodec.ReadEnvelopeAsync(
                    _transport.EvidenceStream,
                    Negotiation.Limits.MaximumEvidenceChunkBytes,
                    read.Token)
                .ConfigureAwait(false);
            if (frame.Outcome != InfrastructureSessionFrameOutcome.Success || frame.Value == null)
            {
                State = InfrastructureSessionLifecycleState.Failed;
                return new(InfrastructureSessionDecision.Deny(
                    frame.Outcome switch
                    {
                        InfrastructureSessionFrameOutcome.EndOfStream => InfrastructureSessionFailure.SessionClosed,
                        InfrastructureSessionFrameOutcome.TooLarge => InfrastructureSessionFailure.MessageTooLarge,
                        _ => InfrastructureSessionFailure.MessageMalformed
                    },
                    frame.ErrorCode,
                    "The inbound evidence frame failed closed."), null);
            }

            var decision = _messages.AcceptInbound(frame.Value, DateTime.UtcNow);
            if (!decision.Allowed)
            {
                State = InfrastructureSessionLifecycleState.Failed;
            }
            return new(decision, frame.Value);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            State = InfrastructureSessionLifecycleState.Failed;
            return new(InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.KeepAliveTimedOut,
                "EvidenceStreamStale",
                "The evidence stream exceeded its bounded stale timeout."), null);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
        {
            State = InfrastructureSessionLifecycleState.Failed;
            return new(InfrastructureSessionDecision.Deny(
                InfrastructureSessionFailure.SessionClosed,
                "EvidenceStreamClosed",
                "The evidence stream disconnected."), null);
        }
    }

    public async ValueTask DisposeAsync()
    {
        State = InfrastructureSessionLifecycleState.Closed;
        await _transport.DisposeAsync().ConfigureAwait(false);
        _controlWriteGate.Dispose();
        _evidenceWriteGate.Dispose();
    }

    private sealed record ControlEnvelopeReadResult(
        InfrastructureSessionDecision Decision,
        InfrastructureSessionEnvelope? Envelope);
}

internal sealed record AgentInfrastructureEvidenceReadResult(
    InfrastructureSessionDecision Decision,
    InfrastructureSessionEnvelope? Envelope);
