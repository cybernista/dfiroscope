using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models.Agent;
using ProcInsider.Services;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.AgentIpc;

public sealed record AgentNamedPipeExchangeResult(
    Guid ExpectedRequestId,
    AgentIpcResponse Response,
    string ConnectedPipeName,
    AgentPairingStoreResult PairingStatus,
    bool ProtectedRequestSent = false,
    bool AuthoritativeResponseReceived = false);

public sealed class AgentNamedPipeClient
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);

    private readonly IReadOnlyList<string> _pipeNames;
    private readonly TimeSpan _timeout;
    private readonly string _viewerReleaseId;
    private readonly AgentPairingClientSession _pairingSession;
    private int _preferredPipeIndex;
    private string? _lastConnectedPipeName;
    private AgentPairingStoreResult _lastPairingStatus = new(
        AgentPairingState.RePairRequired,
        0,
        null,
        "No active live session is bound for local-agent pairing.");

    public AgentNamedPipeClient(
        string pipeName = AgentContracts.PipeName,
        TimeSpan? timeout = null,
        string? viewerReleaseId = null,
        IReadOnlyList<string>? fallbackPipeNames = null,
        AgentPairingClientSession? pairingSession = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        fallbackPipeNames ??= GetDefaultFallbackPipeNames(pipeName);
        _pipeNames = new[] { pipeName }
            .Concat(fallbackPipeNames)
            .Where(candidate => !string.IsNullOrWhiteSpace(candidate))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        _timeout = timeout ?? DefaultTimeout;
        _viewerReleaseId = string.IsNullOrWhiteSpace(viewerReleaseId)
            ? CurrentEducationalReleaseProfile.ReleaseId
            : viewerReleaseId;
        _pairingSession = pairingSession ?? new AgentPairingClientSession();
    }

    public IReadOnlyList<string> CompatiblePipeNames => _pipeNames;

    public string? LastConnectedPipeName => Volatile.Read(ref _lastConnectedPipeName);

    public AgentPairingStoreResult LastPairingStatus => Volatile.Read(ref _lastPairingStatus);

    public void BindSession(InvestigationSessionPaths sessionPaths) =>
        _pairingSession.Bind(sessionPaths, _viewerReleaseId);

    public void UnbindSession() => _pairingSession.Unbind();

    public AgentPairingStoreResult InspectPairing(DateTime? nowUtc = null)
    {
        var status = _pairingSession.Inspect(nowUtc);
        Volatile.Write(ref _lastPairingStatus, status);
        return status;
    }

    public AgentPairingStoreResult PrepareNewPairing(DateTime? nowUtc = null)
    {
        var status = _pairingSession.PrepareNewPairing(nowUtc);
        Volatile.Write(ref _lastPairingStatus, status);
        return status;
    }

    public async Task<AgentIpcResponse> GetHealthAsync(CancellationToken cancellationToken = default) =>
        (await GetHealthExchangeAsync(cancellationToken).ConfigureAwait(false)).Response;

    public Task<AgentNamedPipeExchangeResult> GetHealthExchangeAsync(
        CancellationToken cancellationToken = default) =>
        SendExchangeAsync(
            AgentIpcRequest.CreateHealthRequest(_viewerReleaseId),
            cancellationToken,
            allowReleaseMismatch: false);

    public Task<AgentNamedPipeExchangeResult> GetHealthExchangeAsync(
        AgentCommandKind commandKind,
        CancellationToken cancellationToken = default) =>
        SendExchangeAsync(
            AgentIpcRequest.CreateHealthRequest(_viewerReleaseId),
            cancellationToken,
            AllowsReleaseMismatchCleanup(commandKind));

    public async Task<AgentIpcResponse> SubmitCommandAsync(
        AgentCommand command,
        CancellationToken cancellationToken = default) =>
        (await SubmitCommandExchangeAsync(command, cancellationToken).ConfigureAwait(false)).Response;

    public Task<AgentNamedPipeExchangeResult> SubmitCommandExchangeAsync(
        AgentCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var payload = JsonSerializer.SerializeToElement(command, command.GetType(), AgentIpcJson.JsonOptions);
        return SendExchangeAsync(
            AgentIpcRequest.CreateCommandRequest(command, payload, _viewerReleaseId),
            cancellationToken,
            AllowsReleaseMismatchCleanup(command.Kind));
    }

    public Task<AgentNamedPipeExchangeResult> SubmitCommandExchangeAsync(
        AgentCommand command,
        string expectedPipeName,
        long expectedPairingGeneration,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedPipeName);
        if (expectedPairingGeneration <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedPairingGeneration),
                "The expected pairing generation must be positive.");
        }

        var payload = JsonSerializer.SerializeToElement(command, command.GetType(), AgentIpcJson.JsonOptions);
        return SendExpectedExchangeAsync(
            AgentIpcRequest.CreateCommandRequest(command, payload, _viewerReleaseId),
            expectedPipeName,
            expectedPairingGeneration,
            cancellationToken,
            AllowsReleaseMismatchCleanup(command.Kind));
    }

    public Task<AgentIpcResponse> GetJobStatusAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        return SendAsync(
            AgentIpcRequest.CreateJobStatusRequest(jobId, _viewerReleaseId),
            cancellationToken);
    }

    public Task<AgentIpcResponse> RotatePairingAsync(CancellationToken cancellationToken = default) =>
        SendAsync(
            new AgentIpcRequest
            {
                Kind = AgentIpcRequestKind.RotatePairing,
                ViewerReleaseId = _viewerReleaseId
            },
            cancellationToken);

    public async Task<AgentIpcResponse> RevokePairingAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(
            new AgentIpcRequest
            {
                Kind = AgentIpcRequestKind.RevokePairing,
                ViewerReleaseId = _viewerReleaseId
            },
            cancellationToken).ConfigureAwait(false);
        if (response.Success)
        {
            _pairingSession.RevokeLocal();
            Volatile.Write(ref _lastPairingStatus, new AgentPairingStoreResult(
                AgentPairingState.Revoked,
                response.PairingStatus?.PairingGeneration ?? 0,
                response.PairingStatus?.ExpiresAtUtc,
                "The local-agent pairing was explicitly revoked."));
        }

        return response;
    }

    public async Task<AgentIpcResponse> SendAsync(
        AgentIpcRequest request,
        CancellationToken cancellationToken = default) =>
        (await SendExchangeAsync(request, cancellationToken).ConfigureAwait(false)).Response;

    private async Task<AgentNamedPipeExchangeResult> SendExchangeAsync(
        AgentIpcRequest request,
        CancellationToken cancellationToken,
        bool allowReleaseMismatch = false)
    {
        ArgumentNullException.ThrowIfNull(request);
        var preferredIndex = Math.Clamp(Volatile.Read(ref _preferredPipeIndex), 0, _pipeNames.Count - 1);
        AgentIpcResponse? lastResponse = null;
        AgentPairingStoreResult lastPairingStatus = LastPairingStatus;
        var protectedRequestSent = false;
        var authoritativeResponseReceived = false;

        for (var offset = 0; offset < _pipeNames.Count; offset++)
        {
            var pipeIndex = (preferredIndex + offset) % _pipeNames.Count;
            var attempt = await SendAuthenticatedToPipeAsync(
                _pipeNames[pipeIndex],
                request,
                cancellationToken,
                allowReleaseMismatch).ConfigureAwait(false);
            lastResponse = attempt.Response;
            lastPairingStatus = attempt.PairingStatus;
            protectedRequestSent |= attempt.ProtectedRequestSent;
            authoritativeResponseReceived |= attempt.AuthoritativeResponseReceived;
            if (!attempt.CanTryFallback)
            {
                Volatile.Write(ref _preferredPipeIndex, pipeIndex);
                if (attempt.Connected)
                {
                    Volatile.Write(ref _lastConnectedPipeName, _pipeNames[pipeIndex]);
                }

                return new AgentNamedPipeExchangeResult(
                    request.RequestId,
                    attempt.Response,
                    attempt.Connected ? _pipeNames[pipeIndex] : string.Empty,
                    attempt.PairingStatus,
                    attempt.ProtectedRequestSent,
                    attempt.AuthoritativeResponseReceived);
            }
        }

        var failed = lastResponse ?? AgentIpcResponse.Failure(
            request.RequestId,
            "PipeUnavailable",
            "No compatible local agent pipe endpoint was available.");
        failed = _pipeNames.Count == 1
            ? failed
            : failed with
            {
                ErrorMessage =
                    $"{failed.ErrorMessage} Compatible endpoints tried: {string.Join(", ", _pipeNames.Select(FormatPipeIdentity))}. " +
                    $"Start {ProcInsider.Models.ProductIdentity.AgentDisplayName} for this session or update the viewer/agent pair together."
            };
        return new AgentNamedPipeExchangeResult(
            request.RequestId,
            failed,
            string.Empty,
            lastPairingStatus,
            protectedRequestSent,
            authoritativeResponseReceived);
    }

    private async Task<AgentNamedPipeExchangeResult> SendExpectedExchangeAsync(
        AgentIpcRequest request,
        string expectedPipeName,
        long expectedPairingGeneration,
        CancellationToken cancellationToken,
        bool allowReleaseMismatch)
    {
        if (!_pipeNames.Contains(expectedPipeName, StringComparer.Ordinal))
        {
            return new AgentNamedPipeExchangeResult(
                request.RequestId,
                AgentIpcResponse.Failure(
                    request.RequestId,
                    "PairingEndpointMismatch",
                    "The authenticated preflight endpoint is not configured for this client."),
                string.Empty,
                LastPairingStatus,
                ProtectedRequestSent: false,
                AuthoritativeResponseReceived: false);
        }

        var attempt = await SendAuthenticatedToPipeAsync(
            expectedPipeName,
            request,
            cancellationToken,
            allowReleaseMismatch,
            expectedPairingGeneration).ConfigureAwait(false);
        if (attempt.Connected)
        {
            Volatile.Write(ref _lastConnectedPipeName, expectedPipeName);
        }

        return new AgentNamedPipeExchangeResult(
            request.RequestId,
            attempt.Response,
            attempt.Connected ? expectedPipeName : string.Empty,
            attempt.PairingStatus,
            attempt.ProtectedRequestSent,
            attempt.AuthoritativeResponseReceived);
    }

    private async Task<AuthenticatedPipeSendAttempt> SendAuthenticatedToPipeAsync(
        string pipeName,
        AgentIpcRequest request,
        CancellationToken cancellationToken,
        bool allowReleaseMismatch,
        long? expectedPairingGeneration = null)
    {
        using var secret = _pairingSession.LoadForEndpoint(
            pipeName,
            DateTime.UtcNow,
            out var pairingStatus,
            allowReleaseMismatch);
        Volatile.Write(ref _lastPairingStatus, pairingStatus);
        if (secret == null)
        {
            return new AuthenticatedPipeSendAttempt(
                PairingFailure(request.RequestId, pairingStatus),
                CanTryFallback: false,
                Connected: false,
                ProtectedRequestSent: false,
                AuthoritativeResponseReceived: false,
                pairingStatus);
        }

        if (expectedPairingGeneration.HasValue &&
            (secret.Context.PairingGeneration != expectedPairingGeneration.Value ||
             pairingStatus.PairingGeneration != expectedPairingGeneration.Value ||
             pairingStatus.Lease?.PairingGeneration != expectedPairingGeneration.Value))
        {
            return new AuthenticatedPipeSendAttempt(
                AgentIpcResponse.Failure(
                    request.RequestId,
                    "PairingGenerationMismatch",
                    "The local-agent pairing generation changed after authenticated health preflight."),
                CanTryFallback: false,
                Connected: false,
                ProtectedRequestSent: false,
                AuthoritativeResponseReceived: false,
                pairingStatus);
        }

        var challengeRequest = AgentIpcRequest.CreatePairingChallengeRequest(
            secret.Context,
            request.RequestId);
        var challengeAttempt = await SendRawToPipeAsync(
            pipeName,
            challengeRequest,
            cancellationToken).ConfigureAwait(false);
        if (challengeAttempt.Response.ContractVersion != AgentContracts.ContractVersion ||
            challengeAttempt.Response.RequestId != challengeRequest.RequestId)
        {
            return new AuthenticatedPipeSendAttempt(
                AgentIpcResponse.Failure(
                    request.RequestId,
                    "PairingChallengeInvalid",
                    "The local agent returned a pairing challenge with an invalid contract or request identity."),
                CanTryFallback: false,
                challengeAttempt.Connected,
                ProtectedRequestSent: false,
                AuthoritativeResponseReceived: false,
                pairingStatus);
        }

        if (!challengeAttempt.Response.Success)
        {
            return new AuthenticatedPipeSendAttempt(
                challengeAttempt.Response with { RequestId = request.RequestId },
                challengeAttempt.CanTryFallback,
                challengeAttempt.Connected,
                ProtectedRequestSent: false,
                AuthoritativeResponseReceived: false,
                pairingStatus);
        }

        if (challengeAttempt.Response.PairingChallenge == null)
        {
            return new AuthenticatedPipeSendAttempt(
                AgentIpcResponse.Failure(
                    request.RequestId,
                    "PairingChallengeInvalid",
                    "The local agent did not return a pairing challenge for the authenticated request."),
                CanTryFallback: false,
                challengeAttempt.Connected,
                ProtectedRequestSent: false,
                AuthoritativeResponseReceived: false,
                pairingStatus);
        }

        var challenge = challengeAttempt.Response.PairingChallenge;
        if (challenge.PairingGeneration != secret.Context.PairingGeneration ||
            challenge.ExpiresAtUtc <= DateTime.UtcNow)
        {
            return new AuthenticatedPipeSendAttempt(
                AgentIpcResponse.Failure(
                    request.RequestId,
                    "PairingChallengeInvalid",
                    "The local agent returned an invalid or expired pairing challenge."),
                CanTryFallback: false,
                Connected: true,
                ProtectedRequestSent: false,
                AuthoritativeResponseReceived: false,
                pairingStatus);
        }

        var protectedRequest = request with { PairingProof = null, PairingChallenge = null };
        var proof = new AgentPairingProof
        {
            ChallengeId = challenge.ChallengeId,
            ResponseMac = AgentPairingProofCrypto.ComputeResponseMac(
                secret.Secret,
                secret.Context,
                challenge,
                protectedRequest)
        };
        var authenticatedAttempt = await SendRawToPipeAsync(
            pipeName,
            protectedRequest with { PairingProof = proof },
            cancellationToken).ConfigureAwait(false);
        if (authenticatedAttempt.Response.Success)
        {
            Volatile.Write(ref _lastPairingStatus, new AgentPairingStoreResult(
                authenticatedAttempt.Response.PairingStatus?.State ?? AgentPairingState.Connected,
                authenticatedAttempt.Response.PairingStatus?.PairingGeneration ?? secret.Context.PairingGeneration,
                authenticatedAttempt.Response.PairingStatus?.ExpiresAtUtc ?? secret.ExpiresAtUtc,
                authenticatedAttempt.Response.PairingStatus?.Status ?? "The local-agent pairing authenticated successfully."));
        }

        return new AuthenticatedPipeSendAttempt(
            authenticatedAttempt.Response,
            authenticatedAttempt.CanTryFallback,
            authenticatedAttempt.Connected,
            authenticatedAttempt.RequestSent,
            authenticatedAttempt.ResponseReceived,
            pairingStatus);
    }

    private async Task<PipeSendAttempt> SendRawToPipeAsync(
        string pipeName,
        AgentIpcRequest request,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        var connected = false;
        var requestSent = false;

        try
        {
            await using var pipe = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification);

            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            connected = true;

            await using var writer = new StreamWriter(pipe, leaveOpen: true);
            using var reader = new StreamReader(pipe, leaveOpen: true);

            var requestJson = JsonSerializer.Serialize(request, AgentIpcJson.JsonOptions);
            requestSent = true;
            await writer.WriteLineAsync(requestJson.AsMemory(), timeout.Token).ConfigureAwait(false);
            await writer.FlushAsync(timeout.Token).ConfigureAwait(false);

            var responseJson = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(responseJson))
            {
                return new PipeSendAttempt(
                    AgentIpcResponse.Failure(request.RequestId, "EmptyResponse", "The agent pipe closed without returning a response."),
                    CanTryFallback: false,
                    Connected: true,
                    RequestSent: true,
                    ResponseReceived: false);
            }

            var response = JsonSerializer.Deserialize<AgentIpcResponse>(
                responseJson,
                AgentIpcJson.JsonOptions);
            if (response == null)
            {
                return new PipeSendAttempt(
                    AgentIpcResponse.Failure(
                        request.RequestId,
                        "InvalidResponse",
                        "The agent returned an empty or invalid response."),
                    CanTryFallback: false,
                    Connected: true,
                    RequestSent: true,
                    ResponseReceived: false);
            }

            return new PipeSendAttempt(
                response,
                CanTryFallback: false,
                Connected: true,
                RequestSent: true,
                ResponseReceived: true);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new PipeSendAttempt(
                AgentIpcResponse.Failure(
                    request.RequestId,
                    "Timeout",
                    $"The local agent pipe '{pipeName}' did not answer {FormatRequest(request)} within {_timeout.TotalSeconds:0.#} seconds."),
                CanTryFallback: !connected,
                Connected: connected,
                RequestSent: requestSent,
                ResponseReceived: false);
        }
        catch (OperationCanceledException)
        {
            return new PipeSendAttempt(
                AgentIpcResponse.Failure(
                    request.RequestId,
                    "Canceled",
                    $"The local agent pipe '{pipeName}' canceled {FormatRequest(request)} before a response was received."),
                CanTryFallback: false,
                Connected: connected,
                RequestSent: requestSent,
                ResponseReceived: false);
        }
        catch (IOException ex)
        {
            return new PipeSendAttempt(
                AgentIpcResponse.Failure(
                    request.RequestId,
                    "PipeIoError",
                    $"The local agent pipe '{pipeName}' could not complete {FormatRequest(request)}: {ex.Message}"),
                CanTryFallback: !connected,
                Connected: connected,
                RequestSent: requestSent,
                ResponseReceived: false);
        }
        catch (UnauthorizedAccessException ex)
        {
            return new PipeSendAttempt(
                AgentIpcResponse.Failure(
                    request.RequestId,
                    "PipeAccessDenied",
                    $"Access to the local agent pipe '{pipeName}' was denied during {FormatRequest(request)}: {ex.Message}"),
                CanTryFallback: false,
                Connected: connected,
                RequestSent: requestSent,
                ResponseReceived: false);
        }
        catch (JsonException ex)
        {
            return new PipeSendAttempt(
                AgentIpcResponse.Failure(
                    request.RequestId,
                    "InvalidJson",
                    $"The local agent pipe '{pipeName}' returned malformed JSON for {FormatRequest(request)}: {ex.Message}"),
                CanTryFallback: false,
                Connected: connected,
                RequestSent: requestSent,
                ResponseReceived: false);
        }
    }

    private static AgentIpcResponse PairingFailure(Guid requestId, AgentPairingStoreResult status)
    {
        var code = status.State switch
        {
            AgentPairingState.Revoked => "PairingRevoked",
            AgentPairingState.Expired => "PairingExpired",
            AgentPairingState.Corrupt => "PairingCorrupt",
            AgentPairingState.WrongUser => "PairingWrongUser",
            AgentPairingState.WrongSession => "PairingSessionMismatch",
            AgentPairingState.WrongRelease => "PairingReleaseMismatch",
            AgentPairingState.AgentExited => "PairedAgentExited",
            AgentPairingState.ProcessMismatch => "PairingProcessMismatch",
            _ => "PairingRequired"
        };
        return AgentIpcResponse.Failure(
            requestId,
            code,
            string.IsNullOrWhiteSpace(status.Status)
                ? "A valid protected local-agent pairing is required."
                : status.Status);
    }

    internal static bool AllowsReleaseMismatchCleanup(AgentCommandKind commandKind) =>
        commandKind is AgentCommandKind.ShutdownAgent or AgentCommandKind.CancelJob;

    private static IReadOnlyList<string> GetDefaultFallbackPipeNames(string pipeName)
    {
        if (string.Equals(pipeName, AgentContracts.PipeName, StringComparison.Ordinal))
        {
            return [AgentContracts.LegacyPipeName];
        }

        if (string.Equals(pipeName, AgentContracts.ShutdownControlPipeName, StringComparison.Ordinal))
        {
            return [AgentContracts.LegacyShutdownControlPipeName];
        }

        return Array.Empty<string>();
    }

    private static string FormatPipeIdentity(string pipeName)
        => string.Equals(pipeName, AgentContracts.PipeName, StringComparison.Ordinal) ||
           string.Equals(pipeName, AgentContracts.ShutdownControlPipeName, StringComparison.Ordinal)
            ? $"'{pipeName}' (primary)"
            : $"'{pipeName}' (legacy alias)";

    private static string FormatRequest(AgentIpcRequest request)
    {
        return request.Kind switch
        {
            AgentIpcRequestKind.SubmitCommand => $"{request.CommandKind} command",
            AgentIpcRequestKind.GetJobStatus when request.JobId.HasValue => $"job-status request {request.JobId.Value}",
            AgentIpcRequestKind.PairingChallenge => "pairing challenge",
            AgentIpcRequestKind.RotatePairing => "pairing rotation",
            AgentIpcRequestKind.RevokePairing => "pairing revocation",
            _ => $"{request.Kind} request"
        };
    }

    private readonly record struct PipeSendAttempt(
        AgentIpcResponse Response,
        bool CanTryFallback,
        bool Connected,
        bool RequestSent,
        bool ResponseReceived);

    private readonly record struct AuthenticatedPipeSendAttempt(
        AgentIpcResponse Response,
        bool CanTryFallback,
        bool Connected,
        bool ProtectedRequestSent,
        bool AuthoritativeResponseReceived,
        AgentPairingStoreResult PairingStatus);
}
