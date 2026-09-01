using System.IO;
using System.Net.Http;
using System.Text.Json;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.AgentIpc;

public enum InfrastructureAgentCommandPhase
{
    Unbound = 0,
    Ready = 1,
    Dispatching = 2,
    Completed = 3,
    Failed = 4,
    Disposed = 5
}

public sealed record InfrastructureAgentCommandState(
    DeploymentModeKind DeploymentMode,
    string CaseId,
    long WorkspaceGeneration,
    long RequestGeneration,
    InfrastructureAgentCommandPhase Phase,
    InfrastructureCommandDispatchResult? LastResult,
    string ErrorCode,
    string Message)
{
    public static InfrastructureAgentCommandState Unbound(long workspaceGeneration = 0) =>
        new(
            DeploymentModeKind.Standalone,
            string.Empty,
            workspaceGeneration,
            0,
            InfrastructureAgentCommandPhase.Unbound,
            null,
            string.Empty,
            "Standalone commands use only the retained local authenticated Agent path.");
}

public interface IInfrastructureAgentCommandClient : IAsyncDisposable
{
    Task<InfrastructureCommandDispatchResult> DispatchAsync(
        InfrastructureCommandDispatchRequest request,
        IReadOnlyList<InfrastructureViewerCommandGrant> grants,
        CancellationToken cancellationToken);
}

/// <summary>
/// Viewer-side Server-only command adapter. It creates one exact bounded request from a
/// typed Agent command, rejects late workspace generations, and never constructs or falls
/// back to a direct Agent client. The Server and Agent remain the authorization owners.
/// </summary>
public sealed class InfrastructureAgentCommandAdapter : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly IInfrastructureAgentCommandClient _client;
    private CancellationTokenSource? _operationCancellation;
    private InfrastructureAgentCommandState _state = InfrastructureAgentCommandState.Unbound();
    private long _workspaceGeneration;
    private long _requestGeneration;
    private bool _requestInFlight;
    private bool _disposed;

    private InfrastructureAgentCommandAdapter(IInfrastructureAgentCommandClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public event EventHandler? StateChanged;

    public InfrastructureAgentCommandState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    public static bool TryCreate(
        InfrastructureModeAccessService access,
        Func<IInfrastructureAgentCommandClient> clientFactory,
        out InfrastructureAgentCommandAdapter? adapter,
        out InfrastructureAccessDecision decision)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(clientFactory);
        return access.TryCreate(
            InfrastructureEntryPointKind.IpcOrNetworkClientCreation,
            () => new InfrastructureAgentCommandAdapter(clientFactory()),
            out adapter,
            out decision,
            InfrastructureFeatureArea.AgentManagement,
            CurrentInfrastructureModeProfile.Definition.CreateIdentity(InfrastructureComponentKind.Server));
    }

    public InfrastructureAgentCommandState BindWorkspace(DeploymentModeKind deploymentMode, string caseId)
    {
        InfrastructureAgentCommandState state;
        lock (_gate)
        {
            ThrowIfDisposed();
            _operationCancellation?.Cancel();
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            _requestInFlight = false;
            _workspaceGeneration++;
            _requestGeneration = 0;
            state = deploymentMode == DeploymentModeKind.Infrastructure && !string.IsNullOrWhiteSpace(caseId)
                ? new InfrastructureAgentCommandState(
                    deploymentMode,
                    caseId,
                    _workspaceGeneration,
                    0,
                    InfrastructureAgentCommandPhase.Ready,
                    null,
                    string.Empty,
                    "Infrastructure commands are bound to one Server case workspace.")
                : InfrastructureAgentCommandState.Unbound(_workspaceGeneration);
            _state = state;
        }

        Raise();
        return state;
    }

    public async Task<InfrastructureCommandDispatchResult> SubmitAsync(
        AuthenticatedInfrastructureViewerContext viewer,
        IReadOnlyList<InfrastructureViewerCommandGrant> grants,
        InfrastructureCommandTarget target,
        AgentCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(viewer);
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(command);
        InfrastructureCommandDispatchRequest request;
        CancellationTokenSource operationCancellation;
        CancellationToken operationToken;
        lock (_gate)
        {
            ThrowIfDisposed();
            if (_state.DeploymentMode != DeploymentModeKind.Infrastructure ||
                !string.Equals(_state.CaseId, target.Scope.CaseId, StringComparison.Ordinal))
            {
                return LocalFailure(
                    Guid.NewGuid(),
                    InfrastructureCommandFailure.InvalidRequest,
                    "InfrastructureCommandWorkspaceMismatch",
                    "The Viewer is not bound to the exact Infrastructure case target.",
                    target,
                    _state.WorkspaceGeneration,
                    _state.RequestGeneration);
            }

            if (_requestInFlight)
            {
                return LocalFailure(
                    Guid.NewGuid(),
                    InfrastructureCommandFailure.DispatchRejected,
                    "InfrastructureCommandSingleFlight",
                    "One Infrastructure command is already awaiting its exact result.",
                    target,
                    _state.WorkspaceGeneration,
                    _state.RequestGeneration);
            }

            var classification = InfrastructureCommandPolicy.Classify(command.Kind);
            var payload = JsonSerializer.Serialize(command, command.GetType(), AgentIpcJson.JsonOptions);
            var requestId = Guid.NewGuid();
            var requestGeneration = ++_requestGeneration;
            request = new InfrastructureCommandDispatchRequest
            {
                Viewer = viewer,
                RequestId = requestId,
                Target = target with { Scope = target.Scope with { } },
                CommandKind = command.Kind,
                CommandPayloadJson = payload,
                Idempotency = classification.Idempotency,
                Attempt = 1,
                DeadlineUtc = DateTime.UtcNow + InfrastructureSessionLimits.CompiledRequestDeadline,
                WorkspaceGeneration = _state.WorkspaceGeneration,
                RequestGeneration = requestGeneration
            };
            var localPolicy = InfrastructureCommandPolicy.Evaluate(request, grants, DateTime.UtcNow);
            if (!localPolicy.Allowed)
            {
                return LocalFailure(
                    requestId,
                    localPolicy.Failure,
                    localPolicy.ErrorCode,
                    localPolicy.Message,
                    target,
                    request.WorkspaceGeneration,
                    request.RequestGeneration);
            }

            operationCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _operationCancellation = operationCancellation;
            operationToken = operationCancellation.Token;
            _requestInFlight = true;
            _state = _state with
            {
                RequestGeneration = requestGeneration,
                Phase = InfrastructureAgentCommandPhase.Dispatching,
                LastResult = null,
                ErrorCode = string.Empty,
                Message = "Authorizing and routing one exact command through the Server."
            };
        }

        Raise();
        InfrastructureCommandDispatchResult result;
        try
        {
            result = await _client.DispatchAsync(request, grants, operationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (operationToken.IsCancellationRequested)
        {
            result = LocalFailure(
                request.RequestId,
                InfrastructureCommandFailure.Canceled,
                "InfrastructureCommandCanceled",
                "The current Viewer command request was canceled; it was not retried.",
                target,
                request.WorkspaceGeneration,
                request.RequestGeneration);
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException or InvalidOperationException)
        {
            result = LocalFailure(
                request.RequestId,
                InfrastructureCommandFailure.TransportUnavailable,
                "InfrastructureCommandTransportUnavailable",
                "The Server command request failed before a current result was received.",
                target,
                request.WorkspaceGeneration,
                request.RequestGeneration);
        }

        lock (_gate)
        {
            if (ReferenceEquals(_operationCancellation, operationCancellation))
            {
                _requestInFlight = false;
                _operationCancellation.Dispose();
                _operationCancellation = null;
            }

            if (_disposed || _state.WorkspaceGeneration != request.WorkspaceGeneration ||
                _state.RequestGeneration != request.RequestGeneration || !IsValidResult(request, result))
            {
                return LocalFailure(
                    request.RequestId,
                    InfrastructureCommandFailure.ResponseSuperseded,
                    "InfrastructureCommandResponseSuperseded",
                    "A late or malformed Server result was rejected after the workspace/request changed.",
                    target,
                    request.WorkspaceGeneration,
                    request.RequestGeneration);
            }

            _state = _state with
            {
                Phase = result.Failure == InfrastructureCommandFailure.None &&
                        (result.Outcome is InfrastructureSessionCommandOutcome.Accepted or
                            InfrastructureSessionCommandOutcome.Completed)
                    ? InfrastructureAgentCommandPhase.Completed
                    : InfrastructureAgentCommandPhase.Failed,
                LastResult = result,
                ErrorCode = result.ErrorCode,
                Message = result.Message
            };
        }

        Raise();
        return result;
    }

    public async ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _operationCancellation?.Cancel();
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            _requestInFlight = false;
            _state = _state with
            {
                Phase = InfrastructureAgentCommandPhase.Disposed,
                LastResult = null,
                ErrorCode = string.Empty,
                Message = "The Infrastructure command adapter was disposed."
            };
        }

        await _client.DisposeAsync().ConfigureAwait(false);
    }

    private static bool IsValidResult(
        InfrastructureCommandDispatchRequest request,
        InfrastructureCommandDispatchResult result) =>
        result != null &&
        result.RequestId == request.RequestId &&
        result.WorkspaceGeneration == request.WorkspaceGeneration &&
        result.RequestGeneration == request.RequestGeneration &&
        string.Equals(result.AgentId, request.Target.AgentId, StringComparison.Ordinal) &&
        string.Equals(result.HostId, request.Target.HostId, StringComparison.Ordinal) &&
        string.Equals(result.CaseId, request.Target.Scope.CaseId, StringComparison.Ordinal) &&
        result.ConnectionGeneration == request.Target.ConnectionGeneration &&
        result.ServerSessionGeneration == request.Target.ServerSessionGeneration &&
        result.SessionId == request.Target.SessionId &&
        result.CompletedAtUtc.Kind == DateTimeKind.Utc &&
        result.Outcome != InfrastructureSessionCommandOutcome.Unknown &&
        Enum.IsDefined(result.Failure) && Enum.IsDefined(result.Outcome) &&
        result.ErrorCode is { Length: <= 128 } &&
        result.JobId is { Length: <= 128 } &&
        result.Message is { Length: <= 2048 };

    private static InfrastructureCommandDispatchResult LocalFailure(
        Guid requestId,
        InfrastructureCommandFailure failure,
        string errorCode,
        string message,
        InfrastructureCommandTarget target,
        long workspaceGeneration,
        long requestGeneration) =>
        new()
        {
            RequestId = requestId,
            Outcome = InfrastructureSessionCommandOutcome.Rejected,
            Failure = failure,
            ErrorCode = errorCode,
            Message = message,
            AgentId = target.AgentId,
            HostId = target.HostId,
            CaseId = target.Scope.CaseId,
            ConnectionGeneration = target.ConnectionGeneration,
            ServerSessionGeneration = target.ServerSessionGeneration,
            SessionId = target.SessionId,
            WorkspaceGeneration = workspaceGeneration,
            RequestGeneration = requestGeneration,
            CompletedAtUtc = DateTime.UtcNow
        };

    private void Raise() => StateChanged?.Invoke(this, EventArgs.Empty);

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(InfrastructureAgentCommandAdapter));
        }
    }
}
