using ProcInsider.Models.Features;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.AgentIpc;

public enum InfrastructureAgentControlPlanePhase
{
    Unbound = 0,
    Ready = 1,
    Refreshing = 2,
    Failed = 3,
    Disposed = 4
}

public sealed record InfrastructureAgentControlPlaneState(
    DeploymentModeKind DeploymentMode,
    string CaseId,
    long WorkspaceGeneration,
    long RequestGeneration,
    InfrastructureAgentControlPlanePhase Phase,
    IReadOnlyList<InfrastructureAgentProjectionRow> Agents,
    int ConnectedAgentCount,
    long ProjectionRevision,
    DateTime RefreshedAtUtc,
    string ErrorCode,
    string Message)
{
    public static InfrastructureAgentControlPlaneState Unbound(long workspaceGeneration = 0) =>
        new(
            DeploymentModeKind.Standalone,
            string.Empty,
            workspaceGeneration,
            0,
            InfrastructureAgentControlPlanePhase.Unbound,
            Array.Empty<InfrastructureAgentProjectionRow>(),
            0,
            0,
            DateTime.MinValue,
            string.Empty,
            "Standalone mode uses only the retained local Agent control plane.");
}

public sealed class InfrastructureAgentControlPlaneStateChangedEventArgs(
    InfrastructureAgentControlPlaneState state) : EventArgs
{
    public InfrastructureAgentControlPlaneState State { get; } = state;
}

public interface IInfrastructureAgentRegistryClient : IAsyncDisposable
{
    Task<InfrastructureAgentProjectionResponse> ListAgentsAsync(
        InfrastructureAgentProjectionRequest request,
        IReadOnlyList<InfrastructureViewerHealthGrant> grants,
        CancellationToken cancellationToken);
}

/// <summary>
/// Viewer-side, Server-only Infrastructure Agent control-plane adapter. It owns workspace and
/// request generations, rejects late responses, and never constructs or falls back to a direct
/// Agent client. Command routing remains unavailable until #338.
/// </summary>
public sealed class InfrastructureAgentControlPlaneAdapter : IAsyncDisposable
{
    public static readonly TimeSpan MinimumPollingInterval = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan MaximumPollingInterval = TimeSpan.FromMinutes(1);

    private readonly object _gate = new();
    private readonly IInfrastructureAgentRegistryClient _client;
    private CancellationTokenSource? _operationCancellation;
    private InfrastructureAgentControlPlaneState _state = InfrastructureAgentControlPlaneState.Unbound();
    private long _workspaceGeneration;
    private long _requestGeneration;
    private bool _disposed;

    private InfrastructureAgentControlPlaneAdapter(IInfrastructureAgentRegistryClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public event EventHandler<InfrastructureAgentControlPlaneStateChangedEventArgs>? StateChanged;

    public InfrastructureAgentControlPlaneState State
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
        Func<IInfrastructureAgentRegistryClient> clientFactory,
        out InfrastructureAgentControlPlaneAdapter? adapter,
        out InfrastructureAccessDecision decision)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(clientFactory);
        return access.TryCreate(
            InfrastructureEntryPointKind.IpcOrNetworkClientCreation,
            () => new InfrastructureAgentControlPlaneAdapter(clientFactory()),
            out adapter,
            out decision,
            InfrastructureFeatureArea.AgentManagement,
            CurrentInfrastructureModeProfile.Definition.CreateIdentity(InfrastructureComponentKind.Server));
    }

    public InfrastructureAgentControlPlaneState BindWorkspace(
        DeploymentModeKind deploymentMode,
        string caseId)
    {
        InfrastructureAgentControlPlaneState next;
        lock (_gate)
        {
            ThrowIfDisposed();
            _operationCancellation?.Cancel();
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            _workspaceGeneration++;
            _requestGeneration = 0;
            next = deploymentMode == DeploymentModeKind.Infrastructure && !string.IsNullOrWhiteSpace(caseId)
                ? new InfrastructureAgentControlPlaneState(
                    deploymentMode,
                    caseId,
                    _workspaceGeneration,
                    0,
                    InfrastructureAgentControlPlanePhase.Ready,
                    Array.Empty<InfrastructureAgentProjectionRow>(),
                    0,
                    0,
                    DateTime.MinValue,
                    string.Empty,
                    "Infrastructure Agent registry is bound to the Server case scope.")
                : InfrastructureAgentControlPlaneState.Unbound(_workspaceGeneration);
            _state = next;
        }

        Raise(next);
        return next;
    }

    public async Task<InfrastructureAgentProjectionResponse> RefreshAsync(
        AuthenticatedInfrastructureViewerContext viewer,
        IReadOnlyList<InfrastructureViewerHealthGrant> grants,
        CancellationToken cancellationToken = default)
    {
        InfrastructureAgentProjectionRequest request;
        CancellationToken operationToken;
        InfrastructureAgentControlPlaneState refreshing;
        lock (_gate)
        {
            ThrowIfDisposed();
            if (_state.DeploymentMode != DeploymentModeKind.Infrastructure || string.IsNullOrWhiteSpace(_state.CaseId))
            {
                return Failure(InfrastructureAgentProjectionFailure.InvalidRequest,
                    "InfrastructureWorkspaceNotBound",
                    "The Viewer is not bound to an Infrastructure case workspace.",
                    _state.WorkspaceGeneration,
                    _state.RequestGeneration);
            }

            _operationCancellation?.Cancel();
            _operationCancellation?.Dispose();
            _operationCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            operationToken = _operationCancellation.Token;
            var requestGeneration = ++_requestGeneration;
            request = new InfrastructureAgentProjectionRequest
            {
                Viewer = viewer,
                CaseId = _state.CaseId,
                WorkspaceGeneration = _state.WorkspaceGeneration,
                RequestGeneration = requestGeneration,
                MaximumRows = InfrastructureAgentProjectionPolicy.DefaultMaximumRows,
                ExpectedReleaseId = CurrentInfrastructureModeProfile.Definition.ReleaseId,
                ExpectedProtocolGeneration = CurrentInfrastructureModeProfile.ProtocolGeneration
            };
            refreshing = _state with
            {
                RequestGeneration = requestGeneration,
                Phase = InfrastructureAgentControlPlanePhase.Refreshing,
                ErrorCode = string.Empty,
                Message = "Refreshing authorized Agent registry/health through the Server."
            };
            _state = refreshing;
        }

        Raise(refreshing);
        InfrastructureAgentProjectionResponse response;
        try
        {
            response = await _client.ListAgentsAsync(request, grants, operationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (operationToken.IsCancellationRequested)
        {
            var canceled = Failure(InfrastructureAgentProjectionFailure.Canceled,
                "InfrastructureProjectionCanceled",
                "The Server projection request was canceled.",
                request.WorkspaceGeneration,
                request.RequestGeneration);
            PublishFailureIfCurrent(request, canceled);
            return canceled;
        }
        catch (Exception)
        {
            var failed = Failure(InfrastructureAgentProjectionFailure.TransportUnavailable,
                "InfrastructureProjectionTransportFailed",
                "The Server projection request failed before a current response was received.",
                request.WorkspaceGeneration,
                request.RequestGeneration);
            PublishFailureIfCurrent(request, failed);
            return failed;
        }

        InfrastructureAgentControlPlaneState? published = null;
        lock (_gate)
        {
            if (_disposed ||
                _state.WorkspaceGeneration != request.WorkspaceGeneration ||
                _state.RequestGeneration != request.RequestGeneration ||
                response.WorkspaceGeneration != request.WorkspaceGeneration ||
                response.RequestGeneration != request.RequestGeneration)
            {
                return Failure(InfrastructureAgentProjectionFailure.ResponseSuperseded,
                    "InfrastructureProjectionSuperseded",
                    "A late Server response was rejected after the workspace or request generation changed.",
                    request.WorkspaceGeneration,
                    request.RequestGeneration);
            }

            if (!IsValidResponse(request, response))
            {
                response = Failure(
                    InfrastructureAgentProjectionFailure.InvalidRequest,
                    "InfrastructureProjectionResponseInvalid",
                    "The Server returned a malformed or inconsistent Agent projection.",
                    request.WorkspaceGeneration,
                    request.RequestGeneration);
            }

            published = response.Allowed
                ? _state with
                {
                    Phase = InfrastructureAgentControlPlanePhase.Ready,
                    Agents = response.Agents,
                    ConnectedAgentCount = response.ConnectedAgentCount,
                    ProjectionRevision = response.ProjectionRevision,
                    RefreshedAtUtc = response.GeneratedAtUtc,
                    ErrorCode = string.Empty,
                    Message = response.Message
                }
                : _state with
                {
                    Phase = InfrastructureAgentControlPlanePhase.Failed,
                    Agents = Array.Empty<InfrastructureAgentProjectionRow>(),
                    ConnectedAgentCount = 0,
                    ProjectionRevision = response.ProjectionRevision,
                    RefreshedAtUtc = response.GeneratedAtUtc,
                    ErrorCode = response.ErrorCode,
                    Message = response.Message
                };
            _state = published;
        }

        Raise(published);
        return response;
    }

    public async Task RunPollingAsync(
        AuthenticatedInfrastructureViewerContext viewer,
        IReadOnlyList<InfrastructureViewerHealthGrant> grants,
        TimeSpan interval,
        CancellationToken cancellationToken)
    {
        if (interval < MinimumPollingInterval || interval > MaximumPollingInterval)
        {
            throw new ArgumentOutOfRangeException(nameof(interval));
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            await RefreshAsync(viewer, grants, cancellationToken).ConfigureAwait(false);
            await Task.Delay(interval, cancellationToken).ConfigureAwait(false);
        }
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
            _state = _state with
            {
                Phase = InfrastructureAgentControlPlanePhase.Disposed,
                Agents = Array.Empty<InfrastructureAgentProjectionRow>(),
                ConnectedAgentCount = 0,
                ErrorCode = string.Empty,
                Message = "The Infrastructure Agent control-plane adapter was disposed."
            };
        }

        await _client.DisposeAsync().ConfigureAwait(false);
    }

    private void Raise(InfrastructureAgentControlPlaneState state) =>
        StateChanged?.Invoke(this, new InfrastructureAgentControlPlaneStateChangedEventArgs(state));

    private void PublishFailureIfCurrent(
        InfrastructureAgentProjectionRequest request,
        InfrastructureAgentProjectionResponse response)
    {
        InfrastructureAgentControlPlaneState? published = null;
        lock (_gate)
        {
            if (!_disposed &&
                _state.WorkspaceGeneration == request.WorkspaceGeneration &&
                _state.RequestGeneration == request.RequestGeneration)
            {
                published = _state with
                {
                    Phase = InfrastructureAgentControlPlanePhase.Failed,
                    Agents = Array.Empty<InfrastructureAgentProjectionRow>(),
                    ConnectedAgentCount = 0,
                    RefreshedAtUtc = response.GeneratedAtUtc,
                    ErrorCode = response.ErrorCode,
                    Message = response.Message
                };
                _state = published;
            }
        }

        if (published != null)
        {
            Raise(published);
        }
    }

    private static bool IsValidResponse(
        InfrastructureAgentProjectionRequest request,
        InfrastructureAgentProjectionResponse response)
    {
        if (response.GeneratedAtUtc.Kind != DateTimeKind.Utc ||
            response.ProjectionRevision < 0 ||
            !string.Equals(response.CaseId, request.CaseId, StringComparison.Ordinal) ||
            response.WorkspaceGeneration != request.WorkspaceGeneration ||
            response.RequestGeneration != request.RequestGeneration ||
            response.Agents.Count > request.MaximumRows ||
            response.ConnectedAgentCount < 0)
        {
            return false;
        }

        if (!response.Allowed)
        {
            return response.Failure != InfrastructureAgentProjectionFailure.None &&
                   response.Agents.Count == 0 &&
                   response.ConnectedAgentCount == 0;
        }

        if (response.Failure != InfrastructureAgentProjectionFailure.None ||
            response.Agents.Any(row =>
                row == null ||
                string.IsNullOrWhiteSpace(row.AgentId) || row.AgentId.Length > 512 ||
                string.IsNullOrWhiteSpace(row.HostId) || row.HostId.Length > 512 ||
                !string.Equals(row.CaseId, request.CaseId, StringComparison.Ordinal) ||
                !Enum.IsDefined(row.State) || !Enum.IsDefined(row.EnrollmentState) ||
                row.ConfigurationRevision <= 0 || row.CredentialEpoch <= 0 ||
                row.CommandEligible))
        {
            return false;
        }

        var distinctIdentities = response.Agents
            .Select(row => (row.AgentId, row.HostId))
            .Distinct()
            .Count();
        var countedIdentities = response.Agents
            .Where(row => row.CountsAsConnected)
            .Select(row => (row.AgentId, row.HostId))
            .Distinct()
            .Count();
        return distinctIdentities == response.Agents.Count &&
               countedIdentities == response.ConnectedAgentCount;
    }

    private static InfrastructureAgentProjectionResponse Failure(
        InfrastructureAgentProjectionFailure failure,
        string errorCode,
        string message,
        long workspaceGeneration,
        long requestGeneration) =>
        new()
        {
            Failure = failure,
            ErrorCode = errorCode,
            Message = message,
            WorkspaceGeneration = workspaceGeneration,
            RequestGeneration = requestGeneration,
            GeneratedAtUtc = DateTime.UtcNow
        };

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(InfrastructureAgentControlPlaneAdapter));
        }
    }
}
