using System.IO;
using System.Net.Http;
using ProcInsider.Models.Features;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.Features;

namespace ProcInsider.Services;

public enum InfrastructureCaseWorkspacePhase
{
    Unbound = 0,
    Opening = 1,
    Refreshing = 2,
    Ready = 3,
    Failed = 4,
    Disposed = 5
}

public sealed record InfrastructureCaseWorkspaceState(
    DeploymentModeKind DeploymentMode,
    string CaseId,
    long WorkspaceGeneration,
    long RequestGeneration,
    InfrastructureCaseWorkspacePhase Phase,
    InfrastructureCaseRevisionToken? Revision,
    InfrastructureCaseRevisionToken? AvailableRevision,
    string CandidateCaseId,
    DateTime RefreshedAtUtc,
    string ErrorCode,
    string Message)
{
    public static InfrastructureCaseWorkspaceState Unbound(long workspaceGeneration = 0) => new(
        DeploymentModeKind.Standalone,
        string.Empty,
        workspaceGeneration,
        0,
        InfrastructureCaseWorkspacePhase.Unbound,
        null,
        null,
        string.Empty,
        DateTime.MinValue,
        string.Empty,
        "Standalone mode remains bound only to validated local snapshots or archived captures.");
}

public interface IInfrastructureCaseWorkspaceClient : IAsyncDisposable
{
    Task<InfrastructureCaseRevisionResponse> OpenCaseRevisionAsync(
        InfrastructureCaseRevisionRequest request,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken);

    Task<InfrastructureViewerQueryResponse> QueryAsync(
        InfrastructureViewerQueryRequest request,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken);

    Task<InfrastructureAnnotationMutationResponse> MutateAnnotationAsync(
        InfrastructureAnnotationMutationRequest request,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken);
}

/// <summary>
/// Headless Viewer owner for one explicit Infrastructure case revision. Candidate validation
/// completes before the old workspace cancellation token is retired, all surface queries copy
/// the same immutable revision, and no SQLite, Postgres, or direct-Agent fallback exists here.
/// </summary>
public sealed class InfrastructureCaseWorkspaceCoordinator : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly IInfrastructureCaseWorkspaceClient _client;
    private CancellationTokenSource _workspaceCancellation = new();
    private CancellationTokenSource? _candidateCancellation;
    private InfrastructureCaseWorkspaceState _state = InfrastructureCaseWorkspaceState.Unbound();
    private long _nextWorkspaceGeneration;
    private long _nextRequestGeneration;
    private long _candidateGeneration;
    private bool _disposed;

    private InfrastructureCaseWorkspaceCoordinator(IInfrastructureCaseWorkspaceClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public event EventHandler? StateChanged;

    public InfrastructureCaseWorkspaceState State
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
        Func<IInfrastructureCaseWorkspaceClient> clientFactory,
        out InfrastructureCaseWorkspaceCoordinator? coordinator,
        out InfrastructureAccessDecision decision)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(clientFactory);
        return access.TryCreate(
            InfrastructureEntryPointKind.IpcOrNetworkClientCreation,
            () => new InfrastructureCaseWorkspaceCoordinator(clientFactory()),
            out coordinator,
            out decision,
            InfrastructureFeatureArea.CaseWorkspaces,
            CurrentInfrastructureModeProfile.Definition.CreateIdentity(InfrastructureComponentKind.Server));
    }

    public Task<InfrastructureCaseRevisionResponse> OpenAsync(
        AuthenticatedInfrastructureViewerContext viewer,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        string caseId,
        CancellationToken cancellationToken = default) =>
        OpenOrRefreshAsync(viewer, grants, caseId, isRefresh: false, cancellationToken);

    public Task<InfrastructureCaseRevisionResponse> RefreshAsync(
        AuthenticatedInfrastructureViewerContext viewer,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken = default)
    {
        string caseId;
        lock (_gate)
        {
            ThrowIfDisposed();
            caseId = _state.CaseId;
        }
        if (string.IsNullOrWhiteSpace(caseId))
            return Task.FromResult(RevisionFailure(
                string.Empty,
                InfrastructureViewerWorkspaceFailure.InvalidRequest,
                "InfrastructureWorkspaceNotBound",
                0,
                0));
        return OpenOrRefreshAsync(viewer, grants, caseId, isRefresh: true, cancellationToken);
    }

    private async Task<InfrastructureCaseRevisionResponse> OpenOrRefreshAsync(
        AuthenticatedInfrastructureViewerContext viewer,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        string caseId,
        bool isRefresh,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(viewer);
        ArgumentNullException.ThrowIfNull(grants);
        InfrastructureCaseRevisionRequest request;
        CancellationTokenSource candidateCancellation;
        long candidateGeneration;
        lock (_gate)
        {
            ThrowIfDisposed();
            _candidateCancellation?.Cancel();
            _candidateCancellation?.Dispose();
            candidateCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _candidateCancellation = candidateCancellation;
            candidateGeneration = ++_candidateGeneration;
            var candidateWorkspaceGeneration = ++_nextWorkspaceGeneration;
            var requestGeneration = ++_nextRequestGeneration;
            request = new InfrastructureCaseRevisionRequest
            {
                Viewer = viewer,
                CaseId = caseId,
                WorkspaceGeneration = candidateWorkspaceGeneration,
                RequestGeneration = requestGeneration,
                ExpectedReleaseId = CurrentInfrastructureModeProfile.Definition.ReleaseId,
                ExpectedProtocolGeneration = CurrentInfrastructureModeProfile.ProtocolGeneration
            };
            _state = _state with
            {
                RequestGeneration = requestGeneration,
                Phase = isRefresh ? InfrastructureCaseWorkspacePhase.Refreshing :
                    InfrastructureCaseWorkspacePhase.Opening,
                CandidateCaseId = caseId,
                ErrorCode = string.Empty,
                Message = isRefresh
                    ? "Validating a newer Server case revision before replacing the current binding."
                    : "Validating the Server case revision before replacing the current binding."
            };
        }
        Raise();

        InfrastructureCaseRevisionResponse response;
        try
        {
            response = await _client.OpenCaseRevisionAsync(request, grants, candidateCancellation.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (candidateCancellation.IsCancellationRequested)
        {
            response = RevisionFailure(caseId, InfrastructureViewerWorkspaceFailure.Canceled,
                "InfrastructureCaseRevisionCanceled", request.WorkspaceGeneration, request.RequestGeneration);
        }
        catch (Exception exception) when (exception is IOException or HttpRequestException or InvalidOperationException)
        {
            response = RevisionFailure(caseId, InfrastructureViewerWorkspaceFailure.TransportUnavailable,
                "InfrastructureCaseServerUnavailable", request.WorkspaceGeneration, request.RequestGeneration);
        }

        InfrastructureCaseWorkspaceState? published = null;
        InfrastructureCaseRevisionResponse result = response;
        lock (_gate)
        {
            if (ReferenceEquals(_candidateCancellation, candidateCancellation))
            {
                _candidateCancellation.Dispose();
                _candidateCancellation = null;
            }
            if (_disposed || candidateGeneration != _candidateGeneration)
            {
                result = RevisionFailure(caseId, InfrastructureViewerWorkspaceFailure.ResponseSuperseded,
                    "InfrastructureCaseRevisionResponseSuperseded",
                    request.WorkspaceGeneration,
                    request.RequestGeneration);
            }
            else if (!IsValidRevisionResponse(request, response))
            {
                result = RevisionFailure(caseId, InfrastructureViewerWorkspaceFailure.ServerUnavailable,
                    "InfrastructureCaseRevisionResponseInvalid",
                    request.WorkspaceGeneration,
                    request.RequestGeneration);
                _state = _state with
                {
                    Phase = InfrastructureCaseWorkspacePhase.Failed,
                    CandidateCaseId = string.Empty,
                    RefreshedAtUtc = result.RespondedAtUtc,
                    ErrorCode = result.ErrorCode,
                    Message = result.Message
                };
                published = _state;
            }
            else if (!response.Allowed)
            {
                _state = _state with
                {
                    Phase = InfrastructureCaseWorkspacePhase.Failed,
                    CandidateCaseId = string.Empty,
                    RefreshedAtUtc = response.RespondedAtUtc,
                    ErrorCode = response.ErrorCode,
                    Message = response.Message
                };
                published = _state;
            }
            else
            {
                var previousWorkspace = _workspaceCancellation;
                _workspaceCancellation = new CancellationTokenSource();
                previousWorkspace.Cancel();
                previousWorkspace.Dispose();
                _state = new InfrastructureCaseWorkspaceState(
                    DeploymentModeKind.Infrastructure,
                    response.CaseId,
                    response.WorkspaceGeneration,
                    response.RequestGeneration,
                    InfrastructureCaseWorkspacePhase.Ready,
                    response.Revision! with { },
                    null,
                    string.Empty,
                    response.RespondedAtUtc,
                    string.Empty,
                    "The Viewer is bound to one validated immutable Server case revision.");
                published = _state;
            }
        }
        if (published != null) Raise();
        return result;
    }

    public async Task<InfrastructureViewerQueryResponse> QueryAsync(
        AuthenticatedInfrastructureViewerContext viewer,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        InfrastructureViewerQueryKind kind,
        InfrastructureCaseQueryScope? scope = null,
        string searchText = "",
        string filterExpression = "",
        InfrastructureViewerSortField sortField = InfrastructureViewerSortField.DurableIdentity,
        InfrastructureViewerSortDirection sortDirection = InfrastructureViewerSortDirection.Ascending,
        string continuationToken = "",
        int maximumRows = InfrastructureViewerQueryContract.DefaultPageSize,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(viewer);
        ArgumentNullException.ThrowIfNull(grants);
        InfrastructureViewerQueryRequest request;
        CancellationToken workspaceToken;
        lock (_gate)
        {
            ThrowIfDisposed();
            if (_state.DeploymentMode != DeploymentModeKind.Infrastructure || _state.Revision == null)
                return QueryFailure(kind, InfrastructureViewerWorkspaceFailure.InvalidRequest,
                    "InfrastructureWorkspaceNotBound", _state.WorkspaceGeneration, _state.RequestGeneration);
            var requestGeneration = ++_nextRequestGeneration;
            request = new InfrastructureViewerQueryRequest
            {
                Viewer = viewer,
                Revision = _state.Revision with { },
                Scope = (scope ?? new InfrastructureCaseQueryScope()) with { CaseId = _state.CaseId },
                Kind = kind,
                SearchText = searchText,
                FilterExpression = filterExpression,
                SortField = sortField,
                SortDirection = sortDirection,
                ContinuationToken = continuationToken,
                MaximumRows = maximumRows,
                WorkspaceGeneration = _state.WorkspaceGeneration,
                RequestGeneration = requestGeneration,
                ExpectedReleaseId = CurrentInfrastructureModeProfile.Definition.ReleaseId,
                ExpectedProtocolGeneration = CurrentInfrastructureModeProfile.ProtocolGeneration
            };
            workspaceToken = _workspaceCancellation.Token;
        }

        if (!InfrastructureViewerQueryPolicy.IsValidQueryRequest(request))
            return QueryFailure(kind, InfrastructureViewerWorkspaceFailure.InvalidRequest,
                "InfrastructureViewerQueryInvalid", request.WorkspaceGeneration, request.RequestGeneration);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, workspaceToken);
        InfrastructureViewerQueryResponse response;
        try
        {
            response = await QueryWithOneReadRetryAsync(request, grants, linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            response = QueryFailure(kind, InfrastructureViewerWorkspaceFailure.Canceled,
                "InfrastructureViewerQueryCanceled", request.WorkspaceGeneration, request.RequestGeneration);
        }
        catch (Exception exception) when (exception is IOException or HttpRequestException or InvalidOperationException)
        {
            response = QueryFailure(kind, InfrastructureViewerWorkspaceFailure.TransportUnavailable,
                "InfrastructureViewerQueryTransportUnavailable",
                request.WorkspaceGeneration, request.RequestGeneration);
        }

        lock (_gate)
        {
            if (_disposed || _state.WorkspaceGeneration != request.WorkspaceGeneration ||
                _state.Revision?.TokenSha256 != request.Revision.TokenSha256 ||
                !IsValidQueryResponse(request, response))
                return QueryFailure(kind, InfrastructureViewerWorkspaceFailure.ResponseSuperseded,
                    "InfrastructureViewerQueryResponseSuperseded",
                    request.WorkspaceGeneration, request.RequestGeneration);
        }
        return response;
    }

    public async Task<InfrastructureAnnotationMutationResponse> MutateAnnotationAsync(
        AuthenticatedInfrastructureViewerContext viewer,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        InfrastructureAnnotationMutationKind kind,
        string annotationId,
        string targetIdentity,
        string bodyJson,
        long expectedAnnotationRevision,
        CancellationToken cancellationToken = default)
    {
        InfrastructureAnnotationMutationRequest request;
        CancellationToken workspaceToken;
        lock (_gate)
        {
            ThrowIfDisposed();
            if (_state.DeploymentMode != DeploymentModeKind.Infrastructure || _state.Revision == null)
                return AnnotationFailure(annotationId, InfrastructureViewerWorkspaceFailure.InvalidRequest,
                    "InfrastructureWorkspaceNotBound", _state.WorkspaceGeneration, _state.RequestGeneration);
            request = new InfrastructureAnnotationMutationRequest
            {
                Viewer = viewer,
                Revision = _state.Revision with { },
                Kind = kind,
                AnnotationId = annotationId,
                TargetIdentity = targetIdentity,
                BodyJson = bodyJson,
                ExpectedAnnotationRevision = expectedAnnotationRevision,
                WorkspaceGeneration = _state.WorkspaceGeneration,
                RequestGeneration = ++_nextRequestGeneration,
                ExpectedReleaseId = CurrentInfrastructureModeProfile.Definition.ReleaseId,
                ExpectedProtocolGeneration = CurrentInfrastructureModeProfile.ProtocolGeneration
            };
            workspaceToken = _workspaceCancellation.Token;
        }
        if (!InfrastructureViewerQueryPolicy.IsValidAnnotationRequest(request))
            return AnnotationFailure(annotationId, InfrastructureViewerWorkspaceFailure.InvalidRequest,
                "InfrastructureAnnotationRequestInvalid", request.WorkspaceGeneration, request.RequestGeneration);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, workspaceToken);
        InfrastructureAnnotationMutationResponse response;
        try
        {
            response = await _client.MutateAnnotationAsync(request, grants, linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            response = AnnotationFailure(annotationId, InfrastructureViewerWorkspaceFailure.Canceled,
                "InfrastructureAnnotationCanceled", request.WorkspaceGeneration, request.RequestGeneration);
        }
        catch (Exception exception) when (exception is IOException or HttpRequestException or InvalidOperationException)
        {
            response = AnnotationFailure(annotationId, InfrastructureViewerWorkspaceFailure.TransportUnavailable,
                "InfrastructureAnnotationTransportUnavailable",
                request.WorkspaceGeneration, request.RequestGeneration);
        }

        lock (_gate)
        {
            if (_disposed || _state.WorkspaceGeneration != request.WorkspaceGeneration ||
                _state.Revision?.TokenSha256 != request.Revision.TokenSha256 ||
                !IsValidAnnotationResponse(request, response))
                return AnnotationFailure(annotationId, InfrastructureViewerWorkspaceFailure.ResponseSuperseded,
                    "InfrastructureAnnotationResponseSuperseded",
                    request.WorkspaceGeneration, request.RequestGeneration);
            if (response.Allowed && response.CaseRevision != null)
            {
                _state = _state with
                {
                    AvailableRevision = response.CaseRevision with { },
                    Message = "The annotation committed; Refresh from Server can validate the newer case revision."
                };
            }
        }
        if (response.Allowed) Raise();
        return response;
    }

    public InfrastructureCaseWorkspaceState Detach()
    {
        InfrastructureCaseWorkspaceState state;
        lock (_gate)
        {
            ThrowIfDisposed();
            _candidateCancellation?.Cancel();
            _candidateCancellation?.Dispose();
            _candidateCancellation = null;
            _candidateGeneration++;
            _workspaceCancellation.Cancel();
            _workspaceCancellation.Dispose();
            _workspaceCancellation = new CancellationTokenSource();
            state = InfrastructureCaseWorkspaceState.Unbound(++_nextWorkspaceGeneration);
            _state = state;
        }
        Raise();
        return state;
    }

    public async ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _candidateCancellation?.Cancel();
            _candidateCancellation?.Dispose();
            _candidateCancellation = null;
            _workspaceCancellation.Cancel();
            _workspaceCancellation.Dispose();
            _state = _state with
            {
                Phase = InfrastructureCaseWorkspacePhase.Disposed,
                Revision = null,
                AvailableRevision = null,
                CandidateCaseId = string.Empty,
                ErrorCode = string.Empty,
                Message = "The Infrastructure case workspace coordinator was disposed."
            };
        }
        await _client.DisposeAsync().ConfigureAwait(false);
    }

    private async Task<InfrastructureViewerQueryResponse> QueryWithOneReadRetryAsync(
        InfrastructureViewerQueryRequest request,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _client.QueryAsync(request, grants, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or HttpRequestException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await _client.QueryAsync(request, grants, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsValidRevisionResponse(
        InfrastructureCaseRevisionRequest request,
        InfrastructureCaseRevisionResponse response) =>
        response != null && response.CaseId == request.CaseId &&
        response.WorkspaceGeneration == request.WorkspaceGeneration &&
        response.RequestGeneration == request.RequestGeneration &&
        response.RespondedAtUtc.Kind == DateTimeKind.Utc &&
        response.ErrorCode is { Length: <= InfrastructureViewerQueryContract.MaximumErrorCodeCharacters } &&
        response.Message is { Length: <= InfrastructureViewerQueryContract.MaximumMessageCharacters } &&
        (response.Allowed
            ? response.Failure == InfrastructureViewerWorkspaceFailure.None &&
              InfrastructureCaseRevisionTokenCodec.Validate(response.Revision) &&
              response.Revision!.CaseId == request.CaseId
            : response.Failure != InfrastructureViewerWorkspaceFailure.None && response.Revision == null);

    private static bool IsValidQueryResponse(
        InfrastructureViewerQueryRequest request,
        InfrastructureViewerQueryResponse response) =>
        response != null && response.Kind == request.Kind &&
        response.WorkspaceGeneration == request.WorkspaceGeneration &&
        response.RequestGeneration == request.RequestGeneration &&
        response.RespondedAtUtc.Kind == DateTimeKind.Utc && response.Rows is { } &&
        response.Rows.Count <= request.MaximumRows &&
        response.ErrorCode is { Length: <= InfrastructureViewerQueryContract.MaximumErrorCodeCharacters } &&
        response.Message is { Length: <= InfrastructureViewerQueryContract.MaximumMessageCharacters } &&
        response.NextContinuationToken is
            { Length: <= InfrastructureViewerQueryContract.MaximumCursorCharacters } &&
        (response.Allowed
            ? response.Failure == InfrastructureViewerWorkspaceFailure.None &&
              response.Revision?.TokenSha256 == request.Revision.TokenSha256 &&
              response.Rows.All(row => row.Kind == request.Kind &&
                  InfrastructureViewerQueryPolicy.IsValidRow(row, request.Revision.CaseId)) &&
              response.HasMore != string.IsNullOrEmpty(response.NextContinuationToken)
            : response.Failure != InfrastructureViewerWorkspaceFailure.None &&
              response.Revision == null && response.Rows.Count == 0 && !response.HasMore &&
              string.IsNullOrEmpty(response.NextContinuationToken));

    private static bool IsValidAnnotationResponse(
        InfrastructureAnnotationMutationRequest request,
        InfrastructureAnnotationMutationResponse response) =>
        response != null && response.AnnotationId == request.AnnotationId &&
        response.WorkspaceGeneration == request.WorkspaceGeneration &&
        response.RequestGeneration == request.RequestGeneration &&
        response.RespondedAtUtc.Kind == DateTimeKind.Utc &&
        response.ErrorCode is { Length: <= InfrastructureViewerQueryContract.MaximumErrorCodeCharacters } &&
        response.Message is { Length: <= InfrastructureViewerQueryContract.MaximumMessageCharacters } &&
        (response.Allowed
            ? response.Failure == InfrastructureViewerWorkspaceFailure.None &&
              response.AnnotationRevision > request.ExpectedAnnotationRevision &&
              InfrastructureCaseRevisionTokenCodec.Validate(response.CaseRevision) &&
              response.CaseRevision!.CaseId == request.Revision.CaseId &&
              response.CaseRevision.Revision > request.Revision.Revision &&
              response.CaseRevision.ServerInstanceId == request.Revision.ServerInstanceId &&
              response.CaseRevision.RestoreGeneration == request.Revision.RestoreGeneration
            : response.Failure != InfrastructureViewerWorkspaceFailure.None && response.CaseRevision == null);

    private static InfrastructureCaseRevisionResponse RevisionFailure(
        string caseId,
        InfrastructureViewerWorkspaceFailure failure,
        string code,
        long workspaceGeneration,
        long requestGeneration) => new()
        {
            Failure = failure,
            ErrorCode = code,
            Message = "The candidate Server revision was not installed.",
            CaseId = caseId,
            WorkspaceGeneration = workspaceGeneration,
            RequestGeneration = requestGeneration,
            RespondedAtUtc = DateTime.UtcNow
        };

    private static InfrastructureViewerQueryResponse QueryFailure(
        InfrastructureViewerQueryKind kind,
        InfrastructureViewerWorkspaceFailure failure,
        string code,
        long workspaceGeneration,
        long requestGeneration) => new()
        {
            Failure = failure,
            ErrorCode = code,
            Message = "The bounded Server query did not replace or mix Viewer state.",
            Kind = kind,
            WorkspaceGeneration = workspaceGeneration,
            RequestGeneration = requestGeneration,
            RespondedAtUtc = DateTime.UtcNow
        };

    private static InfrastructureAnnotationMutationResponse AnnotationFailure(
        string annotationId,
        InfrastructureViewerWorkspaceFailure failure,
        string code,
        long workspaceGeneration,
        long requestGeneration) => new()
        {
            Failure = failure,
            ErrorCode = code,
            Message = "The annotation mutation did not change case state.",
            AnnotationId = annotationId,
            WorkspaceGeneration = workspaceGeneration,
            RequestGeneration = requestGeneration,
            RespondedAtUtc = DateTime.UtcNow
        };

    private void Raise() => StateChanged?.Invoke(this, EventArgs.Empty);

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(InfrastructureCaseWorkspaceCoordinator));
    }
}
