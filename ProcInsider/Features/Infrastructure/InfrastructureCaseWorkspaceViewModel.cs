using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Features;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services;
using ProcInsider.Services.Features;

namespace ProcInsider.Features.Infrastructure;

/// <summary>
/// WPF-facing projection of the headless Infrastructure workspace coordinator. It displays one
/// immutable Server revision and bounded rows; all authorization and evidence authority remain
/// Server-owned and every operation re-reads the current Viewer session expectation. Case grants
/// are never supplied to this WPF surface or serialized by the production HTTP client.
/// </summary>
public sealed partial class InfrastructureCaseWorkspaceViewModel : ObservableObject, IDisposable
{
    private readonly InfrastructureModeAccessService _access;
    private readonly InfrastructureCaseWorkspaceFeatureDependencies _dependencies;
    private readonly SynchronizationContext? _uiContext;
    private InfrastructureCaseWorkspaceCoordinator? _coordinator;
    private InfrastructureCaseQueryScope? _appliedScope;
    private bool _disposed;

    public InfrastructureCaseWorkspaceViewModel(
        InfrastructureModeAccessService access,
        InfrastructureCaseWorkspaceFeatureDependencies dependencies)
    {
        _access = access ?? throw new ArgumentNullException(nameof(access));
        _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
        _dependencies.Validate();
        _uiContext = SynchronizationContext.Current;
        QueryKinds = Array.AsReadOnly(Enum.GetValues<InfrastructureViewerQueryKind>()
            .Where(kind => kind != InfrastructureViewerQueryKind.Unknown)
            .ToArray());
        AnnotationKinds = Array.AsReadOnly(Enum.GetValues<InfrastructureAnnotationMutationKind>()
            .Where(kind => kind != InfrastructureAnnotationMutationKind.Unknown)
            .ToArray());
    }

    public IReadOnlyList<InfrastructureViewerQueryKind> QueryKinds { get; }

    public IReadOnlyList<InfrastructureAnnotationMutationKind> AnnotationKinds { get; }

    public ObservableCollection<InfrastructureViewerQueryRowViewModel> Rows { get; } = [];

    public ObservableCollection<InfrastructureScopeNodeViewModel> ScopeTree { get; } = [];

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(OpenCaseCommand))]
    private string caseId = string.Empty;

    [ObservableProperty]
    private string hostId = string.Empty;

    [ObservableProperty]
    private string agentId = string.Empty;

    [ObservableProperty]
    private string captureId = string.Empty;

    [ObservableProperty]
    private string sourceRunId = string.Empty;

    [ObservableProperty]
    private string processEntityId = string.Empty;

    [ObservableProperty]
    private string searchText = string.Empty;

    [ObservableProperty]
    private string filterExpression = string.Empty;

    [ObservableProperty]
    private InfrastructureViewerQueryKind selectedQueryKind = InfrastructureViewerQueryKind.CaseInventory;

    [ObservableProperty]
    private InfrastructureAnnotationMutationKind selectedAnnotationKind = InfrastructureAnnotationMutationKind.Note;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveAnnotationCommand))]
    private string annotationId = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveAnnotationCommand))]
    private string annotationTargetIdentity = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveAnnotationCommand))]
    private string annotationBodyJson = "{\"text\":\"\"}";

    [ObservableProperty]
    private long expectedAnnotationRevision;

    [ObservableProperty]
    private InfrastructureViewerQueryRowViewModel? selectedRow;

    [ObservableProperty]
    private string modeDisplay = "INFRASTRUCTURE / NOT BOUND";

    [ObservableProperty]
    private string activeScopeDisplay = "No Infrastructure case is bound.";

    [ObservableProperty]
    private string revisionDisplay = "No Server revision";

    [ObservableProperty]
    private string revisionFreshnessDisplay = "Open an authorized case to validate a Server revision.";

    [ObservableProperty]
    private string availableRevisionDisplay = string.Empty;

    [ObservableProperty]
    private string statusMessage = "Infrastructure Case Workspaces is compiled but unavailable until explicitly opened.";

    [ObservableProperty]
    private string errorCode = string.Empty;

    [ObservableProperty]
    private string continuationToken = string.Empty;

    [ObservableProperty]
    private bool hasMore;

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private int visibleRowCount;

    public bool IsWorkspaceReady =>
        _coordinator?.State is { DeploymentMode: DeploymentModeKind.Infrastructure,
            Revision: not null };

    public bool HasError => !string.IsNullOrWhiteSpace(ErrorCode);

    partial void OnSelectedRowChanged(InfrastructureViewerQueryRowViewModel? value)
    {
        if (value == null)
        {
            return;
        }

        AnnotationTargetIdentity = FirstNonEmpty(value.ProcessEntityId, value.RowId);
    }

    private bool CanOpenCase() => !IsBusy && !string.IsNullOrWhiteSpace(CaseId);

    private bool CanRefresh() => !IsBusy && IsWorkspaceReady;

    private bool CanQuery() => !IsBusy && IsWorkspaceReady;

    private bool CanQueryNextPage() => CanQuery() && HasMore && !string.IsNullOrWhiteSpace(ContinuationToken);

    private bool CanSaveAnnotation() =>
        CanQuery() &&
        !string.IsNullOrWhiteSpace(AnnotationId) &&
        !string.IsNullOrWhiteSpace(AnnotationTargetIdentity) &&
        !string.IsNullOrWhiteSpace(AnnotationBodyJson);

    private bool CanDetach() => !IsBusy && _coordinator != null;

    [RelayCommand(CanExecute = nameof(CanOpenCase))]
    private async Task OpenCaseAsync()
    {
        if (!TryEnsureCoordinator())
        {
            return;
        }

        await ExecuteBusyAsync(async () =>
        {
            var response = await _coordinator!.OpenAsync(
                await CurrentViewerAsync(),
                Array.Empty<InfrastructureViewerCaseGrant>(),
                CaseId.Trim());
            ApplyRevisionResponse(response);
            if (response.Allowed)
            {
                await QueryCoreAsync(continuation: string.Empty, append: false);
            }
        });
    }

    [RelayCommand(CanExecute = nameof(CanRefresh))]
    private async Task RefreshFromServerAsync()
    {
        await ExecuteBusyAsync(async () =>
        {
            var state = _coordinator!.State;
            var response = await _coordinator.RefreshAsync(
                await CurrentViewerAsync(),
                Array.Empty<InfrastructureViewerCaseGrant>());
            ApplyRevisionResponse(response);
            if (response.Allowed)
            {
                await QueryCoreAsync(continuation: string.Empty, append: false);
            }
        });
    }

    [RelayCommand(CanExecute = nameof(CanQuery))]
    private Task RunQueryAsync() => ExecuteBusyAsync(
        () => QueryCoreAsync(continuation: string.Empty, append: false));

    [RelayCommand(CanExecute = nameof(CanQueryNextPage))]
    private Task QueryNextPageAsync() => ExecuteBusyAsync(
        () => QueryCoreAsync(ContinuationToken, append: true));

    [RelayCommand(CanExecute = nameof(CanSaveAnnotation))]
    private async Task SaveAnnotationAsync()
    {
        await ExecuteBusyAsync(async () =>
        {
            var state = _coordinator!.State;
            var response = await _coordinator.MutateAnnotationAsync(
                await CurrentViewerAsync(),
                Array.Empty<InfrastructureViewerCaseGrant>(),
                SelectedAnnotationKind,
                AnnotationId.Trim(),
                AnnotationTargetIdentity.Trim(),
                AnnotationBodyJson,
                ExpectedAnnotationRevision);
            if (!response.Allowed)
            {
                ApplyFailure(response.ErrorCode, response.Message);
                return;
            }

            ExpectedAnnotationRevision = response.AnnotationRevision;
            ErrorCode = string.Empty;
            StatusMessage = response.Message;
            PublishCoordinatorState();
        });
    }

    [RelayCommand(CanExecute = nameof(CanDetach))]
    private void Detach()
    {
        var state = _coordinator!.Detach();
        Rows.Clear();
        ScopeTree.Clear();
        VisibleRowCount = 0;
        ContinuationToken = string.Empty;
        HasMore = false;
        PublishState(state);
    }

    private bool TryEnsureCoordinator()
    {
        if (_coordinator != null)
        {
            return true;
        }

        try
        {
            if (!InfrastructureCaseWorkspaceCoordinator.TryCreate(
                    _access,
                    _dependencies.ClientFactory,
                    out var coordinator,
                    out var decision) || coordinator == null)
            {
                ApplyFailure(decision.ErrorCode, decision.Message);
                return false;
            }

            _coordinator = coordinator;
            _coordinator.StateChanged += OnCoordinatorStateChanged;
            PublishCoordinatorState();
            NotifyCommandStates();
            return true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            ApplyFailure("InfrastructureCaseWorkspaceCompositionUnavailable", exception.Message);
            return false;
        }
    }

    private async Task QueryCoreAsync(string continuation, bool append)
    {
        var state = _coordinator!.State;
        var requestedScope = new InfrastructureCaseQueryScope
        {
            CaseId = state.CaseId,
            HostId = HostId.Trim(),
            AgentId = AgentId.Trim(),
            CaptureId = CaptureId.Trim(),
            SourceRunId = SourceRunId.Trim(),
            ProcessEntityId = ProcessEntityId.Trim()
        };
        var response = await _coordinator.QueryAsync(
            await CurrentViewerAsync(),
            Array.Empty<InfrastructureViewerCaseGrant>(),
            SelectedQueryKind,
            requestedScope,
            SearchText,
            FilterExpression,
            continuationToken: continuation);

        if (!response.Allowed)
        {
            ApplyFailure(response.ErrorCode, response.Message);
            return;
        }

        if (!append)
        {
            Rows.Clear();
        }

        foreach (var row in response.Rows)
        {
            Rows.Add(new InfrastructureViewerQueryRowViewModel(row));
        }

        if (!append && response.Kind is InfrastructureViewerQueryKind.CaseInventory or
            InfrastructureViewerQueryKind.ExplorerSummary)
        {
            PublishScopeTree(response.Revision!.CaseId, response.Rows);
        }

        VisibleRowCount = Rows.Count;
        _appliedScope = requestedScope;
        ContinuationToken = response.NextContinuationToken;
        HasMore = response.HasMore;
        ClearFailure();
        StatusMessage = response.Message;
        PublishCoordinatorState();
    }

    private async Task<AuthenticatedInfrastructureViewerContext> CurrentViewerAsync()
    {
        var viewer = await _dependencies.ViewerContextAccessorAsync(CancellationToken.None);
        return viewer ?? throw new InvalidOperationException("InfrastructureViewerAuthenticationUnavailable");
    }

    private async Task ExecuteBusyAsync(Func<Task> action)
    {
        if (_disposed || IsBusy)
        {
            return;
        }

        SetBusy(true);
        try
        {
            await action();
        }
        catch (OperationCanceledException)
        {
            ApplyFailure("InfrastructureViewerOperationCanceled", "The Server workspace operation was canceled.");
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            ApplyFailure("InfrastructureViewerOperationUnavailable", exception.Message);
        }
        finally
        {
            SetBusy(false);
            PublishCoordinatorState();
        }
    }

    private void ApplyRevisionResponse(InfrastructureCaseRevisionResponse response)
    {
        if (!response.Allowed)
        {
            ApplyFailure(response.ErrorCode, response.Message);
            return;
        }

        ClearFailure();
        StatusMessage = response.Message;
        ContinuationToken = string.Empty;
        HasMore = false;
        PublishCoordinatorState();
    }

    private void ApplyFailure(string code, string message)
    {
        ErrorCode = string.IsNullOrWhiteSpace(code) ? "InfrastructureViewerOperationFailed" : code;
        StatusMessage = string.IsNullOrWhiteSpace(message)
            ? "The Infrastructure Viewer operation failed closed."
            : message;
        OnPropertyChanged(nameof(HasError));
        NotifyCommandStates();
    }

    private void ClearFailure()
    {
        ErrorCode = string.Empty;
        OnPropertyChanged(nameof(HasError));
    }

    private void OnCoordinatorStateChanged(object? sender, EventArgs e)
    {
        if (_uiContext == null || ReferenceEquals(SynchronizationContext.Current, _uiContext))
        {
            PublishCoordinatorState();
            return;
        }

        _uiContext.Post(_ => PublishCoordinatorState(), null);
    }

    private void PublishCoordinatorState()
    {
        if (_coordinator != null)
        {
            PublishState(_coordinator.State);
        }
    }

    private void PublishState(InfrastructureCaseWorkspaceState state)
    {
        ModeDisplay = state.DeploymentMode == DeploymentModeKind.Infrastructure
            ? "INFRASTRUCTURE / SERVER AUTHORITY"
            : "INFRASTRUCTURE / NOT BOUND";
        ActiveScopeDisplay = state.DeploymentMode == DeploymentModeKind.Infrastructure
            ? FormatAppliedScope(state)
            : "No Infrastructure case is bound.";
        RevisionDisplay = state.Revision == null
            ? "No Server revision"
            : $"Revision {state.Revision.Revision:N0}; schema {state.Revision.EvidenceSchemaVersion:N0}; " +
              $"Server {state.Revision.ServerInstanceId}; restore generation {state.Revision.RestoreGeneration:N0}";
        RevisionFreshnessDisplay = state.Revision == null
            ? "Open an authorized case to validate a Server revision."
            : $"Issued {FormatUtc(state.Revision.IssuedAtUtc)}; validated {FormatUtc(state.RefreshedAtUtc)}; " +
              $"source commit {state.Revision.SourceCommitId}";
        AvailableRevisionDisplay = state.AvailableRevision == null
            ? string.Empty
            : $"Revision {state.AvailableRevision.Revision:N0} is available. Refresh from Server must validate it before replacement.";
        if (!string.IsNullOrWhiteSpace(state.ErrorCode))
        {
            ErrorCode = state.ErrorCode;
            StatusMessage = state.Message;
        }
        else if (!IsBusy && string.IsNullOrWhiteSpace(ErrorCode))
            StatusMessage = state.Message;

        OnPropertyChanged(nameof(IsWorkspaceReady));
        OnPropertyChanged(nameof(HasError));
        NotifyCommandStates();
    }

    private void SetBusy(bool value)
    {
        IsBusy = value;
        NotifyCommandStates();
    }

    private void NotifyCommandStates()
    {
        OpenCaseCommand.NotifyCanExecuteChanged();
        RefreshFromServerCommand.NotifyCanExecuteChanged();
        RunQueryCommand.NotifyCanExecuteChanged();
        QueryNextPageCommand.NotifyCanExecuteChanged();
        SaveAnnotationCommand.NotifyCanExecuteChanged();
        DetachCommand.NotifyCanExecuteChanged();
    }

    private static string FormatUtc(DateTime value) => value == DateTime.MinValue
        ? "not yet"
        : value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

    private static string FirstNonEmpty(params string[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private string FormatAppliedScope(InfrastructureCaseWorkspaceState state)
    {
        var scope = _appliedScope;
        if (scope == null || !string.Equals(scope.CaseId, state.CaseId, StringComparison.Ordinal))
        {
            return $"Case {state.CaseId}; workspace generation {state.WorkspaceGeneration:N0}; no query scope applied";
        }

        return string.Join("; ", new[]
        {
            $"Case {scope.CaseId}",
            $"Host {ScopeValue(scope.HostId)}",
            $"Agent {ScopeValue(scope.AgentId)}",
            $"Capture {ScopeValue(scope.CaptureId)}",
            $"Source run {ScopeValue(scope.SourceRunId)}",
            $"Process {ScopeValue(scope.ProcessEntityId)}",
            $"workspace generation {state.WorkspaceGeneration:N0}"
        });
    }

    private static string ScopeValue(string value) =>
        string.IsNullOrWhiteSpace(value) ? "(all authorized)" : value;

    private void PublishScopeTree(string caseId, IReadOnlyList<InfrastructureViewerQueryRow> rows)
    {
        var hostNodes = rows
            .GroupBy(row => IdentityValue(row.HostId), StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(host => new InfrastructureScopeNodeViewModel(
                $"Host {host.Key}",
                host.Any(row => row.RelationshipAmbiguous),
                host.GroupBy(row => IdentityValue(row.AgentId), StringComparer.Ordinal)
                    .OrderBy(group => group.Key, StringComparer.Ordinal)
                    .Select(agent => new InfrastructureScopeNodeViewModel(
                        $"Agent {agent.Key}",
                        false,
                        agent.GroupBy(row => IdentityValue(row.CaptureId), StringComparer.Ordinal)
                            .OrderBy(group => group.Key, StringComparer.Ordinal)
                            .Select(capture => new InfrastructureScopeNodeViewModel(
                                $"Capture {capture.Key}",
                                false,
                                capture.Select(row => IdentityValue(row.SourceRunId))
                                    .Distinct(StringComparer.Ordinal)
                                    .OrderBy(value => value, StringComparer.Ordinal)
                                    .Select(sourceRun => new InfrastructureScopeNodeViewModel(
                                        $"Source run {sourceRun}",
                                        false,
                                        Array.Empty<InfrastructureScopeNodeViewModel>()))
                                    .ToArray()))
                            .ToArray()))
                    .ToArray()))
            .ToArray();
        ScopeTree.Clear();
        ScopeTree.Add(new InfrastructureScopeNodeViewModel(
            $"Case {caseId}",
            false,
            hostNodes));
    }

    private static string IdentityValue(string value) =>
        string.IsNullOrWhiteSpace(value) ? "(unresolved)" : value;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_coordinator == null)
        {
            return;
        }

        _coordinator.StateChanged -= OnCoordinatorStateChanged;
        _coordinator.DisposeAsync().AsTask().GetAwaiter().GetResult();
        _coordinator = null;
    }
}
