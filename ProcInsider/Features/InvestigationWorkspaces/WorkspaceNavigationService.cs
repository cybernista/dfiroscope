using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Features;
using ProcInsider.ViewModels;
using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Features.PersistenceWorkspace;
using System.Text.Json;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal enum WorkspaceNavigationMode { Reuse, OpenNew }
internal sealed record WorkspaceEvidenceTarget(TelemetrySearchResult Result, FeatureId Feature, bool Correlation = false);
internal sealed record WorkspaceNavigationRequest(WorkspaceTypeId Type, WorkspaceContext? Capture,
    ExplorerScope? Scope = null, TelemetrySearchResult? Process = null,
    WorkspaceNavigationMode Mode = WorkspaceNavigationMode.Reuse, ExplorerSelectionGesture Gesture = ExplorerSelectionGesture.Replace,
    WorkspaceEvidenceTarget? Evidence = null, EventsPivot? EventPivot = null, SysmonExplorerNode? SysmonNode = null,
    ProcInsider.Features.NetworkWorkspace.NetworkProcessScope? NetworkScope = null,string? NetworkTitle = null,long? NetworkRevision = null,
    bool NetworkByProcess = false, ProcInsider.Features.NetworkWorkspace.NetworkFacet? NetworkFacet = null,
    ProcInsider.Features.NetworkWorkspace.NetworkEndpointQuery? NetworkEndpoints = null,
    NetworkWorkspaceViewModel? NetworkSource = null, CancellationToken SourceCancellation = default,
    long? ExpectedContextRevision = null, long? ExpectedActionGeneration = null,
    ProcInsider.Features.PersistenceWorkspace.PersistenceView? PersistenceView = null, string? PersistenceCategory = null,
    ProcInsider.Features.PersistenceWorkspace.PersistenceSelector? PersistenceSelector = null,
    IReadOnlyList<ForensicArtifactResultColumnFilter>? ArtifactFilters = null,
    IReadOnlyList<ForensicArtifactResultGreenSelector>? ArtifactSelectors = null,
    string? ArtifactTitle = null, string? PersistencePeriodId = null, EvidenceIdentity? PersistenceScope = null,
    AiEvidenceReference? Citation = null, Func<bool>? CitationSelectionCurrent = null);
internal sealed record WorkspaceNavigationResult(ViewerNavigationOutcome Outcome, WorkspaceInstanceId? Instance = null);

internal sealed partial class WorkspaceNavigationService : ViewModelBase, IDisposable
{
    private readonly WorkspaceManager _manager;
    private readonly FeatureAccessService _access;
    internal FeatureAccessService Access => _access;
    private CancellationTokenSource _request = new();
    private bool _activating;
    private bool _disposed;
    private long _actionGeneration;
    internal long ActionGeneration => _actionGeneration;
    internal long ContextRevision => _manager.ContextRevision;
    private const string NeutralStatus = "Select an Explorer context or open a new investigation.";
    private string _status = NeutralStatus;
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    internal WorkspaceNavigationService(WorkspaceManager manager, FeatureAccessService access)
    {
        _manager = manager;
        _access = access;
        manager.ActiveContextChanging += OnActivation;
    }
    internal WorkspaceContext? Capture => _manager.CaptureBinding is { } binding
        ? new(binding.Paths.SessionId, binding.CaptureGeneration) : null;
    private void OnActivation() { if (!_activating) Cancel(); }
    internal void Cancel() { _actionGeneration++; _request.Cancel(); }
    internal void ResetCapture() { Cancel(); Status = NeutralStatus; }
    internal WorkspaceInstanceViewModel? Resolve(WorkspaceNavigationRequest request) =>
        _manager.ActiveInstance is { IsPinned: false } active && Compatible(active, request) ? active :
        _manager.Instances.Where(x => !x.IsPinned && Compatible(x, request))
            .OrderByDescending(x => x.ActivationOrder).ThenBy(x => x.CreationOrder).FirstOrDefault();
    private static bool Compatible(WorkspaceInstanceViewModel instance, WorkspaceNavigationRequest request) =>
        !instance.IsDisposed && instance.Type.Id == request.Type && instance.Context == request.Capture;

    private async Task<WorkspaceNavigationResult> NavigatePersistenceAsync(WorkspaceNavigationRequest request)
    {
        Cancel(); _request.Dispose(); _request = CancellationTokenSource.CreateLinkedTokenSource(request.SourceCancellation);
        var token = _request.Token; var revision = _manager.PersistenceSession?.Revision;
        try
        {
            var target = request.Mode == WorkspaceNavigationMode.OpenNew ? null : Resolve(request);
            _activating = true;
            try { if (target == null) target = await _manager.OpenPersistenceAsync(); else await _manager.ActivateAsync(target); }
            finally { _activating = false; }
            token.ThrowIfCancellationRequested();
            if (target is not PersistenceWorkspaceViewModel persistence || persistence.IsDisposed || request.Capture != Capture || revision != _manager.PersistenceSession?.Revision || !ReferenceEquals(target, _manager.ActiveInstance)) return new(ViewerNavigationOutcome.Superseded);
            if (request.PersistenceScope != null) persistence.SelectPeriod(request.PersistenceScope, request.PersistencePeriodId);
            if (request.PersistenceSelector is { } selector) persistence.Toggle(selector, selector.Excluded);
            else persistence.Navigate(request.PersistenceView ?? ProcInsider.Features.PersistenceWorkspace.PersistenceView.Current, request.PersistenceCategory);
            await persistence.LoadAsync(); token.ThrowIfCancellationRequested();
            if (request.Capture != Capture || revision != _manager.PersistenceSession?.Revision || !ReferenceEquals(target, _manager.ActiveInstance)) return new(ViewerNavigationOutcome.Superseded);
            Status = persistence.StatusHeadline; return new(ViewerNavigationOutcome.Succeeded, persistence.Id);
        }
        catch (OperationCanceledException) { return new(ViewerNavigationOutcome.Superseded); }
    }
    internal Task<WorkspaceNavigationResult> NavigateSearchResultAsync(TelemetrySearchResult result)
    {
        var kind = result.Kind.ToUpperInvariant();
        var correlation = kind == "CORRELATION" || ((kind is "SIGMA" or "EVENT") &&
            result.CorrelationState is EvidenceCorrelationState.Unresolved or EvidenceCorrelationState.Ambiguous && string.IsNullOrWhiteSpace(result.ProcessEntityId));
        WorkspaceEvidenceTarget? evidence = correlation ? new(result, FeatureIds.SearchAndSigma, true) : kind switch
        {
            "NETWORKCAPTURE" or "ZEEK" => new(result, FeatureIds.NetworkAndZeek),
            "FILESYSTEMARTIFACT" => new(result, FeatureIds.FilesystemArtifacts),
            "MEMORYIMAGE" or "VOLATILITYRUN" or "MEMORYPROCESS" => new(result, FeatureIds.SystemMemoryAndVolatility),
            _ => null
        };
        return evidence != null ? NavigateAsync(new(WorkspaceTypeId.Processes, Capture, Evidence: evidence)) :
            NavigateAsync(new(WorkspaceTypeId.Processes, Capture,
                new ExplorerScope { Kind = ExplorerScopeKind.AllProcesses, Title = "All Processes" }, Process: result));
    }

    internal async Task<WorkspaceNavigationResult> NavigateCitationAsync(
        AiEvidenceReference citation, WorkspaceNavigationMode mode = WorkspaceNavigationMode.Reuse,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(citation);
        if (citation.Evidence.Kind != EvidenceReferenceKind.ProcessEntity)
            return await NavigateObjectCitationAsync(citation, mode, cancellationToken);
        var binding = _manager.CaptureBinding;
        var capture = Capture;
        var revision = ContextRevision;
        var action = ActionGeneration;
        var source = _manager.ActiveInstance as ProcessesWorkspaceViewModel;
        var selection = source?.Presentation.CaptureSelectedTarget();
        if (_disposed || _manager.ReadsSuspended || binding?.Query == null || capture == null ||
            !_manager.IsAvailable(WorkspaceTypeId.Processes))
        {
            Status = "The citation's active evidence context is unavailable.";
            return new(ViewerNavigationOutcome.Unavailable);
        }
        AiEvidenceResolution resolution;
        try
        {
            resolution = await Task.Run(() =>
                new AiEvidenceReferenceResolver(binding.Query).ResolveProcess(citation, binding.Paths.SessionId),
                cancellationToken);
        }
        catch (OperationCanceledException) { return new(ViewerNavigationOutcome.Superseded); }
        catch (Exception error)
        {
            if (revision != ContextRevision || action != ActionGeneration ||
                !ReferenceEquals(binding, _manager.CaptureBinding)) return new(ViewerNavigationOutcome.Superseded);
            Status = "Citation resolution failed: " + error.Message;
            return new(ViewerNavigationOutcome.Failed);
        }
        if (cancellationToken.IsCancellationRequested || revision != ContextRevision || action != ActionGeneration ||
            !ReferenceEquals(binding, _manager.CaptureBinding) || capture != Capture ||
            (source != null && (source.IsDisposed || source.Presentation.CaptureSelectedTarget() != selection)))
            return new(ViewerNavigationOutcome.Superseded);
        if (!resolution.IsResolved)
        {
            Status = resolution.Message;
            return new(resolution.Status == AiEvidenceResolutionStatus.NotFound ? ViewerNavigationOutcome.NotFound : ViewerNavigationOutcome.Unavailable);
        }
        var original = resolution.Process!;
        var result = new TelemetrySearchResult
        {
            Kind = "Process", ProcessEntityId = original.ProcessEntityId,
            ProcessKey = original.ProcessKey, ProcessId = original.ProcessId,
            ProcessName = original.ProcessName
        };
        bool SelectionCurrent() => (source == null || !source.IsDisposed && source.Presentation.CaptureSelectedTarget() == selection) &&
            !cancellationToken.IsCancellationRequested && ReferenceEquals(binding, _manager.CaptureBinding);
        return await NavigateAsync(new(WorkspaceTypeId.Processes, capture, Process: result, Mode: mode,
            SourceCancellation: cancellationToken, ExpectedContextRevision: revision,
            ExpectedActionGeneration: action, Citation: citation,
            CitationSelectionCurrent: SelectionCurrent));
    }

    private async Task<WorkspaceNavigationResult> NavigateObjectCitationAsync(AiEvidenceReference citation,
        WorkspaceNavigationMode mode, CancellationToken cancellationToken)
    {
        var type = citation.Evidence.Kind switch
        {
            EvidenceReferenceKind.Event => WorkspaceTypeId.Events,
            EvidenceReferenceKind.NetworkFlow when citation.DataSource == "NetworkEndpoint" => WorkspaceTypeId.Network,
            EvidenceReferenceKind.GenericArtifact when citation.DataSource == "PersistenceVersions" => WorkspaceTypeId.Persistence,
            _ => (WorkspaceTypeId?)null
        };
        var binding = _manager.CaptureBinding;
        var capture = Capture;
        if (_disposed || _manager.ReadsSuspended || !_access.IsPublished(FeatureIds.AiAssistance) ||
            type == null || !_manager.IsAvailable(type.Value) || binding?.Query == null || capture == null ||
            citation.Identity.EvidenceSessionId != binding.Paths.SessionId)
        {
            Status = "The citation's exact evidence context is unavailable.";
            return new(ViewerNavigationOutcome.Unavailable);
        }
        var source = _manager.ActiveInstance;
        var sourceEvent = (source as EventsWorkspaceViewModel)?.SelectedEvent;
        var sourceEndpoint = (source as NetworkWorkspaceViewModel)?.SelectedEndpoint;
        var sourceNetworkRow = (source as NetworkWorkspaceViewModel)?.SelectedRow;
        var sourcePersistence = (source as PersistenceWorkspaceViewModel)?.SelectedRow;
        var sourceProcess = (source as ProcessesWorkspaceViewModel)?.Presentation.CaptureSelectedTarget();
        var contextRevision = ContextRevision;
        var eventsBinding = _manager.EventsSession?.Binding;
        var networkRevision = _manager.NetworkSession?.Revision;
        var persistenceRevision = _manager.PersistenceSession?.Revision;
        Cancel(); _request.Dispose(); _request = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = _request.Token;
        var action = ActionGeneration;
        bool Current() => !token.IsCancellationRequested && action == ActionGeneration &&
            contextRevision == ContextRevision && ReferenceEquals(binding, _manager.CaptureBinding) && capture == Capture;
        bool SourceCurrent() => source == null || !source.IsDisposed && _manager.Instances.Contains(source) &&
                ReferenceEquals(sourceEvent, (source as EventsWorkspaceViewModel)?.SelectedEvent) &&
                ReferenceEquals(sourceEndpoint, (source as NetworkWorkspaceViewModel)?.SelectedEndpoint) &&
                ReferenceEquals(sourceNetworkRow, (source as NetworkWorkspaceViewModel)?.SelectedRow) &&
                ReferenceEquals(sourcePersistence, (source as PersistenceWorkspaceViewModel)?.SelectedRow) &&
                sourceProcess == (source as ProcessesWorkspaceViewModel)?.Presentation.CaptureSelectedTarget();
        try
        {
            var resolved = await Task.Run(async () =>
            {
                var context = await EvidenceObjectAgentTools.ResolveAsync(binding.Query, _access, citation,
                    binding.Paths.SessionId, token);
                var endpoint = context != null && type == WorkspaceTypeId.Network
                    ? EvidenceObjectAgentTools.FindEndpoint(binding.Query, citation, token) : null;
                return (Context: context, Endpoint: endpoint);
            }, token);
            if (!Current() || !SourceCurrent()) return new(ViewerNavigationOutcome.Superseded);
            if (resolved.Context == null || type == WorkspaceTypeId.Network && resolved.Endpoint == null)
            {
                Status = "The exact recorded original is unavailable or ambiguous in this capture.";
                return new(ViewerNavigationOutcome.Unavailable);
            }
            WorkspaceInstanceViewModel? target = mode == WorkspaceNavigationMode.OpenNew ? null :
                Resolve(new(type.Value, capture));
            _activating = true;
            try
            {
                if (target == null)
                {
                    if (type == WorkspaceTypeId.Events) target = await _manager.OpenEventsAsync();
                    else if (type == WorkspaceTypeId.Network) target = await _manager.OpenNetworkAsync();
                    else if (type == WorkspaceTypeId.Persistence) target = await _manager.OpenPersistenceAsync();
                }
                else await _manager.ActivateAsync(target);
            }
            finally { _activating = false; }
            if (token.IsCancellationRequested || action != ActionGeneration ||
                !ReferenceEquals(binding, _manager.CaptureBinding) || capture != Capture ||
                target == null || target.IsDisposed || !ReferenceEquals(target, _manager.ActiveInstance))
                return new(ViewerNavigationOutcome.Superseded);
            contextRevision = ContextRevision;
            if (target is EventsWorkspaceViewModel events)
            {
                if (eventsBinding != _manager.EventsSession?.Binding ||
                    !long.TryParse(citation.Evidence.Id, out var sequence)) return new(ViewerNavigationOutcome.Superseded);
                var scope = citation.Identity;
                events.SetFilter(new EventsFilter { ExactEvent = new(scope.CaseId, scope.EvidenceSessionId,
                    scope.CaptureId, scope.SourceIdentityId, scope.HostId, citation.SourceRunId, sequence) },
                    "Exact AI event");
                var ownedFilter = events.Filter;
                await events.RefreshAsync();
                // Refresh clears and restores selection, advancing the active context revision itself.
                if (token.IsCancellationRequested || action != ActionGeneration ||
                    !ReferenceEquals(binding, _manager.CaptureBinding) || capture != Capture ||
                    !ReferenceEquals(events.Filter, ownedFilter) || !events.LastRefreshSucceeded ||
                    eventsBinding != _manager.EventsSession?.Binding ||
                    !ReferenceEquals(events, _manager.ActiveInstance)) return new(ViewerNavigationOutcome.Superseded);
                contextRevision = ContextRevision;
                var row = events.Rows.Count == 1 ? events.Rows[0] : null;
                if (row == null || EvidenceObjectAgentTools.EventContext(row.Evidence.Native).Reference.CanonicalObjectKey != citation.CanonicalObjectKey)
                    return ObjectNotFound();
                events.SelectedEvent = row;
            }
            else if (target is NetworkWorkspaceViewModel network)
            {
                if (networkRevision != _manager.NetworkSession?.Revision) return new(ViewerNavigationOutcome.Superseded);
                var kind = resolved.Endpoint!.Observation.Kind == EndpointObservationKind.ConnectionSnapshot
                    ? EndpointScopeKind.ConnectionSnapshots : EndpointScopeKind.ListenerHistory;
                network.SetEndpointScope(new(kind, Scope: citation.Identity, SourceRunId: citation.SourceRunId,
                    ExactObservationId: citation.Evidence.Id), "Exact AI network endpoint");
                network.Text = "";
                foreach (var filter in network.EndpointHeaderFilters.Values) filter.Reset(false);
                contextRevision = ContextRevision;
                var ownedQuery = network.CaptureEndpointQuery()! with
                { Sort = network.EndpointSort, Descending = network.Descending, Offset = network.Offset };
                var refresh = network.RefreshAsync();
                var ownedRequest = network.RequestGeneration;
                await refresh;
                var currentQuery = network.CaptureEndpointQuery();
                if (!Current() || networkRevision != _manager.NetworkSession?.Revision ||
                    !ReferenceEquals(network, _manager.ActiveInstance) ||
                    network.RequestGeneration != ownedRequest || !network.LastRefreshSucceeded ||
                    currentQuery == null || currentQuery.Columns is { Count: > 0 } ||
                    currentQuery.GreenSelectors is { Count: > 0 } ||
                    (currentQuery with { Sort = network.EndpointSort, Descending = network.Descending,
                        Offset = network.Offset, Columns = ownedQuery.Columns,
                        GreenSelectors = ownedQuery.GreenSelectors }) != ownedQuery)
                    return new(ViewerNavigationOutcome.Superseded);
                var row = network.EndpointRows.Count == 1 ? network.EndpointRows[0] : null;
                if (row == null || EvidenceObjectAgentTools.NetworkContext(row).Reference.CanonicalObjectKey != citation.CanonicalObjectKey)
                    return ObjectNotFound();
                network.SelectedEndpoint = row;
            }
            else if (target is PersistenceWorkspaceViewModel persistence)
            {
                if (persistenceRevision != _manager.PersistenceSession?.Revision) return new(ViewerNavigationOutcome.Superseded);
                var locator = JsonSerializer.Deserialize<PersistenceObjectReference>(citation.Evidence.Id);
                if (locator == null || locator.Scope != citation.Identity) return ObjectNotFound();
                if (!await persistence.OpenAiOriginalAsync(locator, token))
                    return token.IsCancellationRequested || action != ActionGeneration ||
                        !ReferenceEquals(binding, _manager.CaptureBinding) || capture != Capture ||
                        !ReferenceEquals(persistence, _manager.ActiveInstance)
                        ? new(ViewerNavigationOutcome.Superseded) : ObjectNotFound();
                contextRevision = ContextRevision;
                if (!Current() || persistenceRevision != _manager.PersistenceSession?.Revision ||
                    !ReferenceEquals(persistence, _manager.ActiveInstance)) return new(ViewerNavigationOutcome.Superseded);
                if (persistence.SelectedRow is not { } row ||
                    EvidenceObjectAgentTools.PersistenceContext(row).Reference.CanonicalObjectKey != citation.CanonicalObjectKey)
                    return ObjectNotFound();
            }
            else return new(ViewerNavigationOutcome.Unavailable);
            Status = "Opened the exact recorded original.";
            return new(ViewerNavigationOutcome.Succeeded, target.Id);
        }
        catch (OperationCanceledException) { return new(ViewerNavigationOutcome.Superseded); }
        catch (Exception error)
        {
            if (Current()) Status = "Exact citation navigation failed: " + error.Message;
            return new(Current() ? ViewerNavigationOutcome.Failed : ViewerNavigationOutcome.Superseded);
        }
        WorkspaceNavigationResult ObjectNotFound()
        {
            Status = "The exact recorded original is unavailable in this workspace read binding.";
            return new(ViewerNavigationOutcome.NotFound);
        }
    }

    internal async Task<WorkspaceNavigationResult> NavigateConversationAsync(string conversationId,
        CancellationToken cancellationToken = default)
    {
        var binding = _manager.CaptureBinding;
        var capture = Capture;
        var revision = ContextRevision;
        var action = ActionGeneration;
        var conversationAction = action;
        if (_disposed || _manager.ReadsSuspended || binding == null || capture == null ||
            !_access.IsPublished(FeatureIds.AiAssistance) || !_manager.IsAvailable(WorkspaceTypeId.Processes) ||
            string.IsNullOrWhiteSpace(conversationId))
        {
            Status = "The conversation's capture or AI workspace is unavailable.";
            return new(ViewerNavigationOutcome.Unavailable);
        }
        try
        {
            // Load the exact persisted ID. Reopening must never create a conversation.
            var conversation = await binding.Annotations.LoadConversationAsync(conversationId, cancellationToken);
            if (cancellationToken.IsCancellationRequested || revision != ContextRevision ||
                action != ActionGeneration || !ReferenceEquals(binding, _manager.CaptureBinding))
                return new(ViewerNavigationOutcome.Superseded);
            if (conversation == null)
            {
                Status = "The saved conversation no longer exists.";
                return new(ViewerNavigationOutcome.NotFound);
            }
            if (ConversationExplorerViewModel.IsCompatible(conversation, binding) &&
                conversation.Scope.ContextType == AiConversationContextType.General)
            {
                return await NavigateAiConversationAsync(conversation.Id, cancellationToken);
            }
            if (!ConversationExplorerViewModel.IsCompatible(conversation, binding) ||
                conversation.Scope.ObjectReference is not { } reference)
            {
                Status = "The conversation belongs to another evidence context.";
                return new(ViewerNavigationOutcome.Unavailable);
            }
            var navigation = await NavigateCitationAsync(reference, cancellationToken: cancellationToken);
            if (navigation.Outcome != ViewerNavigationOutcome.Succeeded) return navigation;
            if (reference.Evidence.Kind != EvidenceReferenceKind.ProcessEntity)
            {
                var active = _manager.ActiveInstance;
                ProcessConversationViewModel? objectConversation = active switch
                {
                    EventsWorkspaceViewModel eventWorkspace => eventWorkspace.ObjectConversationViewModel,
                    NetworkWorkspaceViewModel networkWorkspace => networkWorkspace.ObjectConversationViewModel,
                    PersistenceWorkspaceViewModel persistenceWorkspace => persistenceWorkspace.ObjectConversationViewModel,
                    _ => null
                };
                if (objectConversation is null) return new(ViewerNavigationOutcome.Unavailable);
                var objectAction = ActionGeneration;
                var opened = await objectConversation.LoadConversationAsync(conversationId, cancellationToken);
                if (objectAction != ActionGeneration || !ReferenceEquals(active, _manager.ActiveInstance) ||
                    !ReferenceEquals(binding, _manager.CaptureBinding)) return new(ViewerNavigationOutcome.Superseded);
                if (active is EventsWorkspaceViewModel events) events.ShowObjectConversation();
                if (active is NetworkWorkspaceViewModel network) network.ShowObjectConversation();
                if (active is PersistenceWorkspaceViewModel persistence) persistence.ShowObjectConversation();
                Status = opened ? $"Opened conversation: {conversation.Title}" : objectConversation.Status;
                return new(opened ? ViewerNavigationOutcome.Succeeded : ViewerNavigationOutcome.Unavailable, active?.Id);
            }
            var navigatedAction = ActionGeneration;
            conversationAction = navigatedAction;
            var target = _manager.ActiveInstance as ProcessesWorkspaceViewModel;
            if (cancellationToken.IsCancellationRequested || !ReferenceEquals(binding, _manager.CaptureBinding) ||
                capture != Capture || target == null || target.IsDisposed || target.Id != navigation.Instance)
                return new(ViewerNavigationOutcome.Superseded);
            using var loadCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _request.Token);
            var loaded = await target.Presentation.LoadConversationAsync(conversationId, loadCancellation.Token);
            if (cancellationToken.IsCancellationRequested || navigatedAction != ActionGeneration ||
                !ReferenceEquals(binding, _manager.CaptureBinding) || !ReferenceEquals(target, _manager.ActiveInstance))
                return new(ViewerNavigationOutcome.Superseded);
            Status = loaded ? $"Opened conversation: {conversation.Title}" : target.Presentation.ProcessConversationViewModel.Status;
            return new(loaded ? ViewerNavigationOutcome.Succeeded : ViewerNavigationOutcome.Unavailable,
                loaded ? target.Id : null);
        }
        catch (OperationCanceledException) { return new(ViewerNavigationOutcome.Superseded); }
        catch (Exception error)
        {
            if (ReferenceEquals(binding, _manager.CaptureBinding) && !cancellationToken.IsCancellationRequested &&
                conversationAction == ActionGeneration)
                Status = "Conversation navigation failed: " + error.Message;
            return new(ViewerNavigationOutcome.Failed);
        }
    }

    internal async Task<WorkspaceNavigationResult> NavigateInvestigationAsync(string investigationId,
        CancellationToken cancellationToken = default)
    {
        var binding = _manager.CaptureBinding;
        var capture = Capture;
        var revision = ContextRevision;
        var action = ActionGeneration;
        if (_disposed || _manager.ReadsSuspended || binding is null || capture is null ||
            !_access.IsPublished(FeatureIds.AiAssistance) || !_manager.IsAvailable(WorkspaceTypeId.Processes) ||
            string.IsNullOrWhiteSpace(investigationId))
        {
            Status = "The investigation's capture or AI workspace is unavailable.";
            return new(ViewerNavigationOutcome.Unavailable);
        }
        try
        {
            var saved = await binding.Annotations.LoadInvestigationAsync(investigationId, cancellationToken);
            var conversation = saved is null ? null :
                await binding.Annotations.LoadConversationAsync(saved.ConversationId, cancellationToken);
            if (cancellationToken.IsCancellationRequested || revision != ContextRevision || action != ActionGeneration ||
                !ReferenceEquals(binding, _manager.CaptureBinding)) return new(ViewerNavigationOutcome.Superseded);
            if (saved is null)
            {
                Status = "The saved investigation no longer exists.";
                return new(ViewerNavigationOutcome.NotFound);
            }
            if (!InvestigationExplorerViewModel.IsCompatible(saved, conversation, binding))
            {
                Status = "The investigation belongs to another evidence context.";
                return new(ViewerNavigationOutcome.Unavailable);
            }
            // Opening saved annotations does not require or fabricate an evidence-row selection.
            var navigation = await NavigateAsync(new(WorkspaceTypeId.Processes, capture,
                ExpectedContextRevision: revision, ExpectedActionGeneration: action));
            if (navigation.Outcome != ViewerNavigationOutcome.Succeeded) return navigation;
            action = ActionGeneration;
            var target = _manager.ActiveInstance as ProcessesWorkspaceViewModel;
            if (cancellationToken.IsCancellationRequested || !ReferenceEquals(binding, _manager.CaptureBinding) ||
                capture != Capture || target is null || target.IsDisposed || target.Id != navigation.Instance)
                return new(ViewerNavigationOutcome.Superseded);
            using var loadCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _request.Token);
            var loaded = await target.Presentation.LoadInvestigationAsync(investigationId, loadCancellation.Token);
            if (cancellationToken.IsCancellationRequested || action != ActionGeneration ||
                !ReferenceEquals(binding, _manager.CaptureBinding) || !ReferenceEquals(target, _manager.ActiveInstance))
                return new(ViewerNavigationOutcome.Superseded);
            Status = loaded ? $"Opened investigation: {saved.Title}" : target.Presentation.InvestigationDataViewModel.Status;
            return new(loaded ? ViewerNavigationOutcome.Succeeded : ViewerNavigationOutcome.Unavailable,
                loaded ? target.Id : null);
        }
        catch (OperationCanceledException) { return new(ViewerNavigationOutcome.Superseded); }
        catch (Exception error)
        {
            if (ReferenceEquals(binding, _manager.CaptureBinding) && !cancellationToken.IsCancellationRequested &&
                action == ActionGeneration) Status = "Investigation navigation failed: " + error.Message;
            return new(ViewerNavigationOutcome.Failed);
        }
    }

    internal async Task<WorkspaceNavigationResult> NavigateAsync(WorkspaceNavigationRequest request, bool toggleGreen = false)
    {
        // Reject an older resolved pivot before it can cancel a newer navigation or alter its status.
        if ((request.ExpectedContextRevision is { } context && context != ContextRevision) ||
            (request.ExpectedActionGeneration is { } action && action != ActionGeneration))
            return new(ViewerNavigationOutcome.Superseded);
        if (_disposed || _manager.ReadsSuspended || !_manager.IsAvailable(request.Type) ||
            (request.Type != WorkspaceTypeId.Processes && request.Type != WorkspaceTypeId.Events && request.Type != WorkspaceTypeId.Network && request.Type != WorkspaceTypeId.Persistence && request.Type != WorkspaceTypeId.Artifacts) || request.Capture != Capture ||
            !NetworkSourceCurrent(request) ||
            (request.Type==WorkspaceTypeId.Network && request.NetworkRevision!=_manager.NetworkSession?.Revision) ||
            (request.NetworkScope is { } networkScope && (networkScope.EvidenceSessionId!=Capture?.SessionId || string.IsNullOrWhiteSpace(networkScope.ProcessEntityId))) ||
            (request.EventPivot != null && request.EventPivot.Binding != _manager.EventsSession?.Binding) ||
            (request.SysmonNode != null && request.SysmonNode.Binding != _manager.EventsSession?.Binding) ||
            (request.Evidence != null && !_access.IsPublished(request.Evidence.Feature)) ||
            (request.Scope != null && (!FeatureNavigationPolicy.IsScopePublished(_access, request.Scope) ||
                (!string.IsNullOrEmpty(request.Scope.EvidenceSessionId) && request.Scope.EvidenceSessionId != Capture?.SessionId))) ||
            (request.Process != null && string.IsNullOrWhiteSpace(request.Process.ProcessEntityId) && string.IsNullOrWhiteSpace(request.Process.ProcessKey)))
        {
            Status = "The requested context is unavailable or stale; no investigation was changed.";
            return new(ViewerNavigationOutcome.Unavailable);
        }
        if (request.Type == WorkspaceTypeId.Events) return await NavigateEventsAsync(request, toggleGreen);
        if (request.Type == WorkspaceTypeId.Persistence) return await NavigatePersistenceAsync(request);
        if (request.Type == WorkspaceTypeId.Artifacts) return await NavigateArtifactsAsync(request);
        if (request.Type == WorkspaceTypeId.Network) return await NavigateNetworkAsync(request,toggleGreen);
        Cancel();
        _request.Dispose();
        _request = CancellationTokenSource.CreateLinkedTokenSource(request.SourceCancellation);
        var token = _request.Token;
        try
        {
            var target = request.Mode == WorkspaceNavigationMode.OpenNew ? null : Resolve(request);
            Task activation;
            _activating = true;
            try
            {
                activation = target == null ? _manager.OpenProcessesAsync() : _manager.ActivateAsync(target);
                target ??= _manager.ActiveInstance;
            }
            finally { _activating = false; }
            var revision = _manager.ContextRevision;
            await activation;
            token.ThrowIfCancellationRequested();
            if (!NetworkSourceCurrent(request) || request.Capture != Capture || target is not ProcessesWorkspaceViewModel process || process.IsDisposed ||
                revision != _manager.ContextRevision || !ReferenceEquals(target, _manager.ActiveInstance))
                return new(ViewerNavigationOutcome.Superseded);

            var p = process.Presentation;
            if (request.Evidence is { } evidence)
            {
                p.SelectedProcess = null;
                p.InspectorPaneViewModel.Clear("The requested evidence is unavailable until its exact record is resolved.");
                if (evidence.Correlation) p.LoadCorrelationResultIntoInspector(evidence.Result);
                else p.TryNavigateToIndependentArtifactResult(evidence.Result);
                process.NavigationDescription = evidence.Result.Title.Length > 0 ? evidence.Result.Title : evidence.Result.Kind;
                Status = p.StatusMessage;
                return new(p.InspectorPaneViewModel.CurrentPayload != null ? ViewerNavigationOutcome.Succeeded : ViewerNavigationOutcome.NotFound, process.Id);
            }
            if (request.Scope is { } scope)
            {
                // Tree metadata is shared; selectors and node selection are never shared between presentations.
                var localNode = _manager.ExplorerSections.CopyScopeTo(p, scope);
                if (toggleGreen) p.ToggleExplorerGreenScope(localNode);
                else
                {
                    p.ClearScopedSelection();
                    p.ExplorerViewModel.SelectNode(localNode, request.Gesture);
                }
                process.NavigationDescription = scope.Title;
                // Scope handlers normally debounce UI input; this route awaits one explicit refresh.
                p._listingWorkflow.CancelDebounce();
                var previousRows = p._virtualizedProcessListing;
                var refresh = p.ExecuteDbRefreshAsync();
                var issuedGeneration = p._processListingQueryGeneration;
                await refresh;
                token.ThrowIfCancellationRequested();
                if (!NetworkSourceCurrent(request) || request.Capture != Capture || process.IsDisposed || revision != _manager.ContextRevision)
                    return new(ViewerNavigationOutcome.Superseded);
                if (p._processListingQueryGeneration != issuedGeneration) return new(ViewerNavigationOutcome.Superseded);
                if (p._virtualizedProcessListing is not { } published || ReferenceEquals(published, previousRows) || published.QueryGeneration != issuedGeneration)
                {
                    Status = p._processListingService == null ? "No staged process listing is available for this context." : p.ProcessListingStatus;
                    return new(p._processListingService == null ? ViewerNavigationOutcome.Unavailable : ViewerNavigationOutcome.Failed, process.Id);
                }
                p.ProcessListingStatus = p.TotalProcessCount == 0
                    ? $"No processes match {scope.Title} combined with the retained column filters. Clear Listing Filters to inspect this scope."
                    : $"{scope.Title}; column filters, sorting and layout retained.";
            }
            if (request.Process is { } result)
            {
                if (request.Citation == null) p.SelectedProcess = null;
                var outcome = await p._viewerNavigationCoordinator.NavigateToProcessResultAsync(result, token, retainFilters: true,
                    eligibleRow: request.Citation == null ? null : row => AiEvidenceReferenceResolver.Matches(request.Citation, row.ProcessInfo),
                    canSelect: request.CitationSelectionCurrent);
                if (token.IsCancellationRequested || !NetworkSourceCurrent(request) || request.Capture != Capture || process.IsDisposed || revision != _manager.ContextRevision)
                    return new(ViewerNavigationOutcome.Superseded);
                if (request.Citation != null &&
                    (outcome.Outcome == ViewerNavigationOutcome.Superseded || outcome.Outcome == ViewerNavigationOutcome.Canceled))
                    return new(ViewerNavigationOutcome.Superseded);
                Status = outcome.State.StatusMessage;
                process.NavigationDescription = $"Exact process: {result.ProcessName}";
                return new(outcome.Outcome, process.Id);
            }
            _manager.ExplorerSections.ProjectSelectors();
            Status = p.ProcessListingStatus;
            return new(ViewerNavigationOutcome.Succeeded, process.Id);
        }
        catch (OperationCanceledException) { return new(ViewerNavigationOutcome.Superseded); }
        catch (Exception ex)
        {
            if (!token.IsCancellationRequested) Status = $"Navigation could not complete: {ex.Message}";
            return new(ViewerNavigationOutcome.Failed);
        }
    }
    private async Task<WorkspaceNavigationResult> NavigateArtifactsAsync(WorkspaceNavigationRequest request)
    {
        Cancel(); _request.Dispose(); _request = CancellationTokenSource.CreateLinkedTokenSource(request.SourceCancellation);
        var token = _request.Token; var revision = _manager.ArtifactsSession?.Revision;
        try
        {
            var target = request.Mode == WorkspaceNavigationMode.OpenNew ? null : Resolve(request);
            _activating = true;
            try { if (target == null) target = await _manager.OpenArtifactsAsync(); else await _manager.ActivateAsync(target); }
            finally { _activating = false; }
            token.ThrowIfCancellationRequested();
            if (target is not ArtifactsWorkspaceViewModel artifacts || artifacts.IsDisposed || request.Capture != Capture || revision != _manager.ArtifactsSession?.Revision || !ReferenceEquals(target, _manager.ActiveInstance)) return new(ViewerNavigationOutcome.Superseded);
            if (request.ArtifactFilters != null || request.ArtifactSelectors != null)
                artifacts.SetExplorerScope(request.ArtifactFilters ?? [], request.ArtifactSelectors ?? [], request.ArtifactTitle ?? "Artifacts");
            await artifacts.LoadAsync(); token.ThrowIfCancellationRequested();
            if (artifacts.IsDisposed || request.Capture != Capture || revision != _manager.ArtifactsSession?.Revision || !ReferenceEquals(artifacts, _manager.ActiveInstance))
                return new(ViewerNavigationOutcome.Superseded);
            Status = artifacts.Status; return new(artifacts.LastRefreshSucceeded ? ViewerNavigationOutcome.Succeeded : ViewerNavigationOutcome.Failed, artifacts.Id);
        }
        catch (OperationCanceledException) { return new(ViewerNavigationOutcome.Superseded); }
        catch (Exception error) { if (!token.IsCancellationRequested) Status = "Artifacts navigation unavailable: " + error.Message; return new(ViewerNavigationOutcome.Failed); }
    }
    private bool NetworkSourceCurrent(WorkspaceNavigationRequest request) =>
        !request.SourceCancellation.IsCancellationRequested &&
        (request.NetworkRevision == null || request.NetworkRevision == _manager.NetworkSession?.Revision) &&
        (request.NetworkSource == null || !request.NetworkSource.IsDisposed && !request.NetworkSource.ReadsSuspended &&
            _manager.Instances.Contains(request.NetworkSource));
    private async Task<WorkspaceNavigationResult> NavigateNetworkAsync(WorkspaceNavigationRequest request,bool toggleGreen)
    {
        Cancel();_request.Dispose();_request=new();var token=_request.Token;
        try
        {
            var target=request.Mode==WorkspaceNavigationMode.OpenNew?null:Resolve(request) as NetworkWorkspaceViewModel;
            _activating=true;
            try{if(target==null)target=await _manager.OpenNetworkAsync();else await _manager.ActivateAsync(target);}
            finally{_activating=false;}
            if(token.IsCancellationRequested || request.Capture!=Capture || request.NetworkRevision!=_manager.NetworkSession?.Revision || target.IsDisposed || !ReferenceEquals(target,_manager.ActiveInstance))return new(ViewerNavigationOutcome.Superseded);
            if(request.NetworkEndpoints!=null)
            {
                if(toggleGreen) target.ToggleEndpointGreen(request.NetworkEndpoints);
                else target.SetEndpointScope(request.NetworkEndpoints,request.NetworkTitle??"Live network snapshots");
            }
            else if(toggleGreen)target.ToggleGreen(new(request.NetworkScope,request.NetworkByProcess,Facet:request.NetworkFacet));
            else target.SetScope(request.NetworkScope,request.NetworkTitle??"All network activity",request.NetworkByProcess,request.NetworkFacet);
            await target.RefreshAsync();
            if(token.IsCancellationRequested || request.Capture!=Capture || request.NetworkRevision!=_manager.NetworkSession?.Revision || target.IsDisposed || !ReferenceEquals(target,_manager.ActiveInstance))return new(ViewerNavigationOutcome.Superseded);
            Status=target.Status;return new(target.LastRefreshSucceeded?ViewerNavigationOutcome.Succeeded:ViewerNavigationOutcome.Failed,target.Id);
        }
        catch(OperationCanceledException){return new(ViewerNavigationOutcome.Superseded);}
        catch(Exception error){if(!token.IsCancellationRequested)Status="Network navigation unavailable: "+error.Message;return new(ViewerNavigationOutcome.Failed);}
    }
    private async Task<WorkspaceNavigationResult> NavigateEventsAsync(WorkspaceNavigationRequest request, bool toggleGreen)
    {
        Cancel(); _request.Dispose(); _request = new();
        var token = _request.Token;
        try
        {
            var target = request.Mode == WorkspaceNavigationMode.OpenNew ? null : Resolve(request) as EventsWorkspaceViewModel;
            Task activation;
            _activating = true;
            try { activation = target == null ? _manager.OpenEventsAsync() : _manager.ActivateAsync(target); target ??= _manager.ActiveInstance as EventsWorkspaceViewModel; }
            finally { _activating = false; }
            await activation;
            if (token.IsCancellationRequested || target == null || target.IsDisposed || request.Capture != Capture || !ReferenceEquals(target, _manager.ActiveInstance)) return new(ViewerNavigationOutcome.Superseded);
            if (request.SysmonNode is { } sysmon)
            {
                if (sysmon.Binding != _manager.EventsSession?.Binding) return new(ViewerNavigationOutcome.Superseded);
                if (toggleGreen) target.ToggleSysmonGreen(sysmon);
                else
                {
                    var filter = target.Filter with
                    {
                        GreenSelectors = [],
                        GreenSysmonEventIds = [],
                        Source = SysmonEventTaxonomy.Source,
                        EventIds = sysmon.EventIds,
                        EventId = null,
                        MissingEventId = false,
                    };
                    target.SetFilter(filter, sysmon.Display, explicitTypeFilter: true);
                }
                await target.RefreshAsync();
            }
            else if (request.EventPivot is { } pivot)
            {
                if (pivot.Binding != _manager.EventsSession?.Binding) return new(ViewerNavigationOutcome.Superseded);
                if (toggleGreen) target.ToggleGreen(pivot);
                else
                {
                    var filter = target.Filter with { GreenSelectors = [], GreenSysmonEventIds = [], Source = null, EventIds = [] };
                    filter = pivot.Dimension switch
                    {
                        EventAggregateDimension.Identity => filter with { IdentityKey = pivot.Aggregate.Key, IdentityRole = pivot.Role, IdentitySessionKey = null },
                        EventAggregateDimension.IdentitySession => filter with { IdentityKey = pivot.Aggregate.ParentKey, IdentityRole = pivot.Role, IdentitySessionKey = pivot.Aggregate.Key },
                        EventAggregateDimension.Auditing => filter with { AuditCategoryKey = pivot.Aggregate.Key, AuditSubcategoryKey = null },
                        EventAggregateDimension.AuditSubcategory => filter with { AuditCategoryKey = pivot.Aggregate.ParentKey, AuditSubcategoryKey = pivot.Aggregate.Key },
                        EventAggregateDimension.Provider => filter with { Provider = pivot.Aggregate.Key },
                        EventAggregateDimension.Channel => filter with { Channel = pivot.Aggregate.Key },
                        EventAggregateDimension.EventId when int.TryParse(pivot.Aggregate.Key, out var id) => filter with { EventId = id, MissingEventId = false },
                        EventAggregateDimension.EventId when pivot.Aggregate.Key == "Unknown" => filter with { EventId = null, MissingEventId = true },
                        _ => throw new InvalidOperationException("This missing Event ID bucket has no exact filter representation.")
                    };
                    target.SetFilter(filter, pivot.Display, explicitTypeFilter: pivot.Dimension is EventAggregateDimension.Provider or EventAggregateDimension.Channel or EventAggregateDimension.EventId);
                }
                await target.RefreshAsync();
            }
            if (token.IsCancellationRequested || target.IsDisposed || request.Capture != Capture || !ReferenceEquals(target, _manager.ActiveInstance)) return new(ViewerNavigationOutcome.Superseded);
            Status = target.Status;
            return new(target.LastRefreshSucceeded ? ViewerNavigationOutcome.Succeeded : ViewerNavigationOutcome.Failed, target.Id);
        }
        catch (OperationCanceledException) { return new(ViewerNavigationOutcome.Superseded); }
        catch (Exception ex) { if (!token.IsCancellationRequested) Status = $"Events navigation failed: {ex.Message}"; return new(ViewerNavigationOutcome.Failed); }
    }
    public void Dispose()
    {
        _disposed = true;
        _manager.ActiveContextChanging -= OnActivation;
        Cancel(); _request.Dispose();
    }
}
