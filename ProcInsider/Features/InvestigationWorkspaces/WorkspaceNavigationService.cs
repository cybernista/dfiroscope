using ProcInsider.Models;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal enum WorkspaceNavigationMode { Reuse, OpenNew }
internal sealed record WorkspaceEvidenceTarget(TelemetrySearchResult Result, FeatureId Feature, bool Correlation = false);
internal sealed record WorkspaceNavigationRequest(WorkspaceTypeId Type, WorkspaceContext? Capture,
    ExplorerScope? Scope = null, TelemetrySearchResult? Process = null,
    WorkspaceNavigationMode Mode = WorkspaceNavigationMode.Reuse, ExplorerSelectionGesture Gesture = ExplorerSelectionGesture.Replace,
    WorkspaceEvidenceTarget? Evidence = null, EventsPivot? EventPivot = null, SysmonExplorerNode? SysmonNode = null);
internal sealed record WorkspaceNavigationResult(ViewerNavigationOutcome Outcome, WorkspaceInstanceId? Instance = null);

internal sealed class WorkspaceNavigationService : ViewModelBase, IDisposable
{
    private readonly WorkspaceManager _manager;
    private readonly FeatureAccessService _access;
    private CancellationTokenSource _request = new();
    private bool _activating;
    private bool _disposed;
    private string _status = "Select an Explorer context or open a new investigation.";
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
    internal void Cancel() { _request.Cancel(); }
    internal WorkspaceInstanceViewModel? Resolve(WorkspaceNavigationRequest request) =>
        _manager.ActiveInstance is { IsPinned: false } active && Compatible(active, request) ? active :
        _manager.Instances.Where(x => !x.IsPinned && Compatible(x, request))
            .OrderByDescending(x => x.ActivationOrder).ThenBy(x => x.CreationOrder).FirstOrDefault();
    private static bool Compatible(WorkspaceInstanceViewModel instance, WorkspaceNavigationRequest request) =>
        !instance.IsDisposed && instance.Type.Id == request.Type && instance.Context == request.Capture;

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

    internal async Task<WorkspaceNavigationResult> NavigateAsync(WorkspaceNavigationRequest request, bool toggleGreen = false)
    {
        if (_disposed || _manager.ReadsSuspended || !_manager.IsAvailable(request.Type) ||
            (request.Type != WorkspaceTypeId.Processes && request.Type != WorkspaceTypeId.Events) || request.Capture != Capture ||
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
        Cancel();
        _request.Dispose();
        _request = new();
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
            if (request.Capture != Capture || target is not ProcessesWorkspaceViewModel process || process.IsDisposed ||
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
                if (request.Capture != Capture || process.IsDisposed || revision != _manager.ContextRevision)
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
                p.SelectedProcess = null;
                var outcome = await p._viewerNavigationCoordinator.NavigateToProcessResultAsync(result, token, retainFilters: true);
                if (token.IsCancellationRequested || request.Capture != Capture || process.IsDisposed || revision != _manager.ContextRevision)
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
