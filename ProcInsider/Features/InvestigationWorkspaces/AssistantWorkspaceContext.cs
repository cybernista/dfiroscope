using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Services.Ai;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal static class AssistantWorkspaceContext
{
    internal static AiGeneralSubmissionContext? Capture(WorkspaceManager manager)
    {
        if (manager.CaptureBinding is not { } binding || manager.ReadsSuspended) return null;
        if (manager.ActiveInstance is AiWorkspaceViewModel ai && ai.SubmissionContext is { } retained &&
            retained.ScopeIdentity.EvidenceSessionId == binding.Paths.SessionId)
        {
            var options = ScopeOptions(manager);
            var explicitScope = ai.SelectedEvidenceScopeGeneration == binding.CaptureGeneration &&
                options.Contains(ai.SelectedEvidenceScope!) ? ai.SelectedEvidenceScope : null;
            var resolvedIdentity = explicitScope ?? (options.Contains(retained.ScopeIdentity) ? retained.ScopeIdentity : ResolveUniqueScope(manager));
            return retained with { ScopeIdentity = resolvedIdentity ?? new EvidenceIdentity { EvidenceSessionId = binding.Paths.SessionId } };
        }
        EvidenceIdentity? identity = null;
        var selected = "No selected entity";
        string? investigation = null;
        DateTime? from = null, to = null;
        switch (manager.ActiveInstance)
        {
            case ProcessesWorkspaceViewModel processes:
                var presentation = processes.Presentation;
                if (presentation.SelectedProcess?.ProcessInfo is { } process)
                {
                    identity = ProcessEvidenceAgentTools.ProcessReference(process).Identity;
                    selected = $"Process {process.ProcessName}; entity {process.ProcessEntityId}";
                }
                else if (presentation.ExplorerViewModel.SelectedScopes.Count == 1 &&
                    presentation.ExplorerViewModel.SelectedScopes.Single() is { HostId.Length: > 0, CaptureId.Length: > 0 } scope)
                    identity = new() { CaseId = scope.CaseId ?? "", EvidenceSessionId = scope.EvidenceSessionId ?? "",
                        CaptureId = scope.CaptureId!, HostId = scope.HostId! };
                if (presentation.TryGetActiveInvestigation(out var saved)) investigation = saved.Id;
                if (presentation.BuildFilterSet().ColumnFilters.TryGetValue(ProcessListingSortColumn.StartTime, out var processTime))
                { from = processTime.FromUtc; to = processTime.ToUtc; }
                break;
            case EventsWorkspaceViewModel events:
                if (events.SelectedEvent is { } item)
                {
                    var context = EvidenceObjectAgentTools.EventContext(item.Evidence.Native);
                    identity = context.Reference.Identity;
                    selected = context.Reference.DisplayName + "; exact reference " + context.Reference.ReferenceId;
                }
                if (events.Filter.Columns.TryGetValue(EventSort.Timestamp, out var range)) { from = range.FromUtc; to = range.ToUtc; }
                break;
            case NetworkWorkspaceViewModel network:
                if (network.SelectedEndpoint is { } endpoint)
                {
                    identity = endpoint.Poll.Scope;
                    selected = "Network endpoint; observation " + endpoint.Observation.ObservationId;
                }
                else if (network.SelectedRow is { } observation)
                {
                    var source = observation.Source;
                    identity = new() { CaseId = source.CaseId, EvidenceSessionId = source.EvidenceSessionId,
                        CaptureId = source.CaptureId, HostId = source.HostId };
                    selected = "Network event; recorded sequence " + source.SequenceId;
                }
                var query = network.CaptureEndpointQuery();
                if (query?.FromUtcTicks is { } lower) from = new(lower, DateTimeKind.Utc);
                if (query?.ToUtcTicks is { } upper) to = new(upper, DateTimeKind.Utc);
                break;
            case PersistenceWorkspaceViewModel persistence:
                identity = persistence.SelectedScope?.Scope;
                if (persistence.SelectedRow is { } entry) selected = "Persistence item " + entry.Name + "; version " + entry.Collection.CollectionId;
                break;
        }
        if (identity is null) identity = ResolveUniqueScope(manager);
        if (identity is null || identity.EvidenceSessionId != binding.Paths.SessionId ||
            string.IsNullOrWhiteSpace(identity.HostId) || string.IsNullOrWhiteSpace(identity.CaptureId))
            identity = new() { EvidenceSessionId = binding.Paths.SessionId };
        else identity = identity with { SourceIdentityId = "", ExecutionRootId = "" };
        if (System.Text.Encoding.UTF8.GetByteCount(selected) > 500)
            selected = "Selected entity label omitted because it exceeds the context limit; use its object conversation for exact evidence.";
        return new(identity, DateTime.UtcNow, from, to, manager.ActiveInstance?.Type.Name ?? "No active workspace",
            selected, investigation);
    }

    internal static bool SelectScope(WorkspaceManager manager, EvidenceIdentity? scope)
    {
        if (manager.ActiveInstance is not AiWorkspaceViewModel ai || manager.CaptureBinding is not { } binding ||
            manager.ReadsSuspended || (scope is not null && !ScopeOptions(manager).Contains(scope))) return false;
        ai.SubmissionContext ??= Capture(manager);
        ai.SelectedEvidenceScope = scope;
        ai.SelectedEvidenceScopeGeneration = binding.CaptureGeneration;
        if (ai.SubmissionContext is { } retained)
            ai.SubmissionContext = retained with { ScopeIdentity = new EvidenceIdentity { EvidenceSessionId = binding.Paths.SessionId } };
        return true;
    }

    internal static IReadOnlyList<EvidenceIdentity> ScopeOptions(WorkspaceManager manager)
    {
        // Every retained root must pass the host/capture/session completeness gate.
        if (manager.ReadsSuspended || manager.CaptureBinding is not { Query: { } query } binding ||
            manager.ActiveInstance is AiWorkspaceViewModel ai && ai.Context?.CaptureGeneration != binding.CaptureGeneration ||
            query.CompatibilityAssessment.Context is not
                (CaptureOpenContext.ViewerLiveSnapshot or CaptureOpenContext.ViewerArchivedReadOnly) ||
            !query.CompatibilityAssessment.Allows(CaptureOpenCapability.ReadEvidence) ||
            manager.ExplorerMetadata?.EvidenceRoots is not { Count: > 0 } roots) return [];
        if (roots.Any(root => root.EvidenceSessionId != binding.Paths.SessionId ||
            string.IsNullOrWhiteSpace(root.HostId) || string.IsNullOrWhiteSpace(root.CaptureId))) return [];
        if (roots.Select(root => (root.EvidenceSessionId, root.CaptureId, root.HostId))
            .Distinct().Take(2).Count() != 1) return [];
        var evidenceRoots = roots.Where(root => root.ProcessCount > 0 || root.ProcessObservationCount > 0 ||
            root.EventCount > 0 || root.ModuleCount > 0 || root.HandleCount > 0 ||
            root.NetworkCaptureCount > 0 || root.FilesystemArtifactCount > 0 ||
            root.NetworkEndpointPollCount > 0 || root.PersistenceCollectionCount > 0 ||
            root.MissingSourceRunLinkCount > 0).ToArray();
        var scopeRoots = evidenceRoots.Length > 0 ? evidenceRoots : roots;
        var scopes = scopeRoots.Select(root => new EvidenceIdentity { CaseId = root.CaseId,
            EvidenceSessionId = root.EvidenceSessionId, CaptureId = root.CaptureId, HostId = root.HostId })
            .Distinct().Take(257).ToArray();
        return scopes.Length <= 256 ? scopes : [];
    }

    private static EvidenceIdentity? ResolveUniqueScope(WorkspaceManager manager)
    {
        var options = ScopeOptions(manager);
        return options.Count == 1 ? options[0] : null;
    }

    internal static IReadOnlyList<SkillToolQuery> Queries(AiGeneralSubmissionContext context)
    {
        // General questions have no pinned record. Let the admitted tools discover evidence
        // relevant to the explicit question instead of sending an unrelated inventory preview.
        return [];
    }
}
