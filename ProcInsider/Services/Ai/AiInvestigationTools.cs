using ProcInsider.Models;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public interface IAiInvestigationTools
{
    AiProcessListResult ListProcesses(AiProcessListRequest request);

    AiProcessContextResult GetProcessContext(AiProcessContextRequest request);
}

public sealed class AiInvestigationTools : IAiInvestigationTools
{
    public const int MaximumProcessListCount = 100;
    public const int MaximumChildCount = 100;
    public const int MaximumEventCount = 100;

    private readonly TelemetryProjectionService _projectionService;

    public AiInvestigationTools(TelemetryProjectionService projectionService)
    {
        ArgumentNullException.ThrowIfNull(projectionService);
        _projectionService = projectionService;
    }

    public AiProcessListResult ListProcesses(AiProcessListRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var readScope = _projectionService.BeginReadScope();
        var diagnostics = CreateDiagnostics(_projectionService.PathDiagnostics);
        if (!diagnostics.IsReadable)
        {
            return new AiProcessListResult
            {
                Availability = AiInvestigationToolAvailability.Unavailable,
                StatusMessage = diagnostics.Message,
                Diagnostics = diagnostics
            };
        }

        var maximum = Math.Clamp(request.MaxCount, 1, MaximumProcessListCount);
        var rows = _projectionService.GetProcessList(new ProcessProjectionQuery
        {
            IncludeExited = request.IncludeExited,
            MaxCount = maximum + 1
        });
        var stats = _projectionService.GetStats();
        var available = request.IncludeExited
            ? stats.ProcessCount
            : Math.Max(0, stats.ProcessCount - stats.ExitedProcessCount);
        var included = rows.Take(maximum).Select(ToSummary).ToArray();

        return new AiProcessListResult
        {
            Availability = AiInvestigationToolAvailability.Available,
            StatusMessage = included.Length == 0
                ? "The active evidence path contains no matching processes."
                : "Bounded process discovery completed.",
            Processes = included,
            AvailableCount = Math.Max(available, rows.Count),
            IsTruncated = available > included.Length || rows.Count > included.Length,
            Diagnostics = diagnostics
        };
    }

    public AiProcessContextResult GetProcessContext(AiProcessContextRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Process);
        using var readScope = _projectionService.BeginReadScope();
        var diagnostics = CreateDiagnostics(_projectionService.PathDiagnostics);
        if (!diagnostics.IsReadable)
        {
            return Failed(AiInvestigationToolAvailability.Unavailable, diagnostics.Message, diagnostics);
        }

        var resolution = ResolveProcess(request.Process);
        if (resolution.Process == null)
        {
            return Failed(resolution.Availability, resolution.Message, diagnostics);
        }

        var selected = resolution.Process;
        var childMaximum = Math.Clamp(request.MaxChildren, 1, MaximumChildCount);
        var eventMaximum = Math.Clamp(request.MaxEvents, 1, MaximumEventCount);
        var childProjection = _projectionService.GetImmediateChildProcesses(selected, childMaximum + 1);
        if (!childProjection.IsComplete)
        {
            return Failed(
                childProjection.IsAmbiguous
                    ? AiInvestigationToolAvailability.Ambiguous
                    : AiInvestigationToolAvailability.IdentityMismatch,
                "Immediate-child evidence could not be hydrated by one exact scoped identity.",
                diagnostics);
        }

        var children = childProjection.Processes.ToArray();
        var includedChildren = children.Take(childMaximum).Select(ToSummary).ToArray();
        var events = _projectionService.GetEventsForProcess(new EventProjectionQuery
        {
            ProcessEntityId = selected.ProcessEntityId,
            ProcessKey = selected.GetUniqueKey(),
            MaxCount = eventMaximum + 1
        });
        var includedEvents = events.Take(eventMaximum).Select(ToEvent).ToArray();
        var parentResolution = ResolveParent(selected);

        return new AiProcessContextResult
        {
            Availability = AiInvestigationToolAvailability.Available,
            StatusMessage = "Bounded process context completed.",
            SelectedProcess = ToSummary(selected),
            ParentProcess = parentResolution.Process is { } parent ? ToSummary(parent) : null,
            ParentAvailability = parentResolution.Availability,
            ParentStatusMessage = parentResolution.Message,
            ImmediateChildren = includedChildren,
            ObservedChildCount = children.Length,
            ChildCountIsExact = children.Length <= childMaximum,
            ChildrenTruncated = children.Length > includedChildren.Length,
            RelatedEvents = includedEvents,
            ObservedEventCount = events.Count,
            EventCountIsExact = events.Count <= eventMaximum,
            EventsTruncated = events.Count > includedEvents.Length,
            Diagnostics = diagnostics
        };
    }

    private ProcessResolution ResolveProcess(AiProcessReference reference)
    {
        if (!string.IsNullOrWhiteSpace(reference.ProcessEntityId))
        {
            var process = _projectionService.GetProcessByEntityId(reference.ProcessEntityId);
            if (process == null)
            {
                return new(null, AiInvestigationToolAvailability.NotFound,
                    "The requested durable process entity is not available in the active evidence path.");
            }

            if (!MatchesSuppliedIdentity(process, reference))
            {
                return new(null, AiInvestigationToolAvailability.IdentityMismatch,
                    "The supplied compatibility identity does not match the durable process entity.");
            }

            return new(process, AiInvestigationToolAvailability.Available, string.Empty);
        }

        if (string.IsNullOrWhiteSpace(reference.ProcessKey) || !HasScopedCompatibilityIdentity(reference))
        {
            return new(null, AiInvestigationToolAvailability.InvalidRequest,
                "Process context requires a durable ProcessEntityId or an exact scoped ProcessKey identity; PID-only lookup is not supported.");
        }

        var matches = _projectionService.GetProcessesByExactScope(new ExplorerScope
        {
            Kind = ExplorerScopeKind.AllProcesses,
            ProcessKey = reference.ProcessKey,
            CaseId = reference.CaseId,
            EvidenceSessionId = reference.EvidenceSessionId,
            CaptureId = reference.CaptureId,
            SourceIdentityId = reference.SourceIdentityId,
            HostId = reference.HostId,
            ExecutionRootId = reference.ExecutionRootId
        }, 2);

        return matches.Count switch
        {
            1 => new(matches[0], AiInvestigationToolAvailability.Available, string.Empty),
            > 1 => new(null, AiInvestigationToolAvailability.Ambiguous,
                "The scoped compatibility identity matched more than one process and was rejected."),
            _ => new(null, AiInvestigationToolAvailability.NotFound,
                "The scoped compatibility identity is not available in the active evidence path.")
        };
    }

    private ProcessResolution ResolveParent(ProcessInfo selected)
    {
        if (!string.IsNullOrWhiteSpace(selected.ParentProcessEntityId))
        {
            var parent = _projectionService.GetProcessByEntityId(selected.ParentProcessEntityId);
            return parent == null
                ? new(null, AiInvestigationToolAvailability.NotFound,
                    "The asserted durable parent process entity is not available in the active evidence path.")
                : new(parent, AiInvestigationToolAvailability.Available,
                    "Parent resolved by durable ProcessEntityId.");
        }

        if (string.IsNullOrWhiteSpace(selected.ParentProcessKey))
        {
            return new(null, AiInvestigationToolAvailability.NotFound,
                "No parent process identity is available for the selected process.");
        }

        var reference = CreateReference(selected) with
        {
            ProcessEntityId = string.Empty,
            ProcessKey = selected.ParentProcessKey
        };
        var resolution = ResolveProcess(reference);
        return resolution with
        {
            Message = resolution.Availability == AiInvestigationToolAvailability.Available
                ? "Parent resolved by exact scoped ProcessKey compatibility identity."
                : resolution.Message
        };
    }

    private static bool MatchesSuppliedIdentity(ProcessInfo process, AiProcessReference reference)
    {
        if (!string.IsNullOrWhiteSpace(reference.ProcessKey) &&
            !string.Equals(process.GetUniqueKey(), reference.ProcessKey, StringComparison.Ordinal))
        {
            return false;
        }

        return MatchesOptional(reference.CaseId, process.CaseId) &&
               MatchesOptional(reference.EvidenceSessionId, process.EvidenceSessionId) &&
               MatchesOptional(reference.CaptureId, process.CaptureId) &&
               MatchesOptional(reference.SourceIdentityId, process.SourceIdentityId) &&
               MatchesOptional(reference.HostId, process.HostId) &&
               MatchesOptional(reference.ExecutionRootId, process.ExecutionRootId);
    }

    private static bool MatchesOptional(string supplied, string actual) =>
        string.IsNullOrWhiteSpace(supplied) || string.Equals(supplied, actual, StringComparison.Ordinal);

    private static bool HasScopedCompatibilityIdentity(AiProcessReference reference) =>
        !string.IsNullOrWhiteSpace(reference.CaseId) &&
        !string.IsNullOrWhiteSpace(reference.EvidenceSessionId) &&
        !string.IsNullOrWhiteSpace(reference.SourceIdentityId) &&
        !string.IsNullOrWhiteSpace(reference.HostId) &&
        !string.IsNullOrWhiteSpace(reference.ExecutionRootId);

    private static AiProcessSummary ToSummary(ProcessInfo process) => new(
        CreateReference(process),
        process.ProcessId,
        process.ProcessName,
        process.ProcessPath,
        process.CommandLine,
        process.UserName,
        process.Status.ToString(),
        process.StartTime?.ToUniversalTime(),
        process.EndTime?.ToUniversalTime(),
        process.ParentProcessEntityId,
        process.ParentProcessKey,
        process.ParentProcessName);

    private static AiProcessReference CreateReference(ProcessInfo process) => new(
        process.ProcessEntityId,
        process.GetUniqueKey(),
        process.CaseId,
        process.EvidenceSessionId,
        process.CaptureId,
        process.SourceIdentityId,
        process.HostId,
        process.ExecutionRootId);

    private static AiRelatedProcessEvent ToEvent(ProcessEventInfo processEvent) => new(
        processEvent.SequenceId,
        processEvent.TimestampUtc,
        processEvent.EventCode,
        processEvent.Category.ToString(),
        processEvent.Action.ToString(),
        processEvent.Target,
        processEvent.Summary,
        processEvent.Details,
        processEvent.RiskFlags,
        processEvent.RepeatCount,
        processEvent.SourceRunId);

    private static AiEvidenceReadDiagnostics CreateDiagnostics(EvidencePathDiagnostics diagnostics) => new(
        diagnostics.IsReadable,
        diagnostics.ReadPath.ToString(),
        diagnostics.StatusCode,
        diagnostics.IsReadable
            ? $"Evidence reads use the active {diagnostics.ReadPath} projection."
            : "Evidence reads are unavailable until a snapshot or archived capture is loaded.");

    private static AiProcessContextResult Failed(
        AiInvestigationToolAvailability availability,
        string message,
        AiEvidenceReadDiagnostics diagnostics) => new()
        {
            Availability = availability,
            StatusMessage = message,
            ParentAvailability = AiInvestigationToolAvailability.NotEvaluated,
            ParentStatusMessage = $"Parent resolution was not evaluated because process context failed: {message}",
            Diagnostics = diagnostics
        };

    private sealed record ProcessResolution(
        ProcessInfo? Process,
        AiInvestigationToolAvailability Availability,
        string Message);
}
