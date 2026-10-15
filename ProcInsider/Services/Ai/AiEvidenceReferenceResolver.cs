using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.Ai;

public enum AiEvidenceResolutionStatus { Resolved, Unavailable, NotFound, Ambiguous, IdentityMismatch, Unsupported }

public sealed record AiEvidenceResolution(
    AiEvidenceResolutionStatus Status,
    string Message,
    ProcessInfo? Process = null)
{
    public bool IsResolved => Status == AiEvidenceResolutionStatus.Resolved && Process != null;
}

/// <summary>Resolves an annotation citation through the active snapshot/archive query binding, never its saved annotation snapshot.</summary>
public sealed class AiEvidenceReferenceResolver(SqliteStagingQueryService? query)
{
    /// <summary>Recheck a saved citation against the active read binding before displaying or reusing it.</summary>
    internal static async Task<AiObjectContext?> ResolveObjectAsync(
        TelemetryProjectionService projection, FeatureAccessService access,
        AiEvidenceReference reference, string activeEvidenceSessionId, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (reference is null || reference.Identity is null || reference.Evidence is null ||
            reference.Identity.EvidenceSessionId != activeEvidenceSessionId ||
            !access.IsPublished(ProcInsider.Models.Features.FeatureIds.AiAssistance)) return null;
        var query = projection.ScopedQuery;
        AiObjectContext? original;
        if (reference.Evidence.Kind == EvidenceReferenceKind.ProcessEntity)
        {
            var resolved = new AiEvidenceReferenceResolver(query).ResolveProcess(reference, activeEvidenceSessionId);
            original = resolved.IsResolved ? ProcessEvidenceAgentTools.CreateObjectContext(resolved.Process!) : null;
        }
        else
        {
            original = await EvidenceObjectAgentTools.ResolveAsync(query, access, reference,
                activeEvidenceSessionId, token) ??
                SnapshotEvidenceAgentTools.ResolveSnapshotReference(query, reference, token) ??
                await ArtifactEvidenceAgentTools.ResolveAsync(projection, access, reference, token);
        }
        return original is not null && original.Reference.ReferenceId == reference.ReferenceId &&
            original.Reference.CanonicalObjectKey == reference.CanonicalObjectKey &&
            original.Reference.Identity == reference.Identity ? original : null;
    }

    public AiEvidenceResolution ResolveProcess(AiEvidenceReference reference, string activeEvidenceSessionId)
    {
        ArgumentNullException.ThrowIfNull(reference);
        if (reference.Identity == null || reference.Evidence == null ||
            string.IsNullOrWhiteSpace(activeEvidenceSessionId) ||
            string.IsNullOrWhiteSpace(reference.Identity.EvidenceSessionId) ||
            !string.Equals(reference.Identity.EvidenceSessionId, activeEvidenceSessionId, StringComparison.Ordinal))
            return new(AiEvidenceResolutionStatus.IdentityMismatch, "Citation belongs to another or unspecified evidence session.");
        if (string.IsNullOrWhiteSpace(reference.Identity.CaptureId) ||
            string.IsNullOrWhiteSpace(reference.Identity.SourceIdentityId) ||
            string.IsNullOrWhiteSpace(reference.Identity.HostId) ||
            string.IsNullOrWhiteSpace(reference.Identity.ExecutionRootId))
            return new(AiEvidenceResolutionStatus.IdentityMismatch, "Citation lacks a recorded capture, source, host or execution root.");

        // A process entity is a durable identity. An observation/event is a different immutable row
        // and cannot be proved by finding today's process entity.
        if (reference.Evidence.Kind != EvidenceReferenceKind.ProcessEntity ||
            !string.IsNullOrWhiteSpace(reference.SourceRunId) ||
            !string.IsNullOrWhiteSpace(reference.SourceRevision))
            return new(AiEvidenceResolutionStatus.Unsupported, "This citation's exact observation or source revision cannot be resolved by the process entity projection.");

        if (query == null)
            return new(AiEvidenceResolutionStatus.Unavailable, "The active evidence projection is unavailable.");

        var processRef = reference.Process;
        ProcessInfo? process;
        if (!string.IsNullOrWhiteSpace(reference.Evidence.Id))
        {
            if (processRef != null && !string.IsNullOrWhiteSpace(processRef.ProcessEntityId) &&
                !string.Equals(processRef.ProcessEntityId, reference.Evidence.Id, StringComparison.Ordinal))
                return new(AiEvidenceResolutionStatus.IdentityMismatch, "Citation process identities disagree.");
            var lookup = query.GetProcessByEntityId(reference.Evidence.Id);
            process = lookup.IsFound ? lookup.Process?.ToProcessInfo() : null;
        }
        else if (processRef != null && string.IsNullOrWhiteSpace(processRef.ProcessEntityId) &&
                 !string.IsNullOrWhiteSpace(processRef.ProcessKey))
        {
            // The compatibility query itself requires a complete, exact stored scope. In particular,
            // it cannot treat an empty Standalone CaseId as a wildcard.
            if (string.IsNullOrWhiteSpace(reference.Identity.CaseId) ||
                string.IsNullOrWhiteSpace(reference.Identity.SourceIdentityId) ||
                string.IsNullOrWhiteSpace(reference.Identity.HostId) ||
                string.IsNullOrWhiteSpace(reference.Identity.ExecutionRootId))
                return new(AiEvidenceResolutionStatus.Unsupported, "The legacy process key lacks a queryable exact scope.");
            var matches = query.GetProcessesByExactScope(new ExplorerScope
            {
                Kind = ExplorerScopeKind.AllProcesses,
                ProcessKey = processRef.ProcessKey,
                CaseId = reference.Identity.CaseId,
                EvidenceSessionId = reference.Identity.EvidenceSessionId,
                CaptureId = reference.Identity.CaptureId,
                SourceIdentityId = reference.Identity.SourceIdentityId,
                HostId = reference.Identity.HostId,
                ExecutionRootId = reference.Identity.ExecutionRootId
            }, 2);
            if (matches.Count > 1)
                return new(AiEvidenceResolutionStatus.Ambiguous, "The scoped legacy process key matches multiple originals.");
            process = matches.SingleOrDefault()?.ToProcessInfo();
        }
        else return new(AiEvidenceResolutionStatus.Unsupported, "Citation has no durable process identity or supported scoped legacy key.");

        if (process == null)
            return new(AiEvidenceResolutionStatus.NotFound, "The cited original is missing from the active evidence projection.");
        if (!Matches(reference, process))
            return new(AiEvidenceResolutionStatus.IdentityMismatch, "The cited original's recorded scope or compatibility identity does not match.");
        return new(AiEvidenceResolutionStatus.Resolved, "Exact process original resolved.", process);
    }

    public static bool Matches(AiEvidenceReference reference, ProcessInfo process)
    {
        var scope = reference.Identity;
        var compatibility = reference.Process;
        return scope != null &&
            string.Equals(scope.CaseId, process.CaseId, StringComparison.Ordinal) &&
            string.Equals(scope.EvidenceSessionId, process.EvidenceSessionId, StringComparison.Ordinal) &&
            string.Equals(scope.CaptureId, process.CaptureId, StringComparison.Ordinal) &&
            string.Equals(scope.SourceIdentityId, process.SourceIdentityId, StringComparison.Ordinal) &&
            string.Equals(scope.HostId, process.HostId, StringComparison.Ordinal) &&
            string.Equals(scope.ExecutionRootId, process.ExecutionRootId, StringComparison.Ordinal) &&
            (string.IsNullOrWhiteSpace(reference.Evidence.Id) ||
             string.Equals(reference.Evidence.Id, process.ProcessEntityId, StringComparison.Ordinal)) &&
            (compatibility == null ||
             (string.IsNullOrWhiteSpace(compatibility.ProcessEntityId) || string.Equals(compatibility.ProcessEntityId, process.ProcessEntityId, StringComparison.Ordinal)) &&
             (string.IsNullOrWhiteSpace(compatibility.ProcessKey) || string.Equals(compatibility.ProcessKey, process.ProcessKey, StringComparison.Ordinal)) &&
             string.Equals(compatibility.CaseId, process.CaseId, StringComparison.Ordinal) &&
             string.Equals(compatibility.EvidenceSessionId, process.EvidenceSessionId, StringComparison.Ordinal) &&
             string.Equals(compatibility.CaptureId, process.CaptureId, StringComparison.Ordinal) &&
             string.Equals(compatibility.SourceIdentityId, process.SourceIdentityId, StringComparison.Ordinal) &&
             string.Equals(compatibility.HostId, process.HostId, StringComparison.Ordinal) &&
             string.Equals(compatibility.ExecutionRootId, process.ExecutionRootId, StringComparison.Ordinal));
    }
}
