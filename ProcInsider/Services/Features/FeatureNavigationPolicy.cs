using ProcInsider.Models;
using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

public static class FeatureNavigationPolicy
{
    public static FeatureId? GetFeatureForExplorerScope(ExplorerScope scope) => scope.Kind switch
    {
        ExplorerScopeKind.FilesystemRoot or ExplorerScopeKind.FilesystemEvidenceRoots or
        ExplorerScopeKind.FilesystemArtifacts or ExplorerScopeKind.FilesystemFolder => FeatureIds.FilesystemArtifacts,
        ExplorerScopeKind.NetworkRoot or ExplorerScopeKind.NetworkCaptures or
        ExplorerScopeKind.NetworkCapture or ExplorerScopeKind.ZeekArtifacts => FeatureIds.NetworkAndZeek,
        ExplorerScopeKind.SearchResults or ExplorerScopeKind.SigmaFindings or
        ExplorerScopeKind.CorrelationEvidence or ExplorerScopeKind.UnresolvedEvidence or
        ExplorerScopeKind.AmbiguousEvidence or ExplorerScopeKind.CorrelationEvidenceGroup => FeatureIds.SearchAndSigma,
        ExplorerScopeKind.MemoryDumps or ExplorerScopeKind.PeAnalyses => FeatureIds.DumpsAndPeAnalysis,
        ExplorerScopeKind.Modules or ExplorerScopeKind.Handles => FeatureIds.ModulesAndHandles,
        ExplorerScopeKind.RuntimeEvents or ExplorerScopeKind.EtwEvents or ExplorerScopeKind.SecurityEvents or
        ExplorerScopeKind.PowerShellEvents or ExplorerScopeKind.WindowsOtherEvents or ExplorerScopeKind.SysmonEvents or
        ExplorerScopeKind.SystemActivityRoot or ExplorerScopeKind.ActivityAuthentication or
        ExplorerScopeKind.ActivitySuccessfulLogons or ExplorerScopeKind.ActivityFailedLogons or
        ExplorerScopeKind.ActivityRemoteInteractive or ExplorerScopeKind.ActivityExplicitCredentialUse or
        ExplorerScopeKind.ActivityPrivilegedLogons or ExplorerScopeKind.ActivityAccounts or
        ExplorerScopeKind.ActivityCreatedUsers or ExplorerScopeKind.ActivityDisabledDeletedUsers or
        ExplorerScopeKind.ActivityPasswordChanges or ExplorerScopeKind.ActivityGroups or
        ExplorerScopeKind.ActivityLocalAdministratorsChanges or
        ExplorerScopeKind.ActivitySecurityGroupMembershipChanges or ExplorerScopeKind.ActivityPolicyAudit or
        ExplorerScopeKind.ActivityAuditPolicyChanged or ExplorerScopeKind.ActivityLogIntegrity or
        ExplorerScopeKind.ActivitySecurityLogCleared or ExplorerScopeKind.ActivityServicesTasks or
        ExplorerScopeKind.ActivityServicesInstalled or ExplorerScopeKind.ActivityScheduledTasksChanged or
        ExplorerScopeKind.UsersRoot or ExplorerScopeKind.UserAccount => FeatureIds.EventTelemetry,
        _ => null
    };

    public static bool IsScopePublished(FeatureAccessService access, ExplorerScope scope)
    {
        var featureId = GetFeatureForExplorerScope(scope);
        return !featureId.HasValue || access.IsPublished(featureId.Value);
    }
}
