using ProcInsider.Models;
using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

/// <summary>
/// Stable Explorer-scope to Data-tab routing plus contextual tab membership.
/// This policy is UI-position independent and can be validated without constructing WPF views.
/// </summary>
public static class DataTabNavigationPolicy
{
    public static FeatureTabKey GetTabKey(ExplorerScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);

        return scope.Kind switch
        {
            ExplorerScopeKind.Modules => DataTabKeys.Modules,
            ExplorerScopeKind.Handles => DataTabKeys.Handles,
            ExplorerScopeKind.MemoryDumps => DataTabKeys.MemoryDumps,
            ExplorerScopeKind.PeAnalyses => DataTabKeys.PeAnalysis,
            ExplorerScopeKind.NetworkRoot or ExplorerScopeKind.NetworkCaptures or
            ExplorerScopeKind.NetworkCapture or ExplorerScopeKind.ZeekArtifacts => DataTabKeys.Network,
            ExplorerScopeKind.FilesystemRoot or ExplorerScopeKind.FilesystemEvidenceRoots or
            ExplorerScopeKind.FilesystemArtifacts or ExplorerScopeKind.FilesystemFolder => DataTabKeys.Filesystem,
            ExplorerScopeKind.SystemActivityRoot or ExplorerScopeKind.ActivityAuthentication or
            ExplorerScopeKind.ActivitySuccessfulLogons or ExplorerScopeKind.ActivityFailedLogons or
            ExplorerScopeKind.ActivityRemoteInteractive or ExplorerScopeKind.ActivityExplicitCredentialUse or
            ExplorerScopeKind.ActivityPrivilegedLogons or ExplorerScopeKind.ActivityAccounts or
            ExplorerScopeKind.ActivityCreatedUsers or ExplorerScopeKind.ActivityDisabledDeletedUsers or
            ExplorerScopeKind.ActivityPasswordChanges or ExplorerScopeKind.ActivityGroups or
            ExplorerScopeKind.ActivityLocalAdministratorsChanges or ExplorerScopeKind.ActivitySecurityGroupMembershipChanges or
            ExplorerScopeKind.ActivityPolicyAudit or ExplorerScopeKind.ActivityAuditPolicyChanged or
            ExplorerScopeKind.ActivityLogIntegrity or ExplorerScopeKind.ActivitySecurityLogCleared or
            ExplorerScopeKind.ActivityServicesTasks or ExplorerScopeKind.ActivityServicesInstalled or
            ExplorerScopeKind.ActivityScheduledTasksChanged or ExplorerScopeKind.UsersRoot or
            ExplorerScopeKind.UserAccount => DataTabKeys.SystemActivity,
            ExplorerScopeKind.RuntimeEvents => DataTabKeys.RuntimeEvents,
            ExplorerScopeKind.EtwEvents => DataTabKeys.EtwEvents,
            ExplorerScopeKind.SecurityEvents => DataTabKeys.SecurityEvents,
            ExplorerScopeKind.PowerShellEvents => DataTabKeys.PowerShellEvents,
            ExplorerScopeKind.WindowsOtherEvents => DataTabKeys.WindowsOtherEvents,
            ExplorerScopeKind.SysmonEvents => DataTabKeys.SysmonEvents,
            _ => DataTabKeys.AppInfo
        };
    }

    public static bool IsContextuallyAvailable(
        FeatureTabKey key,
        bool includeNetwork,
        bool includeFilesystem) =>
        key switch
        {
            var network when network == DataTabKeys.Network => includeNetwork,
            var filesystem when filesystem == DataTabKeys.Filesystem => includeFilesystem,
            _ => true
        };
}
