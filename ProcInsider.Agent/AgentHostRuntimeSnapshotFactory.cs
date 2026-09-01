using System.Reflection;
using System.Security.Principal;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal static class AgentHostRuntimeSnapshotFactory
{
    public static AgentHostRuntimeSnapshot Create(AgentOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User;
        var isLocalSystem = sid?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true;
        return new AgentHostRuntimeSnapshot
        {
            Mode = options.HostMode,
            PathScope = options.HostMode == AgentHostMode.WindowsService
                ? AgentHostPathScope.MachineScopedProgramData
                : AgentHostPathScope.SessionScopedLocalAppData,
            EffectiveAccountName = identity.Name ?? string.Empty,
            EffectiveAccountSid = sid?.Value ?? string.Empty,
            IsLocalSystem = isLocalSystem,
            ProcessVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? string.Empty,
            SessionRoot = options.SessionPaths?.SessionRoot ?? string.Empty,
            DatabasePath = options.DatabasePath
        };
    }
}
