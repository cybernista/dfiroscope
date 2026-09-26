using ProcInsider.Features.InvestigationWorkspaces;

namespace ProcInsider.Services;

internal sealed record EventAuditDefinition(string CategoryKey, string Category, string Key, string Name,
    string EventVersions, string Source);

/// <summary>
/// Best-effort static navigation taxonomy. It never reads or changes the analyst machine's
/// audit configuration, and uses Event ID except for narrow retained-field refinements where a
/// documented event supplies a deterministic category distinction.
/// </summary>
internal static partial class EventsAuditProjection
{
    internal const string Unknown = "Unknown";
    private const string FileSystem = "0cce921d-69ae-11d9-bed3-505054503030";
    private const string Registry = "0cce921e-69ae-11d9-bed3-505054503030";
    private const string SensitivePrivilegeUse = "0cce9228-69ae-11d9-bed3-505054503030";
    private const string NonSensitivePrivilegeUse = "0cce9229-69ae-11d9-bed3-505054503030";
    private const string AuthorizationPolicyChange = "0cce9231-69ae-11d9-bed3-505054503030";
    private static readonly HashSet<string> SensitivePrivileges = new(StringComparer.OrdinalIgnoreCase)
    {
        "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeCreateTokenPrivilege",
        "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeAuditPrivilege", "SeImpersonatePrivilege",
        "SeLoadDriverPrivilege", "SeSecurityPrivilege", "SeSystemEnvironmentPrivilege",
        "SeAssignPrimaryTokenPrivilege", "SeTakeOwnershipPrivilege"
    };
    private static readonly HashSet<string> NonSensitivePrivileges = new(StringComparer.OrdinalIgnoreCase)
    {
        "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
        "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeIncreaseBasePriorityPrivilege",
        "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLockMemoryPrivilege",
        "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
        "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
        "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTimeZonePrivilege",
        "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege"
    };
    private static readonly Lazy<IReadOnlyDictionary<int, EventAuditMembership[]>> Mappings = new(() => Definitions
        .SelectMany(definition => definition.EventVersions.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => (EventId: int.Parse(pair[..pair.IndexOf(':')], System.Globalization.CultureInfo.InvariantCulture), definition)))
        .GroupBy(pair => pair.EventId)
        .ToDictionary(group => group.Key, group => group.Select(pair => new EventAuditMembership(
            pair.definition.CategoryKey, pair.definition.Category, pair.definition.Key, pair.definition.Name))
            .Distinct().ToArray()));

    internal static EventAuditProjection Project(int? id, string source, string provider, string channel, EventsNativeXml native)
    {
        if (source != "Security" || channel != "Security")
            return Unmapped("Only records normalized as the Windows Security channel are eligible for audit-category navigation.");
        if (provider != "Microsoft-Windows-Security-Auditing")
            return Unmapped("Security-channel record has no supported Security-Auditing provider metadata.");
        if (id == 4673)
            return ProjectPrivilegedServiceCall(native);
        if (id == 4670)
            return ProjectObjectPermissionsChange(native);
        return ProjectStatic(id);
    }

    private static EventAuditProjection ProjectStatic(int? id)
    {
        if (!id.HasValue || !Mappings.Value.TryGetValue(id.Value, out var memberships))
            return Unmapped("No best-effort audit-category mapping is available for this Security Event ID.");
        return new(memberships, "Best-effort grouping of Windows Security events by audit policy. Some events may appear in multiple categories or remain unmapped.");
    }

    private static EventAuditProjection ProjectPrivilegedServiceCall(EventsNativeXml native)
    {
        if (!native.Available || !native.Fields.TryGetValue("PrivilegeList", out var privilegeList))
            return Unmapped("Security Event 4673 has no parseable PrivilegeList for best-effort audit-category navigation.");

        var privileges = privilegeList.Split([' ', '\t', '\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (privileges.Any(SensitivePrivileges.Contains))
            return new([MembershipFor(SensitivePrivilegeUse)], "Security Event 4673 is grouped by its retained PrivilegeList; sensitive privileges take precedence.");
        if (privileges.Any(NonSensitivePrivileges.Contains))
            return new([MembershipFor(NonSensitivePrivilegeUse)], "Security Event 4673 is grouped by its retained PrivilegeList.");
        return Unmapped("Security Event 4673 has no recognized privilege in its retained PrivilegeList for best-effort audit-category navigation.");
    }

    private static EventAuditProjection ProjectObjectPermissionsChange(EventsNativeXml native)
    {
        if (!native.Available || !native.Fields.TryGetValue("ObjectType", out var objectType))
            return ProjectStatic(4670);

        var key = objectType.Trim() switch
        {
            var value when string.Equals(value, "Token", StringComparison.OrdinalIgnoreCase) => AuthorizationPolicyChange,
            var value when string.Equals(value, "File", StringComparison.OrdinalIgnoreCase) => FileSystem,
            var value when string.Equals(value, "Key", StringComparison.OrdinalIgnoreCase) => Registry,
            _ => null
        };
        return key == null
            ? ProjectStatic(4670)
            : new([MembershipFor(key)], "Security Event 4670 is grouped by its retained ObjectType.");
    }

    private static EventAuditMembership MembershipFor(string subcategoryKey)
    {
        var definition = Definitions.Single(definition => definition.Key == subcategoryKey);
        return new(definition.CategoryKey, definition.Category, definition.Key, definition.Name);
    }

    private static EventAuditProjection Unmapped(string description) => new(
        [new(Unknown, "Unknown / Unmapped", Unknown, "Unknown / Unmapped")], description);

    internal static IReadOnlyList<EventAggregate> Folders(EventAggregateDimension dimension, string? category) =>
        dimension == EventAggregateDimension.Auditing
            ? Definitions.DistinctBy(d => d.CategoryKey).Select(d => new EventAggregate(d.CategoryKey, 0, null, Label: d.Category))
                .Append(new(Unknown, 0, null, Label: "Unknown / Unmapped")).ToArray()
            : Definitions.Where(d => d.CategoryKey == category).Select(d => new EventAggregate(d.Key, 0, null, category, d.Name, d.Source))
                .Append(new(Unknown, 0, null, category, "Unknown / Unmapped")).ToArray();
}
