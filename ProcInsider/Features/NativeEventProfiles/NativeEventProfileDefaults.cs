using System.Collections.Immutable;
using ProcInsider.Services.Events;

namespace ProcInsider.Features.NativeEventProfiles;

// Exact layouts verified against native provider metadata and retained sanitized Security fixtures.
internal static class NativeEventProfileDefaults
{
    // Display suggestion only: exact provider/channel remain independent native scope values.
    public static string SuggestName(NativeEventType type)
    {
        var channel = new string(type.Channel.ToLowerInvariant().Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray());
        if (channel.Length > 200) channel = channel[..200];
        return $"winlog_{channel}_{type.EventId}_v{type.Version?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "unknown"}";
    }
    public const string Coverage = "Bundled Security coverage: 4624 v3; 4657 v0; 4659 v0; 4663 v1; 4670 v0; 4673 v0; 4674 v0; 4688 v2; 4689 v0; 4703 v0; 4798 v0; 4907 v0; 5156 v1; 5157 v3; 5158 v0. Bundled Sysmon coverage is Microsoft-Windows-Sysmon/Operational schema 4.81 for IDs 1-26 and 255, plus schema 4.90 for IDs 27-29. PowerShell coverage is Microsoft-Windows-PowerShell/Operational 4103 v1 and 4104 v1. Other versions are not covered.";
    public static ImmutableArray<NativeEventProfile> All { get; } =
    [
        Create(4624, 3, "Logon", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName", "LogonGuid", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort", "ImpersonationLevel", "RestrictedAdminMode", "RemoteCredentialGuard", "TargetOutboundUserName", "TargetOutboundDomainName", "VirtualAccount", "TargetLinkedLogonId", "ElevatedToken"]),
        Create(4688, 2, "Process creation", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "NewProcessId", "NewProcessName", "TokenElevationType", "ProcessId", "CommandLine", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "ParentProcessName", "MandatoryLabel"]),
        Create(4689, 0, "Process termination", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "Status", "ProcessId", "ProcessName"]),
        Create(5156, 1, "WFP allowed connection", ["ProcessID", "Application", "Direction", "SourceAddress", "SourcePort", "DestAddress", "DestPort", "Protocol", "InterfaceIndex", "FilterOrigin", "FilterRTID", "LayerName", "LayerRTID", "RemoteUserID", "RemoteMachineID"]),
        Create(5157, 3, "WFP blocked connection", ["ProcessID", "Application", "Direction", "SourceAddress", "SourcePort", "DestAddress", "DestPort", "Protocol", "InterfaceIndex", "FilterOrigin", "FilterRTID", "LayerName", "LayerRTID", "RemoteUserID", "RemoteMachineID", "OriginalProfile", "CurrentProfile", "IsLoopback", "HasRemoteDynamicKeywordAddress"]),
        Create(5158, 0, "WFP allowed bind", ["ProcessId", "Application", "SourceAddress", "SourcePort", "Protocol", "FilterRTID", "LayerName", "LayerRTID"]),
        Create(4657, 0, "Registry value change", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectName", "ObjectValueName", "HandleId", "OperationType", "OldValueType", "OldValue", "NewValueType", "NewValue", "ProcessId", "ProcessName"], ["ObjectName", "ObjectValueName", "OperationType"]),
        Create(4659, 0, "Delete-intent handle request", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType", "ObjectName", "HandleId", "TransactionId", "AccessList", "AccessMask", "PrivilegeList", "ProcessId"], ["ObjectName", "AccessMask"]),
        Create(4663, 1, "Object access", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType", "ObjectName", "HandleId", "AccessList", "AccessMask", "ProcessId", "ProcessName", "ResourceAttributes"], ["ObjectName", "AccessMask"]),
        Create(4670, 0, "Permissions change", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType", "ObjectName", "HandleId", "OldSd", "NewSd", "ProcessId", "ProcessName"], ["ObjectName", "SubjectDomainName", "SubjectUserName"]),
        Create(4673, 0, "Privileged service call", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "Service", "PrivilegeList", "ProcessId", "ProcessName"], ["Service", "PrivilegeList"]),
        Create(4674, 0, "Privileged object operation", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType", "ObjectName", "HandleId", "AccessMask", "PrivilegeList", "ProcessId", "ProcessName"], ["ObjectName", "PrivilegeList"]),
        Create(4703, 0, "Token privileges adjustment", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "ProcessName", "ProcessId", "EnabledPrivilegeList", "DisabledPrivilegeList"], ["TargetDomainName", "TargetUserName", "EnabledPrivilegeList", "DisabledPrivilegeList"]),
        Create(4798, 0, "Group membership query", ["TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "CallerProcessId", "CallerProcessName"], ["TargetDomainName", "TargetUserName", "CallerProcessName"]),
        Create(4907, 0, "Auditing settings change", ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType", "ObjectName", "HandleId", "OldSd", "NewSd", "ProcessId", "ProcessName"], ["ObjectName", "SubjectDomainName", "SubjectUserName"]),
        ..CreateAdditional(),
    ];

    // These are reviewed against Sysmon schema 4.81 (IDs 1-26/255), Sysmon schema 4.90
    // (IDs 27-29), and the Windows 11 PowerShell provider manifest (4103/4104 v1).
    // Only the exact listed native version receives one of these presentation profiles.
    private static IEnumerable<NativeEventProfile> CreateAdditional()
    {
        const string sp = "Microsoft-Windows-Sysmon", sc = "Microsoft-Windows-Sysmon/Operational";
        yield return Catalog("sysmon", sp, sc, 255, 3, "Error", "UtcTime ID Description", "ID Description");
        yield return Catalog("sysmon", sp, sc, 1, 5, "Process created", "RuleName UtcTime ProcessGuid ProcessId Image FileVersion Description Product Company OriginalFileName CommandLine CurrentDirectory User LogonGuid LogonId TerminalSessionId IntegrityLevel Hashes ParentProcessGuid ParentProcessId ParentImage ParentCommandLine ParentUser", "Image CommandLine Hashes ParentImage ParentCommandLine ProcessGuid ParentProcessGuid");
        yield return Catalog("sysmon", sp, sc, 2, 5, "File creation time changed", "RuleName UtcTime ProcessGuid ProcessId Image TargetFilename CreationUtcTime PreviousCreationUtcTime User", "Image TargetFilename CreationUtcTime PreviousCreationUtcTime ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 3, 5, "Network connection", "RuleName UtcTime ProcessGuid ProcessId Image User Protocol Initiated SourceIsIpv6 SourceIp SourceHostname SourcePort SourcePortName DestinationIsIpv6 DestinationIp DestinationHostname DestinationPort DestinationPortName", "Image ProcessGuid DestinationIp DestinationHostname DestinationPort SourceIp SourcePort Protocol");
        yield return Catalog("sysmon", sp, sc, 4, 3, "Service state changed", "UtcTime State Version SchemaVersion", "State Version SchemaVersion");
        yield return Catalog("sysmon", sp, sc, 5, 3, "Process terminated", "RuleName UtcTime ProcessGuid ProcessId Image User", "Image ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 6, 4, "Driver loaded", "RuleName UtcTime ImageLoaded Hashes Signed Signature SignatureStatus", "ImageLoaded Hashes Signature SignatureStatus");
        yield return Catalog("sysmon", sp, sc, 7, 3, "Image loaded", "RuleName UtcTime ProcessGuid ProcessId Image ImageLoaded FileVersion Description Product Company OriginalFileName Hashes Signed Signature SignatureStatus User", "Image ImageLoaded Hashes Signature SignatureStatus ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 8, 2, "Remote thread created", "RuleName UtcTime SourceProcessGuid SourceProcessId SourceImage TargetProcessGuid TargetProcessId TargetImage NewThreadId StartAddress StartModule StartFunction SourceUser TargetUser", "SourceImage TargetImage SourceProcessGuid TargetProcessGuid StartAddress StartModule StartFunction");
        yield return Catalog("sysmon", sp, sc, 9, 2, "Raw disk access", "RuleName UtcTime ProcessGuid ProcessId Image Device User", "Image Device ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 10, 3, "Process accessed", "RuleName UtcTime SourceProcessGUID SourceProcessId SourceThreadId SourceImage TargetProcessGUID TargetProcessId TargetImage GrantedAccess CallTrace SourceUser TargetUser", "SourceImage TargetImage SourceProcessGUID TargetProcessGUID GrantedAccess CallTrace");
        yield return Catalog("sysmon", sp, sc, 11, 2, "File created", "RuleName UtcTime ProcessGuid ProcessId Image TargetFilename CreationUtcTime User", "Image TargetFilename CreationUtcTime ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 12, 2, "Registry object created or deleted", "RuleName EventType UtcTime ProcessGuid ProcessId Image TargetObject User", "Image TargetObject EventType ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 13, 2, "Registry value set", "RuleName EventType UtcTime ProcessGuid ProcessId Image TargetObject Details User", "Image TargetObject Details EventType ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 14, 2, "Registry object renamed", "RuleName EventType UtcTime ProcessGuid ProcessId Image TargetObject NewName User", "Image TargetObject NewName EventType ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 15, 2, "Named stream created", "RuleName UtcTime ProcessGuid ProcessId Image TargetFilename CreationUtcTime Hash Contents User", "Image TargetFilename Hash Contents ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 16, 3, "Configuration changed", "UtcTime Configuration ConfigurationFileHash", "Configuration ConfigurationFileHash");
        yield return Catalog("sysmon", sp, sc, 17, 1, "Pipe created", "RuleName EventType UtcTime ProcessGuid ProcessId PipeName Image User", "PipeName Image ProcessGuid EventType");
        yield return Catalog("sysmon", sp, sc, 18, 1, "Pipe connected", "RuleName EventType UtcTime ProcessGuid ProcessId PipeName Image User", "PipeName Image ProcessGuid EventType");
        yield return Catalog("sysmon", sp, sc, 19, 3, "WMI filter registered", "RuleName EventType UtcTime Operation User EventNamespace Name Query", "EventNamespace Name Query Operation");
        yield return Catalog("sysmon", sp, sc, 20, 3, "WMI consumer registered", "RuleName EventType UtcTime Operation User Name Type Destination", "Name Type Destination Operation");
        yield return Catalog("sysmon", sp, sc, 21, 3, "WMI consumer bound to filter", "RuleName EventType UtcTime Operation User Consumer Filter", "Consumer Filter Operation");
        yield return Catalog("sysmon", sp, sc, 22, 5, "DNS query", "RuleName UtcTime ProcessGuid ProcessId QueryName QueryStatus QueryResults Image User", "QueryName QueryResults Image ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 23, 5, "File deleted and archived", "RuleName UtcTime ProcessGuid ProcessId User Image TargetFilename Hashes IsExecutable Archived", "Image TargetFilename Hashes ProcessGuid Archived");
        yield return Catalog("sysmon", sp, sc, 24, 5, "Clipboard changed", "RuleName UtcTime ProcessGuid ProcessId Image Session ClientInfo Hashes Archived User", "Image ClientInfo Hashes ProcessGuid Archived");
        yield return Catalog("sysmon", sp, sc, 25, 5, "Process tampering", "RuleName UtcTime ProcessGuid ProcessId Image Type User", "Image Type ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 26, 5, "File deletion detected", "RuleName UtcTime ProcessGuid ProcessId User Image TargetFilename Hashes IsExecutable", "Image TargetFilename Hashes ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 27, 5, "Executable creation blocked", "RuleName UtcTime ProcessGuid ProcessId User Image TargetFilename Hashes", "Image TargetFilename Hashes ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 28, 5, "File shredding blocked", "RuleName UtcTime ProcessGuid ProcessId User Image TargetFilename Hashes IsExecutable", "Image TargetFilename Hashes ProcessGuid");
        yield return Catalog("sysmon", sp, sc, 29, 5, "Executable created", "RuleName UtcTime ProcessGuid ProcessId User Image TargetFilename Hashes", "Image TargetFilename Hashes ProcessGuid");
        const string pp = "Microsoft-Windows-PowerShell", pc = "Microsoft-Windows-PowerShell/Operational";
        yield return Catalog("powershell", pp, pc, 4103, 1, "Module logging", "ContextInfo UserData Payload PayloadName HostName HostVersion HostId HostApplication EngineVersion RunspaceId PipelineId CommandName CommandType CommandPath CommandLine SequenceNumber User ConnectedUser ShellId", "ContextInfo Payload PayloadName CommandName CommandType CommandPath CommandLine HostApplication User");
        yield return Catalog("powershell", pp, pc, 4104, 1, "Script block logging", "MessageNumber MessageTotal ScriptBlockText ScriptBlockId Path", "ScriptBlockText ScriptBlockId Path");
    }
    private static NativeEventProfile Catalog(string family, string provider, string channel, int id, int version, string name, string fields, string high)
    {
        var highNames = high.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var highSet = highNames.ToHashSet(StringComparer.Ordinal);
        var names = fields.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        // Profile order is the analyst-facing priority order; the extractor retains the original XML order separately.
        var ordered = highNames.Where(names.Contains).Concat(names.Where(field => !highSet.Contains(field))).ToArray();
        return new($"{family}-{id}-v{version}", new Guid($"69800000-0000-0000-{id:D4}-{version:D12}"),
            $"winlog_{family}_{id}_v{version} — {name}", new(provider, channel, id, version),
            ordered.Select((field, order) => new NativeEventProfileField("EventData/" + Uri.EscapeDataString(field) + "[1]", field,
                highSet.Contains(field) ? NativeEventFieldPriority.High : NativeEventFieldPriority.Medium, order)));
    }
    private static NativeEventProfile Create(int id, int version, string name, string[] fields, string[]? migratedHigh = null)
    {
        string[] high = migratedHigh ?? id switch
        {
            4624 => ["TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "WorkstationName", "TargetLogonId"],
            4688 => ["NewProcessName", "CommandLine", "ParentProcessName", "NewProcessId", "SubjectUserName"],
            4689 => ["ProcessName", "ProcessId", "Status", "SubjectUserName"],
            _ => ["Application", "Direction", "SourceAddress", "SourcePort", "DestAddress", "DestPort", "Protocol"]
        };
        string[] low = ["FilterRTID", "LayerRTID", "KeyLength", "LogonGuid"];
        var ordered = high.Where(fields.Contains).Concat(fields.Where(f => !high.Contains(f))).ToArray();
        return new($"security-{id}-v{version}", new Guid($"61400000-0000-0000-{id:D4}-{version:D12}"), $"winlog_security_{id}_v{version} — {name}",
            new("Microsoft-Windows-Security-Auditing", "Security", id, version),
            ordered.Select((field, index) => new NativeEventProfileField("EventData/" + Uri.EscapeDataString(field) + "[1]",
                field, high.Contains(field) ? NativeEventFieldPriority.High : low.Contains(field) ? NativeEventFieldPriority.Low : NativeEventFieldPriority.Medium, index)));
    }
}
