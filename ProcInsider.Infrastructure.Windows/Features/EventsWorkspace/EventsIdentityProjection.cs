using System.Globalization;
using System.Security.Principal;
using System.Text.Json;
using ProcInsider.Features.InvestigationWorkspaces;

namespace ProcInsider.Services;

/// <summary>Version 1, read interpretation only. Never resolves accounts against the current machine.</summary>
internal static class EventsIdentityProjection
{
    public const int MaximumXmlCharacters = 1_048_576;
    public static IReadOnlyList<EventIdentity> Project(EventReference reference, int? eventId,
        string provider, string details, EventsNativeXml? parsedNative = null, bool matchedLiveProcess = false)
    {
        var native = parsedNative ?? EventsNativeXml.Parse(eventId, provider, details);
        var fields = native.Fields;
        var status = native.Available ? EventIdentityStatus.Unknown : EventIdentityStatus.Unavailable;
        var computer = native.Computer;
        string Field(string name) => fields.GetValueOrDefault(name, "");
        EventIdentity Principal(EventIdentityRole role, string prefix, string sidName = "", string userName = "")
        {
            var sid = Field(sidName.Length == 0 ? prefix + "UserSid" : sidName);
            var name = Field(userName.Length == 0 ? prefix + "UserName" : userName);
            var domain = Field(prefix + "DomainName");
            var logon = Field(prefix + "LogonId");
            var state = status;
            var scope = EventIdentityScope.Unknown;
            var normalizedSid = "";
            if (state != EventIdentityStatus.Unavailable)
            {
                if (sid is "" or "-" or "S-1-0-0")
                    state = name is "" or "-" ? EventIdentityStatus.Unknown : EventIdentityStatus.MissingSid;
                else
                {
                    try { normalizedSid = new SecurityIdentifier(sid).Value; state = EventIdentityStatus.Sid; }
                    catch (ArgumentException) { state = EventIdentityStatus.InvalidSid; }
                }
                if (normalizedSid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20") scope = EventIdentityScope.WellKnown;
                else if (normalizedSid.StartsWith("S-1-5-80-", StringComparison.Ordinal) || role == EventIdentityRole.Service)
                    scope = EventIdentityScope.Service;
                else if (name is not ("" or "-") || normalizedSid.Length > 0)
                    scope = domain is "" or "." || string.Equals(domain, computer, StringComparison.OrdinalIgnoreCase)
                        ? EventIdentityScope.HostAccount : EventIdentityScope.DomainNamedUnverified;
            }
            // Empty HostId is scoped by source as well. Even well-known SIDs never merge across hosts/captures.
            var key = JsonSerializer.Serialize(new[] { reference.CaseId, reference.EvidenceSessionId,
                reference.CaptureId, reference.HostId, reference.HostId.Length == 0 ? reference.SourceIdentityId : "",
                reference.HostId.Length == 0 ? reference.SourceRunId : "",
                reference.HostId.Length == 0 ? reference.SequenceId.ToString(CultureInfo.InvariantCulture) : "",
                state.ToString(), normalizedSid.Length > 0 ? normalizedSid : sid,
                normalizedSid.Length > 0 ? "" : domain.ToUpperInvariant(), normalizedSid.Length > 0 ? "" : name.ToUpperInvariant() });
            if (reference.HostId.Length == 0) scope = EventIdentityScope.Unknown;
            return new(key, role, state, scope, sid, domain, name, logon, prefix);
        }
        EventIdentity Empty(EventIdentityRole role, EventIdentityStatus state)
        {
            var p = Principal(role, "__absent__");
            return p with { Status = state, Scope = EventIdentityScope.Unknown, Key = p.Key + ":" + state, NativePrefix = "" };
        }
        var subject = Principal(EventIdentityRole.Subject, "Subject");
        var target = Principal(EventIdentityRole.Target, "Target", fields.ContainsKey("TargetSid") ? "TargetSid" : "");
        var knownProvider = provider == "Microsoft-Windows-Security-Auditing";
        // Only documented families map a native subject to an initiating actor.
        var subjectActor = knownProvider && eventId is (4624 or 4625 or 4648 or 4674 or 4703 or 4688 or 4689 or
            4697 or 4698 or 4699 or 4700 or 4701 or 4702 or 4719 or 4720 or 4722 or 4723 or 4724 or 4725 or
            4726 or 4728 or 4729 or 4732 or 4733 or 4738 or 4740 or 4756 or 4757 or 4767 or 4781 or
            4656 or 4657 or 4660 or 4663 or 4670 or 5140 or 5145);
        var targetLogon = knownProvider && eventId is (4624 or 4625 or 4634 or 4647);
        var actor = knownProvider && eventId == 4647 ? target with { Role = EventIdentityRole.Actor } :
            knownProvider && eventId is (5447 or 5449) ? Principal(EventIdentityRole.Actor, "", "UserSid", "UserName") :
            subjectActor ? subject with { Role = EventIdentityRole.Actor } :
            Empty(EventIdentityRole.Actor, status == EventIdentityStatus.Unavailable ? status : EventIdentityStatus.Unknown);
        if (matchedLiveProcess && knownProvider && eventId is 5156 or 5157 && native.Available &&
            actor.Status == EventIdentityStatus.Unknown && HasRecordedNetworkServiceUser(details))
        {
            const string sid = "S-1-5-20";
            var key = JsonSerializer.Serialize(new[] { reference.CaseId, reference.EvidenceSessionId,
                reference.CaptureId, reference.HostId, reference.HostId.Length == 0 ? reference.SourceIdentityId : "",
                reference.HostId.Length == 0 ? reference.SourceRunId : "",
                reference.HostId.Length == 0 ? reference.SequenceId.ToString(CultureInfo.InvariantCulture) : "",
                EventIdentityStatus.Sid.ToString(), sid, "", "" });
            actor = new EventIdentity(key, EventIdentityRole.Actor, EventIdentityStatus.Sid,
                reference.HostId.Length == 0 ? EventIdentityScope.Unknown : EventIdentityScope.WellKnown,
                sid, "NT AUTHORITY", "NETWORK SERVICE", "", "Derived: recorded process user");
        }
        var account = target with { Role = EventIdentityRole.Account };
        var service = knownProvider && eventId == 4697
            ? Principal(EventIdentityRole.Service, "Service", "ServiceSid", "ServiceAccount")
            : Empty(EventIdentityRole.Service, status == EventIdentityStatus.Unavailable ? status : EventIdentityStatus.NotApplicable);
        var logon = targetLogon ? target with { Role = EventIdentityRole.Logon } :
            knownProvider && eventId is (4648 or 4672) ? subject with { Role = EventIdentityRole.Logon } :
            Empty(EventIdentityRole.Logon, status == EventIdentityStatus.Unavailable ? status : EventIdentityStatus.NotApplicable);
        return Array.AsReadOnly(new[] { subject, actor, target, account, service, logon });
    }

    public static IReadOnlyList<EventIdentity> ProjectSysmon(EventReference reference, EventsNativeXml native,
        bool nativeChannelMatches = true)
    {
        var available = native.Available && nativeChannelMatches;
        string Field(string name) => available ? native.Fields.GetValueOrDefault(name, "").Trim() : "";
        var sourceUser = Field("SourceUser");
        var user = sourceUser is not ("" or "-") ? sourceUser : Field("User");
        var actor = SysmonPrincipal(reference, EventIdentityRole.Actor, user, native.Computer,
            !available ? "Sysmon native payload unavailable" :
            sourceUser is not ("" or "-") ? "Sysmon SourceUser" : "Sysmon User (execution context)", available);
        var targetUser = Field("TargetUser");
        return targetUser is "" or "-" ? [actor] :
            [actor, SysmonPrincipal(reference, EventIdentityRole.Target, targetUser, native.Computer,
                "Sysmon TargetUser", available)];
    }

    private static EventIdentity SysmonPrincipal(EventReference reference, EventIdentityRole role,
        string recordedUser, string computer, string origin, bool nativeAvailable)
    {
        var value = recordedUser.Trim();
        var separator = value.IndexOf('\\');
        var domain = separator > 0 ? value[..separator] : "";
        var name = separator > 0 && separator < value.Length - 1 ? value[(separator + 1)..] :
            value is "" or "-" ? "" : value;
        var sid = (domain.ToUpperInvariant(), name.ToUpperInvariant()) switch
        {
            ("NT AUTHORITY", "SYSTEM") => "S-1-5-18",
            ("NT AUTHORITY", "LOCAL SERVICE") => "S-1-5-19",
            ("NT AUTHORITY", "NETWORK SERVICE") => "S-1-5-20",
            _ => ""
        };
        var status = !nativeAvailable ? EventIdentityStatus.Unavailable : sid.Length > 0 ? EventIdentityStatus.Sid :
            name.Length > 0 ? EventIdentityStatus.MissingSid : EventIdentityStatus.Unknown;
        var scope = sid.Length > 0 && reference.HostId.Length > 0 ? EventIdentityScope.WellKnown :
            name.Length == 0 || reference.HostId.Length == 0 ? EventIdentityScope.Unknown :
            domain.Length == 0 || domain.Equals(computer, StringComparison.OrdinalIgnoreCase)
                ? EventIdentityScope.HostAccount : EventIdentityScope.DomainNamedUnverified;
        var key = JsonSerializer.Serialize(new[] { reference.CaseId, reference.EvidenceSessionId,
            reference.CaptureId, reference.HostId, reference.HostId.Length == 0 ? reference.SourceIdentityId : "",
            reference.HostId.Length == 0 ? reference.SourceRunId : "",
            reference.HostId.Length == 0 ? reference.SequenceId.ToString(CultureInfo.InvariantCulture) : "",
            status.ToString(), sid, sid.Length > 0 ? "" : domain.ToUpperInvariant(),
            sid.Length > 0 ? "" : name.ToUpperInvariant() });
        return new(key, role, status, scope, sid, domain, name, "", origin);
    }

    private static bool HasRecordedNetworkServiceUser(string details)
    {
        var boundary = details.LastIndexOf("Event XML:", StringComparison.Ordinal);
        if (boundary < 0) return false;
        var header = details.AsSpan(0, Math.Min(boundary, 4096));
        var rendered = header.IndexOf("Rendered Message:", StringComparison.Ordinal);
        if (rendered >= 0) header = header[..rendered];
        var processLine = false;
        var userLine = false;
        foreach (var line in header.EnumerateLines())
        {
            var value = line.Trim();
            if (value.StartsWith("Process:", StringComparison.OrdinalIgnoreCase)) processLine = true;
            if (value.StartsWith("User:", StringComparison.OrdinalIgnoreCase) &&
                value[5..].Trim().Equals("NT AUTHORITY\\NETWORK SERVICE", StringComparison.OrdinalIgnoreCase))
                userLine = true;
        }
        return processLine && userLine;
    }
}
