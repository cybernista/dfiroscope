using System.Globalization;
using System.Text.Json;
using ProcInsider.Features.InvestigationWorkspaces;

namespace ProcInsider.Services;

internal sealed record EventSessionProjection(string Key, string Label, string Description);

/// <summary>Native role attribution only; no process lookup and no equivalence across source runs.</summary>
internal static class EventsSessionProjection
{
    internal static EventSessionProjection Project(EventReference reference, string executionRoot,
        EventIdentity identity, int? eventId, string provider, EventsNativeXml native, bool exactLiveRun)
    {
        EventSessionProjection Unknown(string reason) => new("Unknown:" + reason, "Unknown / " + reason,
            $"{identity.Role}; native logon value: {identity.LogonId}; {reason}. Native evidence remains available in Event / Fields.");
        if (!native.Available || identity.Status == EventIdentityStatus.Unavailable) return Unknown("unavailable native session");
        if (provider != "Microsoft-Windows-Security-Auditing" || identity.NativePrefix.Length == 0 && identity.LogonId.Length == 0)
            return Unknown("no attributed session");
        string kind, value;
        var logon = identity.LogonId;
        if (logon.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            ulong.TryParse(logon.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var luid) && luid != 0)
        { kind = "Windows Logon ID"; value = "0x" + luid.ToString("x", CultureInfo.InvariantCulture); }
        // Only these documented native Target sessions are supported. System/Execution ProcessID is unrelated.
        else if (logon is "" or "-" or "0x0" && eventId is 4800 or 4801 && native.Version == 0 &&
            identity.NativePrefix == "Target" && native.Fields.TryGetValue("SessionId", out var terminal) &&
            uint.TryParse(terminal, NumberStyles.None, CultureInfo.InvariantCulture, out var terminalId))
        { kind = "Terminal SessionId"; value = terminalId.ToString(CultureInfo.InvariantCulture); }
        else return Unknown(logon is "" or "-" or "0x0" ? "no attributed session" : "invalid logon ID");
        // ExecutionRootId currently names an evidence execution context, not a proven boot identifier.
        // A matched production live-capture run cannot survive a reboot. Imports/legacy gaps do not prove this.
        // Terminal IDs may be reused even within one boot; without a LogonId they remain record-local.
        var knownContext = kind == "Windows Logon ID" && exactLiveRun && reference.HostId.Length > 0 && reference.CaptureId.Length > 0 &&
            executionRoot.Length > 0 && native.Computer.Length > 0;
        // The query/selector always pairs this key with its exact parent IdentityKey.
        var key = JsonSerializer.Serialize(new[] { identity.Role.ToString(), reference.CaseId,
            reference.EvidenceSessionId, reference.CaptureId, reference.HostId, executionRoot,
            reference.SourceIdentityId, reference.SourceRunId, native.Computer.ToUpperInvariant(), kind, value,
            knownContext ? "" : reference.SequenceId.ToString(CultureInfo.InvariantCulture) });
        return new(key, $"{kind}: {value}" + (knownContext ? "" : $" · Unknown context · event {reference.SequenceId}"),
            $"{identity.Role}; {native.Computer}; capture {reference.CaptureId}; execution {executionRoot}; source run {reference.SourceRunId}. " +
            (knownContext ? "Grouped only within this recorded live acquisition run; no equivalence to another run or to a process SessionId is inferred." :
                "Session context unavailable: this native ID remains a record-local observation; no cross-event or cross-boot session equivalence is asserted."));
    }
}
