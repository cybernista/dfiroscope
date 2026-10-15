using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using ProcInsider.Services.Events;

namespace ProcInsider.Features.NetworkWorkspace;

/// <summary>Identity of one assessed evidence binding. Snapshot/request generations are deliberately not persistence keys.</summary>
public sealed record NetworkAnalysisBinding(
    string CaseId,
    string EvidenceSessionId,
    string CaptureId,
    string PackageContextId,
    string SourceDatabasePath)
{
    public string PersistentIdentity => Hash("evidence", CaseId, EvidenceSessionId, CaptureId, PackageContextId, "ProcessEvents");

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(EvidenceSessionId) || string.IsNullOrWhiteSpace(PackageContextId) ||
            string.IsNullOrWhiteSpace(SourceDatabasePath))
            throw new ArgumentException("Network analysis requires assessed evidence-session, package, and source identities.");
    }

    public static string Hash(params string?[] values)
    {
        var text = string.Join("|", values.Select(value => (value ?? string.Empty).Length.ToString(CultureInfo.InvariantCulture) + ":" + (value ?? string.Empty)));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    }
}

public enum NetworkObservationKind { CapturedSysmonNetworkConnection, CapturedDnsQuery, CapturedDroppedPacket, CapturedBlockedListen, CapturedBlockedBind, CapturedAllowedListen, CapturedAllowedBind }
public enum NetworkDirection { Unknown, Outbound, Inbound }
public enum NetworkProcessingState { Ready, RebuildRequired, UnsupportedSchema, NewerSchema, Failed }
public enum NetworkSourceOutcome { Normalized, Malformed }
public enum NetworkSort { Provider, ObservationKind, QueryName, QueryStatus, QueryResults, CapturedUtc, Process, Protocol, Direction, SourceEndpoint, DestinationEndpoint, ProcessId, SourcePort, DestinationPort, LocalEndpoint }
public enum NetworkColumn { Provider, ObservationKind, QueryName, QueryStatus, QueryResults, CapturedUtc, Process, ProcessId, Protocol, Direction, SourceAddress, SourcePort, DestinationAddress, DestinationPort, LocalEndpoint }
public sealed record NetworkColumnFilter(NetworkColumn Column, ProcInsider.Services.ColumnFilterCriteria Criteria);
public sealed record NetworkProcessScope(string CaseId, string EvidenceSessionId, string CaptureId, string HostId, string ExecutionRootId, string ProcessEntityId);
public sealed record NetworkProcessActivity(NetworkProcessScope Scope, string ProcessName, long Observations);
public sealed record NetworkValueCount(string? Value, long Count);
public enum NetworkDimension { Provider, Process, DestinationPort, Protocol, Direction, AddressScope, Conversation, Time }
public sealed record NetworkFacet(NetworkDimension Dimension, string? Key = null, long? FromUtcTicks = null, long? ToUtcTicks = null);
public sealed record NetworkFacetCount(NetworkFacet Facet, string Title, long Observations);

/// <summary>UTC intervals chosen over the complete recorded dataset, independent of analyst filters.</summary>
public sealed record NetworkTimeBuckets(long OriginTicks, long SpanTicks, int Count)
{
    public static NetworkTimeBuckets Choose(long firstTicks, long lastTicks)
    {
        if (firstTicks < 0 || lastTicks < firstTicks || lastTicks > DateTime.MaxValue.Ticks) throw new ArgumentOutOfRangeException(nameof(firstTicks));
        long[] minutes = [1, 5, 15, 30, 60, 360, 1440];
        foreach (var minute in minutes)
        {
            var span = minute * TimeSpan.TicksPerMinute;
            var origin = firstTicks / span * span;
            var count = (lastTicks - origin) / span + 1;
            if (count <= 12) return new(origin, span, (int)count);
        }
        // Beyond twelve days retain the cap with whole-day spans anchored at the first UTC day.
        var start = firstTicks / TimeSpan.TicksPerDay * TimeSpan.TicksPerDay;
        var days = (lastTicks - start) / TimeSpan.TicksPerDay + 1;
        var step = ((days + 11) / 12) * TimeSpan.TicksPerDay;
        return new(start, step, (int)((lastTicks - start) / step + 1));
    }
}

public static class NetworkAddressScopes
{
    public static string Classify(string? address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return "Unknown";
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return "Loopback";
        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            if (bytes[0] == 0 || bytes.All(b => b == 255)) return "Unspecified / broadcast";
            if (bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 || bytes[0] == 192 && bytes[1] == 168) return "Private";
            if (bytes[0] == 169 && bytes[1] == 254) return "Link-local";
            if (bytes[0] is >= 224 and <= 239) return "Multicast";
            if (bytes[0] == 100 && bytes[1] is >= 64 and <= 127) return "Shared address space";
            if (bytes[0] >= 240 || bytes[0] == 192 && bytes[1] == 0 && bytes[2] is 0 or 2 || bytes[0] == 198 && bytes[1] is 18 or 19 || bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100 || bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) return "Other special-use";
            return "Other unicast";
        }
        if (ip.Equals(IPAddress.IPv6Any)) return "Unspecified / broadcast";
        if (ip.IsIPv6Multicast) return "Multicast";
        if (ip.IsIPv6LinkLocal) return "Link-local";
        if ((bytes[0] & 0xfe) == 0xfc) return "Private";
        if (ip.IsIPv6SiteLocal || bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8 || (bytes[0] & 0xe0) != 0x20) return "Other special-use";
        return "Other unicast";
    }
}

/// <summary>Transient Network view selection, never persisted as evidence.</summary>
public sealed record NetworkGreenSelector(NetworkProcessScope? Scope = null, bool ResolvedProcessesOnly = false, bool IsExcluded = false, NetworkFacet? Facet = null)
{
    public NetworkDimension? Dimension => Facet?.Dimension ?? (Scope != null || ResolvedProcessesOnly ? NetworkDimension.Process : null);
    public bool Covers(NetworkGreenSelector other) => Facet != null ? other.Facet != null && Facet.Dimension == other.Facet.Dimension && (Facet.Key == null || Facet == other.Facet) :
        Scope != null ? Scope == other.Scope : ResolvedProcessesOnly ? other.Dimension == NetworkDimension.Process : true;
    public static bool Includes(IEnumerable<NetworkGreenSelector> selectors, NetworkGreenSelector value) =>
        selectors.Any(s => !s.IsExcluded && s.Covers(value)) && !selectors.Any(s => s.IsExcluded && s.Covers(value));
}

public static class NetworkAddressPresentation
{
    public static string Address(string? address, uint? scope = null)
    {
        if (string.IsNullOrWhiteSpace(address)) return string.Empty;
        if (!IPAddress.TryParse(address, out var ip)) return address;
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) return ip.ToString();
        var zone = scope ?? (uint)ip.ScopeId;
        ip.ScopeId = 0;
        return ip.ToString() + (zone == 0 ? "" : "%" + zone.ToString(CultureInfo.InvariantCulture));
    }
    public static string Endpoint(string? address, int? port, uint? scope = null)
    {
        var display = Address(address, scope);
        if (display.Length == 0 || port == null) return display;
        return IPAddress.TryParse(address, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{display}]:{port}" : $"{display}:{port}";
    }
}

public sealed record NetworkEndpoint(string? Address, int? Port)
{
    [System.Text.Json.Serialization.JsonIgnore] public string AddressPresentation => NetworkAddressPresentation.Address(Address);
    [System.Text.Json.Serialization.JsonIgnore] public string Presentation => NetworkAddressPresentation.Endpoint(Address, Port);
    public string Display => string.IsNullOrWhiteSpace(Address) ? string.Empty : Port is null ? Address :
        IPAddress.TryParse(Address, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{Address}]:{Port}" : $"{Address}:{Port}";
}

/// <summary>Exact stored-event identity. Sequence is scoped; it is never a capture commit watermark.</summary>
public sealed record NetworkSourceReference(
    string CaseId, string EvidenceSessionId, string CaptureId, string SourceIdentityId, string HostId,
    string ExecutionRootId, long SequenceId, string SourceRunId, string IngestionJobId, string RawRecordIdText)
{
    public string SourceTable => "ProcessEvents";
    public string PersistentIdentity => NetworkAnalysisBinding.Hash("source", CaseId, EvidenceSessionId, CaptureId,
        SourceIdentityId, HostId, ExecutionRootId, SourceTable, SequenceId.ToString(CultureInfo.InvariantCulture));
}

public sealed record NetworkSourceEvent(
    NetworkSourceReference Reference, DateTime TimestampUtc, string Source, int? EventId,
    string RawProvider, string RawLogName, string Details, string ProcessEntityId, string ProcessGuid,
    int ProcessId, string ProcessName, string ProcessImage, string UserName, int? ResolvedProcessId = null);

public sealed record NetworkObservation(
    NetworkSourceReference Source, DateTime CapturedUtc, string ProcessEntityId, string ProcessGuid,
    int? ProcessId, string ProcessName, string ProcessImage, string UserName, string? Protocol,
    NetworkEndpoint SourceEndpoint, NetworkEndpoint DestinationEndpoint, NetworkDirection Direction,
    NetworkEndpoint? LocalEndpoint, NetworkEndpoint? RemoteEndpoint, string Diagnostic,
    string Provider = "Microsoft-Windows-Sysmon", string Channel = "Microsoft-Windows-Sysmon/Operational", int NativeEventId = 3,
    NetworkObservationKind Kind = NetworkObservationKind.CapturedSysmonNetworkConnection, string? QueryName = null, string? QueryStatus = null, string? QueryResults = null,
    string? NativeProcessId = null, string? NativeDirection = null, string? FilterRunTimeId = null, string? LayerName = null, string? LayerRunTimeId = null,
    IReadOnlyDictionary<string,string>? NativeFields = null)
{
    public string ObservationKind => Kind.ToString();
    public string ObservationDisplay => DisplayKind(Kind);
    public static string DisplayKind(NetworkObservationKind kind) => kind switch
    {
        NetworkObservationKind.CapturedSysmonNetworkConnection => "Network connection observation",
        NetworkObservationKind.CapturedDnsQuery => "DNS query",
        NetworkObservationKind.CapturedDroppedPacket => "Packet dropped",
        NetworkObservationKind.CapturedBlockedListen => "Listening blocked",
        NetworkObservationKind.CapturedBlockedBind => "Local bind blocked",
        NetworkObservationKind.CapturedAllowedListen => "Listening permitted",
        NetworkObservationKind.CapturedAllowedBind => "Local bind permitted",
        _ => "Unknown observation"
    };
}

public sealed record NetworkNormalizationResult(NetworkSourceOutcome Outcome, NetworkObservation? Observation, string Diagnostic);
public sealed record NetworkSourceDiagnostic(NetworkSourceReference Source, NetworkSourceOutcome Outcome, string Diagnostic);
public sealed record NetworkAnalysisStatus(NetworkProcessingState State, string Detail, long NormalizedRecords,
    long MalformedRecords, string ProcessorVersion);
public sealed record NetworkAnalysisQuery(string? ProcessEntityId = null, string? Text = null,
    NetworkSort Sort = NetworkSort.CapturedUtc, bool Descending = true, long Offset = 0, int PageSize = 128,
    NetworkProcessScope? ProcessScope = null, IReadOnlyList<NetworkColumnFilter>? Columns = null,
    bool ResolvedProcessesOnly = false, IReadOnlyList<NetworkGreenSelector>? GreenSelectors = null, NetworkFacet? FacetScope = null);
public sealed record NetworkAnalysisPage(IReadOnlyList<NetworkObservation> Records, long MatchingRecords,
    NetworkAnalysisStatus Status);

/// <summary>Pure supported native Network interpretation. It does not read storage, attach processes, or infer connectivity.</summary>
public static class SysmonNetworkNormalizer
{
    public const string ProcessorVersion = "recorded-network-v4";
    public const string SysmonProvider = "Microsoft-Windows-Sysmon";

    public static NetworkNormalizationResult Normalize(NetworkSourceEvent source, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        cancellationToken.ThrowIfCancellationRequested();
        if (source.EventId != 3 || !string.Equals(source.Source, "Sysmon", StringComparison.OrdinalIgnoreCase))
            return NormalizeComplement(source, cancellationToken);
        if (!string.Equals(source.Source, "Sysmon", StringComparison.OrdinalIgnoreCase) || source.EventId != 3)
            return new(NetworkSourceOutcome.Malformed, null, "The stored event is not a Sysmon Event ID 3 record.");
        if ((!string.IsNullOrWhiteSpace(source.RawLogName) && source.RawLogName != "Microsoft-Windows-Sysmon/Operational") || !string.IsNullOrWhiteSpace(source.RawProvider) &&
            !string.Equals(source.RawProvider, SysmonProvider, StringComparison.OrdinalIgnoreCase))
            return new(NetworkSourceOutcome.Malformed, null, "The captured provider conflicts with Sysmon Event ID 3.");

        var extraction = NativeEventFieldExtractor.Extract(source.Details, 3, SysmonProvider,
            "Microsoft-Windows-Sysmon/Operational", cancellationToken);
        if (extraction.Status is not (EventFieldExtractionStatus.Available or EventFieldExtractionStatus.Partial))
            return new(NetworkSourceOutcome.Malformed, null, extraction.Diagnostic);

        foreach (var name in new[] { "SourceIp", "SourcePort", "DestinationIp", "DestinationPort", "Initiated", "Protocol", "ProcessGuid", "ProcessId", "Image", "User" })
        {
            var prefix = "EventData/" + name + "[";
            if (extraction.Fields.Where(field => field.Path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .Select(field => field.Value).Distinct(StringComparer.Ordinal).Skip(1).Any())
                return new(NetworkSourceOutcome.Malformed, null, "Conflicting repeated " + name + " values prevent reliable Network interpretation.");
        }

        var fields = extraction.Fields.GroupBy(field => field.Path, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().Value, StringComparer.OrdinalIgnoreCase);
        string? Value(string name) => fields.TryGetValue("EventData/" + name + "[1]", out var value) ? value : null;
        var sourceEndpoint = new NetworkEndpoint(Value("SourceIp"), Port(Value("SourcePort")));
        var destinationEndpoint = new NetworkEndpoint(Value("DestinationIp"), Port(Value("DestinationPort")));
        var initiated = Value("Initiated");
        var direction = bool.TryParse(initiated, out var isInitiated)
            ? isInitiated ? NetworkDirection.Outbound : NetworkDirection.Inbound
            : NetworkDirection.Unknown;
        var diagnostics = new List<string>();
        if (direction == NetworkDirection.Unknown) diagnostics.Add("Initiated is missing or invalid; local and remote endpoints are undetermined.");
        foreach (var name in new[] { "SourceIp", "DestinationIp", "Protocol" })
            if (string.IsNullOrWhiteSpace(Value(name))) diagnostics.Add(name + " is unavailable.");
        foreach (var name in new[] { "SourceIp", "DestinationIp" })
            if (!string.IsNullOrWhiteSpace(Value(name)) && !IPAddress.TryParse(Value(name), out _)) diagnostics.Add(name + " is invalid; the recorded value is retained.");
        foreach (var name in new[] { "SourcePort", "DestinationPort" })
            if (Port(Value(name)) is null) diagnostics.Add(name + " is missing or invalid.");
        if (!string.IsNullOrWhiteSpace(extraction.Diagnostic)) diagnostics.Add(extraction.Diagnostic);
        var diagnostic = string.Join(" ", diagnostics);
        var observation = new NetworkObservation(
            source.Reference, source.TimestampUtc, source.ProcessEntityId, First(Value("ProcessGuid"), source.ProcessGuid),
            Int(Value("ProcessId")) ?? source.ProcessId, source.ProcessName, First(Value("Image"), source.ProcessImage),
            First(Value("User"), source.UserName), Value("Protocol"), sourceEndpoint, destinationEndpoint, direction,
            direction == NetworkDirection.Outbound ? sourceEndpoint : direction == NetworkDirection.Inbound ? destinationEndpoint : null,
            direction == NetworkDirection.Outbound ? destinationEndpoint : direction == NetworkDirection.Inbound ? sourceEndpoint : null,
            diagnostic);
        return new(NetworkSourceOutcome.Normalized, observation, diagnostic);
    }

    private static NetworkNormalizationResult NormalizeComplement(NetworkSourceEvent source, CancellationToken token)
    {
        var dns = string.Equals(source.Source, "Sysmon", StringComparison.OrdinalIgnoreCase) && source.EventId == 22;
        var wfp = string.Equals(source.Source, "Security", StringComparison.OrdinalIgnoreCase) && source.EventId is 5152 or 5153 or 5154 or 5155 or 5158 or 5159;
        if (!dns && !wfp) return new(NetworkSourceOutcome.Malformed, null, "Unsupported recorded Network source identity.");
        var provider = dns ? SysmonProvider : "Microsoft-Windows-Security-Auditing";
        var channel = dns ? "Microsoft-Windows-Sysmon/Operational" : "Security";
        if ((!string.IsNullOrEmpty(source.RawProvider) && source.RawProvider != provider) || (!string.IsNullOrEmpty(source.RawLogName) && source.RawLogName != channel))
            return new(NetworkSourceOutcome.Malformed, null, "Recorded provider/channel conflicts with the supported native identity.");
        var extraction = NativeEventFieldExtractor.Extract(source.Details, source.EventId, provider, channel, token);
        if (extraction.Status is not (EventFieldExtractionStatus.Available or EventFieldExtractionStatus.Partial)) return new(NetworkSourceOutcome.Malformed, null, extraction.Diagnostic);
        var groups = extraction.Fields.Where(f => f.Path.StartsWith("EventData/", StringComparison.Ordinal)).GroupBy(f => f.Path[..f.Path.LastIndexOf('[')], StringComparer.OrdinalIgnoreCase).ToArray();
        if (groups.Any(g => g.Select(f => f.Value).Distinct(StringComparer.Ordinal).Skip(1).Any())) return new(NetworkSourceOutcome.Malformed, null, "Conflicting repeated native fields prevent reliable interpretation.");
        var fields = groups.ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
        string? V(string name) => fields.GetValueOrDefault("EventData/" + name);
        var packet = source.EventId is 5152 or 5153;
        var src = packet ? new NetworkEndpoint(V("SourceAddress"), Port(V("SourcePort"))) : new NetworkEndpoint(null, null);
        var dst = packet ? new NetworkEndpoint(V("DestAddress"), Port(V("DestPort"))) : new NetworkEndpoint(null, null);
        var local = wfp && !packet ? new NetworkEndpoint(V("SourceAddress"), Port(V("SourcePort"))) : null;
        var direction = packet ? V("Direction") switch { "%%14592" => NetworkDirection.Inbound, "%%14593" => NetworkDirection.Outbound, _ => NetworkDirection.Unknown } : NetworkDirection.Unknown;
        var remote = direction == NetworkDirection.Outbound ? dst : direction == NetworkDirection.Inbound ? src : null;
        if (packet) local = direction == NetworkDirection.Outbound ? src : direction == NetworkDirection.Inbound ? dst : null;
        var pid = V(dns ? "ProcessId" : "ProcessID");
        int? NativePid()
        {
            var number = pid?.StartsWith("0x", StringComparison.OrdinalIgnoreCase) == true
                ? int.TryParse(pid[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsed) ? parsed : (int?)null
                : Int(pid);
            return number >= 0 ? number : null;
        }
        var kind = dns ? NetworkObservationKind.CapturedDnsQuery : packet ? NetworkObservationKind.CapturedDroppedPacket : source.EventId switch
        {
            5154 => NetworkObservationKind.CapturedAllowedListen,
            5155 => NetworkObservationKind.CapturedBlockedListen,
            5158 => NetworkObservationKind.CapturedAllowedBind,
            _ => NetworkObservationKind.CapturedBlockedBind
        };
        var nativePid = NativePid();
        var entity = source.ProcessEntityId;
        var diagnostic = extraction.Diagnostic;
        if (!nativePid.HasValue) diagnostic += string.IsNullOrWhiteSpace(pid) ? " Native PID is unavailable." : " Native PID is invalid; the exact value is retained.";
        if (packet && direction != NetworkDirection.Unknown) diagnostic += " Local/remote endpoints follow the recorded packet direction.";
        return new(NetworkSourceOutcome.Normalized, new(source.Reference, source.TimestampUtc, entity, dns ? First(V("ProcessGuid"), source.ProcessGuid) : "",
            nativePid, source.ProcessName, First(V(dns ? "Image" : "Application"), source.ProcessImage), dns ? First(V("User"), source.UserName) : source.UserName,
            dns ? null : V("Protocol"), src, dst, direction, local, remote,
            diagnostic, provider, channel, source.EventId!.Value, kind, V("QueryName"), V("QueryStatus"), V("QueryResults"), pid, V("Direction"), V("FilterRTID"), V("LayerName"), V("LayerRTID"), fields.ToDictionary(p => p.Key[10..], p => p.Value)), diagnostic);
    }

    private static int? Port(string? value) => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port is >= 0 and <= 65535 ? port : null;
    private static int? Int(string? value) => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) ? number : null;
    private static string First(string? preferred, string fallback) => string.IsNullOrWhiteSpace(preferred) ? fallback : preferred;
}
