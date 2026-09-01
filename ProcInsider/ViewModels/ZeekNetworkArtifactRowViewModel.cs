using System.Collections.Generic;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public sealed class ZeekNetworkArtifactRowViewModel : ViewModelBase
{
    private readonly ZeekNetworkRecord _record;

    public ZeekNetworkArtifactRowViewModel(ZeekNetworkRecord record)
    {
        _record = record;
    }

    public string ArtifactId => _record.ArtifactId;
    public string CaptureId => _record.CaptureId;
    public string Status => _record.Status.ToString();
    public DateTime TimestampUtc => _record.TimestampUtc;
    public string TimestampDisplay => _record.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string LogType => _record.LogType;
    public string ZeekUid => _record.ZeekUid;
    public string SourceIp => _record.SourceIp;
    public int SourcePort => _record.SourcePort;
    public string DestinationIp => _record.DestinationIp;
    public int DestinationPort => _record.DestinationPort;
    public string SourceEndpoint => FormatEndpoint(_record.SourceIp, _record.SourcePort);
    public string DestinationEndpoint => FormatEndpoint(_record.DestinationIp, _record.DestinationPort);
    public string Protocol => _record.Protocol;
    public string Service => _record.Service;
    public string DnsQuery => _record.DnsQuery;
    public string HttpHost => _record.HttpHost;
    public string HttpUri => _record.HttpUri;
    public double DurationSeconds => _record.DurationSeconds;
    public string DurationDisplay => DurationSeconds > 0 ? TimeSpan.FromSeconds(DurationSeconds).ToString(@"hh\:mm\:ss\.fff") : string.Empty;
    public long OrigBytes => _record.OrigBytes;
    public long RespBytes => _record.RespBytes;
    public string OrigBytesDisplay => FormatBytes(_record.OrigBytes);
    public string RespBytesDisplay => FormatBytes(_record.RespBytes);
    public long OrigPackets => _record.OrigPackets;
    public long RespPackets => _record.RespPackets;
    public long OrigIpBytes => _record.OrigIpBytes;
    public long RespIpBytes => _record.RespIpBytes;
    public string ConnectionState => _record.ConnectionState;
    public string History => _record.History;
    public string ServerName => _record.ServerName;
    public string ClientProtocol => _record.ClientProtocol;
    public string TlsVersion => _record.TlsVersion;
    public string TlsCipher => _record.TlsCipher;
    public string TlsEstablished => _record.TlsEstablished ? "Yes" : string.Empty;
    public string WeirdName => _record.WeirdName;
    public string WeirdAdditional => _record.WeirdAdditional;
    public string Summary => _record.Summary;
    public string ProcessKey => _record.ProcessKey;
    public int ProcessId => _record.ProcessId;
    public string ProcessName => _record.ProcessName;
    public bool HasProcessCorrelation => !string.IsNullOrWhiteSpace(_record.ProcessKey);
    public string CorrelationDisplay => string.IsNullOrWhiteSpace(_record.CorrelationMethod)
        ? "Uncorrelated"
        : $"{_record.CorrelationState}: {_record.CorrelationMethod} ({_record.CorrelationConfidence:P0})";
    public string RawLogPath => _record.RawLogPath;
    public long RawLineNumber => _record.RawLineNumber;
    public string ErrorMessage => _record.ErrorMessage;
    public bool HasFlowTuple =>
        !string.IsNullOrWhiteSpace(SourceIp) &&
        SourcePort > 0 &&
        !string.IsNullOrWhiteSpace(DestinationIp) &&
        DestinationPort > 0;
    public string WiresharkFilter => BuildWiresharkFilter(includeTimeWindow: true);

    public TelemetrySearchResult ToNavigationResult()
    {
        return new TelemetrySearchResult
        {
            Kind = "Zeek",
            ProcessKey = _record.ProcessKey,
            ProcessId = _record.ProcessId,
            ProcessName = _record.ProcessName,
            TimestampUtc = _record.TimestampUtc,
            Source = _record.Source,
            Title = _record.Summary,
            Subtitle = CorrelationDisplay
        };
    }

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.ZeekNetworkArtifact,
            TargetKind = "ZeekNetworkArtifact",
            TargetTable = "ZeekNetworkArtifacts",
            TargetId = ArtifactId,
            ArtifactId = ArtifactId,
            CaseId = _record.CaseId,
            EvidenceSessionId = _record.EvidenceSessionId,
            CaptureId = _record.CaptureId,
            SourceIdentityId = _record.SourceIdentityId,
            HostId = _record.HostId,
            ExecutionRootId = _record.ExecutionRootId,
            SourceRunId = _record.SourceRunId,
            IngestionJobId = _record.IngestionJobId,
            ProcessKey = ProcessKey,
            ProcessId = ProcessId,
            ProcessName = ProcessName,
            DisplayPath = RawLogPath,
            Header = $"Zeek {LogType} | {Status}",
            Subtitle = Summary,
            EmptyStateMessage = "Select a Zeek artifact to inspect it here.",
            RawText = BuildRawText(),
            Properties = new List<PropertyItemViewModel>
            {
                new("Identity", "Artifact ID", ArtifactId),
                new("Identity", "Capture ID", string.IsNullOrWhiteSpace(CaptureId) ? "<none>" : CaptureId),
                new("Provenance", "Source Run ID", string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId),
                new("Provenance", "Ingestion Job ID", string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId),
                new("Zeek", "Log Type", LogType),
                new("Zeek", "UID", string.IsNullOrWhiteSpace(ZeekUid) ? "<none>" : ZeekUid),
                new("Zeek", "Timestamp", TimestampDisplay),
                new("Network", "Source", string.IsNullOrWhiteSpace(SourceEndpoint) ? "<none>" : SourceEndpoint),
                new("Network", "Destination", string.IsNullOrWhiteSpace(DestinationEndpoint) ? "<none>" : DestinationEndpoint),
                new("Network", "Protocol", string.IsNullOrWhiteSpace(Protocol) ? "<none>" : Protocol),
                new("Network", "Service", string.IsNullOrWhiteSpace(Service) ? "<none>" : Service),
                new("Network", "Duration", string.IsNullOrWhiteSpace(DurationDisplay) ? "<none>" : DurationDisplay),
                new("Network", "Originator Bytes", OrigBytesDisplay),
                new("Network", "Responder Bytes", RespBytesDisplay),
                new("Network", "Originator Packets", OrigPackets.ToString()),
                new("Network", "Responder Packets", RespPackets.ToString()),
                new("Network", "Originator IP Bytes", FormatBytes(OrigIpBytes)),
                new("Network", "Responder IP Bytes", FormatBytes(RespIpBytes)),
                new("Network", "Connection State", string.IsNullOrWhiteSpace(ConnectionState) ? "<none>" : ConnectionState),
                new("Network", "History", string.IsNullOrWhiteSpace(History) ? "<none>" : History),
                new("DNS", "Query", string.IsNullOrWhiteSpace(DnsQuery) ? "<none>" : DnsQuery),
                new("HTTP", "Host", string.IsNullOrWhiteSpace(HttpHost) ? "<none>" : HttpHost),
                new("HTTP", "URI", string.IsNullOrWhiteSpace(HttpUri) ? "<none>" : HttpUri),
                new("TLS/QUIC", "Server Name", string.IsNullOrWhiteSpace(ServerName) ? "<none>" : ServerName),
                new("TLS/QUIC", "Client Protocol", string.IsNullOrWhiteSpace(ClientProtocol) ? "<none>" : ClientProtocol),
                new("TLS", "Version", string.IsNullOrWhiteSpace(TlsVersion) ? "<none>" : TlsVersion),
                new("TLS", "Cipher", string.IsNullOrWhiteSpace(TlsCipher) ? "<none>" : TlsCipher),
                new("TLS", "Established", string.IsNullOrWhiteSpace(TlsEstablished) ? "<none>" : TlsEstablished),
                new("Weird", "Name", string.IsNullOrWhiteSpace(WeirdName) ? "<none>" : WeirdName),
                new("Weird", "Additional", string.IsNullOrWhiteSpace(WeirdAdditional) ? "<none>" : WeirdAdditional),
                new("Correlation", "Process", HasProcessCorrelation ? $"{ProcessName} ({ProcessId})" : "<none>"),
                new("Correlation", "Process Key", string.IsNullOrWhiteSpace(ProcessKey) ? "<none>" : ProcessKey),
                new("Correlation", "Method", CorrelationDisplay),
                new("Correlation", "State", _record.CorrelationState.ToString()),
                new("Review", "Wireshark Filter", string.IsNullOrWhiteSpace(WiresharkFilter) ? "<none>" : WiresharkFilter),
                new("Raw", "Log Path", string.IsNullOrWhiteSpace(RawLogPath) ? "<none>" : RawLogPath),
                new("Raw", "Line", RawLineNumber.ToString()),
                new("Raw", "Line SHA256", string.IsNullOrWhiteSpace(_record.RawLineHash) ? "<none>" : _record.RawLineHash),
                new("Execution", "Error", string.IsNullOrWhiteSpace(ErrorMessage) ? "<none>" : ErrorMessage)
            }
        };
    }

    private string BuildRawText()
    {
        var lines = new List<string>
        {
            $"ArtifactId: {ArtifactId}",
            $"CaptureId: {CaptureId}",
            $"SourceRunId: {(string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId)}",
            $"IngestionJobId: {(string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId)}",
            $"Status: {Status}",
            $"Timestamp: {TimestampDisplay}",
            $"LogType: {LogType}",
            $"Uid: {ZeekUid}",
            $"Source: {SourceEndpoint}",
            $"Destination: {DestinationEndpoint}",
            $"Protocol: {Protocol}",
            $"Service: {Service}",
            $"DurationSeconds: {DurationSeconds:F6}",
            $"OrigBytes: {OrigBytes}",
            $"RespBytes: {RespBytes}",
            $"OrigPackets: {OrigPackets}",
            $"RespPackets: {RespPackets}",
            $"OrigIpBytes: {OrigIpBytes}",
            $"RespIpBytes: {RespIpBytes}",
            $"ConnectionState: {ConnectionState}",
            $"History: {History}",
            $"ServerName: {ServerName}",
            $"ClientProtocol: {ClientProtocol}",
            $"TlsVersion: {TlsVersion}",
            $"TlsCipher: {TlsCipher}",
            $"TlsEstablished: {TlsEstablished}",
            $"WeirdName: {WeirdName}",
            $"WeirdAdditional: {WeirdAdditional}",
            $"Summary: {Summary}",
            $"Correlation: {CorrelationDisplay}",
            $"ProcessKey: {(string.IsNullOrWhiteSpace(ProcessKey) ? "<none>" : ProcessKey)}",
            $"WiresharkFilter: {WiresharkFilter}",
            $"RawLogPath: {RawLogPath}",
            $"RawLineNumber: {RawLineNumber}",
            $"RawText: {_record.RawText}"
        };

        if (!string.IsNullOrWhiteSpace(ErrorMessage))
        {
            lines.Add($"Error: {ErrorMessage}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatEndpoint(string address, int port)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return string.Empty;
        }

        return port > 0 ? $"{address}:{port}" : address;
    }

    private string BuildWiresharkFilter(bool includeTimeWindow)
    {
        if (!HasFlowTuple)
        {
            return string.Empty;
        }

        var portFilter = Protocol.ToLowerInvariant() switch
        {
            "tcp" => $"tcp.port == {SourcePort} && tcp.port == {DestinationPort}",
            "udp" => $"udp.port == {SourcePort} && udp.port == {DestinationPort}",
            _ => $"(tcp.port == {SourcePort} || udp.port == {SourcePort}) && (tcp.port == {DestinationPort} || udp.port == {DestinationPort})"
        };
        var parts = new List<string>
        {
            BuildAddressFilter(SourceIp),
            BuildAddressFilter(DestinationIp),
            portFilter
        };

        if (includeTimeWindow)
        {
            var start = ToUnixSeconds(TimestampUtc.AddSeconds(-1));
            var end = ToUnixSeconds(TimestampUtc.AddSeconds(Math.Max(DurationSeconds, 5) + 1));
            parts.Add($"frame.time_epoch >= {start}");
            parts.Add($"frame.time_epoch <= {end}");
        }

        return string.Join(" && ", parts);
    }

    private static string BuildAddressFilter(string address)
    {
        return address.Contains(':', StringComparison.Ordinal)
            ? $"ipv6.addr == {address}"
            : $"ip.addr == {address}";
    }

    private static string ToUnixSeconds(DateTime value)
    {
        var utc = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
        var seconds = (utc - DateTime.UnixEpoch).TotalSeconds;
        return seconds.ToString("F6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0)
        {
            return "0 B";
        }

        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0 ? $"{bytes} B" : $"{value:F1} {units[unit]}";
    }
}
