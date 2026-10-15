using ProcInsider.Models;
using System.Globalization;

namespace ProcInsider.Features.NetworkWorkspace;

public enum EndpointFamily { TcpV4, TcpV6, UdpV4, UdpV6 }
public enum EndpointPollOutcome { Complete, Failed, Cancelled }
public enum EndpointObservationKind { Appeared, Absent, ConnectionSnapshot }
public enum EndpointOwnership { VerifiedLifetime, Unresolved }
public enum EndpointScopeKind { TcpListeners, UdpEndpoints, ConnectionSnapshots, ListenerHistory }
public enum EndpointSort { ObservedUtc, LocalAddress, LocalPort, ProcessId, ProcessName, ImagePath, CommandLine, LastObservedUtc, FirstAbsentUtc, Family, RemoteEndpoint, TcpState, Ownership, CoverageGap }
public enum EndpointMetadataState { NotRecorded, Available, AccessDenied, Unavailable, Exited, Timeout, Unsupported }
public sealed record NetworkEndpointProcessMetadata(string? ProcessName, string? ImagePath, string? CommandLine,
    EndpointMetadataState NameState, EndpointMetadataState ImageState, EndpointMetadataState CommandLineState,
    DateTime WindowStartUtc, DateTime WindowEndUtc, string Method);
public sealed record NetworkEndpointNative(EndpointFamily Family, string LocalAddress, uint LocalScopeId,
    int LocalPort, string? RemoteAddress, uint? RemoteScopeId, int? RemotePort, int? TcpState,
    int ProcessId, DateTime? NativeCreationUtc, DateTime? ProcessStartUtc = null,
    string ProcessEntityId = "", EndpointOwnership Ownership = EndpointOwnership.Unresolved,
    NetworkEndpointProcessMetadata? Metadata = null)
{
    [System.Text.Json.Serialization.JsonIgnore] public string ProcessNameDisplay => Metadata?.ProcessName ?? Metadata?.NameState.ToString() ?? "Not recorded";
    [System.Text.Json.Serialization.JsonIgnore] public string ImagePathDisplay => Metadata?.ImagePath ?? Metadata?.ImageState.ToString() ?? "Not recorded";
    [System.Text.Json.Serialization.JsonIgnore] public string CommandLineDisplay => Metadata?.CommandLine ?? Metadata?.CommandLineState.ToString() ?? "Not recorded";
    [System.Text.Json.Serialization.JsonIgnore] public string LocalPresentation => NetworkAddressPresentation.Endpoint(LocalAddress, LocalPort, LocalScopeId);
    [System.Text.Json.Serialization.JsonIgnore] public string RemotePresentation => NetworkAddressPresentation.Endpoint(RemoteAddress, RemotePort, RemoteScopeId);
    public bool IsListener => Family is EndpointFamily.UdpV4 or EndpointFamily.UdpV6 || TcpState == 2;
    public string MembershipKey => NetworkAnalysisBinding.Hash(Family.ToString(), LocalAddress,
        LocalScopeId.ToString(CultureInfo.InvariantCulture), LocalPort.ToString(CultureInfo.InvariantCulture), ProcessId.ToString(CultureInfo.InvariantCulture), ProcessStartUtc?.Ticks.ToString(CultureInfo.InvariantCulture),
        NativeCreationUtc?.Ticks.ToString(CultureInfo.InvariantCulture), ProcessEntityId);
    public string LocalDisplay => Family is EndpointFamily.TcpV6 or EndpointFamily.UdpV6
        ? $"[{LocalAddress}%{LocalScopeId}]:{LocalPort}" : $"{LocalAddress}:{LocalPort}";
    public string RemoteDisplay => RemoteAddress == null ? "" : Family == EndpointFamily.TcpV6
        ? $"[{RemoteAddress}%{RemoteScopeId}]:{RemotePort}" : $"{RemoteAddress}:{RemotePort}";
    public NetworkEndpointNative VerifyOwner(EvidenceIdentity scope,DateTime processStartUtc,DateTime collectionStartUtc,bool sameLivingProcess)
    {
        if(ProcessId<=0 || !sameLivingProcess || processStartUtc.Kind!=DateTimeKind.Utc || processStartUtc>collectionStartUtc ||
            NativeCreationUtc is { } creation && creation<processStartUtc)
            return this with{ProcessEntityId="",ProcessStartUtc=null,Ownership=EndpointOwnership.Unresolved};
        return this with{ProcessStartUtc=processStartUtc,Ownership=EndpointOwnership.VerifiedLifetime,
            ProcessEntityId=ProcessEntityIdentity.CreateExact(scope.CaseId,scope.EvidenceSessionId,scope.HostId,scope.ExecutionRootId,ProcessId,processStartUtc)};
    }
}
public sealed record NetworkEndpointPoll(string PollId, EvidenceIdentity Scope, string SourceRunId,
    Guid IngestionJobId, string SegmentId, EndpointFamily Family, DateTime WindowStartUtc,
    DateTime WindowEndUtc, EndpointPollOutcome Outcome, bool IncludesConnections, int ExpectedRows,
    string Diagnostic, string SnapshotId = "", DateTime? SnapshotStartUtc = null);
public sealed record NetworkEndpointObservation(string ObservationId, string PollId, string EpisodeId,
    EndpointObservationKind Kind, NetworkEndpointNative Native, NetworkEndpointPoll Provenance);
public sealed record NetworkEndpointFamilyResult(EndpointFamily Family, DateTime WindowStartUtc,
    DateTime WindowEndUtc, EndpointPollOutcome Outcome, IReadOnlyList<NetworkEndpointNative> Endpoints,
    string Diagnostic = "", IReadOnlyList<NetworkEndpointNative>? FreshOwners = null);
public sealed record NetworkEndpointSourceInput(NetworkEndpointPoll Poll,
    IReadOnlyList<NetworkEndpointObservation> Observations, IReadOnlyList<NetworkEndpointNative>? FreshOwners = null);
public sealed record NetworkEndpointQuery(EndpointScopeKind Kind, string? PollId = null,
    long? FromUtcTicks = null, long? ToUtcTicks = null, string? Text = null,
    EndpointSort Sort = EndpointSort.ObservedUtc, bool Descending = true, long Offset = 0, int PageSize = 128,
    EvidenceIdentity? Scope = null, string? SourceRunId = null, string? SnapshotId = null,
    IReadOnlyList<NetworkEndpointGreenSelector>? GreenSelectors = null, IReadOnlyList<NetworkEndpointColumnFilter>? Columns = null,
    string? ExactObservationId = null);
public sealed record NetworkEndpointColumnFilter(EndpointSort Column, ProcInsider.Services.ColumnFilterCriteria Criteria);

/// <summary>Transient selection over recorded endpoint families or UTC snapshot scopes.</summary>
public sealed record NetworkEndpointGreenSelector(NetworkEndpointQuery Query, bool IsExcluded = false)
{
    public bool Covers(NetworkEndpointGreenSelector other) =>
        (Query.Kind == other.Query.Kind || Query.Kind == EndpointScopeKind.ListenerHistory &&
            other.Query.Kind is EndpointScopeKind.TcpListeners or EndpointScopeKind.UdpEndpoints) &&
        (Query.FromUtcTicks == null || other.Query.FromUtcTicks >= Query.FromUtcTicks) &&
        (Query.ToUtcTicks == null || other.Query.ToUtcTicks <= Query.ToUtcTicks) &&
        (Query.Scope == null || Query.Scope == other.Query.Scope) &&
        (Query.PollId == null || Query.PollId == other.Query.PollId) &&
        (Query.SourceRunId == null || Query.SourceRunId == other.Query.SourceRunId) &&
        (Query.SnapshotId == null || Query.SnapshotId == other.Query.SnapshotId);
    public static bool Includes(IEnumerable<NetworkEndpointGreenSelector> selectors, NetworkEndpointGreenSelector value)
    {
        var matches = selectors.Where(s => s.Covers(value)).ToArray();
        return matches.Any(s => !s.IsExcluded && !matches.Any(other => other.IsExcluded &&
            (!other.Covers(s) || s.Covers(other))));
    }
}
public sealed record NetworkEndpointHistoryRow(NetworkEndpointObservation Observation, NetworkEndpointPoll Poll,
    DateTime FirstObservedUtc, DateTime LastObservedUtc, DateTime? FirstAbsentUtc,
    DateTime? FirstAbsentWindowStartUtc, bool HasContinuityGap);
public sealed record NetworkEndpointPage(IReadOnlyList<NetworkEndpointHistoryRow> Rows,
    long MatchingRows, bool Supported, string Diagnostic);
/// <summary>
/// Durable process relation. Scope.SourceIdentityId is not a source pin because the
/// endpoint source may differ from the process source; use SourceIdentityId explicitly.
/// </summary>
public sealed record NetworkEndpointProcessQuery(string ProcessEntityId, EvidenceIdentity Scope,
    string? SourceIdentityId = null, long? FromUtcTicks = null, long? ToUtcTicks = null,
    int MaxRows = 100);
public interface INetworkEndpointQueryService
{
    NetworkEndpointPage Query(NetworkEndpointQuery query, CancellationToken cancellationToken = default);
    /// <summary>Host/capture read across sources, with optional exact or compatible execution-root filtering.</summary>
    NetworkEndpointPage QueryForHostCapture(NetworkEndpointQuery query, bool includeCompatibleExecutionRoots = false,
        CancellationToken cancellationToken = default);
    NetworkEndpointPage QueryForProcess(NetworkEndpointProcessQuery query, CancellationToken cancellationToken = default);
    ProcInsider.Services.ColumnFilterValuePage Values(NetworkEndpointQuery query, EndpointSort column, string? search, ProcInsider.Services.ColumnFilterValueSort sort, CancellationToken cancellationToken = default);
    IReadOnlyList<NetworkEndpointPoll> GetPolls(long offset, int pageSize, CancellationToken cancellationToken = default);
}

/// <summary>Sequential polling schedule: skip missed ticks; connections use the next future UTC boundary.</summary>
public sealed class NetworkEndpointCadence
{
    public static readonly TimeSpan ListenerInterval = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan ConnectionInterval = TimeSpan.FromMinutes(5);
    public DateTime NextListenersUtc { get; private set; } = DateTime.MinValue;
    public DateTime NextConnectionsUtc { get; private set; } = DateTime.MinValue;
    private DateTime? _listenerOrigin;
    public bool ConnectionsDue(DateTime utc) => utc >= NextConnectionsUtc;
    public void Complete(DateTime utc, bool connections, DateTime? collectionStartUtc = null)
    {
        _listenerOrigin ??= collectionStartUtc ?? utc;
        NextListenersUtc = _listenerOrigin.Value + TimeSpan.FromTicks(
            checked(((utc.Ticks-_listenerOrigin.Value.Ticks)/ListenerInterval.Ticks+1)*ListenerInterval.Ticks));
        if (connections) NextConnectionsUtc = new DateTime(
            checked((utc.Ticks / ConnectionInterval.Ticks + 1) * ConnectionInterval.Ticks), DateTimeKind.Utc);
    }
    public void Reset() { NextListenersUtc = NextConnectionsUtc = DateTime.MinValue; _listenerOrigin=null; }
}
