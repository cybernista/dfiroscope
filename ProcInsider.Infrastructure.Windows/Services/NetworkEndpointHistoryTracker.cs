using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>Run-local sparse membership. State advances only after the adapter commits the complete poll marker.</summary>
public sealed class NetworkEndpointHistoryTracker
{
    private sealed record FamilyState(string SegmentId, DateTime LastEndUtc,
        Dictionary<string,(string EpisodeId,NetworkEndpointNative Native)> Members);
    private readonly Dictionary<EndpointFamily,FamilyState> _families = [];
    public void Reset() => _families.Clear();
    public NetworkEndpointSourceInput Prepare(NetworkEndpointFamilyResult result, bool connections,
        EvidenceIdentity scope, string runId, Guid jobId, string snapshotId = "", DateTime? snapshotStartUtc = null)
    {
        var prior = _families.GetValueOrDefault(result.Family);
        if (prior != null && result.WindowStartUtc - prior.LastEndUtc > NetworkEndpointCadence.ListenerInterval + TimeSpan.FromSeconds(1)) prior = null;
        // A changed ownership assessment does not prove the old socket disappeared.
        // End continuity instead of inventing an absence from an identity-only change.
        if (prior != null)
        {
            static string NativeKey(NetworkEndpointNative native) => (native with
                { ProcessStartUtc = null, ProcessEntityId = "", Ownership = EndpointOwnership.Unresolved }).MembershipKey;
            var previous = prior.Members.Values.ToLookup(old => NativeKey(old.Native));
            if (result.Endpoints.Any(current => previous[NativeKey(current)].Any(old => old.Native.MembershipKey != current.MembershipKey))) prior = null;
        }
        var segment = prior?.SegmentId ?? Guid.NewGuid().ToString("N");
        var pollId = Guid.NewGuid().ToString("N");
        var pending = new List<(string Episode,EndpointObservationKind Kind,NetworkEndpointNative Native)>();
        if (result.Outcome == EndpointPollOutcome.Complete)
        {
            var members = result.Endpoints.Where(e=>e.IsListener).DistinctBy(e=>e.MembershipKey).ToDictionary(e=>e.MembershipKey);
            foreach (var (key,native) in members)
                if (prior == null || !prior.Members.ContainsKey(key)) pending.Add((Guid.NewGuid().ToString("N"),EndpointObservationKind.Appeared,native));
            if (prior != null)
                foreach (var (key,value) in prior.Members)
                    if (!members.ContainsKey(key)) pending.Add((value.EpisodeId,EndpointObservationKind.Absent,value.Native));
            if (connections)
                foreach (var endpoint in result.Endpoints.Where(e=>!e.IsListener)) pending.Add((Guid.NewGuid().ToString("N"),EndpointObservationKind.ConnectionSnapshot,endpoint));
        }
        var poll = new NetworkEndpointPoll(pollId,scope,runId,jobId,segment,result.Family,result.WindowStartUtc,result.WindowEndUtc,
            result.Outcome,connections && result.Family is EndpointFamily.TcpV4 or EndpointFamily.TcpV6,pending.Count,result.Diagnostic,
            snapshotId, snapshotStartUtc);
        return new(poll,pending.Select(r=>new NetworkEndpointObservation(Guid.NewGuid().ToString("N"),pollId,r.Episode,r.Kind,r.Native,poll)).ToArray(),result.FreshOwners);
    }
    public void Commit(NetworkEndpointSourceInput input, NetworkEndpointFamilyResult result)
    {
        if (input.Poll.Outcome != EndpointPollOutcome.Complete) { _families.Remove(input.Poll.Family); return; }
        var prior = _families.GetValueOrDefault(input.Poll.Family);
        var members = prior?.SegmentId == input.Poll.SegmentId ? new Dictionary<string,(string EpisodeId,NetworkEndpointNative Native)>(prior.Members) : [];
        foreach (var observation in input.Observations)
        {
            if (observation.Kind==EndpointObservationKind.Appeared) members[observation.Native.MembershipKey]=(observation.EpisodeId,observation.Native);
            if (observation.Kind==EndpointObservationKind.Absent) members.Remove(observation.Native.MembershipKey);
        }
        _families[input.Poll.Family]=new(input.Poll.SegmentId,result.WindowEndUtc,members);
    }
}
