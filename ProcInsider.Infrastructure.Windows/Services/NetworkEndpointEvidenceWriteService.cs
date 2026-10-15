using System.Text.Json;
using ProcInsider.Features.NetworkWorkspace;

namespace ProcInsider.Services;

internal sealed class NetworkEndpointEvidenceWriteService(SqliteWriteTransactionContext context)
{
    private void ValidateRun(NetworkEndpointPoll poll)
    {
        using var command = context.CreateCommand("""
            SELECT COUNT(*) FROM SourceRuns WHERE SourceRunId=$run AND IngestionJobId=$job
              AND CaseId=$case AND EvidenceSessionId=$session AND CaptureId=$capture AND HostId=$host
              AND ExecutionRootId=$root AND SourceIdentityId=$source
              AND EvidenceSessionId=(SELECT Value FROM SchemaInfo WHERE Key='EvidenceSessionId');
            """);
        foreach (var (key,value) in new[] { ("run",poll.SourceRunId),("job",poll.IngestionJobId.ToString("D")),("case",poll.Scope.CaseId),
            ("session",poll.Scope.EvidenceSessionId),("capture",poll.Scope.CaptureId),("host",poll.Scope.HostId),("root",poll.Scope.ExecutionRootId),("source",poll.Scope.SourceIdentityId) })
            command.Parameters.AddWithValue("$"+key,value);
        if (Convert.ToInt64(command.ExecuteScalar())!=1) throw new InvalidOperationException("Endpoint provenance does not match the exact stored source execution and session.");
    }
    internal const string SchemaSql = """
        CREATE TABLE NetworkEndpointPolls(
            PollId TEXT PRIMARY KEY, SourceRunId TEXT NOT NULL REFERENCES SourceRuns(SourceRunId),
            IngestionJobId TEXT NOT NULL, CaseId TEXT NOT NULL, EvidenceSessionId TEXT NOT NULL,
            CaptureId TEXT NOT NULL, HostId TEXT NOT NULL, ExecutionRootId TEXT NOT NULL, SourceIdentityId TEXT NOT NULL,
            SegmentId TEXT NOT NULL, Family INTEGER NOT NULL, WindowStartTicks INTEGER NOT NULL,
            WindowEndTicks INTEGER NOT NULL, Outcome INTEGER NOT NULL, IncludesConnections INTEGER NOT NULL,
            ExpectedRows INTEGER NOT NULL, SnapshotId TEXT NOT NULL, SnapshotStartTicks INTEGER, Payload TEXT NOT NULL);
        CREATE INDEX IX_EndpointPollCoverage ON NetworkEndpointPolls(SegmentId,Family,Outcome,WindowEndTicks);
        CREATE INDEX IX_EndpointPollSnapshots ON NetworkEndpointPolls(IncludesConnections,WindowStartTicks);
        CREATE TABLE NetworkEndpointObservations(
            ObservationId TEXT PRIMARY KEY, PollId TEXT NOT NULL, EpisodeId TEXT NOT NULL,
            Kind INTEGER NOT NULL, LocalAddress TEXT NOT NULL, LocalPort INTEGER NOT NULL, ProcessId INTEGER NOT NULL,
            SourceRunId TEXT NOT NULL REFERENCES SourceRuns(SourceRunId), IngestionJobId TEXT NOT NULL,
            CaseId TEXT NOT NULL, EvidenceSessionId TEXT NOT NULL, CaptureId TEXT NOT NULL, HostId TEXT NOT NULL,
            ExecutionRootId TEXT NOT NULL, SourceIdentityId TEXT NOT NULL, ProcessEntityId TEXT NOT NULL,
            Payload TEXT NOT NULL);
        CREATE INDEX IX_EndpointObservationPoll ON NetworkEndpointObservations(PollId);
        CREATE INDEX IX_EndpointObservationEpisode ON NetworkEndpointObservations(EpisodeId,Kind);
        CREATE INDEX IX_EndpointObservationRun ON NetworkEndpointObservations(SourceRunId);
        """;
    internal void Append(IReadOnlyList<NetworkEndpointObservation> rows, IReadOnlyList<NetworkEndpointPoll> markers)
    {
        context.Execute(() =>
        {
            foreach (var row in rows)
            {
                ValidateRun(row.Provenance);
                if (row.PollId != row.Provenance.PollId || row.Native.Family != row.Provenance.Family || row.Provenance.Outcome != EndpointPollOutcome.Complete)
                    throw new InvalidOperationException("Endpoint row does not match its immutable provenance.");
                var payload = JsonSerializer.Serialize(row);
                using var existing = context.CreateCommand("SELECT Payload FROM NetworkEndpointObservations WHERE ObservationId=$id;");
                existing.Parameters.AddWithValue("$id",row.ObservationId);
                if (existing.ExecuteScalar() is string stored)
                { if (stored != payload) throw new InvalidOperationException("Conflicting immutable endpoint retry."); continue; }
                using var closed = context.CreateCommand("SELECT COUNT(*) FROM NetworkEndpointPolls WHERE PollId=$id;");
                closed.Parameters.AddWithValue("$id", row.PollId);
                if (Convert.ToInt64(closed.ExecuteScalar()) != 0) throw new InvalidOperationException("Cannot append to a finalized endpoint poll.");
                using var cmd = context.CreateCommand("INSERT INTO NetworkEndpointObservations VALUES($id,$poll,$episode,$kind,$address,$port,$pid,$run,$job,$case,$session,$capture,$host,$root,$source,$entity,$payload);");
                cmd.Parameters.AddWithValue("$id", row.ObservationId); cmd.Parameters.AddWithValue("$poll", row.PollId);
                cmd.Parameters.AddWithValue("$episode", row.EpisodeId); cmd.Parameters.AddWithValue("$kind", (int)row.Kind);
                cmd.Parameters.AddWithValue("$address", row.Native.LocalAddress); cmd.Parameters.AddWithValue("$port", row.Native.LocalPort);
                cmd.Parameters.AddWithValue("$pid", row.Native.ProcessId); cmd.Parameters.AddWithValue("$payload", payload);
                var p=row.Provenance;var s=p.Scope;
                foreach(var (key,value) in new[]{("run",p.SourceRunId),("job",p.IngestionJobId.ToString("D")),("case",s.CaseId),("session",s.EvidenceSessionId),
                    ("capture",s.CaptureId),("host",s.HostId),("root",s.ExecutionRootId),("source",s.SourceIdentityId),("entity",row.Native.ProcessEntityId)})
                    cmd.Parameters.AddWithValue("$"+key,value);
                cmd.ExecuteNonQuery();
            }
            foreach (var poll in markers)
            {
                ValidateRun(poll);
                var payload = JsonSerializer.Serialize(poll);
                using var existing = context.CreateCommand("SELECT Payload FROM NetworkEndpointPolls WHERE PollId=$id;");
                existing.Parameters.AddWithValue("$id",poll.PollId);
                if (existing.ExecuteScalar() is string stored)
                { if (stored != payload) throw new InvalidOperationException("Conflicting immutable endpoint marker retry."); continue; }
                if (poll.WindowStartUtc.Kind != DateTimeKind.Utc || poll.WindowEndUtc.Kind != DateTimeKind.Utc || poll.WindowEndUtc < poll.WindowStartUtc ||
                    string.IsNullOrWhiteSpace(poll.SourceRunId) || poll.IngestionJobId == Guid.Empty || string.IsNullOrWhiteSpace(poll.Scope.EvidenceSessionId))
                    throw new InvalidOperationException("Endpoint completion requires exact provenance and an actual UTC window.");
                using var count = context.CreateCommand("SELECT COUNT(*) FROM NetworkEndpointObservations WHERE PollId=$id;");
                count.Parameters.AddWithValue("$id", poll.PollId);
                if (Convert.ToInt64(count.ExecuteScalar()) != poll.ExpectedRows) throw new InvalidOperationException("Endpoint payload count does not match completion marker.");
                using var verify = context.CreateCommand("SELECT Payload FROM NetworkEndpointObservations WHERE PollId=$id;");
                verify.Parameters.AddWithValue("$id",poll.PollId);
                using (var reader=verify.ExecuteReader())
                    while(reader.Read())
                        if (JsonSerializer.Deserialize<NetworkEndpointObservation>(reader.GetString(0))!.Provenance != poll)
                            throw new InvalidOperationException("Endpoint payload has conflicting source provenance.");
                using var cmd = context.CreateCommand("INSERT INTO NetworkEndpointPolls VALUES($id,$run,$job,$case,$session,$capture,$host,$root,$source,$segment,$family,$start,$end,$outcome,$connections,$rows,$snapshot,$snapshotStart,$payload);");
                var values = new (string, object)[] { ("id",poll.PollId),("run",poll.SourceRunId),("job",poll.IngestionJobId.ToString("N")),
                    ("case",poll.Scope.CaseId),("session",poll.Scope.EvidenceSessionId),("capture",poll.Scope.CaptureId),("host",poll.Scope.HostId),
                    ("root",poll.Scope.ExecutionRootId),("source",poll.Scope.SourceIdentityId),("segment",poll.SegmentId),("family",(int)poll.Family),
                    ("start",poll.WindowStartUtc.Ticks),("end",poll.WindowEndUtc.Ticks),("outcome",(int)poll.Outcome),
                    ("connections",poll.IncludesConnections?1:0),("rows",poll.ExpectedRows),("snapshot",poll.SnapshotId),
                    ("snapshotStart",poll.SnapshotStartUtc?.Ticks is { } ticks ? ticks : DBNull.Value),("payload",payload) };
                foreach (var (key,value) in values) cmd.Parameters.AddWithValue("$"+key,value);
                cmd.ExecuteNonQuery();
            }
        });
    }
}
