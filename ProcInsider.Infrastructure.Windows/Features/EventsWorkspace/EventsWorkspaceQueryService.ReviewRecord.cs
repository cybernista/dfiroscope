using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal sealed partial class EventsWorkspaceQueryService
{
    /// <summary>All stored columns and the exactly linked raw payload for one previously resolved published original.</summary>
    public Task<IReadOnlyDictionary<string, object?>?> GetEventRecordFieldsAsync(TelemetryEventRecord resolved,
        CancellationToken cancellationToken = default) => RunAsync<IReadOnlyDictionary<string, object?>?>(() =>
        {
            if (!_publishedSourceNames.Contains(resolved.Source)) return null;
            using var command = Command("""
                SELECT * FROM main.ProcessEvents WHERE SequenceId=$sequence AND SourceRunId=$run
                  AND COALESCE(CaseId,'')=$case AND EvidenceSessionId=$session AND CaptureId=$capture
                  AND SourceIdentityId=$source AND HostId=$host AND ExecutionRootId=$root LIMIT 2
                """);
            command.Parameters.AddWithValue("$sequence", resolved.SequenceId);
            command.Parameters.AddWithValue("$run", resolved.SourceRunId);
            command.Parameters.AddWithValue("$case", resolved.CaseId);
            command.Parameters.AddWithValue("$session", resolved.EvidenceSessionId);
            command.Parameters.AddWithValue("$capture", resolved.CaptureId);
            command.Parameters.AddWithValue("$source", resolved.SourceIdentityId);
            command.Parameters.AddWithValue("$host", resolved.HostId);
            command.Parameters.AddWithValue("$root", resolved.ExecutionRootId);
            EnsureWholeEventRecordBound(command, Columns("ProcessEvents"));
            Dictionary<string, object?> fields;
            using (var reader = command.ExecuteReader())
            {
                if (!reader.Read()) return null;
                fields = StoredEventFields(reader, cancellationToken);
                if (reader.Read()) return null;
            }
            if (fields.TryGetValue("RawRecordId", out var rawId) && rawId is not null)
            {
                if (!Columns("RawRecords").Contains("SourceRunId")) return null;
                command.CommandText = """
                    SELECT * FROM main.RawRecords WHERE RawRecordId=$raw AND SourceRunId=$run
                      AND SourceId=(SELECT SourceId FROM main.SourceRuns WHERE SourceRunId=$run)
                      AND COALESCE(CaseId,'')=$case AND EvidenceSessionId=$session AND CaptureId=$capture
                      AND SourceIdentityId=$source AND HostId=$host AND ExecutionRootId=$root LIMIT 2
                    """;
                command.Parameters.AddWithValue("$raw", rawId);
                EnsureWholeEventRecordBound(command, Columns("RawRecords"));
                using var reader = command.ExecuteReader();
                if (!reader.Read()) return null;
                var raw = StoredEventFields(reader, cancellationToken);
                if (reader.Read()) return null;
                if (fields.TryGetValue("SourceId", out var eventSourceId) && eventSourceId is not null &&
                    (!raw.TryGetValue("SourceId", out var rawSourceId) || !Equals(eventSourceId, rawSourceId))) return null;
                fields.Add("RawRecord", raw);
            }
            else fields.Add("RawRecord", null);
            return fields;
        }, cancellationToken);

    private static void EnsureWholeEventRecordBound(SqliteCommand command, IEnumerable<string> columns)
    {
        // These columns come only from the two fixed assessed native tables above, never model input.
        var storedSql = command.CommandText;
        var sizes = columns.Select(column => "COALESCE(length(CAST(\"" + column.Replace("\"", "\"\"") + "\" AS BLOB)),0)");
        command.CommandText = storedSql.Replace("SELECT *", "SELECT " + string.Join(" + ", sizes), StringComparison.Ordinal);
        var scalar = command.ExecuteScalar();
        if (scalar is not null && Convert.ToInt64(scalar) > 64_000)
            throw new ArgumentOutOfRangeException("recordSizeBytes", "The complete selected stored record exceeds 64 KB.");
        command.CommandText = storedSql;
    }

    private static Dictionary<string, object?> StoredEventFields(SqliteDataReader reader, CancellationToken token)
    {
        var fields = new Dictionary<string, object?>(StringComparer.Ordinal);
        for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
        {
            token.ThrowIfCancellationRequested();
            fields.Add(reader.GetName(ordinal), reader.IsDBNull(ordinal) ? null : reader.GetValue(ordinal));
        }
        return fields;
    }
}
