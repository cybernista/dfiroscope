using ProcInsider.Models;

namespace ProcInsider.Services;

internal sealed partial class ProcessListingQueryService
{
    /// <summary>Every stored scalar of one already resolved exact process entity, including SQL nulls.
    /// The caller must resolve its citation first; this owner repeats the complete recorded identity pin.</summary>
    public IReadOnlyDictionary<string, object?>? GetProcessRecordFields(ProcessRecord resolved,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resolved);
        if (string.IsNullOrWhiteSpace(resolved.ProcessEntityId)) return null;
        using var connection = OpenListingConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT * FROM ProcessEntities
            WHERE ProcessEntityId=$entity AND ProcessKey=$key
              AND COALESCE(CaseId,'')=$case AND EvidenceSessionId=$session AND CaptureId=$capture
              AND SourceIdentityId=$source AND HostId=$host AND ExecutionRootId=$root LIMIT 2
            """;
        command.Parameters.AddWithValue("$entity", resolved.ProcessEntityId);
        command.Parameters.AddWithValue("$key", resolved.ProcessKey);
        command.Parameters.AddWithValue("$case", resolved.CaseId);
        command.Parameters.AddWithValue("$session", resolved.EvidenceSessionId);
        command.Parameters.AddWithValue("$capture", resolved.CaptureId);
        command.Parameters.AddWithValue("$source", resolved.SourceIdentityId);
        command.Parameters.AddWithValue("$host", resolved.HostId);
        command.Parameters.AddWithValue("$root", resolved.ExecutionRootId);
        cancellationToken.ThrowIfCancellationRequested();
        using var cancellation = cancellationToken.Register(command.Cancel);
        // Measure stored scalar bytes in SQLite before materializing potentially huge text/blob values.
        var storedSql = command.CommandText;
        var columns = new List<string>();
        using (var schema = connection.CreateCommand())
        {
            schema.CommandText = "PRAGMA table_info('ProcessEntities')";
            using var metadata = schema.ExecuteReader();
            while (metadata.Read()) columns.Add(metadata.GetString(1));
        }
        var sizes = columns.Select(column => "COALESCE(length(CAST(\"" + column.Replace("\"", "\"\"") + "\" AS BLOB)),0)");
        command.CommandText = storedSql.Replace("SELECT *", "SELECT " + string.Join(" + ", sizes), StringComparison.Ordinal);
        var scalar = command.ExecuteScalar();
        if (scalar is not null && Convert.ToInt64(scalar) > 64_000)
            throw new ArgumentOutOfRangeException("recordSizeBytes", "The complete selected stored record exceeds 64 KB.");
        command.CommandText = storedSql;
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var fields = new Dictionary<string, object?>(StringComparer.Ordinal);
        for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fields.Add(reader.GetName(ordinal), reader.IsDBNull(ordinal) ? null : reader.GetValue(ordinal));
        }
        return reader.Read() ? null : fields;
    }
}
