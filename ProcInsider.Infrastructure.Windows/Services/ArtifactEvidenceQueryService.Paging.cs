using System.Globalization;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

public enum ArtifactEvidenceFamily { Filesystem, Module, Handle, Pe, Signature, Dump, MemoryImage, MemoryProcess, Volatility, Pcap, Zeek }
public sealed record ArtifactEvidenceReadQuery(ArtifactEvidenceFamily Family, EvidenceIdentity Scope,
    string ProcessEntityId = "", long Offset = 0, int PageSize = 50, string ExactEvidenceId = "",
    bool IncludeAllStoredFields = false, int FieldOffset = 0, int FieldPageSize = 16);
public sealed record ArtifactEvidenceReadRow(EvidenceIdentity Scope, EvidenceReference Evidence, string DataSource,
    string SourceRunId, string SourceRevision, DateTime? TimestampUtc, IReadOnlyDictionary<string, string> Fields, int StoredFieldCount = 0);
public sealed record ArtifactEvidenceReadPage(IReadOnlyList<ArtifactEvidenceReadRow> Rows, long MatchingRows, bool Supported,
    long MissingSourceRunRows = 0);

// Counts and pages native stored metadata in one pinned read transaction. Every SQL identifier
// comes from the typed family map; callers supply only parameter values and never file paths to open.
internal sealed partial class ArtifactEvidenceQueryService
{
    public ArtifactEvidenceReadPage ReadPage(ArtifactEvidenceReadQuery query, CancellationToken cancellationToken = default) =>
        _readContext.MeasureRead("ReadArtifactEvidencePage", () => ReadPageCore(query, cancellationToken),
            $"family={query.Family}; offset={query.Offset}; page={query.PageSize}", page => page.Rows.Count);

    private ArtifactEvidenceReadPage ReadPageCore(ArtifactEvidenceReadQuery query, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(query);
        var scope = query.Scope;
        if (!Enum.IsDefined(query.Family) || scope is null || string.IsNullOrWhiteSpace(scope.EvidenceSessionId) ||
            string.IsNullOrWhiteSpace(scope.CaptureId) || string.IsNullOrWhiteSpace(scope.HostId) ||
            query.Offset < 0 || query.Offset > int.MaxValue || query.PageSize is < 1 or > 50 || query.FieldOffset < 0 || query.FieldPageSize is < 1 or > 16)
            throw new ArgumentException("An assessed host/capture scope and bounded page are required.");
        var definition = PageDefinition(query.Family);
        if (definition.ProcessAttached && string.IsNullOrWhiteSpace(query.ProcessEntityId) && string.IsNullOrWhiteSpace(query.ExactEvidenceId))
            throw new ArgumentException("A durable process entity is required for process-attached evidence.");
        token.ThrowIfCancellationRequested();
        using var connection = _readContext.OpenReadOnlyConnection();
        string[] identityColumns = ["CaseId", "EvidenceSessionId", "CaptureId", "SourceIdentityId", "HostId", "ExecutionRootId"];
        var required = identityColumns.Concat([definition.Id, definition.Time, "SourceRunId"])
            .Concat(definition.Fields.Select(field => field.Column))
            .Concat(definition.ProcessAttached ? ["ProcessEntityId"] : Array.Empty<string>()).Distinct(StringComparer.Ordinal).ToArray();
        if (required.Any(column => !ColumnExists(connection, definition.Table, column))) return new([], 0, false);
        if (query.Family == ArtifactEvidenceFamily.Filesystem && !ColumnExists(connection, definition.Table, "StructuredPayloadVersion"))
            return new([], 0, false);
        var hasProperties = query.Family == ArtifactEvidenceFamily.Filesystem && ColumnExists(connection, "ArtifactProperties", "Name");
        using var snapshot = connection.BeginTransaction(deferred: true);
        var fields = definition.Fields;
        var storedFieldCount = fields.Length;
        var propertyFields = new Dictionary<string, string>(StringComparer.Ordinal);
        if (query.IncludeAllStoredFields)
        {
            if (string.IsNullOrWhiteSpace(query.ExactEvidenceId)) throw new ArgumentException("Full stored fields require an exact evidence object.");
            using var schema = connection.CreateCommand();
            schema.Transaction = snapshot;
            schema.CommandText = "PRAGMA table_info(" + definition.Table + ")";
            using var schemaRows = schema.ExecuteReader();
            var native = new List<(string Name, string Column)>();
            while (schemaRows.Read()) { var name = schemaRows.GetString(1); native.Add((name, name)); }
            storedFieldCount = native.Count;
            fields = native.Skip(query.FieldOffset).Take(query.FieldPageSize).ToArray();
            schemaRows.Close();
            if (hasProperties)
            {
                using var properties = connection.CreateCommand();
                properties.Transaction = snapshot;
                var propertyScope = string.Join(" AND ", identityColumns.Select((column, index) => "COALESCE(a." + column + ",'')=$PropertyScope" + index));
                var propertyWhere = "p.ArtifactId=$Id AND EXISTS(SELECT 1 FROM Artifacts a WHERE a.ArtifactId=p.ArtifactId AND " + propertyScope + ")";
                var propertyScopeValues = new[] { scope.CaseId, scope.EvidenceSessionId, scope.CaptureId, scope.SourceIdentityId, scope.HostId, scope.ExecutionRootId };
                for (var index = 0; index < identityColumns.Length; index++) properties.Parameters.AddWithValue("$PropertyScope" + index, propertyScopeValues[index]);
                properties.CommandText = "SELECT COUNT(*) FROM ArtifactProperties p WHERE " + propertyWhere;
                properties.Parameters.AddWithValue("$Id", query.ExactEvidenceId);
                storedFieldCount += Convert.ToInt32(properties.ExecuteScalar(), CultureInfo.InvariantCulture);
                var remaining = query.FieldPageSize - fields.Length;
                if (remaining > 0)
                {
                    properties.CommandText = "SELECT p.Name,p.Value,p.ValueType FROM ArtifactProperties p WHERE " + propertyWhere + " ORDER BY p.Name COLLATE BINARY LIMIT $Take OFFSET $Skip";
                    properties.Parameters.AddWithValue("$Take", remaining);
                    properties.Parameters.AddWithValue("$Skip", Math.Max(0, query.FieldOffset - native.Count));
                    using var propertyRows = properties.ExecuteReader();
                    while (propertyRows.Read()) propertyFields["Property: " + GetString(propertyRows, 0)] =
                        GetString(propertyRows, 2) + ": " + (propertyRows.IsDBNull(1) ? "<null>" : GetString(propertyRows, 1));
                }
            }
        }
        using var command = connection.CreateCommand();
        command.Transaction = snapshot;
        var network = query.Family is ArtifactEvidenceFamily.Pcap or ArtifactEvidenceFamily.Zeek;
        var from = definition.Table + " e" + (network ? " JOIN SourceRuns s ON s.SourceRunId=e.SourceRunId" : "");
        var identityOwner = network ? "s." : "e.";
        // Native non-network rows own their complete capture identity even when legacy run
        // provenance is absent. Network container identity still requires the exact SourceRuns join.
        var clauses = new List<string>();
        if (network)
        {
            clauses.Add("COALESCE(e.SourceRunId,'')<>''");
            clauses.AddRange(identityColumns.Where(column => column != "CaptureId").Select(column =>
                "COALESCE(e." + column + ",'')=COALESCE(s." + column + ",'')"));
        }
        var values = new[] { scope.CaseId, scope.EvidenceSessionId, scope.CaptureId, scope.SourceIdentityId, scope.HostId, scope.ExecutionRootId };
        for (var index = 0; index < identityColumns.Length; index++)
        {
            // An empty selected source/root is the established host-query wildcard; case/session/capture/host stay exact.
            if (index is 3 or 5 && string.IsNullOrEmpty(values[index])) continue;
            var parameter = "$Scope" + index;
            clauses.Add("COALESCE(" + identityOwner + identityColumns[index] + ",'')=" + parameter);
            command.Parameters.AddWithValue(parameter, values[index]);
        }
        if (definition.ProcessAttached && !string.IsNullOrWhiteSpace(query.ProcessEntityId))
        {
            clauses.Add("e.ProcessEntityId=$Entity");
            command.Parameters.AddWithValue("$Entity", query.ProcessEntityId);
        }
        if (!string.IsNullOrWhiteSpace(query.ExactEvidenceId))
        {
            clauses.Add("e." + definition.Id + "=$Exact");
            command.Parameters.AddWithValue("$Exact", query.ExactEvidenceId);
        }
        if (query.Family == ArtifactEvidenceFamily.Filesystem)
            clauses.Add("e.StructuredPayloadVersion IS NULL AND e.ArtifactType IN ('NtfsMft','NtfsUsnJournal','NtfsLogFile','Prefetch','FileMetadata')");
        var where = string.Join(" AND ", clauses);
        using var cancelled = token.Register(command.Cancel);
        command.CommandText = "SELECT COUNT(*),COALESCE(SUM(CASE WHEN COALESCE(e.SourceRunId,'')='' THEN 1 ELSE 0 END),0) FROM " + from + " WHERE " + where;
        long matching; long missingSourceRunRows;
        using (var counts = command.ExecuteReader())
        {
            counts.Read();
            matching = counts.GetInt64(0);
            missingSourceRunRows = counts.GetInt64(1);
        }
        var columns = identityColumns.Select(column => identityOwner + column).Concat(new[] { definition.Id, "SourceRunId", definition.Time }.Select(column => "e." + column))
            .Concat(fields.Select(field => "e.\"" + field.Column.Replace("\"", "\"\"") + "\""));
        command.CommandText = "SELECT " + string.Join(',', columns) + " FROM " + from + " WHERE " + where +
            " ORDER BY e." + definition.Time + " DESC,e." + definition.Id + " ASC LIMIT $Take OFFSET $Skip";
        command.Parameters.AddWithValue("$Take", query.PageSize);
        command.Parameters.AddWithValue("$Skip", query.Offset);
        using var reader = command.ExecuteReader();
        var rows = new List<ArtifactEvidenceReadRow>();
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            var rowScope = new EvidenceIdentity { CaseId = GetString(reader, 0), EvidenceSessionId = GetString(reader, 1),
                CaptureId = GetString(reader, 2), SourceIdentityId = GetString(reader, 3), HostId = GetString(reader, 4), ExecutionRootId = GetString(reader, 5) };
            var id = GetString(reader, 6); var run = GetString(reader, 7); var time = GetDateTime(reader, 8)?.ToUniversalTime();
            var valuesByName = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var index = 0; index < fields.Length; index++)
            {
                var nativeValue = reader.IsDBNull(index + 9) ? "<null>" : Convert.ToString(reader.GetValue(index + 9), CultureInfo.InvariantCulture) ?? string.Empty;
                valuesByName[fields[index].Name] = query.IncludeAllStoredFields && nativeValue.Length == 0 ? "<empty string>" : nativeValue;
            }
            foreach (var property in propertyFields) valuesByName[property.Key] = property.Value;
            rows.Add(new(rowScope, new(definition.Kind, id), query.Family == ArtifactEvidenceFamily.Filesystem ? "FilesystemArtifacts" : definition.Table, run,
                id + ":" + time?.Ticks.ToString(CultureInfo.InvariantCulture), time, valuesByName, storedFieldCount));
        }
        return new(rows.AsReadOnly(), matching, true, missingSourceRunRows);
    }

    private sealed record ArtifactPageDefinition(string Table, string Id, string Time, EvidenceReferenceKind Kind,
        bool ProcessAttached, (string Name, string Column)[] Fields);
    private static ArtifactPageDefinition PageDefinition(ArtifactEvidenceFamily family) => family switch
    {
        ArtifactEvidenceFamily.Filesystem => new("Artifacts", "ArtifactId", "TimestampUtc", EvidenceReferenceKind.FileArtifact, false,
            [("Kind", "ArtifactType"), ("Name", "Name"), ("Summary", "Summary"), ("SHA256", "Hash"), ("Source path metadata", "Path")]),
        ArtifactEvidenceFamily.Module => new("Modules", "ModuleKey", "LastSeenUtc", EvidenceReferenceKind.Module, true,
            [("Name", "ModuleName"), ("Path metadata", "FullPath"), ("State", "State"), ("SHA256", "Sha256Hash"), ("First seen UTC", "FirstSeenUtc"), ("Last seen UTC", "LastSeenUtc")]),
        ArtifactEvidenceFamily.Handle => new("Handles", "HandleKey", "LastSeenUtc", EvidenceReferenceKind.Handle, true,
            [("Handle", "HandleValue"), ("Type", "ObjectType"), ("Object name", "ObjectName"), ("State", "State"), ("Granted access", "GrantedAccess"), ("First seen UTC", "FirstSeenUtc"), ("Last seen UTC", "LastSeenUtc")]),
        ArtifactEvidenceFamily.Pe => new("PeAnalyses", "AnalysisId", "AnalyzedUtc", EvidenceReferenceKind.PeAnalysis, true,
            [("Status", "Status"), ("SHA256", "Sha256Hash"), ("Machine", "Machine"), ("Sections", "SectionCount"), ("Imports", "ImportCount"), ("String analysis", "StringAnalysisStatus")]),
        ArtifactEvidenceFamily.Signature => new("AuthenticodeVerifications", "VerificationId", "VerificationTimeUtc", EvidenceReferenceKind.AuthenticodeVerification, true,
            [("Status", "VerificationStatus"), ("Publisher", "Publisher"), ("Signer", "SignerSubject"), ("Policy", "VerificationPolicy"), ("Revocation", "RevocationStatus"), ("SHA256", "Sha256Hash")]),
        ArtifactEvidenceFamily.Dump => new("MemoryDumps", "DumpId", "RequestedUtc", EvidenceReferenceKind.MemoryDump, true,
            [("Status", "Status"), ("Kind", "DumpKind"), ("Size bytes", "FileSizeBytes"), ("SHA256", "Sha256Hash"), ("Error", "ErrorMessage")]),
        ArtifactEvidenceFamily.MemoryImage => new("MemoryImages", "ImageId", "ImportedUtc", EvidenceReferenceKind.MemoryImage, false,
            [("Status", "Status"), ("Name", "DisplayName"), ("Format", "ImageFormat"), ("SHA256", "Sha256Hash"), ("Size bytes", "FileSizeBytes")]),
        ArtifactEvidenceFamily.MemoryProcess => new("MemoryProcesses", "ArtifactId", "CreateTimeUtc", EvidenceReferenceKind.MemoryProcess, false,
            [("Image ID", "ImageId"), ("Plugin run", "PluginRunId"), ("Name", "ProcessName"), ("PID", "ProcessId"), ("Correlation", "CorrelationState"), ("Row hash", "RawRowHash")]),
        ArtifactEvidenceFamily.Volatility => new("VolatilityPluginRuns", "RunId", "RequestedUtc", EvidenceReferenceKind.VolatilityPluginRun, false,
            [("Status", "Status"), ("Plugin", "PluginName"), ("Image ID", "ImageId"), ("Normalized rows", "NormalizedRowCount"), ("Output hash", "RawOutputHash")]),
        ArtifactEvidenceFamily.Pcap => new("NetworkCaptures", "CaptureId", "RequestedUtc", EvidenceReferenceKind.Capture, false,
            [("Status", "Status"), ("SHA256", "Sha256Hash"), ("Size bytes", "FileSizeBytes"), ("Filter", "FilterDescription")]),
        ArtifactEvidenceFamily.Zeek => new("ZeekNetworkArtifacts", "ArtifactId", "TimestampUtc", EvidenceReferenceKind.NetworkFlow, false,
            [("Status", "Status"), ("Log", "LogType"), ("UID", "ZeekUid"), ("Summary", "Summary"), ("Correlation method", "CorrelationMethod"), ("Correlation confidence", "CorrelationConfidence")]),
        _ => throw new ArgumentOutOfRangeException(nameof(family))
    };
}
