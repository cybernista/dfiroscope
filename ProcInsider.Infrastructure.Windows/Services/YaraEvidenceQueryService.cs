using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum YaraEvidenceTargetResolutionState
{
    Resolved = 0,
    NotFound = 1,
    Ambiguous = 2,
    InvalidStatus = 3,
    MetadataMismatch = 4
}

public sealed record YaraEvidenceTargetRecord
{
    public YaraScanTargetKind Kind { get; init; }

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string SourceRunId { get; init; } = string.Empty;

    public EvidenceReference EvidenceReference { get; init; } =
        new(EvidenceReferenceKind.GenericArtifact, string.Empty);

    public string FilePath { get; init; } = string.Empty;

    public long FileSizeBytes { get; init; }

    public string RecordedContentHashSha256 { get; init; } = string.Empty;

    public string Status { get; init; } = string.Empty;
}

public sealed record YaraEvidenceTargetResolution
{
    public YaraEvidenceTargetResolutionState State { get; init; }

    public YaraEvidenceTargetRecord? Target { get; init; }
}

public interface IYaraEvidenceQueryService
{
    YaraEvidenceTargetResolution ResolveExactTarget(YaraScanTarget target);
}

/// <summary>
/// Exact, parameterized read owner for the Agent YARA execution boundary. It
/// resolves only the current evidence identity/source run/reference tuple and
/// returns recorded file metadata; it never reads target bytes or launches a
/// scanner.
/// </summary>
internal sealed class YaraEvidenceQueryService : IYaraEvidenceQueryService
{
    private readonly SqliteReadQueryContext _readContext;

    internal YaraEvidenceQueryService(SqliteReadQueryContext readContext)
    {
        _readContext = readContext;
    }

    public YaraEvidenceTargetResolution ResolveExactTarget(YaraScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);

        return _readContext.MeasureRead(
            "ResolveExactYaraTarget",
            () => ResolveCore(target),
            $"kind={target.Kind}; reference={target.EvidenceReference?.Kind}",
            result => result.State == YaraEvidenceTargetResolutionState.Resolved ? 1 : 0);
    }

    private YaraEvidenceTargetResolution ResolveCore(YaraScanTarget target)
    {
        if (target.EvidenceIdentity == null || target.EvidenceReference == null ||
            target.EvidenceReference.IsEmpty)
        {
            return Reject(YaraEvidenceTargetResolutionState.NotFound);
        }

        using var connection = _readContext.OpenReadOnlyConnection();
        return target.Kind switch
        {
            YaraScanTargetKind.FileArtifact when
                target.EvidenceReference.Kind == EvidenceReferenceKind.FileArtifact =>
                ResolveFileArtifact(connection, target),
            YaraScanTargetKind.MemoryDump when
                target.EvidenceReference.Kind == EvidenceReferenceKind.MemoryDump =>
                ResolveMemoryDump(connection, target),
            YaraScanTargetKind.MemoryImageRegion when
                target.EvidenceReference.Kind == EvidenceReferenceKind.MemoryImage =>
                ResolveMemoryImage(connection, target),
            _ => Reject(YaraEvidenceTargetResolutionState.NotFound)
        };
    }

    private static YaraEvidenceTargetResolution ResolveFileArtifact(
        SqliteConnection connection,
        YaraScanTarget target)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT a.ArtifactId, a.Path, a.Hash, a.CaseId, a.EvidenceSessionId,
                   a.CaptureId, a.SourceIdentityId, a.HostId, a.ExecutionRootId,
                   a.SourceRunId,
                   COALESCE((SELECT p.Value FROM ArtifactProperties p
                             WHERE p.ArtifactId = a.ArtifactId AND p.Name = 'Status'
                             LIMIT 1), ''),
                   COALESCE((SELECT p.Value FROM ArtifactProperties p
                             WHERE p.ArtifactId = a.ArtifactId AND p.Name = 'FileSizeBytes'
                             LIMIT 1), '0')
            FROM Artifacts a
            WHERE a.ArtifactId = $ReferenceId
              AND a.CaseId = $CaseId
              AND a.EvidenceSessionId = $EvidenceSessionId
              AND a.CaptureId = $CaptureId
              AND a.SourceIdentityId = $SourceIdentityId
              AND a.HostId = $HostId
              AND a.ExecutionRootId = $ExecutionRootId
              AND a.SourceRunId = $SourceRunId
            LIMIT 2;
            """;
        AddTargetParameters(command, target);
        var rows = new List<YaraEvidenceTargetRecord>(2);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new YaraEvidenceTargetRecord
            {
                Kind = YaraScanTargetKind.FileArtifact,
                EvidenceReference = new EvidenceReference(
                    EvidenceReferenceKind.FileArtifact,
                    GetString(reader, 0)),
                FilePath = GetString(reader, 1),
                RecordedContentHashSha256 = GetString(reader, 2),
                EvidenceIdentity = ReadIdentity(reader, 3),
                SourceRunId = GetString(reader, 9),
                Status = GetString(reader, 10),
                FileSizeBytes = ParseLong(GetString(reader, 11))
            });
        }

        return Finish(target, rows, FilesystemArtifactStatus.Imported.ToString());
    }

    private static YaraEvidenceTargetResolution ResolveMemoryDump(
        SqliteConnection connection,
        YaraScanTarget target)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT d.DumpId, d.FilePath, d.Sha256Hash, d.CaseId,
                   d.EvidenceSessionId, d.CaptureId, d.SourceIdentityId,
                   d.HostId, d.ExecutionRootId, d.SourceRunId, d.Status,
                   d.FileSizeBytes
            FROM MemoryDumps d
            WHERE d.DumpId = $ReferenceId
              AND d.CaseId = $CaseId
              AND d.EvidenceSessionId = $EvidenceSessionId
              AND d.CaptureId = $CaptureId
              AND d.SourceIdentityId = $SourceIdentityId
              AND d.HostId = $HostId
              AND d.ExecutionRootId = $ExecutionRootId
              AND d.SourceRunId = $SourceRunId
            LIMIT 2;
            """;
        AddTargetParameters(command, target);
        var rows = ReadRows(
            command,
            YaraScanTargetKind.MemoryDump,
            EvidenceReferenceKind.MemoryDump);
        return Finish(target, rows, MemoryDumpStatus.Captured.ToString());
    }

    private static YaraEvidenceTargetResolution ResolveMemoryImage(
        SqliteConnection connection,
        YaraScanTarget target)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT m.ImageId, m.FilePath, m.Sha256Hash, m.CaseId,
                   m.EvidenceSessionId, m.CaptureId, m.SourceIdentityId,
                   m.HostId, m.ExecutionRootId, m.SourceRunId, m.Status,
                   m.FileSizeBytes
            FROM MemoryImages m
            WHERE m.ImageId = $ReferenceId
              AND m.CaseId = $CaseId
              AND m.EvidenceSessionId = $EvidenceSessionId
              AND m.CaptureId = $CaptureId
              AND m.SourceIdentityId = $SourceIdentityId
              AND m.HostId = $HostId
              AND m.ExecutionRootId = $ExecutionRootId
              AND m.SourceRunId = $SourceRunId
            LIMIT 2;
            """;
        AddTargetParameters(command, target);
        var rows = ReadRows(
            command,
            YaraScanTargetKind.MemoryImageRegion,
            EvidenceReferenceKind.MemoryImage);
        return Finish(target, rows, MemoryImageStatus.Imported.ToString());
    }

    private static List<YaraEvidenceTargetRecord> ReadRows(
        SqliteCommand command,
        YaraScanTargetKind targetKind,
        EvidenceReferenceKind referenceKind)
    {
        var rows = new List<YaraEvidenceTargetRecord>(2);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new YaraEvidenceTargetRecord
            {
                Kind = targetKind,
                EvidenceReference = new EvidenceReference(referenceKind, GetString(reader, 0)),
                FilePath = GetString(reader, 1),
                RecordedContentHashSha256 = GetString(reader, 2),
                EvidenceIdentity = ReadIdentity(reader, 3),
                SourceRunId = GetString(reader, 9),
                Status = GetString(reader, 10),
                FileSizeBytes = reader.IsDBNull(11) ? 0 : reader.GetInt64(11)
            });
        }

        return rows;
    }

    private static YaraEvidenceTargetResolution Finish(
        YaraScanTarget request,
        IReadOnlyList<YaraEvidenceTargetRecord> rows,
        string requiredStatus)
    {
        if (rows.Count == 0)
        {
            return Reject(YaraEvidenceTargetResolutionState.NotFound);
        }

        if (rows.Count != 1)
        {
            return Reject(YaraEvidenceTargetResolutionState.Ambiguous);
        }

        var row = rows[0];
        if (!string.Equals(row.Status, requiredStatus, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(row.FilePath) || row.FileSizeBytes <= 0)
        {
            return Reject(YaraEvidenceTargetResolutionState.InvalidStatus);
        }

        var fullTarget = request.Kind is YaraScanTargetKind.FileArtifact or YaraScanTargetKind.MemoryDump;
        var rangeEnd = request.OffsetBytes > long.MaxValue - request.LengthBytes
            ? long.MaxValue
            : request.OffsetBytes + request.LengthBytes;
        var metadataMatches = fullTarget
            ? request.OffsetBytes == 0 && request.LengthBytes == row.FileSizeBytes &&
              string.Equals(
                  request.ContentHashSha256,
                  row.RecordedContentHashSha256,
                  StringComparison.OrdinalIgnoreCase)
            : request.OffsetBytes >= 0 && request.LengthBytes > 0 && rangeEnd <= row.FileSizeBytes;
        if (!metadataMatches)
        {
            return Reject(YaraEvidenceTargetResolutionState.MetadataMismatch);
        }

        return new YaraEvidenceTargetResolution
        {
            State = YaraEvidenceTargetResolutionState.Resolved,
            Target = row
        };
    }

    private static void AddTargetParameters(SqliteCommand command, YaraScanTarget target)
    {
        command.Parameters.AddWithValue("$ReferenceId", target.EvidenceReference.Id);
        command.Parameters.AddWithValue("$CaseId", target.EvidenceIdentity.CaseId);
        command.Parameters.AddWithValue("$EvidenceSessionId", target.EvidenceIdentity.EvidenceSessionId);
        command.Parameters.AddWithValue("$CaptureId", target.EvidenceIdentity.CaptureId);
        command.Parameters.AddWithValue("$SourceIdentityId", target.EvidenceIdentity.SourceIdentityId);
        command.Parameters.AddWithValue("$HostId", target.EvidenceIdentity.HostId);
        command.Parameters.AddWithValue("$ExecutionRootId", target.EvidenceIdentity.ExecutionRootId);
        command.Parameters.AddWithValue("$SourceRunId", target.SourceRunId);
    }

    private static EvidenceIdentity ReadIdentity(SqliteDataReader reader, int firstOrdinal) => new()
    {
        CaseId = GetString(reader, firstOrdinal),
        EvidenceSessionId = GetString(reader, firstOrdinal + 1),
        CaptureId = GetString(reader, firstOrdinal + 2),
        SourceIdentityId = GetString(reader, firstOrdinal + 3),
        HostId = GetString(reader, firstOrdinal + 4),
        ExecutionRootId = GetString(reader, firstOrdinal + 5)
    };

    private static string GetString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private static long ParseLong(string value) =>
        long.TryParse(value, System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 0;

    private static YaraEvidenceTargetResolution Reject(
        YaraEvidenceTargetResolutionState state) => new() { State = state };
}
