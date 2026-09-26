using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal interface IFilesystemEvidenceWriteService
{
    void UpsertFilesystemArtifact(FilesystemArtifactRecord artifact);
    void UpsertFilesystemArtifacts(IEnumerable<FilesystemArtifactRecord> artifacts);
}

/// <summary>
/// Focused runtime filesystem-artifact evidence writer. The store facade owns
/// database selection, the connection, and transaction lifetime; this component
/// owns only family-specific raw/normalized rows, properties, lineage, and search.
/// </summary>
internal sealed class FilesystemEvidenceWriteService : IFilesystemEvidenceWriteService
{
    private readonly SqliteWriteTransactionContext _context;

    internal FilesystemEvidenceWriteService(SqliteWriteTransactionContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public void UpsertFilesystemArtifact(FilesystemArtifactRecord artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        _context.Execute(() =>
        {
            using var rawRecord = CreateRawRecordInsertCommand();
            using var normalizedArtifact = CreateArtifactUpsertCommand();
            using var deleteProperties = CreatePropertyDeleteCommand();
            using var insertProperty = CreatePropertyInsertCommand();
            WriteFilesystemArtifactCore(
                artifact,
                rawRecord,
                normalizedArtifact,
                deleteProperties,
                insertProperty);
        });
    }

    public void UpsertFilesystemArtifacts(IEnumerable<FilesystemArtifactRecord> artifacts)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        var snapshot = artifacts.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var rawRecord = CreateRawRecordInsertCommand();
            using var normalizedArtifact = CreateArtifactUpsertCommand();
            using var deleteProperties = CreatePropertyDeleteCommand();
            using var insertProperty = CreatePropertyInsertCommand();
            rawRecord.Prepare();
            normalizedArtifact.Prepare();
            deleteProperties.Prepare();
            insertProperty.Prepare();

            foreach (var artifact in snapshot)
            {
                ArgumentNullException.ThrowIfNull(artifact);
                WriteFilesystemArtifactCore(
                    artifact,
                    rawRecord,
                    normalizedArtifact,
                    deleteProperties,
                    insertProperty);
            }
        });
    }

    private void WriteFilesystemArtifactCore(
        FilesystemArtifactRecord artifact,
        SqliteCommand rawRecord,
        SqliteCommand normalizedArtifact,
        SqliteCommand deleteProperties,
        SqliteCommand insertProperty)
    {
        artifact.ArtifactId = NormalizeIdentifier(artifact.ArtifactId);
        var sourceId = _context.EnsureTelemetrySource(artifact.Source, "FilesystemArtifact");
        var identity = _context.ResolveEvidenceIdentity(artifact, "FilesystemArtifact", artifact.Source);
        ApplyEvidenceIdentity(artifact, identity);
        _context.ApplyFilesystemEvidenceProvenance(artifact);

        var rawRecordId = InsertRawRecord(rawRecord, sourceId, identity, artifact);
        UpsertNormalizedArtifact(normalizedArtifact, sourceId, identity, rawRecordId, artifact);
        artifact.RawRecordId = rawRecordId.ToString(CultureInfo.InvariantCulture);

        _context.PersistFilesystemSourceRunRelation(
            artifact,
            artifact.ArtifactId,
            artifact.TimestampUtc,
            artifact.RawPayloadHash);
        ReplaceArtifactProperties(deleteProperties, insertProperty, artifact);
        _context.UpsertSearchIndex(CreateFilesystemArtifactSearchIndexRow(artifact));
    }

    private long InsertRawRecord(
        SqliteCommand command,
        int? sourceId,
        EvidenceIdentity identity,
        FilesystemArtifactRecord artifact)
    {
        Set(command, "$CaseId", identity.CaseId);
        Set(command, "$EvidenceSessionId", identity.EvidenceSessionId);
        Set(command, "$CaptureId", identity.CaptureId);
        Set(command, "$SourceIdentityId", identity.SourceIdentityId);
        Set(command, "$HostId", identity.HostId);
        Set(command, "$ExecutionRootId", identity.ExecutionRootId);
        Set(command, "$SourceRunId", EmptyToNull(artifact.SourceRunId));
        Set(command, "$IngestionJobId", EmptyToNull(artifact.IngestionJobId));
        Set(command, "$SourceId", sourceId);
        Set(command, "$ExternalRecordId", artifact.ArtifactId);
        Set(command, "$TimestampUtc", artifact.TimestampUtc);
        Set(command, "$RecordType", artifact.Kind.ToString());
        Set(command, "$PayloadJson", JsonSerializer.Serialize(artifact.Properties));
        Set(command, "$PayloadText", artifact.RawText);
        Set(command, "$PayloadHash", artifact.RawPayloadHash);
        Set(command, "$CreatedUtc", DateTime.UtcNow);
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static void UpsertNormalizedArtifact(
        SqliteCommand command,
        int? sourceId,
        EvidenceIdentity identity,
        long rawRecordId,
        FilesystemArtifactRecord artifact)
    {
        var now = DateTime.UtcNow;
        Set(command, "$ArtifactId", artifact.ArtifactId);
        Set(command, "$CaseId", identity.CaseId);
        Set(command, "$EvidenceSessionId", identity.EvidenceSessionId);
        Set(command, "$CaptureId", identity.CaptureId);
        Set(command, "$SourceIdentityId", identity.SourceIdentityId);
        Set(command, "$HostId", identity.HostId);
        Set(command, "$ExecutionRootId", identity.ExecutionRootId);
        Set(command, "$SourceRunId", EmptyToNull(artifact.SourceRunId));
        Set(command, "$IngestionJobId", artifact.IngestionJobId);
        Set(command, "$ArtifactType", artifact.Kind.ToString());
        Set(command, "$SourceId", sourceId);
        Set(command, "$TimestampUtc", artifact.TimestampUtc);
        Set(command, "$Name", artifact.Name);
        Set(command, "$Path", artifact.SourcePath);
        Set(command, "$Summary", artifact.Summary);
        Set(command, "$Hash", artifact.Sha256Hash);
        Set(command, "$ProcessKey", string.Empty);
        Set(command, "$ParentArtifactId", artifact.ParentArtifactId);
        Set(command, "$CreatedUtc", now);
        Set(command, "$UpdatedUtc", now);
        Set(command, "$RawRecordId", rawRecordId);
        command.ExecuteNonQuery();
    }

    private static void ReplaceArtifactProperties(
        SqliteCommand deleteProperties,
        SqliteCommand insertProperty,
        FilesystemArtifactRecord artifact)
    {
        Set(deleteProperties, "$ArtifactId", artifact.ArtifactId);
        deleteProperties.ExecuteNonQuery();

        var properties = new Dictionary<string, string>(artifact.Properties, StringComparer.OrdinalIgnoreCase)
        {
            ["Status"] = artifact.Status.ToString(),
            ["FileSizeBytes"] = artifact.FileSizeBytes.ToString(CultureInfo.InvariantCulture),
            ["Sha256Hash"] = artifact.Sha256Hash,
            ["ProcessName"] = artifact.ProcessName,
            ["RunCount"] = artifact.RunCount.ToString(CultureInfo.InvariantCulture),
            ["ErrorMessage"] = artifact.ErrorMessage
        };
        if (artifact.CreatedUtc.HasValue)
        {
            properties["CreatedUtc"] = artifact.CreatedUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (artifact.LastModifiedUtc.HasValue)
        {
            properties["LastModifiedUtc"] = artifact.LastModifiedUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (artifact.LastRunUtc.HasValue)
        {
            properties["LastRunUtc"] = artifact.LastRunUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        foreach (var property in properties.Where(property => !string.IsNullOrWhiteSpace(property.Value)))
        {
            Set(insertProperty, "$ArtifactId", artifact.ArtifactId);
            Set(insertProperty, "$Name", property.Key);
            Set(insertProperty, "$Value", property.Value);
            Set(insertProperty, "$ValueType", "String");
            insertProperty.ExecuteNonQuery();
        }
    }

    private SqliteCommand CreateRawRecordInsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO RawRecords (
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, SourceId, ExternalRecordId, TimestampUtc, RecordType,
                PayloadJson, PayloadText, PayloadHash, CreatedUtc)
            VALUES (
                $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceRunId, $IngestionJobId, $SourceId, $ExternalRecordId, $TimestampUtc, $RecordType,
                $PayloadJson, $PayloadText, $PayloadHash, $CreatedUtc);
            SELECT last_insert_rowid();
            """);
        AddParameters(command, new[]
        {
            "$CaseId", "$EvidenceSessionId", "$CaptureId", "$SourceIdentityId", "$HostId", "$ExecutionRootId",
            "$SourceRunId", "$IngestionJobId", "$SourceId", "$ExternalRecordId", "$TimestampUtc", "$RecordType",
            "$PayloadJson", "$PayloadText", "$PayloadHash", "$CreatedUtc"
        });
        return command;
    }

    private SqliteCommand CreateArtifactUpsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO Artifacts (
                ArtifactId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, ArtifactType, SourceId, TimestampUtc, Name, Path, Summary, Hash,
                ProcessKey, ParentArtifactId, CreatedUtc, UpdatedUtc, RawRecordId)
            VALUES (
                $ArtifactId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceRunId, $IngestionJobId, $ArtifactType, $SourceId, $TimestampUtc, $Name, $Path, $Summary, $Hash,
                $ProcessKey, $ParentArtifactId, $CreatedUtc, $UpdatedUtc, $RawRecordId)
            ON CONFLICT(ArtifactId) DO UPDATE SET
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceRunId = excluded.SourceRunId,
                IngestionJobId = excluded.IngestionJobId,
                ArtifactType = excluded.ArtifactType,
                SourceId = excluded.SourceId,
                TimestampUtc = excluded.TimestampUtc,
                Name = excluded.Name,
                Path = excluded.Path,
                Summary = excluded.Summary,
                Hash = excluded.Hash,
                ParentArtifactId = excluded.ParentArtifactId,
                UpdatedUtc = excluded.UpdatedUtc,
                RawRecordId = excluded.RawRecordId;
            """);
        AddParameters(command, new[]
        {
            "$ArtifactId", "$CaseId", "$EvidenceSessionId", "$CaptureId", "$SourceIdentityId", "$HostId",
            "$ExecutionRootId", "$SourceRunId", "$IngestionJobId", "$ArtifactType", "$SourceId", "$TimestampUtc",
            "$Name", "$Path", "$Summary", "$Hash", "$ProcessKey", "$ParentArtifactId", "$CreatedUtc",
            "$UpdatedUtc", "$RawRecordId"
        });
        return command;
    }

    private SqliteCommand CreatePropertyDeleteCommand()
    {
        var command = _context.CreateCommand("DELETE FROM ArtifactProperties WHERE ArtifactId = $ArtifactId;");
        SqliteWriteTransactionContext.Add(command, "$ArtifactId", null);
        return command;
    }

    private SqliteCommand CreatePropertyInsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT OR REPLACE INTO ArtifactProperties (ArtifactId, Name, Value, ValueType)
            VALUES ($ArtifactId, $Name, $Value, $ValueType);
            """);
        AddParameters(command, new[] { "$ArtifactId", "$Name", "$Value", "$ValueType" });
        return command;
    }

    internal static SearchIndexRow CreateFilesystemArtifactSearchIndexRow(FilesystemArtifactRecord artifact)
    {
        var details = string.Join(
            Environment.NewLine,
            artifact.Properties.Select(property => $"{property.Key}: {property.Value}"));
        return new SearchIndexRow
        {
            Kind = "FilesystemArtifact",
            RecordKey = artifact.ArtifactId,
            TimestampUtc = SqliteWriteTransactionContext.FormatDate(artifact.TimestampUtc),
            Source = artifact.Source,
            Title = $"{artifact.Kind}: {artifact.Name}",
            Subtitle = artifact.Summary,
            StatusText = artifact.Status.ToString(),
            ProcessNameText = artifact.ProcessName,
            PathText = artifact.SourcePath,
            Sha256Text = artifact.Sha256Hash,
            TargetText = artifact.Name,
            SummaryText = artifact.Summary,
            DetailsText = string.Join(
                " ",
                new[]
                {
                    details,
                    artifact.RawText,
                    artifact.SourceRunId,
                    artifact.IngestionJobId,
                    artifact.ErrorMessage
                }.Where(value => !string.IsNullOrWhiteSpace(value))),
            CategoryText = "FilesystemArtifact",
            ActionText = artifact.Kind.ToString()
        }.WithSearchText();
    }

    private static void ApplyEvidenceIdentity(IHasEvidenceIdentity record, EvidenceIdentity identity)
    {
        record.CaseId = identity.CaseId;
        record.EvidenceSessionId = identity.EvidenceSessionId;
        record.CaptureId = identity.CaptureId;
        record.SourceIdentityId = identity.SourceIdentityId;
        record.HostId = identity.HostId;
        record.ExecutionRootId = identity.ExecutionRootId;
    }

    private static void AddParameters(SqliteCommand command, IEnumerable<string> names)
    {
        foreach (var name in names)
        {
            SqliteWriteTransactionContext.Add(command, name, null);
        }
    }

    private static string NormalizeIdentifier(string value)
        => string.IsNullOrWhiteSpace(value) ? Guid.NewGuid().ToString("N") : value;

    private static object? EmptyToNull(string value)
        => string.IsNullOrWhiteSpace(value) ? null : value;

    private static void Set(SqliteCommand command, string name, object? value)
    {
        if (value is DateTime dateTime)
        {
            value = SqliteWriteTransactionContext.FormatDate(dateTime);
        }

        command.Parameters[name].Value = value ?? DBNull.Value;
    }
}
