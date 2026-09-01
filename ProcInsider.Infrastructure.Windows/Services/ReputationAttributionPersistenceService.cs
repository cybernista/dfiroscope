using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum ReputationAttributionPersistenceOutcome
{
    Created = 0,
    Unchanged = 1
}

public sealed record ReputationAttributionPersistenceResult(
    ReputationAttributionPersistenceOutcome Outcome,
    string AttributionHashSha256,
    string PayloadHashSha256);

internal sealed record PersistedReputationAttribution(
    ReputationProcessAttributionResult Attribution,
    string AttributionJson,
    string PayloadHashSha256,
    EvidenceReference SourceReference,
    string RelationId);

internal static class ReputationAttributionPersistencePolicy
{
    internal const int MaximumSerializedLength = 256 * 1024;
    internal const int MaximumRowsPerProcess = 256;
    internal const int MaximumReadRows = 256;

    internal static PersistedReputationAttribution Normalize(
        ReputationProcessAttributionResult attribution)
    {
        ArgumentNullException.ThrowIfNull(attribution);
        var validation = ReputationProcessAttributionContract.Validate(attribution);
        if (!validation.Accepted || validation.Result == null)
        {
            throw new InvalidDataException(
                $"The reputation attribution failed canonical validation ({validation.Failure}).");
        }

        var canonical = validation.Result;
        var sourceReferences = canonical.EvidenceReferences
            .Where(reference => reference.Kind is EvidenceReferenceKind.ProcessObservation or
                EvidenceReferenceKind.FileArtifact)
            .ToArray();
        if (sourceReferences.Length != 1)
        {
            throw new InvalidDataException(
                "A persisted reputation attribution must cite exactly one source record.");
        }

        var relationReferences = canonical.EvidenceReferences
            .Where(reference => reference.Kind == EvidenceReferenceKind.EvidenceRelation)
            .ToArray();
        var expectedRelations = sourceReferences[0].Kind == EvidenceReferenceKind.FileArtifact ? 1 : 0;
        if (relationReferences.Length != expectedRelations)
        {
            throw new InvalidDataException(
                "A persisted reputation attribution has an invalid relation-reference shape.");
        }

        var json = JsonSerializer.Serialize(canonical);
        if (Encoding.UTF8.GetByteCount(json) > MaximumSerializedLength)
        {
            throw new InvalidDataException(
                "The canonical reputation attribution exceeds the bounded persistence limit.");
        }

        return new PersistedReputationAttribution(
            canonical,
            json,
            Sha256(json),
            sourceReferences[0] with { },
            relationReferences.SingleOrDefault()?.Id ?? string.Empty);
    }

    internal static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    internal static bool MatchesIndexedRow(
        SqliteDataReader reader,
        PersistedReputationAttribution row)
    {
        var item = row.Attribution;
        var result = item.Receipt.Result;
        var provider = result.Provider;
        var relationId = reader.IsDBNull(13) ? string.Empty : reader.GetString(13);
        return string.Equals(item.AttributionHashSha256, reader.GetString(0),
                   StringComparison.Ordinal) &&
               string.Equals(item.ProcessEntityId, reader.GetString(1),
                   StringComparison.Ordinal) &&
               string.Equals(item.ProcessKey, reader.GetString(2),
                   StringComparison.Ordinal) &&
               (int)item.SourceKind == reader.GetInt32(3) &&
               string.Equals(provider.ProviderId, reader.GetString(4),
                   StringComparison.Ordinal) &&
               string.Equals(provider.ProviderVersion, reader.GetString(5),
                   StringComparison.Ordinal) &&
               string.Equals(provider.DatasetId, reader.GetString(6),
                   StringComparison.Ordinal) &&
               string.Equals(provider.DatasetVersion, reader.GetString(7),
                   StringComparison.Ordinal) &&
               (int)provider.QueryMode == reader.GetInt32(8) &&
               string.Equals(item.TargetRequest.Indicator.Value, reader.GetString(9),
                   StringComparison.Ordinal) &&
               string.Equals(item.TargetRequest.SourceRunId, reader.GetString(10),
                   StringComparison.Ordinal) &&
               (int)row.SourceReference.Kind == reader.GetInt32(11) &&
               string.Equals(row.SourceReference.Id, reader.GetString(12),
                   StringComparison.Ordinal) &&
               string.Equals(row.RelationId, relationId, StringComparison.Ordinal) &&
               (int)result.Availability == reader.GetInt32(14) &&
               result.RecordFound == (reader.GetInt64(15) != 0) &&
               result.AnalyzedCount == reader.GetInt32(16) &&
               result.PositiveCount == reader.GetInt32(17) &&
               result.SuspiciousCount == reader.GetInt32(18) &&
               result.UndetectedCount == reader.GetInt32(19) &&
               string.Equals(FormatUtc(result.RetrievedUtc), reader.GetString(20),
                   StringComparison.Ordinal) &&
               string.Equals(FormatUtc(item.Receipt.CompletedUtc), reader.GetString(21),
                   StringComparison.Ordinal) &&
               string.Equals(item.Receipt.ReceiptHashSha256, reader.GetString(22),
                   StringComparison.Ordinal) &&
               string.Equals(item.CacheEvaluation?.DecisionHashSha256 ?? string.Empty,
                   reader.GetString(23), StringComparison.Ordinal) &&
               string.Equals(row.PayloadHashSha256, reader.GetString(24),
                   StringComparison.Ordinal) &&
               string.Equals(row.AttributionJson, reader.GetString(25),
                   StringComparison.Ordinal);
    }

    private static string FormatUtc(DateTime value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
}

/// <summary>
/// Store-owned derived-analysis writer. The offered portable attribution is
/// reconstructed from exact persisted records inside the store transaction
/// before its immutable canonical row is admitted.
/// </summary>
internal sealed class ReputationAttributionPersistenceService
{
    private readonly SqliteWriteTransactionContext _context;

    internal ReputationAttributionPersistenceService(SqliteWriteTransactionContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    internal ReputationAttributionPersistenceResult Persist(
        ReputationProcessAttributionResult attribution,
        CancellationToken cancellationToken)
    {
        var offered = ReputationAttributionPersistencePolicy.Normalize(attribution);
        cancellationToken.ThrowIfCancellationRequested();
        ReputationAttributionPersistenceResult? result = null;
        _context.Execute(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureSchemaPresent();
            ValidateExactSourceRun(offered.Attribution.TargetRequest);

            var process = ReadExactProcess(offered.Attribution.ProcessEntityId) ??
                throw new InvalidDataException(
                    "The attributed durable process entity is not persisted.");
            ProcessObservation? observation = null;
            FilesystemArtifactRecord? artifact = null;
            EvidenceRelation? relation = null;
            if (offered.SourceReference.Kind == EvidenceReferenceKind.ProcessObservation)
            {
                observation = ReadExactObservation(offered.SourceReference.Id) ??
                    throw new InvalidDataException(
                        "The cited process observation is not persisted.");
            }
            else
            {
                artifact = ReadExactArtifact(offered.SourceReference.Id) ??
                    throw new InvalidDataException(
                        "The cited file artifact is not persisted.");
                relation = ReadExactRelation(offered.RelationId) ??
                    throw new InvalidDataException(
                        "The cited file-to-process relation is not persisted.");
            }

            var reconstructed = ReputationProcessAttributionNormalizer.Normalize(
                new ReputationProcessAttributionNormalizationRequest
                {
                    Attribution = offered.Attribution,
                    Process = process,
                    ProcessObservation = observation,
                    FileArtifact = artifact,
                    Relation = relation
                });
            if (!reconstructed.Accepted || reconstructed.Result == null)
            {
                throw new InvalidDataException(
                    $"The persisted reputation evidence failed canonical reconstruction " +
                    $"({reconstructed.Failure}: {reconstructed.Diagnostic}).");
            }

            var canonical = ReputationAttributionPersistencePolicy.Normalize(reconstructed.Result);
            if (!string.Equals(offered.AttributionJson, canonical.AttributionJson,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "The offered reputation attribution disagrees with its persisted-evidence reconstruction.");
            }

            var existing = ReadExisting(canonical);
            if (existing != null)
            {
                if (string.Equals(existing.Value.PayloadHashSha256,
                        canonical.PayloadHashSha256, StringComparison.Ordinal) &&
                    string.Equals(existing.Value.AttributionJson,
                        canonical.AttributionJson, StringComparison.Ordinal))
                {
                    result = new ReputationAttributionPersistenceResult(
                        ReputationAttributionPersistenceOutcome.Unchanged,
                        canonical.Attribution.AttributionHashSha256,
                        canonical.PayloadHashSha256);
                    return;
                }

                throw new InvalidDataException(
                    "The reputation attribution identity conflicts with a different canonical payload.");
            }

            EnsureProcessRowCapacity(canonical.Attribution.ProcessEntityId);
            Insert(canonical);
            cancellationToken.ThrowIfCancellationRequested();
            result = new ReputationAttributionPersistenceResult(
                ReputationAttributionPersistenceOutcome.Created,
                canonical.Attribution.AttributionHashSha256,
                canonical.PayloadHashSha256);
        });
        return result ?? throw new InvalidOperationException(
            "The reputation attribution transaction produced no result.");
    }

    private void EnsureSchemaPresent()
    {
        using var command = _context.CreateCommand(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ReputationAttributions';");
        if (Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) != 1)
        {
            throw new InvalidDataException(
                "The cataloged reputation-attribution analysis schema is unavailable.");
        }
    }

    private void ValidateExactSourceRun(ReputationLookupRequest request)
    {
        using var command = _context.CreateCommand("""
            SELECT COUNT(*)
            FROM SourceRuns
            WHERE SourceRunId = $SourceRunId
              AND CaseId = $CaseId
              AND EvidenceSessionId = $EvidenceSessionId
              AND CaptureId = $CaptureId
              AND SourceIdentityId = $SourceIdentityId
              AND HostId = $HostId
              AND ExecutionRootId = $ExecutionRootId;
            """);
        Add(command, "$SourceRunId", request.SourceRunId);
        Add(command, "$CaseId", request.EvidenceIdentity.CaseId);
        Add(command, "$EvidenceSessionId", request.EvidenceIdentity.EvidenceSessionId);
        Add(command, "$CaptureId", request.EvidenceIdentity.CaptureId);
        Add(command, "$SourceIdentityId", request.EvidenceIdentity.SourceIdentityId);
        Add(command, "$HostId", request.EvidenceIdentity.HostId);
        Add(command, "$ExecutionRootId", request.EvidenceIdentity.ExecutionRootId);
        if (Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) != 1)
        {
            throw new InvalidDataException(
                "The reputation attribution source run does not match the complete evidence scope.");
        }
    }

    private ProcessRecord? ReadExactProcess(string processEntityId)
    {
        using var command = _context.CreateCommand("""
            SELECT ProcessEntityId, ProcessKey, CaseId, EvidenceSessionId, CaptureId,
                   SourceIdentityId, HostId, ExecutionRootId, Sha256Hash
            FROM ProcessEntities
            WHERE ProcessEntityId = $ProcessEntityId
            LIMIT 2;
            """);
        Add(command, "$ProcessEntityId", processEntityId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var process = new ProcessRecord
        {
            ProcessEntityId = GetString(reader, 0),
            ProcessKey = GetString(reader, 1),
            CaseId = GetString(reader, 2),
            EvidenceSessionId = GetString(reader, 3),
            CaptureId = GetString(reader, 4),
            SourceIdentityId = GetString(reader, 5),
            HostId = GetString(reader, 6),
            ExecutionRootId = GetString(reader, 7),
            Sha256Hash = GetString(reader, 8)
        };
        EnsureSingle(reader, "durable process entity");
        return process;
    }

    private ProcessObservation? ReadExactObservation(string observationId)
    {
        using var command = _context.CreateCommand("""
            SELECT ProcessEntityId, ObservationId, AdapterId, ObservationKind, SourceRunId,
                   IngestionJobId, RawRecordId, SourceNativeAlias, ObservedUtc, ValidFromUtc,
                   ValidToUtc, StatusAssertion, CorrelationMethod, CorrelationConfidence,
                   ParserVersion, FieldStatesJson, MetadataJson, PayloadJson
            FROM ProcessObservations
            WHERE ObservationId = $ObservationId
            LIMIT 2;
            """);
        Add(command, "$ObservationId", observationId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var fields = Deserialize<ProcessRecord>(GetString(reader, 17),
            "The cited process-observation payload is malformed.");
        var fieldStates = Deserialize<Dictionary<string, ProcessObservationValueState>>(
            GetString(reader, 15),
            "The cited process-observation field states are malformed.");
        var observation = new ProcessObservation
        {
            ProcessEntityId = GetString(reader, 0),
            ObservationId = GetString(reader, 1),
            AdapterId = GetString(reader, 2),
            ObservationKind = GetEnum<ProcessObservationKind>(reader, 3),
            SourceRunId = GetString(reader, 4),
            IngestionJobId = Guid.TryParse(GetString(reader, 5), out var jobId) ? jobId : null,
            RawRecordId = GetString(reader, 6),
            SourceNativeAlias = GetString(reader, 7),
            ObservedUtc = GetUtc(reader, 8),
            ValidFromUtc = GetNullableUtc(reader, 9),
            ValidToUtc = GetNullableUtc(reader, 10),
            StatusAssertion = GetEnum<ProcessStatus>(reader, 11),
            CorrelationMethod = GetEnum<ProcessCorrelationMethod>(reader, 12),
            CorrelationConfidence = reader.IsDBNull(13) ? 0d : reader.GetDouble(13),
            ParserVersion = GetString(reader, 14),
            FieldStates = fieldStates,
            MetadataJson = GetString(reader, 16),
            Fields = fields
        };
        EnsureSingle(reader, "process observation");
        return observation;
    }

    private FilesystemArtifactRecord? ReadExactArtifact(string artifactId)
    {
        using var command = _context.CreateCommand("""
            SELECT a.ArtifactId, a.ArtifactType, a.TimestampUtc, a.Name, a.Path, a.Hash,
                   a.CaseId, a.EvidenceSessionId, a.CaptureId, a.SourceIdentityId,
                   a.HostId, a.ExecutionRootId, a.SourceRunId, a.IngestionJobId,
                   COALESCE((SELECT p.Value FROM ArtifactProperties p
                             WHERE p.ArtifactId = a.ArtifactId AND p.Name = 'Status'
                             LIMIT 1), 'Imported')
            FROM Artifacts a
            WHERE a.ArtifactId = $ArtifactId
            LIMIT 2;
            """);
        Add(command, "$ArtifactId", artifactId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var artifact = new FilesystemArtifactRecord
        {
            ArtifactId = GetString(reader, 0),
            Kind = GetEnum<FilesystemArtifactKind>(reader, 1),
            TimestampUtc = GetUtc(reader, 2),
            Name = GetString(reader, 3),
            SourcePath = GetString(reader, 4),
            Sha256Hash = GetString(reader, 5),
            CaseId = GetString(reader, 6),
            EvidenceSessionId = GetString(reader, 7),
            CaptureId = GetString(reader, 8),
            SourceIdentityId = GetString(reader, 9),
            HostId = GetString(reader, 10),
            ExecutionRootId = GetString(reader, 11),
            SourceRunId = GetString(reader, 12),
            IngestionJobId = GetString(reader, 13),
            Status = GetEnum<FilesystemArtifactStatus>(reader, 14)
        };
        EnsureSingle(reader, "file artifact");
        return artifact;
    }

    private EvidenceRelation? ReadExactRelation(string relationId)
    {
        using var command = _context.CreateCommand("""
            SELECT RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                   CorrelationState, CorrelationMethod, Confidence, CandidateCount,
                   CorrelationDiagnostics, CaseId, EvidenceSessionId, CaptureId,
                   SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                   RawInputId, ObservedFromUtc, ObservedToUtc, ValidFromUtc, ValidToUtc,
                   ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                   SupersededByRelationId, AnalystAnnotationId
            FROM EvidenceRelations
            WHERE RelationId = $RelationId
            LIMIT 2;
            """);
        Add(command, "$RelationId", relationId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var relation = new EvidenceRelation
        {
            RelationId = GetString(reader, 0),
            DecisionKey = GetString(reader, 1),
            FromKind = GetEnum<EvidenceReferenceKind>(reader, 2),
            FromId = GetString(reader, 3),
            ToKind = GetEnum<EvidenceReferenceKind>(reader, 4),
            ToId = GetString(reader, 5),
            RelationType = GetEnum<EvidenceRelationType>(reader, 6),
            State = GetEnum<EvidenceCorrelationState>(reader, 7),
            CorrelationMethod = GetString(reader, 8),
            Confidence = reader.IsDBNull(9) ? 0d : reader.GetDouble(9),
            CandidateCount = reader.IsDBNull(10) ? 0 : reader.GetInt32(10),
            CorrelationDiagnostics = GetString(reader, 11),
            CaseId = GetString(reader, 12),
            EvidenceSessionId = GetString(reader, 13),
            CaptureId = GetString(reader, 14),
            SourceIdentityId = GetString(reader, 15),
            HostId = GetString(reader, 16),
            ExecutionRootId = GetString(reader, 17),
            SourceRunId = GetString(reader, 18),
            IngestionJobId = GetString(reader, 19),
            RawInputId = GetString(reader, 20),
            ObservedFromUtc = GetUtc(reader, 21),
            ObservedToUtc = GetNullableUtc(reader, 22),
            ValidFromUtc = GetNullableUtc(reader, 23),
            ValidToUtc = GetNullableUtc(reader, 24),
            ResolverName = GetString(reader, 25),
            ResolverVersion = GetString(reader, 26),
            CreatedUtc = GetUtc(reader, 27),
            UpdatedUtc = GetUtc(reader, 28),
            Status = GetEnum<EvidenceRelationStatus>(reader, 29),
            SupersededByRelationId = GetString(reader, 30),
            AnalystAnnotationId = GetString(reader, 31)
        };
        EnsureSingle(reader, "evidence relation");
        return relation;
    }

    private (string PayloadHashSha256, string AttributionJson)? ReadExisting(
        PersistedReputationAttribution canonical)
    {
        using var command = _context.CreateCommand("""
            SELECT AttributionHashSha256, ProcessEntityId, ProcessKey, SourceKind,
                   ProviderId, ProviderVersion, DatasetId, DatasetVersion, QueryMode,
                   IndicatorSha256, SourceRunId, SourceEvidenceKind, SourceEvidenceId,
                   RelationId, Availability, RecordFound, AnalyzedCount, PositiveCount,
                   SuspiciousCount, UndetectedCount, RetrievedUtc, CompletedUtc,
                   ReceiptHashSha256, CacheDecisionHashSha256, PayloadHashSha256,
                   AttributionJson
            FROM ReputationAttributions
            WHERE AttributionHashSha256 = $AttributionHashSha256
            LIMIT 2;
            """);
        Add(command, "$AttributionHashSha256", canonical.Attribution.AttributionHashSha256);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        if (!ReputationAttributionPersistencePolicy.MatchesIndexedRow(reader, canonical))
        {
            throw new InvalidDataException(
                "The existing reputation attribution disagrees with its canonical indexed identity.");
        }

        var value = (GetString(reader, 24), GetString(reader, 25));
        EnsureSingle(reader, "reputation attribution");
        return value;
    }

    private void EnsureProcessRowCapacity(string processEntityId)
    {
        using var command = _context.CreateCommand("""
            SELECT COUNT(*)
            FROM ReputationAttributions
            WHERE ProcessEntityId = $ProcessEntityId;
            """);
        Add(command, "$ProcessEntityId", processEntityId);
        var existingCount = Convert.ToInt32(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture);
        if (existingCount >= ReputationAttributionPersistencePolicy.MaximumRowsPerProcess)
        {
            throw new InvalidDataException(
                "The bounded reputation-attribution history for this process is full.");
        }
    }

    private void Insert(PersistedReputationAttribution row)
    {
        var item = row.Attribution;
        var result = item.Receipt.Result;
        var provider = result.Provider;
        using var command = _context.CreateCommand("""
            INSERT INTO ReputationAttributions(
                AttributionHashSha256, ProcessEntityId, ProcessKey, SourceKind,
                ProviderId, ProviderVersion, DatasetId, DatasetVersion, QueryMode,
                IndicatorSha256, SourceRunId, SourceEvidenceKind, SourceEvidenceId,
                RelationId, Availability, RecordFound, AnalyzedCount, PositiveCount,
                SuspiciousCount, UndetectedCount, RetrievedUtc, CompletedUtc,
                ReceiptHashSha256, CacheDecisionHashSha256, PayloadHashSha256,
                AttributionJson)
            VALUES(
                $AttributionHashSha256, $ProcessEntityId, $ProcessKey, $SourceKind,
                $ProviderId, $ProviderVersion, $DatasetId, $DatasetVersion, $QueryMode,
                $IndicatorSha256, $SourceRunId, $SourceEvidenceKind, $SourceEvidenceId,
                $RelationId, $Availability, $RecordFound, $AnalyzedCount, $PositiveCount,
                $SuspiciousCount, $UndetectedCount, $RetrievedUtc, $CompletedUtc,
                $ReceiptHashSha256, $CacheDecisionHashSha256, $PayloadHashSha256,
                $AttributionJson);
            """);
        Add(command, "$AttributionHashSha256", item.AttributionHashSha256);
        Add(command, "$ProcessEntityId", item.ProcessEntityId);
        Add(command, "$ProcessKey", item.ProcessKey);
        Add(command, "$SourceKind", (int)item.SourceKind);
        Add(command, "$ProviderId", provider.ProviderId);
        Add(command, "$ProviderVersion", provider.ProviderVersion);
        Add(command, "$DatasetId", provider.DatasetId);
        Add(command, "$DatasetVersion", provider.DatasetVersion);
        Add(command, "$QueryMode", (int)provider.QueryMode);
        Add(command, "$IndicatorSha256", item.TargetRequest.Indicator.Value);
        Add(command, "$SourceRunId", item.TargetRequest.SourceRunId);
        Add(command, "$SourceEvidenceKind", (int)row.SourceReference.Kind);
        Add(command, "$SourceEvidenceId", row.SourceReference.Id);
        Add(command, "$RelationId", string.IsNullOrEmpty(row.RelationId) ? null : row.RelationId);
        Add(command, "$Availability", (int)result.Availability);
        Add(command, "$RecordFound", result.RecordFound ? 1 : 0);
        Add(command, "$AnalyzedCount", result.AnalyzedCount);
        Add(command, "$PositiveCount", result.PositiveCount);
        Add(command, "$SuspiciousCount", result.SuspiciousCount);
        Add(command, "$UndetectedCount", result.UndetectedCount);
        Add(command, "$RetrievedUtc", result.RetrievedUtc);
        Add(command, "$CompletedUtc", item.Receipt.CompletedUtc);
        Add(command, "$ReceiptHashSha256", item.Receipt.ReceiptHashSha256);
        Add(command, "$CacheDecisionHashSha256",
            item.CacheEvaluation?.DecisionHashSha256 ?? string.Empty);
        Add(command, "$PayloadHashSha256", row.PayloadHashSha256);
        Add(command, "$AttributionJson", row.AttributionJson);
        command.ExecuteNonQuery();
    }

    private static T Deserialize<T>(string json, string message)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(json) ?? throw new JsonException(message);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(message, ex);
        }
    }

    private static TEnum GetEnum<TEnum>(SqliteDataReader reader, int ordinal)
        where TEnum : struct, Enum
    {
        if (reader.IsDBNull(ordinal))
        {
            return (TEnum)Enum.ToObject(typeof(TEnum), -1);
        }

        if (reader.GetFieldType(ordinal) == typeof(string) &&
            Enum.TryParse<TEnum>(reader.GetString(ordinal), out var parsed))
        {
            return parsed;
        }

        return (TEnum)Enum.ToObject(typeof(TEnum), reader.GetInt32(ordinal));
    }

    private static string GetString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private static DateTime GetUtc(SqliteDataReader reader, int ordinal) =>
        GetNullableUtc(reader, ordinal) ?? DateTime.MinValue;

    private static DateTime? GetNullableUtc(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }

        return DateTime.TryParse(
            reader.GetString(ordinal),
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out var value)
            ? value.ToUniversalTime()
            : DateTime.MinValue;
    }

    private static void EnsureSingle(SqliteDataReader reader, string recordName)
    {
        if (reader.Read())
        {
            throw new InvalidDataException($"The exact persisted {recordName} is ambiguous.");
        }
    }

    private static void Add(SqliteCommand command, string name, object? value) =>
        SqliteWriteTransactionContext.Add(command, name, value);
}
