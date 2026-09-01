using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProcInsider.Models.Infrastructure;

public enum InfrastructureCaseArchiveKind
{
    Unknown = 0,
    PortableExport = 1,
    RecoveryBackup = 2
}

public static class InfrastructureCaseStorageFormat
{
    public const int CurrentArchiveVersion = 1;
    public const int CurrentPostgresSchemaVersion = 3;
    public const int MaximumBatchesPerArchive = 1_000_000;
    public const int MaximumArtifactsPerArchive = 1_000_000;
    public const int MaximumMigrationEntries = 256;
    public const long MaximumManifestBytes = 64L * 1024 * 1024;
    public const string ManifestEntryName = "manifest.json";
    public const string ControlStateEntryName = "recovery/server-control.protected";
}

public sealed record InfrastructureCaseStoreMigrationEntry
{
    public int Version { get; init; }

    public string MigrationId { get; init; } = string.Empty;

    public string DefinitionSha256 { get; init; } = string.Empty;
}

public sealed record InfrastructureCaseArchiveBatchEntry
{
    public string CaseId { get; init; } = string.Empty;

    public string BatchId { get; init; } = string.Empty;

    public string ManifestSha256 { get; init; } = string.Empty;

    public string PackageSha256 { get; init; } = string.Empty;

    public long PackageBytes { get; init; }

    public string CommitId { get; init; } = string.Empty;

    public string AuditEventId { get; init; } = string.Empty;

    public string CaptureId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string SourceRunId { get; init; } = string.Empty;

    public string JobId { get; init; } = string.Empty;

    public string SourceId { get; init; } = string.Empty;

    public long SequenceStart { get; init; }

    public long SequenceEnd { get; init; }

    public DateTime CommittedAtUtc { get; init; }

    public string EntryName => $"batches/{BatchId}.dfev";
}

public sealed record InfrastructureCaseArchiveArtifactEntry
{
    public string Sha256 { get; init; } = string.Empty;

    public long Bytes { get; init; }

    public string StorageKey { get; init; } = string.Empty;

    public int ReferenceCount { get; init; }
}

public sealed record InfrastructureCaseArchiveProjectionEntry
{
    public string CaseId { get; init; } = string.Empty;

    public string ProjectionKind { get; init; } = string.Empty;

    public long Revision { get; init; }

    public string SourceCommitId { get; init; } = string.Empty;

    public int DefinitionVersion { get; init; }

    public string Status { get; init; } = string.Empty;

    public DateTime UpdatedAtUtc { get; init; }
}

public sealed record InfrastructureCaseArchiveManifest
{
    public int ArchiveVersion { get; init; } = InfrastructureCaseStorageFormat.CurrentArchiveVersion;

    public string ArchiveId { get; init; } = string.Empty;

    public string ManifestSha256 { get; init; } = string.Empty;

    public InfrastructureCaseArchiveKind Kind { get; init; }

    public string CaseId { get; init; } = string.Empty;

    public string ServerInstanceId { get; init; } = string.Empty;

    public long RestoreGeneration { get; init; }

    public string CreatedByActorId { get; init; } = string.Empty;

    public DateTime CreatedAtUtc { get; init; }

    public DateTime? CaseSealedAtUtc { get; init; }

    public string CaseSealReason { get; init; } = string.Empty;

    public bool LegalHold { get; init; }

    public string RetentionPolicyJson { get; init; } = "{}";

    public int EvidenceInterchangeVersion { get; init; } = InfrastructureEvidenceInterchange.CurrentVersion;

    public int PostgresSchemaVersion { get; init; } = InfrastructureCaseStorageFormat.CurrentPostgresSchemaVersion;

    public string ControlStateSha256 { get; init; } = string.Empty;

    public string DatabaseBackupFormat { get; init; } = string.Empty;

    public long DatabaseBackupBytes { get; init; }

    public string DatabaseBackupSha256 { get; init; } = string.Empty;

    public string CaEscrowReference { get; init; } = string.Empty;

    public string CaRecoveryMaterialSha256 { get; init; } = string.Empty;

    public IReadOnlyList<InfrastructureCaseStoreMigrationEntry> Migrations { get; init; } =
        Array.Empty<InfrastructureCaseStoreMigrationEntry>();

    public IReadOnlyList<InfrastructureCaseArchiveBatchEntry> Batches { get; init; } =
        Array.Empty<InfrastructureCaseArchiveBatchEntry>();

    public IReadOnlyList<InfrastructureCaseArchiveArtifactEntry> Artifacts { get; init; } =
        Array.Empty<InfrastructureCaseArchiveArtifactEntry>();

    public IReadOnlyList<InfrastructureCaseArchiveProjectionEntry> Projections { get; init; } =
        Array.Empty<InfrastructureCaseArchiveProjectionEntry>();
}

public sealed record InfrastructureCaseArchiveValidation(
    bool Valid,
    string ErrorCode,
    string Message)
{
    public static InfrastructureCaseArchiveValidation Success { get; } = new(true, string.Empty, string.Empty);

    public static InfrastructureCaseArchiveValidation Reject(string code, string message) =>
        new(false, code, message);
}

public static class InfrastructureCaseArchiveManifestCodec
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    static InfrastructureCaseArchiveManifestCodec()
    {
        JsonOptions.Converters.Add(new JsonStringEnumConverter());
    }

    public static InfrastructureCaseArchiveManifest Stamp(InfrastructureCaseArchiveManifest draft)
    {
        ArgumentNullException.ThrowIfNull(draft);
        var draftMigrations = draft.Migrations ?? Array.Empty<InfrastructureCaseStoreMigrationEntry>();
        var draftBatches = draft.Batches ?? Array.Empty<InfrastructureCaseArchiveBatchEntry>();
        var draftArtifacts = draft.Artifacts ?? Array.Empty<InfrastructureCaseArchiveArtifactEntry>();
        var draftProjections = draft.Projections ?? Array.Empty<InfrastructureCaseArchiveProjectionEntry>();
        var normalized = draft with
        {
            ArchiveId = string.Empty,
            ManifestSha256 = string.Empty,
            Migrations = Array.AsReadOnly(draftMigrations.OrderBy(item => item.Version).ToArray()),
            Batches = Array.AsReadOnly(draftBatches
                .OrderBy(item => item.CaseId, StringComparer.Ordinal)
                .ThenBy(item => item.CaptureId, StringComparer.Ordinal)
                .ThenBy(item => item.AgentId, StringComparer.Ordinal)
                .ThenBy(item => item.HostId, StringComparer.Ordinal)
                .ThenBy(item => item.SourceRunId, StringComparer.Ordinal)
                .ThenBy(item => item.JobId, StringComparer.Ordinal)
                .ThenBy(item => item.SequenceStart)
                .ThenBy(item => item.BatchId, StringComparer.Ordinal)
                .ToArray()),
            Artifacts = Array.AsReadOnly(draftArtifacts.OrderBy(item => item.Sha256, StringComparer.Ordinal).ToArray()),
            Projections = Array.AsReadOnly(draftProjections
                .OrderBy(item => item.CaseId, StringComparer.Ordinal)
                .ThenBy(item => item.ProjectionKind, StringComparer.Ordinal)
                .ToArray())
        };
        var shape = ValidateShape(normalized, requireIdentity: false);
        if (!shape.Valid)
        {
            throw new InvalidDataException(shape.ErrorCode);
        }

        var archiveId = "case-archive-" + Hash(SerializeCanonical(normalized, includeArchiveId: false));
        var identified = normalized with { ArchiveId = archiveId };
        var manifest = identified with
        {
            ManifestSha256 = Hash(SerializeCanonical(identified, includeArchiveId: true))
        };
        var validation = Validate(manifest);
        if (!validation.Valid)
        {
            throw new InvalidDataException(validation.ErrorCode);
        }
        return manifest;
    }

    public static InfrastructureCaseArchiveValidation Validate(InfrastructureCaseArchiveManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var shape = ValidateShape(manifest, requireIdentity: true);
        if (!shape.Valid)
        {
            return shape;
        }

        var withoutIdentity = manifest with { ArchiveId = string.Empty, ManifestSha256 = string.Empty };
        var expectedArchiveId = "case-archive-" + Hash(SerializeCanonical(withoutIdentity, includeArchiveId: false));
        var expectedManifestHash = Hash(SerializeCanonical(manifest with { ManifestSha256 = string.Empty }, includeArchiveId: true));
        return string.Equals(manifest.ArchiveId, expectedArchiveId, StringComparison.Ordinal) &&
               string.Equals(manifest.ManifestSha256, expectedManifestHash, StringComparison.Ordinal)
            ? InfrastructureCaseArchiveValidation.Success
            : InfrastructureCaseArchiveValidation.Reject(
                "InfrastructureCaseArchiveManifestHashMismatch",
                "The archive identity or manifest hash does not match its canonical content.");
    }

    public static byte[] Serialize(InfrastructureCaseArchiveManifest manifest)
    {
        var validation = Validate(manifest);
        if (!validation.Valid)
        {
            throw new InvalidDataException(validation.ErrorCode);
        }
        return SerializeCanonical(manifest, includeArchiveId: true, includeManifestHash: true);
    }

    public static InfrastructureCaseArchiveManifest Deserialize(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty || bytes.Length > InfrastructureCaseStorageFormat.MaximumManifestBytes)
        {
            throw new InvalidDataException("InfrastructureCaseArchiveManifestBoundsExceeded");
        }
        var manifest = JsonSerializer.Deserialize<InfrastructureCaseArchiveManifest>(bytes, JsonOptions) ??
            throw new InvalidDataException("InfrastructureCaseArchiveManifestMissing");
        var validation = Validate(manifest);
        if (!validation.Valid)
        {
            throw new InvalidDataException(validation.ErrorCode);
        }
        return manifest;
    }

    public static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static InfrastructureCaseArchiveValidation ValidateShape(
        InfrastructureCaseArchiveManifest manifest,
        bool requireIdentity)
    {
        if (manifest.ArchiveVersion != InfrastructureCaseStorageFormat.CurrentArchiveVersion ||
            !Enum.IsDefined(manifest.Kind) || manifest.Kind == InfrastructureCaseArchiveKind.Unknown ||
            !IsIdentifier(manifest.CaseId) || !IsIdentifier(manifest.ServerInstanceId) ||
            !IsIdentifier(manifest.CreatedByActorId) || manifest.RestoreGeneration < 0 ||
            manifest.CreatedAtUtc.Kind != DateTimeKind.Utc ||
            (manifest.CaseSealedAtUtc.HasValue && manifest.CaseSealedAtUtc.Value.Kind != DateTimeKind.Utc) ||
            (manifest.CaseSealReason?.Length ?? int.MaxValue) > InfrastructureEvidenceInterchange.MaximumIdentifierCharacters ||
            string.IsNullOrWhiteSpace(manifest.RetentionPolicyJson) || !IsJsonObject(manifest.RetentionPolicyJson) ||
            manifest.EvidenceInterchangeVersion != InfrastructureEvidenceInterchange.CurrentVersion ||
            manifest.PostgresSchemaVersion != InfrastructureCaseStorageFormat.CurrentPostgresSchemaVersion ||
            manifest.Migrations is null || manifest.Batches is null || manifest.Artifacts is null ||
            manifest.Projections is null ||
            manifest.Migrations.Count == 0 ||
            manifest.Migrations.Count > InfrastructureCaseStorageFormat.MaximumMigrationEntries ||
            manifest.Batches.Count > InfrastructureCaseStorageFormat.MaximumBatchesPerArchive ||
            manifest.Artifacts.Count > InfrastructureCaseStorageFormat.MaximumArtifactsPerArchive)
        {
            return InfrastructureCaseArchiveValidation.Reject(
                "InfrastructureCaseArchiveManifestInvalid",
                "The archive manifest contains an unsupported version, identity, time, or bound.");
        }

        if (requireIdentity && (!IsIdentifier(manifest.ArchiveId) || !IsSha256(manifest.ManifestSha256)))
        {
            return InfrastructureCaseArchiveValidation.Reject(
                "InfrastructureCaseArchiveIdentityInvalid",
                "The archive identity or manifest hash is missing or malformed.");
        }

        if (manifest.Kind == InfrastructureCaseArchiveKind.PortableExport &&
            (!string.IsNullOrEmpty(manifest.ControlStateSha256) || manifest.DatabaseBackupBytes != 0 ||
             !string.IsNullOrEmpty(manifest.DatabaseBackupFormat) ||
             !string.IsNullOrEmpty(manifest.DatabaseBackupSha256) ||
             !string.IsNullOrEmpty(manifest.CaEscrowReference) ||
             !string.IsNullOrEmpty(manifest.CaRecoveryMaterialSha256)))
        {
            return InfrastructureCaseArchiveValidation.Reject(
                "InfrastructureCasePortableExportContainsRecoveryState",
                "A portable export cannot contain Server recovery-control metadata.");
        }
        if (manifest.Kind == InfrastructureCaseArchiveKind.RecoveryBackup &&
            (!IsSha256(manifest.ControlStateSha256) || !IsIdentifier(manifest.DatabaseBackupFormat) ||
             manifest.DatabaseBackupBytes <= 0 || !IsSha256(manifest.DatabaseBackupSha256) ||
             !IsIdentifier(manifest.CaEscrowReference) ||
             !IsSha256(manifest.CaRecoveryMaterialSha256)))
        {
            return InfrastructureCaseArchiveValidation.Reject(
                "InfrastructureCaseRecoveryMetadataInvalid",
                "A recovery backup requires protected control-state and separately escrowed CA hashes.");
        }

        var expectedMigrationVersion = 1;
        var migrationIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var migration in manifest.Migrations)
        {
            if (migration.Version != expectedMigrationVersion++ || !IsIdentifier(migration.MigrationId) ||
                !migrationIds.Add(migration.MigrationId) || !IsSha256(migration.DefinitionSha256))
            {
                return InfrastructureCaseArchiveValidation.Reject(
                    "InfrastructureCaseArchiveMigrationCatalogInvalid",
                    "Migration metadata must be complete, ordered, unique, and hash-bound.");
            }
        }
        if (manifest.Migrations[^1].Version != manifest.PostgresSchemaVersion)
        {
            return InfrastructureCaseArchiveValidation.Reject(
                "InfrastructureCaseArchiveMigrationVersionMismatch",
                "The migration catalog does not reach the declared Postgres schema version.");
        }

        var batchIds = new HashSet<string>(StringComparer.Ordinal);
        var commitIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var batch in manifest.Batches)
        {
            if (!IsIdentifier(batch.CaseId) || !IsIdentifier(batch.BatchId) || !IsSha256(batch.ManifestSha256) ||
                !IsSha256(batch.PackageSha256) || batch.PackageBytes <= 0 ||
                !IsIdentifier(batch.CommitId) || !commitIds.Add(batch.CommitId) ||
                !IsIdentifier(batch.AuditEventId) || !IsIdentifier(batch.CaptureId) ||
                !IsIdentifier(batch.AgentId) || !IsIdentifier(batch.HostId) ||
                !IsIdentifier(batch.SourceRunId) || !IsIdentifier(batch.JobId) ||
                !IsIdentifier(batch.SourceId) || batch.SequenceStart <= 0 ||
                batch.SequenceEnd < batch.SequenceStart || batch.CommittedAtUtc.Kind != DateTimeKind.Utc ||
                !batchIds.Add(batch.BatchId))
            {
                return InfrastructureCaseArchiveValidation.Reject(
                    "InfrastructureCaseArchiveBatchInvalid",
                    "A batch entry contains invalid identity, hash, sequence, or commit metadata.");
            }
        }

        var artifactHashes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var artifact in manifest.Artifacts)
        {
            if (!IsSha256(artifact.Sha256) || artifact.Bytes <= 0 || artifact.ReferenceCount <= 0 ||
                !IsSafeStorageKey(artifact.StorageKey, artifact.Sha256) || !artifactHashes.Add(artifact.Sha256))
            {
                return InfrastructureCaseArchiveValidation.Reject(
                    "InfrastructureCaseArchiveArtifactInvalid",
                    "An artifact inventory entry is malformed, duplicated, or not hash-addressed.");
            }
        }


        var projectionKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var projection in manifest.Projections)
        {
            var key = projection.CaseId + "\n" + projection.ProjectionKind;
            if (!IsIdentifier(projection.CaseId) || !IsIdentifier(projection.ProjectionKind) ||
                projection.Revision < 0 || !IsIdentifier(projection.SourceCommitId) ||
                projection.DefinitionVersion <= 0 || !IsIdentifier(projection.Status) ||
                projection.UpdatedAtUtc.Kind != DateTimeKind.Utc || !projectionKeys.Add(key) ||
                (manifest.Kind == InfrastructureCaseArchiveKind.PortableExport &&
                 !string.Equals(projection.CaseId, manifest.CaseId, StringComparison.Ordinal)))
            {
                return InfrastructureCaseArchiveValidation.Reject(
                    "InfrastructureCaseArchiveProjectionInvalid",
                    "A rebuildable projection entry has invalid, duplicate, or cross-case metadata.");
            }
        }

        return InfrastructureCaseArchiveValidation.Success;
    }

    private static byte[] SerializeCanonical(
        InfrastructureCaseArchiveManifest manifest,
        bool includeArchiveId,
        bool includeManifestHash = false)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("archiveVersion", manifest.ArchiveVersion);
            if (includeArchiveId)
            {
                writer.WriteString("archiveId", manifest.ArchiveId);
            }
            if (includeManifestHash)
            {
                writer.WriteString("manifestSha256", manifest.ManifestSha256);
            }
            writer.WriteString("kind", manifest.Kind.ToString());
            writer.WriteString("caseId", manifest.CaseId);
            writer.WriteString("serverInstanceId", manifest.ServerInstanceId);
            writer.WriteNumber("restoreGeneration", manifest.RestoreGeneration);
            writer.WriteString("createdByActorId", manifest.CreatedByActorId);
            writer.WriteString("createdAtUtc", manifest.CreatedAtUtc);
            if (manifest.CaseSealedAtUtc.HasValue)
            {
                writer.WriteString("caseSealedAtUtc", manifest.CaseSealedAtUtc.Value);
            }
            else
            {
                writer.WriteNull("caseSealedAtUtc");
            }
            writer.WriteString("caseSealReason", manifest.CaseSealReason);
            writer.WriteBoolean("legalHold", manifest.LegalHold);
            writer.WriteString("retentionPolicyJson", manifest.RetentionPolicyJson);
            writer.WriteNumber("evidenceInterchangeVersion", manifest.EvidenceInterchangeVersion);
            writer.WriteNumber("postgresSchemaVersion", manifest.PostgresSchemaVersion);
            writer.WriteString("controlStateSha256", manifest.ControlStateSha256);
            writer.WriteString("databaseBackupFormat", manifest.DatabaseBackupFormat);
            writer.WriteNumber("databaseBackupBytes", manifest.DatabaseBackupBytes);
            writer.WriteString("databaseBackupSha256", manifest.DatabaseBackupSha256);
            writer.WriteString("caEscrowReference", manifest.CaEscrowReference);
            writer.WriteString("caRecoveryMaterialSha256", manifest.CaRecoveryMaterialSha256);
            writer.WriteStartArray("migrations");
            foreach (var migration in manifest.Migrations)
            {
                writer.WriteStartObject();
                writer.WriteNumber("version", migration.Version);
                writer.WriteString("migrationId", migration.MigrationId);
                writer.WriteString("definitionSha256", migration.DefinitionSha256);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartArray("batches");
            foreach (var batch in manifest.Batches)
            {
                writer.WriteStartObject();
                writer.WriteString("caseId", batch.CaseId);
                writer.WriteString("batchId", batch.BatchId);
                writer.WriteString("manifestSha256", batch.ManifestSha256);
                writer.WriteString("packageSha256", batch.PackageSha256);
                writer.WriteNumber("packageBytes", batch.PackageBytes);
                writer.WriteString("commitId", batch.CommitId);
                writer.WriteString("auditEventId", batch.AuditEventId);
                writer.WriteString("captureId", batch.CaptureId);
                writer.WriteString("agentId", batch.AgentId);
                writer.WriteString("hostId", batch.HostId);
                writer.WriteString("sourceRunId", batch.SourceRunId);
                writer.WriteString("jobId", batch.JobId);
                writer.WriteString("sourceId", batch.SourceId);
                writer.WriteNumber("sequenceStart", batch.SequenceStart);
                writer.WriteNumber("sequenceEnd", batch.SequenceEnd);
                writer.WriteString("committedAtUtc", batch.CommittedAtUtc);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartArray("artifacts");
            foreach (var artifact in manifest.Artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("sha256", artifact.Sha256);
                writer.WriteNumber("bytes", artifact.Bytes);
                writer.WriteString("storageKey", artifact.StorageKey);
                writer.WriteNumber("referenceCount", artifact.ReferenceCount);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartArray("projections");
            foreach (var projection in manifest.Projections)
            {
                writer.WriteStartObject();
                writer.WriteString("caseId", projection.CaseId);
                writer.WriteString("projectionKind", projection.ProjectionKind);
                writer.WriteNumber("revision", projection.Revision);
                writer.WriteString("sourceCommitId", projection.SourceCommitId);
                writer.WriteNumber("definitionVersion", projection.DefinitionVersion);
                writer.WriteString("status", projection.Status);
                writer.WriteString("updatedAtUtc", projection.UpdatedAtUtc);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static bool IsIdentifier(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= InfrastructureEvidenceInterchange.MaximumIdentifierCharacters &&
        value.All(character => character >= 0x20 && character != '/' && character != '\\');

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsSafeStorageKey(string? value, string sha256) =>
        IsSha256(sha256) &&
        string.Equals(value, $"{sha256[..2]}/{sha256[2..4]}/{sha256}.artifact", StringComparison.Ordinal);

    private static bool IsJsonObject(string value)
    {
        try
        {
            using var document = JsonDocument.Parse(value);
            return document.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
