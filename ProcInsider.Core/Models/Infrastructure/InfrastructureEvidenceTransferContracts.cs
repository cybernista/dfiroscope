using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProcInsider.Models.Infrastructure;

public enum InfrastructureEvidenceContentKind
{
    Unknown = 0,
    BatchPayload = 1,
    Artifact = 2
}

public enum InfrastructureEvidenceTransferOutcome
{
    Unknown = 0,
    Prepared = 1,
    ChunkAccepted = 2,
    Committed = 3,
    DuplicateCommitted = 4,
    Rejected = 5,
    Conflict = 6,
    Incomplete = 7
}

public enum InfrastructureEvidenceFailure
{
    None = 0,
    InvalidManifest = 1,
    InvalidRoute = 2,
    CapabilityUnavailable = 3,
    VersionUnsupported = 4,
    TargetUnassigned = 5,
    TargetSealed = 6,
    BoundsExceeded = 7,
    HashMismatch = 8,
    SequenceGap = 9,
    DuplicateConflict = 10,
    ChunkOutOfOrder = 11,
    TransferIncomplete = 12,
    StoreUnavailable = 13,
    AuditUnavailable = 14,
    SessionStale = 15,
    Canceled = 16
}

public enum InfrastructureEvidenceSpoolState
{
    Healthy = 0,
    Offline = 1,
    Backpressured = 2,
    QuotaBlocked = 3,
    Corrupt = 4,
    Draining = 5
}

public static class InfrastructureEvidenceInterchange
{
    public const int CurrentVersion = 1;
    public const int MaximumRecordsPerBatch = 4096;
    public const int MaximumArtifactsPerBatch = 256;
    public const int MaximumIdentifierCharacters = 512;
    public const int MaximumFileNameCharacters = 255;
    public const int MaximumContentTypeCharacters = 256;
    // JSON/base64 transport overhead must still fit inside the 4 MiB decoded evidence envelope.
    public const int MaximumDecodedChunkBytes = (3 * 1024 * 1024) - (64 * 1024);
    public const long DefaultMaximumSpoolBytes = 20L * 1024 * 1024 * 1024;
    public const long DefaultFreeSpaceReserveBytes = 5L * 1024 * 1024 * 1024;
    public const int DefaultVolumeQuotaPercent = 10;
    public static readonly TimeSpan MinimumReconnectDelay = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan MaximumReconnectDelay = TimeSpan.FromMinutes(5);
}

public sealed record InfrastructureEvidenceRoute
{
    public string CaseId { get; init; } = string.Empty;

    public string CaptureId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string SourceRunId { get; init; } = string.Empty;

    public string JobId { get; init; } = string.Empty;

    public string SourceId { get; init; } = string.Empty;

    public string DatabaseIdentity { get; init; } = string.Empty;
}

public sealed record InfrastructureEvidenceRecordDescriptor
{
    public long Sequence { get; init; }

    public string RecordId { get; init; } = string.Empty;

    public string Sha256 { get; init; } = string.Empty;

    public DateTime NativeTimestampUtc { get; init; }
}

public sealed record InfrastructureEvidenceArtifactReference
{
    public string ArtifactId { get; init; } = string.Empty;

    public string FileName { get; init; } = string.Empty;

    public string ContentType { get; init; } = string.Empty;

    public long Bytes { get; init; }

    public string Sha256 { get; init; } = string.Empty;

    public int ChunkBytes { get; init; } = InfrastructureEvidenceInterchange.MaximumDecodedChunkBytes;
}

public sealed record InfrastructureEvidenceBatchDraft
{
    public InfrastructureEvidenceRoute Route { get; init; } = new();

    public long SequenceStart { get; init; }

    public long SequenceEnd { get; init; }

    public string PreviousBatchId { get; init; } = string.Empty;

    public int EvidenceSchemaVersion { get; init; }

    public int SourceVersion { get; init; }

    public DateTime CreatedAtUtc { get; init; }

    public DateTime SourceTimeStartUtc { get; init; }

    public DateTime SourceTimeEndUtc { get; init; }

    public long ClockUncertaintyMilliseconds { get; init; }

    public InfrastructureSessionCompression Compression { get; init; }

    public IReadOnlyList<InfrastructureEvidenceRecordDescriptor> Records { get; init; } =
        Array.Empty<InfrastructureEvidenceRecordDescriptor>();

    public IReadOnlyList<InfrastructureEvidenceArtifactReference> Artifacts { get; init; } =
        Array.Empty<InfrastructureEvidenceArtifactReference>();
}

public sealed record InfrastructureEvidenceBatchManifest
{
    public int InterchangeVersion { get; init; } = InfrastructureEvidenceInterchange.CurrentVersion;

    public string BatchId { get; init; } = string.Empty;

    public string ManifestSha256 { get; init; } = string.Empty;

    public InfrastructureEvidenceRoute Route { get; init; } = new();

    public long SequenceStart { get; init; }

    public long SequenceEnd { get; init; }

    public int RecordCount { get; init; }

    public string PreviousBatchId { get; init; } = string.Empty;

    public int EvidenceSchemaVersion { get; init; }

    public int SourceVersion { get; init; }

    public DateTime CreatedAtUtc { get; init; }

    public DateTime SourceTimeStartUtc { get; init; }

    public DateTime SourceTimeEndUtc { get; init; }

    public long ClockUncertaintyMilliseconds { get; init; }

    public InfrastructureSessionCompression Compression { get; init; }

    public long PayloadBytes { get; init; }

    public long UncompressedPayloadBytes { get; init; }

    public string PayloadSha256 { get; init; } = string.Empty;

    public string UncompressedPayloadSha256 { get; init; } = string.Empty;

    public IReadOnlyList<InfrastructureEvidenceRecordDescriptor> Records { get; init; } =
        Array.Empty<InfrastructureEvidenceRecordDescriptor>();

    public IReadOnlyList<InfrastructureEvidenceArtifactReference> Artifacts { get; init; } =
        Array.Empty<InfrastructureEvidenceArtifactReference>();
}

public sealed record InfrastructureEvidenceArtifactContent
{
    public InfrastructureEvidenceArtifactReference Reference { get; init; } = new();

    public byte[] Bytes { get; init; } = Array.Empty<byte>();
}

public sealed record InfrastructureEvidenceBatchPackage
{
    public InfrastructureEvidenceBatchManifest Manifest { get; init; } = new();

    public byte[] Payload { get; init; } = Array.Empty<byte>();

    public IReadOnlyList<InfrastructureEvidenceArtifactContent> Artifacts { get; init; } =
        Array.Empty<InfrastructureEvidenceArtifactContent>();
}

public sealed record InfrastructureEvidenceValidationResult(
    bool Valid,
    InfrastructureEvidenceFailure Failure,
    string ErrorCode)
{
    public static InfrastructureEvidenceValidationResult Success { get; } =
        new(true, InfrastructureEvidenceFailure.None, string.Empty);

    public static InfrastructureEvidenceValidationResult Reject(
        InfrastructureEvidenceFailure failure,
        string errorCode) => new(false, failure, errorCode);
}

public static class InfrastructureEvidenceBatchCodec
{
    private static readonly byte[] PackageMagic = "DFEV1"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public static InfrastructureEvidenceBatchPackage Create(
        InfrastructureEvidenceBatchDraft draft,
        ReadOnlySpan<byte> uncompressedPayload,
        IReadOnlyList<InfrastructureEvidenceArtifactContent>? artifacts = null)
    {
        ArgumentNullException.ThrowIfNull(draft);
        var artifactContents = (artifacts ?? Array.Empty<InfrastructureEvidenceArtifactContent>())
            .OrderBy(item => item.Reference.ArtifactId, StringComparer.Ordinal)
            .ToArray();
        var draftValidation = ValidateDraft(draft, uncompressedPayload.Length, artifactContents);
        if (!draftValidation.Valid)
        {
            throw new InvalidDataException(draftValidation.ErrorCode);
        }

        var encodedPayload = EncodePayload(uncompressedPayload, draft.Compression);
        var records = draft.Records.OrderBy(record => record.Sequence).ToArray();
        var references = draft.Artifacts.OrderBy(artifact => artifact.ArtifactId, StringComparer.Ordinal).ToArray();
        var provisional = new InfrastructureEvidenceBatchManifest
        {
            Route = draft.Route with { },
            SequenceStart = draft.SequenceStart,
            SequenceEnd = draft.SequenceEnd,
            RecordCount = records.Length,
            PreviousBatchId = draft.PreviousBatchId,
            EvidenceSchemaVersion = draft.EvidenceSchemaVersion,
            SourceVersion = draft.SourceVersion,
            CreatedAtUtc = draft.CreatedAtUtc,
            SourceTimeStartUtc = draft.SourceTimeStartUtc,
            SourceTimeEndUtc = draft.SourceTimeEndUtc,
            ClockUncertaintyMilliseconds = draft.ClockUncertaintyMilliseconds,
            Compression = draft.Compression,
            PayloadBytes = encodedPayload.LongLength,
            UncompressedPayloadBytes = uncompressedPayload.Length,
            PayloadSha256 = Hash(encodedPayload),
            UncompressedPayloadSha256 = Hash(uncompressedPayload),
            Records = Array.AsReadOnly(records),
            Artifacts = Array.AsReadOnly(references)
        };
        var batchId = "batch-" + Hash(SerializeStableBatchIdentity(provisional));
        var identified = provisional with { BatchId = batchId };
        var manifest = identified with
        {
            ManifestSha256 = Hash(SerializeIdentity(identified))
        };
        var package = new InfrastructureEvidenceBatchPackage
        {
            Manifest = manifest,
            Payload = encodedPayload,
            Artifacts = Array.AsReadOnly(artifactContents)
        };
        var validation = ValidatePackage(package, InfrastructureSessionLimits.CompiledMaximumEvidenceBatchBytes);
        if (!validation.Valid)
        {
            throw new InvalidDataException(validation.ErrorCode);
        }

        return package;
    }

    public static InfrastructureEvidenceValidationResult ValidateManifest(
        InfrastructureEvidenceBatchManifest manifest,
        long maximumBatchBytes)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (manifest.InterchangeVersion != InfrastructureEvidenceInterchange.CurrentVersion)
        {
            return Reject(InfrastructureEvidenceFailure.VersionUnsupported, "EvidenceInterchangeVersionUnsupported");
        }

        if (!IsIdentifier(manifest.BatchId) || !IsSha256(manifest.ManifestSha256) ||
            !IsRouteValid(manifest.Route) || manifest.SequenceStart <= 0 ||
            manifest.SequenceEnd < manifest.SequenceStart || manifest.RecordCount <= 0 ||
            manifest.RecordCount > InfrastructureEvidenceInterchange.MaximumRecordsPerBatch ||
            manifest.RecordCount != manifest.Records.Count ||
            manifest.SequenceEnd - manifest.SequenceStart + 1 != manifest.RecordCount ||
            manifest.EvidenceSchemaVersion <= 0 || manifest.SourceVersion <= 0 ||
            !IsUtc(manifest.CreatedAtUtc) || !IsUtc(manifest.SourceTimeStartUtc) ||
            !IsUtc(manifest.SourceTimeEndUtc) || manifest.SourceTimeEndUtc < manifest.SourceTimeStartUtc ||
            manifest.ClockUncertaintyMilliseconds < 0 ||
            manifest.Compression is not (InfrastructureSessionCompression.None or InfrastructureSessionCompression.Gzip) ||
            manifest.PayloadBytes <= 0 || manifest.PayloadBytes > maximumBatchBytes ||
            manifest.UncompressedPayloadBytes <= 0 || manifest.UncompressedPayloadBytes > maximumBatchBytes ||
            !IsSha256(manifest.PayloadSha256) || !IsSha256(manifest.UncompressedPayloadSha256) ||
            manifest.Artifacts.Count > InfrastructureEvidenceInterchange.MaximumArtifactsPerBatch ||
            (!string.IsNullOrEmpty(manifest.PreviousBatchId) && !IsIdentifier(manifest.PreviousBatchId)))
        {
            return Reject(InfrastructureEvidenceFailure.InvalidManifest, "EvidenceBatchManifestInvalid");
        }

        if (manifest.Compression == InfrastructureSessionCompression.Gzip &&
            manifest.UncompressedPayloadBytes > manifest.PayloadBytes *
            InfrastructureSessionLimits.CompiledMaximumDecompressionRatio)
        {
            return Reject(InfrastructureEvidenceFailure.BoundsExceeded, "EvidenceDecompressionRatioExceeded");
        }

        var expectedSequence = manifest.SequenceStart;
        var recordIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var record in manifest.Records)
        {
            if (record.Sequence != expectedSequence++ || !IsIdentifier(record.RecordId) ||
                !recordIds.Add(record.RecordId) || !IsSha256(record.Sha256) ||
                !IsUtc(record.NativeTimestampUtc))
            {
                return Reject(InfrastructureEvidenceFailure.InvalidManifest, "EvidenceRecordManifestInvalid");
            }
        }

        var artifactIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var artifact in manifest.Artifacts)
        {
            if (!IsArtifactReferenceValid(artifact) || !artifactIds.Add(artifact.ArtifactId))
            {
                return Reject(InfrastructureEvidenceFailure.InvalidManifest, "EvidenceArtifactManifestInvalid");
            }
        }

        if (!manifest.Records.SequenceEqual(manifest.Records.OrderBy(record => record.Sequence)) ||
            !manifest.Artifacts.SequenceEqual(manifest.Artifacts.OrderBy(item => item.ArtifactId, StringComparer.Ordinal)))
        {
            return Reject(InfrastructureEvidenceFailure.InvalidManifest, "EvidenceManifestOrderingInvalid");
        }

        var expectedBatchId = "batch-" + Hash(SerializeStableBatchIdentity(manifest));
        var expectedHash = Hash(SerializeIdentity(manifest));
        return string.Equals(expectedBatchId, manifest.BatchId, StringComparison.Ordinal) &&
               string.Equals(expectedHash, manifest.ManifestSha256, StringComparison.Ordinal)
            ? InfrastructureEvidenceValidationResult.Success
            : Reject(InfrastructureEvidenceFailure.HashMismatch, "EvidenceManifestHashMismatch");
    }

    public static InfrastructureEvidenceValidationResult ValidatePackage(
        InfrastructureEvidenceBatchPackage package,
        long maximumBatchBytes)
    {
        ArgumentNullException.ThrowIfNull(package);
        var manifest = ValidateManifest(package.Manifest, maximumBatchBytes);
        if (!manifest.Valid)
        {
            return manifest;
        }

        if (package.Payload.LongLength != package.Manifest.PayloadBytes ||
            !string.Equals(Hash(package.Payload), package.Manifest.PayloadSha256, StringComparison.Ordinal))
        {
            return Reject(InfrastructureEvidenceFailure.HashMismatch, "EvidencePayloadHashMismatch");
        }

        byte[] decoded;
        try
        {
            decoded = DecodePayload(package.Payload, package.Manifest.Compression, maximumBatchBytes);
        }
        catch (InvalidDataException)
        {
            return Reject(InfrastructureEvidenceFailure.HashMismatch, "EvidencePayloadDecompressionFailed");
        }

        if (decoded.LongLength != package.Manifest.UncompressedPayloadBytes ||
            !string.Equals(Hash(decoded), package.Manifest.UncompressedPayloadSha256, StringComparison.Ordinal))
        {
            return Reject(InfrastructureEvidenceFailure.HashMismatch, "EvidenceUncompressedPayloadHashMismatch");
        }

        var contents = package.Artifacts.OrderBy(item => item.Reference.ArtifactId, StringComparer.Ordinal).ToArray();
        if (contents.Length != package.Manifest.Artifacts.Count)
        {
            return Reject(InfrastructureEvidenceFailure.InvalidManifest, "EvidenceArtifactContentCountMismatch");
        }

        for (var index = 0; index < contents.Length; index++)
        {
            var content = contents[index];
            var reference = package.Manifest.Artifacts[index];
            if (!Equals(content.Reference, reference) || content.Bytes.LongLength != reference.Bytes ||
                !string.Equals(Hash(content.Bytes), reference.Sha256, StringComparison.Ordinal))
            {
                return Reject(InfrastructureEvidenceFailure.HashMismatch, "EvidenceArtifactContentHashMismatch");
            }
        }

        return InfrastructureEvidenceValidationResult.Success;
    }

    public static byte[] EncodePackage(InfrastructureEvidenceBatchPackage package)
    {
        var validation = ValidatePackage(package, InfrastructureSessionLimits.CompiledMaximumEvidenceBatchBytes);
        if (!validation.Valid)
        {
            throw new InvalidDataException(validation.ErrorCode);
        }

        using var output = new MemoryStream();
        output.Write(PackageMagic);
        WriteBlock(output, JsonSerializer.SerializeToUtf8Bytes(package.Manifest, JsonOptions));
        WriteBlock(output, package.Payload);
        WriteInt32(output, package.Artifacts.Count);
        foreach (var artifact in package.Artifacts.OrderBy(item => item.Reference.ArtifactId, StringComparer.Ordinal))
        {
            WriteBlock(output, JsonSerializer.SerializeToUtf8Bytes(artifact.Reference, JsonOptions));
            WriteBlock(output, artifact.Bytes);
        }

        return output.ToArray();
    }

    public static InfrastructureEvidenceBatchPackage DecodePackage(
        ReadOnlySpan<byte> bytes,
        long maximumBatchBytes = InfrastructureSessionLimits.CompiledMaximumEvidenceBatchBytes)
    {
        if (bytes.Length <= PackageMagic.Length || bytes.Length > maximumBatchBytes + 4 * 1024 * 1024)
        {
            throw new InvalidDataException("EvidencePackageLengthInvalid");
        }

        using var input = new MemoryStream(bytes.ToArray(), writable: false);
        Span<byte> magic = stackalloc byte[PackageMagic.Length];
        ReadExact(input, magic);
        if (!magic.SequenceEqual(PackageMagic))
        {
            throw new InvalidDataException("EvidencePackageMagicInvalid");
        }

        var manifest = JsonSerializer.Deserialize<InfrastructureEvidenceBatchManifest>(
                           ReadBlock(input, 2 * 1024 * 1024), JsonOptions)
                       ?? throw new InvalidDataException("EvidencePackageManifestMissing");
        var payload = ReadBlock(input, checked((int)Math.Min(maximumBatchBytes, int.MaxValue)));
        var artifactCount = ReadInt32(input);
        if (artifactCount < 0 || artifactCount > InfrastructureEvidenceInterchange.MaximumArtifactsPerBatch)
        {
            throw new InvalidDataException("EvidencePackageArtifactCountInvalid");
        }

        var artifacts = new List<InfrastructureEvidenceArtifactContent>(artifactCount);
        for (var index = 0; index < artifactCount; index++)
        {
            var reference = JsonSerializer.Deserialize<InfrastructureEvidenceArtifactReference>(
                                ReadBlock(input, 64 * 1024), JsonOptions)
                            ?? throw new InvalidDataException("EvidencePackageArtifactReferenceMissing");
            var content = ReadBlock(input, checked((int)Math.Min(maximumBatchBytes, int.MaxValue)));
            artifacts.Add(new InfrastructureEvidenceArtifactContent { Reference = reference, Bytes = content });
        }

        if (input.Position != input.Length)
        {
            throw new InvalidDataException("EvidencePackageTrailingBytes");
        }

        var package = new InfrastructureEvidenceBatchPackage
        {
            Manifest = manifest,
            Payload = payload,
            Artifacts = Array.AsReadOnly(artifacts.ToArray())
        };
        var validation = ValidatePackage(package, maximumBatchBytes);
        if (!validation.Valid)
        {
            throw new InvalidDataException(validation.ErrorCode);
        }

        return package;
    }

    public static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    public static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    public static bool IsIdentifier(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= InfrastructureEvidenceInterchange.MaximumIdentifierCharacters &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or ':');

    private static InfrastructureEvidenceValidationResult ValidateDraft(
        InfrastructureEvidenceBatchDraft draft,
        int payloadBytes,
        IReadOnlyList<InfrastructureEvidenceArtifactContent> artifacts)
    {
        if (!IsRouteValid(draft.Route) || draft.SequenceStart <= 0 || draft.SequenceEnd < draft.SequenceStart ||
            draft.Records is not { Count: > 0 and <= InfrastructureEvidenceInterchange.MaximumRecordsPerBatch } ||
            draft.SequenceEnd - draft.SequenceStart + 1 != draft.Records.Count ||
            draft.Artifacts.Count > InfrastructureEvidenceInterchange.MaximumArtifactsPerBatch ||
            draft.Artifacts.Count != artifacts.Count || payloadBytes <= 0 ||
            payloadBytes > InfrastructureSessionLimits.CompiledMaximumEvidenceBatchBytes ||
            draft.EvidenceSchemaVersion <= 0 || draft.SourceVersion <= 0 ||
            !IsUtc(draft.CreatedAtUtc) || !IsUtc(draft.SourceTimeStartUtc) || !IsUtc(draft.SourceTimeEndUtc) ||
            draft.SourceTimeEndUtc < draft.SourceTimeStartUtc || draft.ClockUncertaintyMilliseconds < 0 ||
            draft.Compression is not (InfrastructureSessionCompression.None or InfrastructureSessionCompression.Gzip) ||
            (!string.IsNullOrEmpty(draft.PreviousBatchId) && !IsIdentifier(draft.PreviousBatchId)))
        {
            return Reject(InfrastructureEvidenceFailure.InvalidManifest, "EvidenceBatchDraftInvalid");
        }

        var references = draft.Artifacts.OrderBy(item => item.ArtifactId, StringComparer.Ordinal).ToArray();
        for (var index = 0; index < references.Length; index++)
        {
            if (!IsArtifactReferenceValid(references[index]) ||
                !Equals(references[index], artifacts[index].Reference) ||
                artifacts[index].Bytes.LongLength != references[index].Bytes ||
                !string.Equals(Hash(artifacts[index].Bytes), references[index].Sha256, StringComparison.Ordinal))
            {
                return Reject(InfrastructureEvidenceFailure.HashMismatch, "EvidenceArtifactDraftInvalid");
            }
        }

        return InfrastructureEvidenceValidationResult.Success;
    }

    private static bool IsRouteValid(InfrastructureEvidenceRoute route) =>
        route != null && IsIdentifier(route.CaseId) && IsIdentifier(route.CaptureId) &&
        IsIdentifier(route.AgentId) && IsIdentifier(route.HostId) && IsIdentifier(route.SourceRunId) &&
        IsIdentifier(route.JobId) && IsIdentifier(route.SourceId) && IsIdentifier(route.DatabaseIdentity);

    private static bool IsArtifactReferenceValid(InfrastructureEvidenceArtifactReference artifact) =>
        artifact != null && IsIdentifier(artifact.ArtifactId) && IsSha256(artifact.Sha256) &&
        string.Equals(artifact.ArtifactId, "artifact-" + artifact.Sha256, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(artifact.FileName) &&
        artifact.FileName.Length <= InfrastructureEvidenceInterchange.MaximumFileNameCharacters &&
        !Path.IsPathRooted(artifact.FileName) &&
        string.Equals(artifact.FileName, Path.GetFileName(artifact.FileName), StringComparison.Ordinal) &&
        artifact.FileName.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 &&
        artifact.FileName is not "." and not ".." &&
        !string.IsNullOrWhiteSpace(artifact.ContentType) &&
        artifact.ContentType.Length <= InfrastructureEvidenceInterchange.MaximumContentTypeCharacters &&
        artifact.Bytes > 0 && artifact.ChunkBytes is > 0 and <= InfrastructureEvidenceInterchange.MaximumDecodedChunkBytes;

    private static byte[] EncodePayload(ReadOnlySpan<byte> bytes, InfrastructureSessionCompression compression)
    {
        if (compression == InfrastructureSessionCompression.None)
        {
            return bytes.ToArray();
        }

        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gzip.Write(bytes);
        }

        return output.ToArray();
    }

    private static byte[] DecodePayload(
        ReadOnlySpan<byte> bytes,
        InfrastructureSessionCompression compression,
        long maximumBytes)
    {
        if (compression == InfrastructureSessionCompression.None)
        {
            return bytes.ToArray();
        }

        using var input = new MemoryStream(bytes.ToArray(), writable: false);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = gzip.Read(buffer);
            if (read == 0)
            {
                break;
            }

            if (output.Length + read > maximumBytes ||
                output.Length + read > bytes.Length * InfrastructureSessionLimits.CompiledMaximumDecompressionRatio)
            {
                throw new InvalidDataException("EvidencePayloadExpansionRejected");
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }

    private static byte[] SerializeIdentity(InfrastructureEvidenceBatchManifest manifest)
    {
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("interchangeVersion", manifest.InterchangeVersion);
            writer.WriteString("batchId", manifest.BatchId);
            WriteRoute(writer, manifest.Route);
            writer.WriteNumber("sequenceStart", manifest.SequenceStart);
            writer.WriteNumber("sequenceEnd", manifest.SequenceEnd);
            writer.WriteNumber("recordCount", manifest.RecordCount);
            writer.WriteString("previousBatchId", manifest.PreviousBatchId);
            writer.WriteNumber("evidenceSchemaVersion", manifest.EvidenceSchemaVersion);
            writer.WriteNumber("sourceVersion", manifest.SourceVersion);
            writer.WriteString("createdAtUtc", manifest.CreatedAtUtc.ToString("O"));
            writer.WriteString("sourceTimeStartUtc", manifest.SourceTimeStartUtc.ToString("O"));
            writer.WriteString("sourceTimeEndUtc", manifest.SourceTimeEndUtc.ToString("O"));
            writer.WriteNumber("clockUncertaintyMilliseconds", manifest.ClockUncertaintyMilliseconds);
            writer.WriteString("compression", manifest.Compression.ToString());
            writer.WriteNumber("payloadBytes", manifest.PayloadBytes);
            writer.WriteNumber("uncompressedPayloadBytes", manifest.UncompressedPayloadBytes);
            writer.WriteString("payloadSha256", manifest.PayloadSha256);
            writer.WriteString("uncompressedPayloadSha256", manifest.UncompressedPayloadSha256);
            writer.WriteStartArray("records");
            foreach (var record in manifest.Records)
            {
                writer.WriteStartObject();
                writer.WriteNumber("sequence", record.Sequence);
                writer.WriteString("recordId", record.RecordId);
                writer.WriteString("sha256", record.Sha256);
                writer.WriteString("nativeTimestampUtc", record.NativeTimestampUtc.ToString("O"));
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartArray("artifacts");
            foreach (var artifact in manifest.Artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("artifactId", artifact.ArtifactId);
                writer.WriteString("fileName", artifact.FileName);
                writer.WriteString("contentType", artifact.ContentType);
                writer.WriteNumber("bytes", artifact.Bytes);
                writer.WriteString("sha256", artifact.Sha256);
                writer.WriteNumber("chunkBytes", artifact.ChunkBytes);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return output.ToArray();
    }

    private static byte[] SerializeStableBatchIdentity(InfrastructureEvidenceBatchManifest manifest)
    {
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("interchangeVersion", manifest.InterchangeVersion);
            WriteRoute(writer, manifest.Route);
            writer.WriteNumber("sequenceStart", manifest.SequenceStart);
            writer.WriteNumber("sequenceEnd", manifest.SequenceEnd);
            writer.WriteString("previousBatchId", manifest.PreviousBatchId);
            writer.WriteNumber("evidenceSchemaVersion", manifest.EvidenceSchemaVersion);
            writer.WriteNumber("sourceVersion", manifest.SourceVersion);
            writer.WriteEndObject();
        }
        return output.ToArray();
    }

    private static void WriteRoute(Utf8JsonWriter writer, InfrastructureEvidenceRoute route)
    {
        writer.WriteStartObject("route");
        writer.WriteString("caseId", route.CaseId);
        writer.WriteString("captureId", route.CaptureId);
        writer.WriteString("agentId", route.AgentId);
        writer.WriteString("hostId", route.HostId);
        writer.WriteString("sourceRunId", route.SourceRunId);
        writer.WriteString("jobId", route.JobId);
        writer.WriteString("sourceId", route.SourceId);
        writer.WriteString("databaseIdentity", route.DatabaseIdentity);
        writer.WriteEndObject();
    }

    private static bool IsUtc(DateTime value) => value.Kind == DateTimeKind.Utc;

    private static InfrastructureEvidenceValidationResult Reject(
        InfrastructureEvidenceFailure failure,
        string code) => InfrastructureEvidenceValidationResult.Reject(failure, code);

    private static void WriteBlock(Stream stream, ReadOnlySpan<byte> bytes)
    {
        WriteInt32(stream, bytes.Length);
        stream.Write(bytes);
    }

    private static byte[] ReadBlock(Stream stream, int maximumBytes)
    {
        var length = ReadInt32(stream);
        if (length <= 0 || length > maximumBytes)
        {
            throw new InvalidDataException("EvidencePackageBlockLengthInvalid");
        }
        var bytes = new byte[length];
        ReadExact(stream, bytes);
        return bytes;
    }

    private static void WriteInt32(Stream stream, int value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static int ReadInt32(Stream stream)
    {
        Span<byte> bytes = stackalloc byte[4];
        ReadExact(stream, bytes);
        return BinaryPrimitives.ReadInt32BigEndian(bytes);
    }

    private static void ReadExact(Stream stream, Span<byte> bytes)
    {
        var total = 0;
        while (total < bytes.Length)
        {
            var read = stream.Read(bytes[total..]);
            if (read == 0)
            {
                throw new EndOfStreamException("EvidencePackageTruncated");
            }
            total += read;
        }
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            AllowDuplicateProperties = false,
            MaxDepth = 32
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false));
        return options;
    }
}

public sealed record InfrastructureEvidenceBatchPreparePayload
{
    public Guid TransferId { get; init; }

    public InfrastructureEvidenceBatchManifest Manifest { get; init; } = new();
}

public sealed record InfrastructureEvidenceArtifactPreparePayload
{
    public Guid TransferId { get; init; }

    public string BatchId { get; init; } = string.Empty;

    public InfrastructureEvidenceArtifactReference Artifact { get; init; } = new();
}

public sealed record InfrastructureEvidenceContentChunkPayload
{
    public Guid TransferId { get; init; }

    public string BatchId { get; init; } = string.Empty;

    public InfrastructureEvidenceContentKind ContentKind { get; init; }

    public string ContentId { get; init; } = string.Empty;

    public int ChunkIndex { get; init; }

    public long Offset { get; init; }

    public bool IsFinal { get; init; }

    public string Sha256 { get; init; } = string.Empty;

    public byte[] Bytes { get; init; } = Array.Empty<byte>();
}

public sealed record InfrastructureEvidenceCommitPayload
{
    public Guid TransferId { get; init; }

    public string BatchId { get; init; } = string.Empty;

    public string ManifestSha256 { get; init; } = string.Empty;
}

public sealed record InfrastructureEvidenceAcknowledgementPayload
{
    public Guid TransferId { get; init; }

    public string BatchId { get; init; } = string.Empty;

    public string ManifestSha256 { get; init; } = string.Empty;

    public InfrastructureEvidenceTransferOutcome Outcome { get; init; }

    public InfrastructureEvidenceFailure Failure { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public string ContentId { get; init; } = string.Empty;

    public int NextChunkIndex { get; init; }

    public string CommitId { get; init; } = string.Empty;

    public DateTime ServerReceiptTimeUtc { get; init; }
}

public sealed record InfrastructureEvidenceTransferMessage
{
    public InfrastructureSessionMessageKind Kind { get; init; }

    public InfrastructureEvidenceBatchPreparePayload? BatchPrepare { get; init; }

    public InfrastructureEvidenceArtifactPreparePayload? ArtifactPrepare { get; init; }

    public InfrastructureEvidenceContentChunkPayload? Chunk { get; init; }

    public InfrastructureEvidenceCommitPayload? Commit { get; init; }

    public InfrastructureEvidenceAcknowledgementPayload? Acknowledgement { get; init; }
}

public static class InfrastructureEvidenceTransferMessagePolicy
{
    public static InfrastructureEvidenceValidationResult Validate(
        InfrastructureEvidenceTransferMessage message,
        InfrastructureSessionBinding binding,
        InfrastructureSessionLimits limits,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(limits);
        var count = new object?[]
        {
            message.BatchPrepare,
            message.ArtifactPrepare,
            message.Chunk,
            message.Commit,
            message.Acknowledgement
        }.Count(value => value != null);
        if (count != 1 || !PayloadMatchesKind(message))
        {
            return Reject(InfrastructureEvidenceFailure.InvalidManifest, "EvidenceTransferPayloadMismatch");
        }

        if (message.BatchPrepare is { } prepare)
        {
            var validation = InfrastructureEvidenceBatchCodec.ValidateManifest(
                prepare.Manifest,
                limits.MaximumEvidenceBatchBytes);
            if (!validation.Valid)
            {
                return validation;
            }
            if (prepare.TransferId == Guid.Empty ||
                !string.Equals(prepare.Manifest.Route.AgentId, binding.AgentId, StringComparison.Ordinal) ||
                !string.Equals(prepare.Manifest.Route.HostId, binding.HostId, StringComparison.Ordinal))
            {
                return Reject(InfrastructureEvidenceFailure.InvalidRoute, "EvidenceTransferBindingMismatch");
            }
        }

        if (message.ArtifactPrepare is { } artifact &&
            (artifact.TransferId == Guid.Empty || !InfrastructureEvidenceBatchCodec.IsIdentifier(artifact.BatchId) ||
             artifact.Artifact == null || !InfrastructureEvidenceBatchCodec.IsIdentifier(artifact.Artifact.ArtifactId) ||
             !InfrastructureEvidenceBatchCodec.IsSha256(artifact.Artifact.Sha256) || artifact.Artifact.Bytes <= 0 ||
             artifact.Artifact.ChunkBytes is <= 0 or > InfrastructureEvidenceInterchange.MaximumDecodedChunkBytes ||
             Path.IsPathRooted(artifact.Artifact.FileName) ||
             !string.Equals(artifact.Artifact.FileName, Path.GetFileName(artifact.Artifact.FileName), StringComparison.Ordinal) ||
             artifact.Artifact.FileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0))
        {
            return Reject(InfrastructureEvidenceFailure.InvalidManifest, "EvidenceArtifactPrepareInvalid");
        }

        if (message.Chunk is { } chunk &&
            (chunk.TransferId == Guid.Empty || !InfrastructureEvidenceBatchCodec.IsIdentifier(chunk.BatchId) ||
             chunk.ContentKind == InfrastructureEvidenceContentKind.Unknown || !Enum.IsDefined(chunk.ContentKind) ||
             !InfrastructureEvidenceBatchCodec.IsIdentifier(chunk.ContentId) || chunk.ChunkIndex < 0 ||
             chunk.Offset < 0 || chunk.Bytes is not { Length: > 0 } ||
             chunk.Bytes.Length > InfrastructureEvidenceInterchange.MaximumDecodedChunkBytes ||
             chunk.Bytes.Length > limits.MaximumEvidenceChunkBytes ||
             !InfrastructureEvidenceBatchCodec.IsSha256(chunk.Sha256) ||
             !string.Equals(InfrastructureEvidenceBatchCodec.Hash(chunk.Bytes), chunk.Sha256, StringComparison.Ordinal)))
        {
            return Reject(InfrastructureEvidenceFailure.HashMismatch, "EvidenceChunkInvalid");
        }

        if (message.Commit is { } commit &&
            (commit.TransferId == Guid.Empty || !InfrastructureEvidenceBatchCodec.IsIdentifier(commit.BatchId) ||
             !InfrastructureEvidenceBatchCodec.IsSha256(commit.ManifestSha256)))
        {
            return Reject(InfrastructureEvidenceFailure.InvalidManifest, "EvidenceCommitInvalid");
        }

        if (message.Acknowledgement is { } acknowledgement &&
            (acknowledgement.TransferId == Guid.Empty ||
             !InfrastructureEvidenceBatchCodec.IsIdentifier(acknowledgement.BatchId) ||
             !InfrastructureEvidenceBatchCodec.IsSha256(acknowledgement.ManifestSha256) ||
             acknowledgement.Outcome == InfrastructureEvidenceTransferOutcome.Unknown ||
             !Enum.IsDefined(acknowledgement.Outcome) || !Enum.IsDefined(acknowledgement.Failure) ||
             acknowledgement.NextChunkIndex < 0 || acknowledgement.ServerReceiptTimeUtc.Kind != DateTimeKind.Utc ||
             acknowledgement.ServerReceiptTimeUtc > nowUtc + TimeSpan.FromMinutes(5) ||
             (!string.IsNullOrEmpty(acknowledgement.ContentId) &&
              !InfrastructureEvidenceBatchCodec.IsIdentifier(acknowledgement.ContentId)) ||
             (!string.IsNullOrEmpty(acknowledgement.CommitId) &&
              !InfrastructureEvidenceBatchCodec.IsIdentifier(acknowledgement.CommitId)) ||
             (!string.IsNullOrEmpty(acknowledgement.ErrorCode) &&
              !InfrastructureEvidenceBatchCodec.IsIdentifier(acknowledgement.ErrorCode)) ||
             !IsAcknowledgementOutcomeConsistent(acknowledgement)))
        {
            return Reject(InfrastructureEvidenceFailure.InvalidManifest, "EvidenceAcknowledgementInvalid");
        }

        return InfrastructureEvidenceValidationResult.Success;
    }

    private static bool PayloadMatchesKind(InfrastructureEvidenceTransferMessage message) => message.Kind switch
    {
        InfrastructureSessionMessageKind.EvidenceBatchManifest => message.BatchPrepare != null,
        InfrastructureSessionMessageKind.EvidenceArtifactManifest => message.ArtifactPrepare != null,
        InfrastructureSessionMessageKind.EvidenceContentChunk => message.Chunk != null,
        InfrastructureSessionMessageKind.EvidenceCommit => message.Commit != null,
        InfrastructureSessionMessageKind.EvidenceAcknowledgement => message.Acknowledgement != null,
        _ => false
    };

    private static bool IsAcknowledgementOutcomeConsistent(
        InfrastructureEvidenceAcknowledgementPayload acknowledgement)
    {
        var committed = acknowledgement.Outcome is InfrastructureEvidenceTransferOutcome.Committed or
            InfrastructureEvidenceTransferOutcome.DuplicateCommitted;
        var accepted = acknowledgement.Outcome is InfrastructureEvidenceTransferOutcome.Prepared or
            InfrastructureEvidenceTransferOutcome.ChunkAccepted;
        var failed = acknowledgement.Outcome is InfrastructureEvidenceTransferOutcome.Rejected or
            InfrastructureEvidenceTransferOutcome.Conflict or InfrastructureEvidenceTransferOutcome.Incomplete;
        return committed
            ? acknowledgement.Failure == InfrastructureEvidenceFailure.None &&
              !string.IsNullOrEmpty(acknowledgement.CommitId)
            : string.IsNullOrEmpty(acknowledgement.CommitId) &&
              ((accepted && acknowledgement.Failure == InfrastructureEvidenceFailure.None) ||
               (failed && acknowledgement.Failure != InfrastructureEvidenceFailure.None));
    }

    private static InfrastructureEvidenceValidationResult Reject(
        InfrastructureEvidenceFailure failure,
        string errorCode) => InfrastructureEvidenceValidationResult.Reject(failure, errorCode);
}
