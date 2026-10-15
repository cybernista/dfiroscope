using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProcInsider.Models;

/// <summary>One owned read. Parsing and hashing see the same original bytes; no source path can be reopened here.</summary>
public sealed class ForensicOwnedInput
{
    public const int MaximumBytes = 64 * 1024 * 1024;
    private readonly byte[] _bytes;
    public ForensicOwnedInput(ReadOnlySpan<byte> bytes, int maximumBytes = MaximumBytes)
    {
        if (maximumBytes < 0 || maximumBytes > MaximumBytes || bytes.Length > maximumBytes)
            throw new InvalidDataException("Forensic input exceeds its admitted byte allowance.");
        _bytes = bytes.ToArray();
        Sha256 = Convert.ToHexString(SHA256.HashData(_bytes));
    }
    public int ByteCount => _bytes.Length;
    public string Sha256 { get; }
    public Stream OpenRead() => new MemoryStream(_bytes, 0, _bytes.Length, writable: false, publiclyVisible: false);
}

public enum ForensicReadStatus { Succeeded, Failed, Cancelled }
public enum ForensicParseStatus { NotAttempted, Succeeded, Partial, Unsupported, Failed, Cancelled }
public enum ForensicReadConsistency { Unknown, Stable, ChangedDuringRead }
public enum ForensicSourcePathSemantics { WindowsOrdinalIgnoreCase, WindowsOrdinal }

public sealed record ForensicParserIdentity
{
    public string ParserId { get; init; } = string.Empty;
    public string ParserVersion { get; init; } = string.Empty;
    public string SettingsJson { get; init; } = "{}";
}

public sealed record ForensicArtifactOutput
{
    public string OutputKey { get; init; } = string.Empty;
    public string ArtifactType { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public DateTime? PrimaryTimeUtc { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;
    public int PayloadVersion { get; init; } = 1;
    public string PropertiesJson { get; init; } = "{}";
}

public interface IForensicArtifactParser
{
    ForensicParserIdentity Identity { get; }
    ForensicParseResult Parse(ForensicOwnedInput input, CancellationToken cancellationToken);
}

public sealed record ForensicParseResult(ForensicParseStatus Status, IReadOnlyList<ForensicArtifactOutput> Outputs, string DiagnosticCode = "", string Diagnostic = "");

public sealed record ForensicArtifactAppendResult(int PersistedRowCount, int DuplicateReadCount, int ReusedResultCount);

/// <summary>Stable columns available for the read-only structured forensic-result table.</summary>
public enum ForensicArtifactResultColumn
{
    ObservedUtc,
    ArtifactType,
    Category,
    ParserId,
    ParserVersion,
    Name,
    Summary,
    SourcePath,
    Host,
    InputSha256,
    SourceRunId,
    IngestionJobId
}

/// <summary>One evidence-scope family used by transient green result selection.</summary>
public enum ForensicArtifactResultScopeFacet
{
    Case,
    EvidenceSession,
    Capture,
    SourceIdentity,
    Host,
    ExecutionRoot,
    ArtifactType,
    Category
}

public enum ForensicArtifactResultAvailability { Available, Unavailable, Failed }

public sealed record ForensicArtifactResultColumnFilter(
    ForensicArtifactResultColumn Column,
    ProcInsider.Services.ColumnFilterCriteria Criteria);

/// <summary>
/// A transient result scope selector. Inclusions are OR alternatives inside one facet and
/// combine across facets; exclusions subtract after inclusion. It never changes evidence.
/// </summary>
public sealed record ForensicArtifactResultGreenSelector(
    ForensicArtifactResultScopeFacet Facet,
    string Value,
    bool IsExcluded = false);

public sealed record ForensicArtifactResultQuery(
    IReadOnlyList<ForensicArtifactResultGreenSelector>? GreenSelectors = null,
    IReadOnlyList<ForensicArtifactResultColumnFilter>? Filters = null,
    ForensicArtifactResultColumn Sort = ForensicArtifactResultColumn.ObservedUtc,
    bool Descending = true,
    long Offset = 0,
    int PageSize = 128);

public sealed record ForensicArtifactResultRow(
    string ArtifactId,
    EvidenceIdentity Scope,
    string SourceRunId,
    string IngestionJobId,
    long RawRecordId,
    DateTime? PrimaryTimeUtc,
    string ArtifactType,
    string Category,
    string ParserId,
    string ParserVersion,
    string Name,
    string SourcePath,
    string Summary,
    string InputSha256,
    long? InputByteCount,
    string ResultSha256,
    string OutputKey,
    bool? OriginalFileRetained);

public sealed record ForensicArtifactResultFacetCount(string Value, long Count);

public sealed record ForensicArtifactResultPage(
    IReadOnlyList<ForensicArtifactResultRow> Rows,
    long RootCount,
    long ViewCount,
    IReadOnlyDictionary<string, long> CategoryCounts,
    IReadOnlyDictionary<ForensicArtifactResultScopeFacet, IReadOnlyList<ForensicArtifactResultFacetCount>> FacetCounts,
    ForensicArtifactResultAvailability Availability,
    string Diagnostic);

public enum ForensicArtifactResultPropertyColumn { Name, Value, ValueType }

public sealed record ForensicArtifactResultPropertyColumnFilter(
    ForensicArtifactResultPropertyColumn Column,
    ProcInsider.Services.ColumnFilterCriteria Criteria);

public sealed record ForensicArtifactResultPropertyQuery(
    IReadOnlyList<ForensicArtifactResultPropertyColumnFilter>? Filters = null,
    ForensicArtifactResultPropertyColumn Sort = ForensicArtifactResultPropertyColumn.Name,
    bool Descending = false,
    long Offset = 0,
    int PageSize = 128);

public sealed record ForensicArtifactResultProperty(string Name, string? Value, string ValueType);

public sealed record ForensicArtifactResultPropertiesPage(
    IReadOnlyList<ForensicArtifactResultProperty> Rows,
    long MatchingRows,
    ForensicArtifactResultAvailability Availability,
    string Diagnostic);

/// <summary>One exact immutable receipt-to-result derivation; the receipt does not duplicate result body JSON.</summary>
public sealed record ForensicArtifactResultReadOccurrence(
    long RawRecordId,
    string RelationId,
    EvidenceIdentity Scope,
    string SourceRunId,
    string IngestionJobId,
    DateTime ReadCompletedUtc,
    string ReceiptSha256,
    bool OriginalFileRetained)
{
    public ForensicReadAttempt? ReadMetadata { get; init; }
    public string SourceRunMetadataJson { get; init; } = "{}";
    public string SourceRunStatus { get; init; } = "Unknown";
}

public sealed record ForensicArtifactResultDetail(
    ForensicArtifactResultRow? Result,
    IReadOnlyList<ForensicArtifactResultReadOccurrence> ReadOccurrences,
    long ReadOccurrenceCount,
    ForensicArtifactResultAvailability Availability,
    string Diagnostic);

/// <summary>Immutable attempt metadata, not preserved file bytes. Failed attempts can be followed by a new attempt.</summary>
public sealed record ForensicReadAttempt
{
    public int ContractVersion { get; init; } = 1;
    public string AttemptId { get; init; } = string.Empty;
    public EvidenceIdentity Scope { get; init; } = new();
    public string SourceRunId { get; init; } = string.Empty;
    public Guid IngestionJobId { get; init; }
    public string SourcePath { get; init; } = string.Empty;
    public ForensicSourcePathSemantics PathSemantics { get; init; }
    public DateTime ReadStartedUtc { get; init; }
    public DateTime ReadCompletedUtc { get; init; }
    public DateTime? SourceCreatedUtc { get; init; }
    public DateTime? SourceLastModifiedUtc { get; init; }
    public long? InputByteCount { get; init; }
    public string? InputSha256 { get; init; }
    public ForensicReadConsistency Consistency { get; init; }
    public ForensicReadStatus Status { get; init; }
    public ForensicParseStatus ParserStatus { get; init; }
    public string DiagnosticCode { get; init; } = string.Empty;
    public string Diagnostic { get; init; } = string.Empty;
    public bool OriginalFileRetained => false;
    public ForensicParserIdentity Parser { get; init; } = new();
    public IReadOnlyList<ForensicArtifactOutput> Outputs { get; init; } = [];
}

/// <summary>Version-1 identity and lossless JSON rules, scoped only to the new structured-result path.</summary>
public static class ForensicArtifactContract
{
    public const int MaximumJsonBytes = 1024 * 1024;
    public const int MaximumOutputsPerRead = 128;
    public const int MaximumPublicationBytes = 16 * 1024 * 1024;

    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public static string CanonicalJson(string json)
    {
        if (Encoding.UTF8.GetByteCount(json) > MaximumJsonBytes) throw new InvalidDataException("Forensic JSON exceeds its byte allowance.");
        ValidateText(json, MaximumJsonBytes, allowEmpty: false);
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Forensic properties/settings require a JSON object.");
        using var buffer = new BoundedJsonBuffer(MaximumJsonBytes);
        using (var writer = new Utf8JsonWriter(buffer)) Write(document.RootElement, writer);
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static void Write(JsonElement element, Utf8JsonWriter writer)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var properties = element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal).ToArray();
            if (properties.Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != properties.Length)
                throw new InvalidDataException("Duplicate forensic JSON property.");
            writer.WriteStartObject();
            foreach (var property in properties) { ValidateText(property.Name, MaximumJsonBytes, true); writer.WritePropertyName(property.Name); Write(property.Value, writer); }
            writer.WriteEndObject();
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            writer.WriteStartArray(); foreach (var item in element.EnumerateArray()) Write(item, writer); writer.WriteEndArray();
        }
        else if (element.ValueKind == JsonValueKind.String)
        {
            var value = element.GetString()!; ValidateText(value, MaximumJsonBytes, true); writer.WriteStringValue(value);
        }
        else element.WriteTo(writer); // Numbers, nulls and booleans retain their native JSON representation.
    }

    public static string PathKey(string path, ForensicSourcePathSemantics semantics)
    {
        ValidateText(path, 16384, false);
        if (!Enum.IsDefined(semantics) || path.Any(char.IsControl)) throw new InvalidDataException("Unsupported forensic source path semantics.");
        var normalized = path.Replace('/', '\\');
        if (normalized.Length < 3 || !char.IsAsciiLetter(normalized[0]) || normalized[1] != ':' || normalized[2] != '\\' ||
            normalized[3..].Split('\\').Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.') || p.Contains(':')))
            throw new InvalidDataException("Forensic source paths require an ordinary absolute Windows drive path.");
        return semantics == ForensicSourcePathSemantics.WindowsOrdinalIgnoreCase ? normalized.ToUpperInvariant() : normalized;
    }

    public static void ValidateText(string value, int maximumCharacters, bool allowEmpty)
    {
        if (value == null || value.Length > maximumCharacters || (!allowEmpty && string.IsNullOrWhiteSpace(value)) || value.Contains('\0'))
            throw new InvalidDataException("Invalid or over-limit forensic text.");
        for (var i = 0; i < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i])) { if (++i >= value.Length || !char.IsLowSurrogate(value[i])) throw new InvalidDataException("Unpaired forensic UTF-16 surrogate."); }
            else if (char.IsLowSurrogate(value[i])) throw new InvalidDataException("Unpaired forensic UTF-16 surrogate.");
        }
    }

    public static IReadOnlyList<ForensicReadAttempt> Freeze(IReadOnlyList<ForensicReadAttempt> reads)
    {
        if (reads.Count > 128) throw new InvalidDataException("Forensic publication read cap exceeded.");
        long bytes = 0;
        // Charge the entire admitted publication before any canonicalization/snapshot allocation.
        foreach (var read in reads)
        {
            if (read.Outputs.Count > MaximumOutputsPerRead) throw new InvalidDataException("Forensic output cap exceeded.");
            bytes += Encoding.UTF8.GetByteCount(read.Parser.SettingsJson) + Encoding.UTF8.GetByteCount(read.SourcePath) + Encoding.UTF8.GetByteCount(read.Diagnostic);
            foreach (var output in read.Outputs) bytes += Encoding.UTF8.GetByteCount(output.PropertiesJson) + Encoding.UTF8.GetByteCount(output.Name) + Encoding.UTF8.GetByteCount(output.Summary) + 4096;
            if (bytes > MaximumPublicationBytes) throw new InvalidDataException("Forensic aggregate publication cap exceeded.");
        }
        var frozen = new List<ForensicReadAttempt>(reads.Count);
        long serializedBytes = 0;
        foreach (var read in reads) frozen.Add(FreezeRead(read, ref serializedBytes));
        return frozen.ToArray();
    }

    private static ForensicReadAttempt FreezeRead(ForensicReadAttempt read, ref long serializedBytes)
    {
        ValidateText(read.AttemptId, 256, false); ValidateText(read.SourceRunId, 256, false);
        foreach (var value in new[] { read.Scope.CaseId, read.Scope.EvidenceSessionId, read.Scope.CaptureId, read.Scope.SourceIdentityId, read.Scope.HostId, read.Scope.ExecutionRootId }) ValidateText(value, 1024, true);
        if (read.ContractVersion != 1 || read.IngestionJobId == Guid.Empty || string.IsNullOrWhiteSpace(read.Scope.EvidenceSessionId) ||
            string.IsNullOrWhiteSpace(read.Scope.CaptureId) || string.IsNullOrWhiteSpace(read.Scope.SourceIdentityId) || string.IsNullOrWhiteSpace(read.Scope.HostId) || string.IsNullOrWhiteSpace(read.Scope.ExecutionRootId) ||
            !Enum.IsDefined(read.Status) || !Enum.IsDefined(read.ParserStatus) || !Enum.IsDefined(read.Consistency) || read.ReadStartedUtc.Kind != DateTimeKind.Utc || read.ReadCompletedUtc.Kind != DateTimeKind.Utc || read.ReadCompletedUtc < read.ReadStartedUtc)
            throw new InvalidDataException("Forensic read requires exact scope, provenance and a valid UTC interval.");
        foreach (var time in new[] { read.SourceCreatedUtc, read.SourceLastModifiedUtc }) if (time.HasValue && time.Value.Kind != DateTimeKind.Utc) throw new InvalidDataException("Forensic source time must be UTC or unknown.");
        _ = PathKey(read.SourcePath, read.PathSemantics); ValidateText(read.Diagnostic, 16384, true); ValidateText(read.DiagnosticCode,256,true);
        ValidateText(read.Parser.ParserId, 256, false); ValidateText(read.Parser.ParserVersion, 256, false);
        if (read.InputByteCount is < 0 or > ForensicOwnedInput.MaximumBytes ||
            (read.InputByteCount.HasValue != (read.InputSha256 != null)) || (read.InputSha256 != null && (read.InputSha256.Length != 64 || !read.InputSha256.All(Uri.IsHexDigit))) ||
            (read.Status == ForensicReadStatus.Succeeded && !read.InputByteCount.HasValue) ||
            (read.Outputs.Count > 0 && (read.Status != ForensicReadStatus.Succeeded || read.ParserStatus is not (ForensicParseStatus.Succeeded or ForensicParseStatus.Partial) || read.Consistency == ForensicReadConsistency.ChangedDuringRead)) ||
            (read.Status != ForensicReadStatus.Succeeded && read.ParserStatus is not (ForensicParseStatus.NotAttempted or ForensicParseStatus.Cancelled)))
            throw new InvalidDataException("Forensic outcomes cannot invent a successful result or unknown input hash/count.");
        var parser = read.Parser with { SettingsJson = CanonicalJson(read.Parser.SettingsJson) };
        var metadata = read with { Parser=parser, Outputs=[] };
        ChargeSerialized(metadata, ref serializedBytes);
        var outputList = new List<ForensicArtifactOutput>(read.Outputs.Count);
        foreach (var output in read.Outputs)
        {
            foreach (var value in new[] { output.OutputKey, output.ArtifactType, output.Category }) ValidateText(value, 256, false);
            ValidateText(output.Name, 4096, true); ValidateText(output.Summary, 16384, true);
            if (output.PayloadVersion <= 0 || (output.PrimaryTimeUtc.HasValue && output.PrimaryTimeUtc.Value.Kind != DateTimeKind.Utc)) throw new InvalidDataException("Invalid forensic payload version/time.");
            var normalized = output with { PropertiesJson = CanonicalJson(output.PropertiesJson) };
            ChargeSerialized(normalized, ref serializedBytes);
            outputList.Add(normalized);
        }
        var outputs = outputList.OrderBy(o => o.OutputKey, StringComparer.Ordinal).ToArray();
        if (outputs.Select(o => o.OutputKey).Distinct(StringComparer.Ordinal).Count() != outputs.Length) throw new InvalidDataException("Duplicate forensic output key.");
        return read with { Scope = new EvidenceIdentity { CaseId=read.Scope.CaseId, EvidenceSessionId=read.Scope.EvidenceSessionId, CaptureId=read.Scope.CaptureId, SourceIdentityId=read.Scope.SourceIdentityId, HostId=read.Scope.HostId, ExecutionRootId=read.Scope.ExecutionRootId },
            InputSha256 = read.InputSha256?.ToUpperInvariant(), Parser = parser, Outputs = outputs };
    }

    private static void ChargeSerialized<T>(T value, ref long bytes)
    {
        bytes += JsonSerializer.SerializeToUtf8Bytes(value).Length + 1024; // Include each receipt's bounded result-key/hash references.
        if (bytes > MaximumPublicationBytes) throw new InvalidDataException("Canonical forensic publication exceeds its serialized byte allowance.");
    }

    private sealed class BoundedJsonBuffer(int limit) : MemoryStream
    {
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (Position + buffer.Length > limit) throw new InvalidDataException("Canonical forensic JSON exceeds its byte allowance.");
            base.Write(buffer);
        }
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (Position + count > limit) throw new InvalidDataException("Canonical forensic JSON exceeds its byte allowance.");
            base.Write(buffer, offset, count); // MemoryStream's subclass span fallback calls this override; never route it back to span.
        }
        public override void WriteByte(byte value)
        {
            if (Position >= limit) throw new InvalidDataException("Canonical forensic JSON exceeds its byte allowance.");
            base.WriteByte(value);
        }
    }

    public static string ResultIdentity(ForensicReadAttempt read, ForensicArtifactOutput output) => Hash(JsonSerializer.Serialize(new
    { Version=1, read.Scope, Path=PathKey(read.SourcePath,read.PathSemantics), read.PathSemantics, read.InputSha256, read.Parser.ParserId, read.Parser.ParserVersion, SettingsHash=Hash(read.Parser.SettingsJson), output.OutputKey }));
    public static string AttemptIdentity(ForensicReadAttempt read) => Hash(JsonSerializer.Serialize(new { Version=1, read.Scope, read.SourceRunId, read.IngestionJobId, read.AttemptId }));
}
