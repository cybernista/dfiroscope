using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using ProcInsider.Models;

namespace ProcInsider.Services.Forensics;

/// <summary>Byte-only, fixture-verified modern SCCA subset. References are observations, not execution attribution.</summary>
public sealed class PrefetchParser : IForensicArtifactParser
{
    public const int MaximumInputBytes = 8 * 1024 * 1024;
    private const int MaximumMetrics = 32768, MaximumVolumes = 64, MaximumDirectories = 4096, MaximumStringCharacters = 2048;
    private const int MaximumRetainedBytes = 512 * 1024;
    private static readonly Encoding StrictUtf16 = new UnicodeEncoding(false, false, true);
    public ForensicParserIdentity Identity { get; } = new()
    {
        ParserId = "dfiroscope.prefetch", ParserVersion = "1",
        SettingsJson = "{\"inputBytes\":8388608,\"decodedBytes\":16777216,\"workspaceBytes\":4194304,\"metrics\":32768,\"volumes\":64,\"directories\":4096,\"stringCharacters\":2048,\"retainedBytes\":524288,\"layouts\":[\"v30-304\",\"v30-296\",\"v31-296-fixture-verified\"]}"
    };

    public ForensicParseResult Parse(ForensicOwnedInput input, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (input.ByteCount > MaximumInputBytes) return Outcome(ForensicParseStatus.Unsupported, "prefetch.input-cap");
            using var stream = input.OpenRead();
            var bytes = new byte[input.ByteCount]; stream.ReadExactly(bytes);
            if (bytes.Length >= 3 && bytes.AsSpan(0, 3).SequenceEqual("MAM"u8))
            {
                if (bytes.Length < 8) throw new InvalidDataException("Truncated MAM header.");
                if (bytes[3] != 4) return Outcome(ForensicParseStatus.Unsupported, "prefetch.wrapper-unsupported");
                bytes = WindowsXpressHuffman.Decode(bytes.AsSpan(8).ToArray(), U32(bytes, 4), cancellationToken);
            }
            return ParseScca(bytes, cancellationToken);
        }
        catch (OperationCanceledException) { return Outcome(ForensicParseStatus.Cancelled, "prefetch.cancelled"); }
        catch (InvalidDataException) { return Outcome(ForensicParseStatus.Failed, "prefetch.corrupt"); }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException or PlatformNotSupportedException)
        { return Outcome(ForensicParseStatus.Failed, "prefetch.native-unavailable"); }
    }

    private static ForensicParseResult ParseScca(byte[] b, CancellationToken ct)
    {
        Region(b, 0, 84);
        if (!b.AsSpan(4, 4).SequenceEqual("SCCA"u8)) throw new InvalidDataException("Invalid SCCA signature.");
        var version = U32(b, 0);
        if (version is not (30 or 31)) return Outcome(ForensicParseStatus.Unsupported, "prefetch.version-unsupported");
        Region(b, 0, 296);
        if (U32(b, 12) != b.Length) throw new InvalidDataException("SCCA declared file length mismatch.");
        var metricOffset = U32(b, 84);
        var runOffset = version == 30 && metricOffset == 304 ? 208 : metricOffset == 296 ? 200 : -1;
        if (runOffset < 0) return Outcome(ForensicParseStatus.Unsupported, "prefetch.layout-unsupported");
        var metricCount = U32(b, 88); var traceOffset = U32(b, 92); var traceCount = U32(b, 96);
        var namesOffset = U32(b, 100); var namesBytes = U32(b, 104); var volumeOffset = U32(b, 108);
        var volumeCount = U32(b, 112); var volumeBytes = U32(b, 116);
        Region(b, metricOffset, (ulong)metricCount * 32); Region(b, traceOffset, (ulong)traceCount * 8);
        Region(b, namesOffset, namesBytes); Region(b, volumeOffset, volumeBytes);
        var hashStringField = runOffset + 12;
        var hashStringOffset = U32(b, hashStringField); var hashStringBytes = U32(b, hashStringField + 4);
        Region(b, hashStringOffset, hashStringBytes);
        if (namesOffset < metricOffset + (ulong)metricCount * 32 || traceOffset < metricOffset + (ulong)metricCount * 32 ||
            namesOffset < traceOffset + (ulong)traceCount * 8 || volumeOffset < namesOffset + (ulong)namesBytes || (ulong)volumeCount * 96 > volumeBytes)
            throw new InvalidDataException("Overlapping SCCA sections.");
        var state = new RetainedBudget();
        var headerEnd = 16;
        while (headerEnd < 76 && U16(b, headerEnd) != 0) headerEnd += 2;
        var executable = headerEnd == 76 ? state.Unknown(b.AsSpan(16, 60), "header-name-unterminated") : state.Text(b.AsSpan(16, headerEnd - 16));
        if (string.IsNullOrEmpty(executable.Value)) state.Issue("header-name-unavailable");
        var times = new List<object>(8); DateTime? latest = null;
        for (var i = 0; i < 8; i++)
        {
            var raw = U64(b, 128 + i * 8); var time = Time(raw, state);
            times.Add(new { Slot = i, RawFileTime = raw, Utc = time });
            if (time.HasValue && (!latest.HasValue || time > latest)) latest = time;
        }
        var references = new List<object>();
        for (uint i = 0; i < metricCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (i >= MaximumMetrics || !state.Reserve(256)) { state.Issue("references-capped"); break; }
            var p = checked((int)(metricOffset + i * 32)); var offset = U32(b, p + 12); var chars = U32(b, p + 16);
            var text = ReadText(b, namesOffset, namesBytes, offset, chars, state);
            references.Add(new { Index = i, FilenameOffset = offset, FilenameCharacters = chars, Path = text, Flags = U32(b, p + 20), FileReference = U64(b, p + 24) });
        }
        var volumes = new List<object>();
        for (uint i = 0; i < volumeCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (i >= MaximumVolumes || !state.Reserve(512)) { state.Issue("volumes-capped"); break; }
            var p = checked((int)(volumeOffset + i * 96));
            var path = ReadText(b, volumeOffset, volumeBytes, U32(b, p), U32(b, p + 4), state);
            var rawTime = U64(b, p + 8); var creation = Time(rawTime, state);
            var refsOffset = U32(b, p + 20); var refsBytes = U32(b, p + 24);
            var refsRangeValid = refsOffset <= volumeBytes && refsBytes <= (ulong)volumeBytes - refsOffset;
            if (!refsRangeValid) state.Issue("volume-reference-range-invalid");
            var directoryCount = U32(b, p + 32); var directoryOffset = (ulong)U32(b, p + 28); var directories = new List<object>();
            for (uint d = 0; d < directoryCount; d++)
            {
                ct.ThrowIfCancellationRequested();
                if (d >= MaximumDirectories || !state.Reserve(128)) { state.Issue("directories-capped"); break; }
                if (directoryOffset > volumeBytes || 2 > (ulong)volumeBytes - directoryOffset) { state.Issue("directory-range-invalid"); break; }
                var chars = U16(b, checked((int)(volumeOffset + directoryOffset))); directoryOffset += 2;
                directories.Add(ReadText(b, volumeOffset, volumeBytes, directoryOffset, chars, state));
                directoryOffset += (ulong)chars * 2 + 2;
            }
            volumes.Add(new { Index = i, Path = path, SerialNumber = U32(b, p + 16), CreationRawFileTime = rawTime, CreationUtc = creation, DirectoryCount = directoryCount, Directories = directories, FileReferencesOffset = refsOffset, FileReferencesBytes = refsBytes, FileReferencesRangeValid = refsRangeValid });
        }
        var json = ForensicArtifactContract.CanonicalJson(JsonSerializer.Serialize(new
        {
            PayloadVersion = 1, FormatVersion = version, Layout = $"v{version}-{metricOffset}", ExecutableName = executable,
            HeaderPrefetchHash = U32(b, 76), RunCount = U32(b, runOffset), RecordedRunTimes = times, LatestRecordedRunUtc = latest,
            DeclaredMetricCount = metricCount, FileReferences = references, DeclaredVolumeCount = volumeCount, Volumes = volumes,
            Qualifications = state.Issues, Interpretation = "Recorded references are not proof of execution, PID/user attribution or maliciousness. Original filename belongs to read SourcePath. Trace chains, hash-string and opaque volume-reference data are range-validated but not interpreted."
        }));
        ct.ThrowIfCancellationRequested();
        return new(state.Issues.Count == 0 ? ForensicParseStatus.Succeeded : ForensicParseStatus.Partial,
            [new() { OutputKey = "prefetch", ArtifactType = "Prefetch", Category = "Execution", Name = string.IsNullOrEmpty(executable.Value) ? "Prefetch" : executable.Value, PrimaryTimeUtc = latest, Summary = "Recorded Prefetch configuration and references", PropertiesJson = json }],
            state.Issues.Count == 0 ? "" : "prefetch.partial", string.Join("; ", state.Issues));
    }

    private sealed record NativeText(string? Value, string? RawUtf16Base64, string State);
    private sealed class RetainedBudget
    {
        private int _remaining = MaximumRetainedBytes - 8192;
        internal List<string> Issues { get; } = [];
        internal void Issue(string code) { if (!Issues.Contains(code, StringComparer.Ordinal)) Issues.Add(code); }
        internal bool Reserve(int bytes) { if (bytes > _remaining) return false; _remaining -= bytes; return true; }
        internal NativeText Unknown(ReadOnlySpan<byte> bytes, string code)
        {
            Issue(code);
            if (!Reserve(checked(bytes.Length * 8 + 128))) { Issue("text-budget-capped"); return new(null, null, "Capped"); }
            return new(null, Convert.ToBase64String(bytes), "Malformed");
        }
        internal NativeText Text(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length / 2 > MaximumStringCharacters || !Reserve(checked(bytes.Length * 3 + 128))) { Issue("text-capped"); return new(null, null, "Capped"); }
            try { var text = StrictUtf16.GetString(bytes); if (text.Contains('\0')) return Unknown(bytes, "embedded-null"); return new(text, null, "Known"); }
            catch (DecoderFallbackException) { return Unknown(bytes, "malformed-utf16"); }
        }
    }
    private static NativeText ReadText(byte[] b, uint origin, uint length, ulong offset, uint characters, RetainedBudget state)
    {
        var bytes = (ulong)characters * 2;
        if (offset > length || bytes + 2 > (ulong)length - offset) { state.Issue("string-range-invalid"); return new(null, null, "Unavailable"); }
        if (characters > MaximumStringCharacters) { state.Issue("string-capped"); return new(null, null, "Capped"); }
        var start = checked((int)(origin + offset));
        if (U16(b, checked(start + (int)bytes)) != 0) return state.Unknown(b.AsSpan(start, checked((int)bytes)), "string-unterminated");
        return state.Text(b.AsSpan(start, checked((int)bytes)));
    }
    private static DateTime? Time(ulong raw, RetainedBudget state)
    {
        if (raw == 0) return null;
        try { return DateTime.FromFileTimeUtc(checked((long)raw)); }
        catch (Exception error) when (error is ArgumentOutOfRangeException or OverflowException) { state.Issue("invalid-filetime"); return null; }
    }
    private static void RelativeRegion(byte[] b, uint origin, uint length, ulong offset, ulong bytes)
    { if (offset > length || bytes > (ulong)length - offset) throw new InvalidDataException("Invalid relative section range."); Region(b, origin + offset, bytes); }
    private static void Region(byte[] b, ulong offset, ulong bytes)
    { if (offset > (ulong)b.Length || bytes > (ulong)b.Length - offset) throw new InvalidDataException("Truncated or overflowing section."); }
    private static ushort U16(byte[] b, int p) { Region(b, checked((ulong)p), 2); return BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p, 2)); }
    private static uint U32(byte[] b, int p) { Region(b, checked((ulong)p), 4); return BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(p, 4)); }
    private static ulong U64(byte[] b, int p) { Region(b, checked((ulong)p), 8); return BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(p, 8)); }
    private static ForensicParseResult Outcome(ForensicParseStatus status, string code) => new(status, [], code, code);
}
