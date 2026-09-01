using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class PeAnalysisService : IPeProcessImageAnalyzer
{
    private const int MaxImportNames = 256;
    private const int MaxExportNames = 256;
    private const int MaxStringSamples = 128;
    private const int MinStringLength = 5;
    private const long MaxStringScanBytes = 32L * 1024 * 1024;
    private const int FileScanBufferSize = 128 * 1024;
    private const int MaxCapturedStringLength = 4096;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false
    };

    private readonly IAuthenticodeVerificationService _authenticodeVerificationService;

    public PeAnalysisService(IAuthenticodeVerificationService? authenticodeVerificationService = null)
    {
        _authenticodeVerificationService = authenticodeVerificationService ?? new AuthenticodeVerificationService();
    }

    public Task<PeAnalysisRecord> AnalyzeProcessImageAsync(
        ProcessInfo process,
        CancellationToken cancellationToken = default)
        => AnalyzeProcessImageAsync(process, PeStringExtractionMode.Immediate, cancellationToken);

    public Task<PeAnalysisRecord> AnalyzeProcessImageAsync(
        ProcessInfo process,
        PeStringExtractionMode stringExtractionMode,
        CancellationToken cancellationToken = default)
    {
        if (process == null)
        {
            throw new ArgumentNullException(nameof(process));
        }

        var record = CreateBaseRecord(process, PeAnalysisSourceKind.ProcessImage, string.Empty, process.ProcessPath);
        return AnalyzeAsync(record, stringExtractionMode, cancellationToken);
    }

    public Task<PeAnalysisRecord> AnalyzeMemoryDumpFileAsync(
        ProcessInfo process,
        MemoryDumpRecord dump,
        CancellationToken cancellationToken = default)
    {
        if (process == null)
        {
            throw new ArgumentNullException(nameof(process));
        }

        if (dump == null)
        {
            throw new ArgumentNullException(nameof(dump));
        }

        var record = CreateBaseRecord(process, PeAnalysisSourceKind.MemoryDumpFile, dump.DumpId, dump.FilePath);
        record.CaseId = dump.CaseId;
        record.EvidenceSessionId = dump.EvidenceSessionId;
        record.CaptureId = dump.CaptureId;
        record.SourceIdentityId = dump.SourceIdentityId;
        record.HostId = dump.HostId;
        record.ExecutionRootId = dump.ExecutionRootId;
        return AnalyzeAsync(record, PeStringExtractionMode.Immediate, cancellationToken);
    }

    public Task<PeAnalysisRecord> AnalyzeFileAsync(
        ProcessInfo process,
        PeAnalysisSourceKind sourceKind,
        string sourceArtifactId,
        string filePath,
        CancellationToken cancellationToken = default)
    {
        if (process == null)
        {
            throw new ArgumentNullException(nameof(process));
        }

        var record = CreateBaseRecord(process, sourceKind, sourceArtifactId, filePath);
        return AnalyzeAsync(record, PeStringExtractionMode.Immediate, cancellationToken);
    }

    public PeAnalysisRecord CreateProcessImageRecordFromTemplate(
        ProcessInfo process,
        PeAnalysisRecord template)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(template);
        if (template.SourceKind != PeAnalysisSourceKind.ProcessImage)
        {
            throw new ArgumentException("Only process-image PE analysis records can be reused for another process.", nameof(template));
        }

        var record = new PeAnalysisRecord
        {
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            AnalysisId = BuildAnalysisId(
                string.IsNullOrWhiteSpace(process.ProcessEntityId) ? process.GetUniqueKey() : process.ProcessEntityId,
                PeAnalysisSourceKind.ProcessImage,
                string.Empty,
                template.FilePath),
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.GetUniqueKey(),
            ProcessId = process.ProcessId,
            ProcessGuid = process.ProcessGuid,
            ProcessName = process.ProcessName,
            SourceKind = PeAnalysisSourceKind.ProcessImage,
            SourceArtifactId = string.Empty,
            FilePath = template.FilePath,
            Status = template.Status,
            AnalyzedUtc = template.AnalyzedUtc,
            FileSizeBytes = template.FileSizeBytes,
            FileLastWriteUtc = template.FileLastWriteUtc,
            Sha256Hash = template.Sha256Hash,
            Md5Hash = template.Md5Hash,
            Machine = template.Machine,
            Subsystem = template.Subsystem,
            PeKind = template.PeKind,
            LinkerTimestampUtc = template.LinkerTimestampUtc,
            EntryPoint = template.EntryPoint,
            ImageBase = template.ImageBase,
            SectionCount = template.SectionCount,
            ImportCount = template.ImportCount,
            ExportCount = template.ExportCount,
            PrintableStringCount = template.PrintableStringCount,
            StringAnalysisStatus = template.StringAnalysisStatus,
            SectionsJson = template.SectionsJson,
            ImportsJson = template.ImportsJson,
            ExportsJson = template.ExportsJson,
            VersionInfoJson = template.VersionInfoJson,
            StringSummaryJson = template.StringSummaryJson,
            ErrorMessage = template.ErrorMessage,
            PerformanceJson = template.PerformanceJson,
            Source = template.Source,
            SourceRunId = template.SourceRunId,
            IngestionJobId = template.IngestionJobId
        };
        if (template.AuthenticodeVerification != null)
        {
            record.AuthenticodeVerification = AuthenticodeVerificationService.CloneForAnalysis(
                template.AuthenticodeVerification,
                record);
        }

        return record;
    }

    private Task<PeAnalysisRecord> AnalyzeAsync(
        PeAnalysisRecord record,
        PeStringExtractionMode stringExtractionMode,
        CancellationToken cancellationToken)
    {
        record.StringAnalysisStatus = stringExtractionMode == PeStringExtractionMode.Immediate
            ? PeStringAnalysisStatus.Completed
            : PeStringAnalysisStatus.Deferred;
        return Task.Run(() =>
        {
            var performance = new PeAnalysisPerformance();
            var totalTimer = Stopwatch.StartNew();
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                AnalyzeFile(record, stringExtractionMode, performance, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                record.Status = PeAnalysisStatus.Failed;
                if (stringExtractionMode == PeStringExtractionMode.Immediate)
                {
                    record.StringAnalysisStatus = PeStringAnalysisStatus.Failed;
                }
                record.ErrorMessage = ex.Message;
                record.AnalyzedUtc = DateTime.UtcNow;
            }
            finally
            {
                if (record.SourceKind == PeAnalysisSourceKind.ProcessImage && !cancellationToken.IsCancellationRequested)
                {
                    record.AuthenticodeVerification = _authenticodeVerificationService.Verify(record);
                }

                performance.TotalMilliseconds = totalTimer.Elapsed.TotalMilliseconds;
                record.PerformanceJson = JsonSerializer.Serialize(performance, JsonOptions);
            }

            return record;
        }, cancellationToken);
    }

    private static void AnalyzeFile(
        PeAnalysisRecord record,
        PeStringExtractionMode stringExtractionMode,
        PeAnalysisPerformance performance,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(record.FilePath))
        {
            throw new InvalidOperationException("No file path is available for PE analysis.");
        }

        var openTimer = Stopwatch.StartNew();
        if (!File.Exists(record.FilePath))
        {
            throw new FileNotFoundException("The file selected for PE analysis does not exist.", record.FilePath);
        }

        var info = new FileInfo(record.FilePath);
        record.FileSizeBytes = info.Length;
        record.FileLastWriteUtc = info.LastWriteTimeUtc;
        record.AnalyzedUtc = DateTime.UtcNow;

        using (var stream = new FileStream(
                   record.FilePath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.ReadWrite | FileShare.Delete,
                   FileScanBufferSize,
                   FileOptions.SequentialScan))
        {
            performance.FileOpenMilliseconds = openTimer.Elapsed.TotalMilliseconds;
            var scan = ScanFile(
                stream,
                stringExtractionMode == PeStringExtractionMode.Immediate,
                performance,
                cancellationToken);
            record.Sha256Hash = scan.Sha256Hash;
            record.Md5Hash = scan.Md5Hash;
            if (scan.StringSummary != null)
            {
                record.PrintableStringCount = scan.StringSummary.TotalCount;
                record.StringSummaryJson = JsonSerializer.Serialize(scan.StringSummary, JsonOptions);
                record.StringAnalysisStatus = PeStringAnalysisStatus.Completed;
            }
            else
            {
                record.PrintableStringCount = 0;
                record.StringSummaryJson = "{}";
                record.StringAnalysisStatus = PeStringAnalysisStatus.Deferred;
            }
            stream.Position = 0;
            var parseTimer = Stopwatch.StartNew();
            ParsePe(stream, record, cancellationToken);
            performance.PeParsingMilliseconds = parseTimer.Elapsed.TotalMilliseconds;
        }

        var versionTimer = Stopwatch.StartNew();
        record.VersionInfoJson = JsonSerializer.Serialize(ReadVersionInfo(record.FilePath), JsonOptions);
        performance.VersionMetadataMilliseconds = versionTimer.Elapsed.TotalMilliseconds;
        record.Status = PeAnalysisStatus.Completed;
        record.ErrorMessage = string.Empty;
    }

    private static void ParsePe(Stream stream, PeAnalysisRecord record, CancellationToken cancellationToken)
    {
        using var reader = new BinaryReader(stream, Encoding.ASCII, leaveOpen: true);
        if (reader.ReadUInt16() != 0x5A4D)
        {
            throw new InvalidDataException("The file is not a PE image: missing MZ header.");
        }

        stream.Position = 0x3C;
        var peOffset = reader.ReadInt32();
        if (peOffset <= 0 || peOffset > stream.Length - 256)
        {
            throw new InvalidDataException("The file has an invalid PE header offset.");
        }

        stream.Position = peOffset;
        if (reader.ReadUInt32() != 0x00004550)
        {
            throw new InvalidDataException("The file is not a PE image: missing PE signature.");
        }

        var machine = reader.ReadUInt16();
        var sectionCount = reader.ReadUInt16();
        var timestamp = reader.ReadUInt32();
        stream.Position += 8;
        var optionalHeaderSize = reader.ReadUInt16();
        stream.Position += 2;
        var optionalHeaderStart = stream.Position;
        var optionalMagic = reader.ReadUInt16();
        var isPe32Plus = optionalMagic == 0x20B;
        if (optionalMagic != 0x10B && optionalMagic != 0x20B)
        {
            throw new InvalidDataException("The PE optional header has an unsupported magic value.");
        }

        stream.Position = optionalHeaderStart + 16;
        var entryPointRva = reader.ReadUInt32();
        stream.Position = optionalHeaderStart + (isPe32Plus ? 24 : 28);
        var imageBase = isPe32Plus ? reader.ReadUInt64() : reader.ReadUInt32();
        stream.Position = optionalHeaderStart + 68;
        var subsystem = reader.ReadUInt16();
        var dataDirectoryStart = optionalHeaderStart + (isPe32Plus ? 112 : 96);
        stream.Position = dataDirectoryStart;
        var exportDirectory = ReadDataDirectory(reader);
        var importDirectory = ReadDataDirectory(reader);

        stream.Position = optionalHeaderStart + optionalHeaderSize;
        var sections = new List<PeSectionInfo>();
        for (var i = 0; i < sectionCount; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            sections.Add(ReadSection(reader));
        }

        record.Machine = FormatMachine(machine);
        record.Subsystem = FormatSubsystem(subsystem);
        record.PeKind = isPe32Plus ? "PE32+" : "PE32";
        record.LinkerTimestampUtc = timestamp == 0
            ? null
            : DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime;
        record.EntryPoint = FormatHex(entryPointRva);
        record.ImageBase = FormatHex(imageBase);
        record.SectionCount = sections.Count;
        record.SectionsJson = JsonSerializer.Serialize(sections, JsonOptions);

        var imports = ReadImports(reader, stream, importDirectory.Rva, sections, isPe32Plus, cancellationToken);
        record.ImportCount = imports.Count;
        record.ImportsJson = JsonSerializer.Serialize(imports, JsonOptions);

        var exports = ReadExports(reader, stream, exportDirectory.Rva, sections, cancellationToken);
        record.ExportCount = exports.Count;
        record.ExportsJson = JsonSerializer.Serialize(exports, JsonOptions);
    }

    private static PeDataDirectory ReadDataDirectory(BinaryReader reader)
        => new(reader.ReadUInt32(), reader.ReadUInt32());

    private static PeSectionInfo ReadSection(BinaryReader reader)
    {
        var nameBytes = reader.ReadBytes(8);
        var name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
        var virtualSize = reader.ReadUInt32();
        var virtualAddress = reader.ReadUInt32();
        var rawSize = reader.ReadUInt32();
        var rawPointer = reader.ReadUInt32();
        reader.BaseStream.Position += 12;
        var characteristics = reader.ReadUInt32();
        return new PeSectionInfo(name, FormatHex(virtualAddress), virtualSize, rawSize, FormatHex(rawPointer), FormatHex(characteristics));
    }

    private static List<PeImportInfo> ReadImports(
        BinaryReader reader,
        Stream stream,
        uint importDirectoryRva,
        IReadOnlyList<PeSectionInfo> sections,
        bool isPe32Plus,
        CancellationToken cancellationToken)
    {
        var imports = new List<PeImportInfo>();
        if (importDirectoryRva == 0 || !TryRvaToOffset(importDirectoryRva, sections, out var importOffset))
        {
            return imports;
        }

        stream.Position = importOffset;
        for (var descriptorIndex = 0; descriptorIndex < 512 && imports.Count < MaxImportNames; descriptorIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var originalThunk = reader.ReadUInt32();
            stream.Position += 4;
            stream.Position += 4;
            var nameRva = reader.ReadUInt32();
            var firstThunk = reader.ReadUInt32();
            if (originalThunk == 0 && nameRva == 0 && firstThunk == 0)
            {
                break;
            }

            if (!TryRvaToOffset(nameRva, sections, out var nameOffset))
            {
                continue;
            }

            var returnOffset = stream.Position;
            stream.Position = nameOffset;
            var library = ReadNullTerminatedAscii(reader, 256);
            var thunkRva = originalThunk == 0 ? firstThunk : originalThunk;
            if (TryRvaToOffset(thunkRva, sections, out var thunkOffset))
            {
                stream.Position = thunkOffset;
                for (var i = 0; i < 4096 && imports.Count < MaxImportNames; i++)
                {
                    var thunk = isPe32Plus ? reader.ReadUInt64() : reader.ReadUInt32();
                    if (thunk == 0)
                    {
                        break;
                    }

                    var ordinalMask = isPe32Plus ? 0x8000000000000000UL : 0x80000000UL;
                    if ((thunk & ordinalMask) != 0)
                    {
                        imports.Add(new PeImportInfo(library, $"ordinal:{thunk & 0xFFFF}"));
                        continue;
                    }

                    if (TryRvaToOffset((uint)thunk, sections, out var hintNameOffset))
                    {
                        var afterThunk = stream.Position;
                        stream.Position = hintNameOffset + 2;
                        imports.Add(new PeImportInfo(library, ReadNullTerminatedAscii(reader, 512)));
                        stream.Position = afterThunk;
                    }
                }
            }

            stream.Position = returnOffset;
        }

        return imports;
    }

    private static List<string> ReadExports(
        BinaryReader reader,
        Stream stream,
        uint exportDirectoryRva,
        IReadOnlyList<PeSectionInfo> sections,
        CancellationToken cancellationToken)
    {
        var exports = new List<string>();
        if (exportDirectoryRva == 0 || !TryRvaToOffset(exportDirectoryRva, sections, out var exportOffset))
        {
            return exports;
        }

        stream.Position = exportOffset + 24;
        var nameCount = reader.ReadUInt32();
        stream.Position += 4;
        var namePointerRva = reader.ReadUInt32();
        if (!TryRvaToOffset(namePointerRva, sections, out var namePointerOffset))
        {
            return exports;
        }

        stream.Position = namePointerOffset;
        var limit = Math.Min(nameCount, MaxExportNames);
        var nameRvas = new List<uint>();
        for (var i = 0; i < limit; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            nameRvas.Add(reader.ReadUInt32());
        }

        foreach (var nameRva in nameRvas)
        {
            if (TryRvaToOffset(nameRva, sections, out var nameOffset))
            {
                stream.Position = nameOffset;
                exports.Add(ReadNullTerminatedAscii(reader, 512));
            }
        }

        return exports;
    }

    private static bool TryRvaToOffset(uint rva, IReadOnlyList<PeSectionInfo> sections, out long offset)
    {
        foreach (var section in sections)
        {
            var virtualAddress = ParseHex(section.VirtualAddress);
            var virtualSize = Math.Max(section.VirtualSize, section.RawSize);
            if (rva >= virtualAddress && rva < virtualAddress + virtualSize)
            {
                offset = ParseHex(section.RawPointer) + (rva - virtualAddress);
                return true;
            }
        }

        offset = 0;
        return false;
    }

    private static Dictionary<string, string> ReadVersionInfo(string path)
    {
        try
        {
            var version = FileVersionInfo.GetVersionInfo(path);
            return new Dictionary<string, string>
            {
                ["CompanyName"] = version.CompanyName ?? string.Empty,
                ["FileDescription"] = version.FileDescription ?? string.Empty,
                ["FileVersion"] = version.FileVersion ?? string.Empty,
                ["ProductName"] = version.ProductName ?? string.Empty,
                ["ProductVersion"] = version.ProductVersion ?? string.Empty,
                ["OriginalFilename"] = version.OriginalFilename ?? string.Empty,
                ["InternalName"] = version.InternalName ?? string.Empty,
                ["LegalCopyright"] = version.LegalCopyright ?? string.Empty
            };
        }
        catch
        {
            return new Dictionary<string, string>();
        }
    }

    private static PeFileScanResult ScanFile(
        Stream stream,
        bool extractStrings,
        PeAnalysisPerformance performance,
        CancellationToken cancellationToken)
    {
        var scanTimer = Stopwatch.StartNew();
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        var stringScanner = extractStrings ? new PrintableStringScanner() : null;
        var buffer = new byte[FileScanBufferSize];
        long stringBytesRemaining = MaxStringScanBytes;
        long stringExtractionTicks = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }

            sha256.AppendData(buffer, 0, read);
            md5.AppendData(buffer, 0, read);
            if (stringScanner != null && stringBytesRemaining > 0)
            {
                var stringBytes = (int)Math.Min(read, stringBytesRemaining);
                var stringStart = Stopwatch.GetTimestamp();
                stringScanner.Append(buffer.AsSpan(0, stringBytes));
                stringExtractionTicks += Stopwatch.GetTimestamp() - stringStart;
                stringBytesRemaining -= stringBytes;
            }
        }

        var scannedStringBytes = Math.Min(stream.Length, MaxStringScanBytes);
        PeStringSummary? stringSummary = null;
        if (stringScanner != null)
        {
            var stringStart = Stopwatch.GetTimestamp();
            stringSummary = stringScanner.Complete(scannedStringBytes, stream.Length > scannedStringBytes);
            stringExtractionTicks += Stopwatch.GetTimestamp() - stringStart;
        }

        performance.StreamScanMilliseconds = scanTimer.Elapsed.TotalMilliseconds;
        performance.StringExtractionMilliseconds = Stopwatch.GetElapsedTime(0, stringExtractionTicks).TotalMilliseconds;
        var hashTimer = Stopwatch.StartNew();
        var sha256Hash = Convert.ToHexString(sha256.GetHashAndReset()).ToLowerInvariant();
        var md5Hash = Convert.ToHexString(md5.GetHashAndReset()).ToLowerInvariant();
        performance.HashFinalizationMilliseconds = hashTimer.Elapsed.TotalMilliseconds;
        return new PeFileScanResult(
            sha256Hash,
            md5Hash,
            stringSummary);
    }

    private static void FlushString(string encoding, StringBuilder builder, List<PeStringSample> samples, ref int total)
    {
        if (builder.Length >= MinStringLength)
        {
            total++;
            if (samples.Count < MaxStringSamples)
            {
                samples.Add(new PeStringSample(encoding, builder.ToString()));
            }
        }

        builder.Clear();
    }

    private static string ReadNullTerminatedAscii(BinaryReader reader, int maxLength)
    {
        var bytes = new List<byte>();
        for (var i = 0; i < maxLength; i++)
        {
            var b = reader.ReadByte();
            if (b == 0)
            {
                break;
            }

            bytes.Add(b);
        }

        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    private static PeAnalysisRecord CreateBaseRecord(
        ProcessInfo process,
        PeAnalysisSourceKind sourceKind,
        string sourceArtifactId,
        string filePath)
    {
        return new PeAnalysisRecord
        {
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            AnalysisId = BuildAnalysisId(
                string.IsNullOrWhiteSpace(process.ProcessEntityId) ? process.GetUniqueKey() : process.ProcessEntityId,
                sourceKind,
                sourceArtifactId,
                filePath),
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.GetUniqueKey(),
            ProcessId = process.ProcessId,
            ProcessGuid = process.ProcessGuid,
            ProcessName = process.ProcessName,
            SourceKind = sourceKind,
            SourceArtifactId = sourceArtifactId,
            FilePath = filePath,
            Source = "PEAnalysis"
        };
    }

    private static string BuildAnalysisId(string processKey, PeAnalysisSourceKind sourceKind, string artifactId, string filePath)
    {
        var input = $"{processKey}|{sourceKind}|{artifactId}|{filePath}".ToLowerInvariant();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant()[..32];
    }

    private static string FormatMachine(ushort machine)
        => machine switch
        {
            0x014C => "I386",
            0x8664 => "AMD64",
            0x01C0 => "ARM",
            0xAA64 => "ARM64",
            _ => $"0x{machine:X4}"
        };

    private static string FormatSubsystem(ushort subsystem)
        => subsystem switch
        {
            2 => "Windows GUI",
            3 => "Windows CUI",
            9 => "Windows CE GUI",
            10 => "EFI application",
            14 => "Xbox",
            _ => subsystem.ToString(CultureInfo.InvariantCulture)
        };

    private static string FormatHex(uint value) => $"0x{value:X8}";

    private static string FormatHex(ulong value) => $"0x{value:X}";

    private static uint ParseHex(string value)
        => uint.TryParse(value.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 0;

    private sealed record PeDataDirectory(uint Rva, uint Size);

    private sealed record PeSectionInfo(
        string Name,
        string VirtualAddress,
        uint VirtualSize,
        uint RawSize,
        string RawPointer,
        string Characteristics);

    private sealed record PeImportInfo(string Library, string Name);

    private sealed record PeFileScanResult(
        string Sha256Hash,
        string Md5Hash,
        PeStringSummary? StringSummary);

    private sealed record PeStringSummary(
        int TotalCount,
        IReadOnlyList<PeStringSample> Samples,
        bool IsSampleTruncated,
        bool IsScanTruncated,
        long ScannedBytes,
        long ScanLimitBytes,
        int MaxSamples,
        int MinLength,
        IReadOnlyList<string> Encodings);

    private sealed record PeStringSample(string Encoding, string Value);

    private sealed class PrintableStringScanner
    {
        private readonly List<PeStringSample> _samples = [];
        private readonly StringBuilder _asciiBuilder = new();
        private readonly StringBuilder _utf16Builder = new();
        private int _total;
        private byte? _utf16PendingLowByte;

        public void Append(ReadOnlySpan<byte> bytes)
        {
            foreach (var value in bytes)
            {
                AppendAsciiByte(value);
                AppendUtf16Byte(value);
            }
        }

        public PeStringSummary Complete(long scannedBytes, bool isScanTruncated)
        {
            FlushString("ASCII", _asciiBuilder, _samples, ref _total);
            FlushString("UTF-16LE", _utf16Builder, _samples, ref _total);
            _utf16PendingLowByte = null;
            return new PeStringSummary(
                _total,
                _samples,
                _total > _samples.Count,
                isScanTruncated,
                scannedBytes,
                MaxStringScanBytes,
                MaxStringSamples,
                MinStringLength,
                ["ASCII", "UTF-16LE"]);
        }

        private void AppendAsciiByte(byte value)
        {
            if (IsPrintableAscii(value))
            {
                _asciiBuilder.Append((char)value);
                if (_asciiBuilder.Length < MaxCapturedStringLength)
                {
                    return;
                }
            }

            FlushString("ASCII", _asciiBuilder, _samples, ref _total);
        }

        private void AppendUtf16Byte(byte value)
        {
            if (_utf16PendingLowByte.HasValue)
            {
                if (value == 0)
                {
                    _utf16Builder.Append((char)_utf16PendingLowByte.Value);
                    if (_utf16Builder.Length >= MaxCapturedStringLength)
                    {
                        FlushString("UTF-16LE", _utf16Builder, _samples, ref _total);
                    }

                    _utf16PendingLowByte = null;
                    return;
                }

                FlushString("UTF-16LE", _utf16Builder, _samples, ref _total);
                _utf16PendingLowByte = IsPrintableAscii(value) ? value : null;
                return;
            }

            if (IsPrintableAscii(value))
            {
                _utf16PendingLowByte = value;
                return;
            }

            FlushString("UTF-16LE", _utf16Builder, _samples, ref _total);
        }

        private static bool IsPrintableAscii(byte value) => value is >= 0x20 and <= 0x7E;
    }
}
