using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class TelemetryArchiveService
{
    private const string ArchiveFormat = "ProcInsider.StagedTelemetry";
    private const int CurrentVersion = 1;
    private const string MetadataEntryName = "metadata.json";
    private const string ProcessesEntryName = "processes.jsonl";
    private const string EventsEntryName = "events.jsonl";
    private const string ModulesEntryName = "modules.jsonl";
    private const string HandlesEntryName = "handles.jsonl";
    private const string MemoryDumpsEntryName = "memory_dumps.jsonl";
    private const string PeAnalysesEntryName = "pe_analyses.jsonl";
    private const string NetworkCapturesEntryName = "network_captures.jsonl";
    private const string ZeekNetworkArtifactsEntryName = "zeek_network_artifacts.jsonl";

    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public async Task<(TelemetryStoreSnapshot Snapshot, TelemetryArchiveImportResult Result)> ReadSnapshotAsync(
        string archivePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(archivePath))
        {
            throw new ArgumentException("Archive path is required.", nameof(archivePath));
        }

        await using var fileStream = new FileStream(
            archivePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1024 * 128,
            useAsync: true);
        using var archive = new ZipArchive(fileStream, ZipArchiveMode.Read, leaveOpen: false);

        var metadata = await ReadMetadataAsync(archive, cancellationToken);
        ValidateMetadata(metadata);

        var snapshot = new TelemetryStoreSnapshot
        {
            Processes = await ReadJsonLinesEntryAsync<ProcessRecord>(archive, ProcessesEntryName, cancellationToken),
            Events = await ReadJsonLinesEntryAsync<TelemetryEventRecord>(archive, EventsEntryName, cancellationToken),
            Modules = await ReadJsonLinesEntryAsync<ModuleObservationRecord>(archive, ModulesEntryName, cancellationToken),
            Handles = await ReadJsonLinesEntryAsync<HandleObservationRecord>(archive, HandlesEntryName, cancellationToken),
            MemoryDumps = await ReadOptionalJsonLinesEntryAsync<MemoryDumpRecord>(archive, MemoryDumpsEntryName, cancellationToken),
            PeAnalyses = await ReadOptionalJsonLinesEntryAsync<PeAnalysisRecord>(archive, PeAnalysesEntryName, cancellationToken),
            NetworkCaptures = await ReadOptionalJsonLinesEntryAsync<NetworkCaptureRecord>(archive, NetworkCapturesEntryName, cancellationToken),
            ZeekNetworkArtifacts = await ReadOptionalJsonLinesEntryAsync<ZeekNetworkRecord>(archive, ZeekNetworkArtifactsEntryName, cancellationToken)
        };

        ValidateSnapshotCounts(metadata, snapshot);
        var result = new TelemetryArchiveImportResult
        {
            ArchivePath = archivePath,
            CreatedUtc = metadata.CreatedUtc,
            ProcessCount = snapshot.Processes.Count,
            EventCount = snapshot.Events.Count,
            ModuleCount = snapshot.Modules.Count,
            HandleCount = snapshot.Handles.Count,
            MemoryDumpCount = snapshot.MemoryDumps.Count,
            PeAnalysisCount = snapshot.PeAnalyses.Count,
            NetworkCaptureCount = snapshot.NetworkCaptures.Count,
            ZeekNetworkArtifactCount = snapshot.ZeekNetworkArtifacts.Count
        };
        return (snapshot, result);
    }

    private static async Task<TelemetryArchiveMetadata> ReadMetadataAsync(
        ZipArchive archive,
        CancellationToken cancellationToken)
    {
        var entry = archive.GetEntry(MetadataEntryName)
            ?? throw new InvalidDataException("The archive is missing metadata.json.");
        await using var stream = entry.Open();
        TelemetryArchiveMetadata? metadata;
        try
        {
            metadata = await JsonSerializer.DeserializeAsync<TelemetryArchiveMetadata>(stream, JsonOptions, cancellationToken);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("The archive metadata.json is not valid JSON.", ex);
        }

        return metadata ?? throw new InvalidDataException("The archive metadata is empty or invalid.");
    }

    private static async Task<IReadOnlyList<T>> ReadJsonLinesEntryAsync<T>(
        ZipArchive archive,
        string entryName,
        CancellationToken cancellationToken)
    {
        var entry = archive.GetEntry(entryName)
            ?? throw new InvalidDataException($"The archive is missing {entryName}.");
        var records = new List<T>();

        await using var stream = entry.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
        var lineNumber = 0;
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            lineNumber++;
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            T? record;
            try
            {
                record = JsonSerializer.Deserialize<T>(line, JsonOptions);
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException($"The archive contains invalid JSON in {entryName} at line {lineNumber}.", ex);
            }

            if (record == null)
            {
                throw new InvalidDataException($"The archive contains an invalid record in {entryName} at line {lineNumber}.");
            }

            records.Add(record);
        }

        return records;
    }

    private static Task<IReadOnlyList<T>> ReadOptionalJsonLinesEntryAsync<T>(
        ZipArchive archive,
        string entryName,
        CancellationToken cancellationToken)
    {
        return archive.GetEntry(entryName) is null
            ? Task.FromResult<IReadOnlyList<T>>(Array.Empty<T>())
            : ReadJsonLinesEntryAsync<T>(archive, entryName, cancellationToken);
    }

    private static void ValidateMetadata(TelemetryArchiveMetadata metadata)
    {
        if (!string.Equals(metadata.Format, ArchiveFormat, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The selected file is not a ProcInsider staged telemetry archive.");
        }

        if (metadata.Version != CurrentVersion)
        {
            throw new InvalidDataException($"Unsupported staged telemetry archive version: {metadata.Version}.");
        }

        if (metadata.ProcessCount < 0 ||
            metadata.EventCount < 0 ||
            metadata.ModuleCount < 0 ||
            metadata.HandleCount < 0 ||
            metadata.MemoryDumpCount < 0 ||
            metadata.PeAnalysisCount < 0 ||
            metadata.NetworkCaptureCount < 0 ||
            metadata.ZeekNetworkArtifactCount < 0)
        {
            throw new InvalidDataException("The archive metadata contains invalid negative record counts.");
        }
    }

    private static void ValidateSnapshotCounts(TelemetryArchiveMetadata metadata, TelemetryStoreSnapshot snapshot)
    {
        if (metadata.ProcessCount != snapshot.Processes.Count ||
            metadata.EventCount != snapshot.Events.Count ||
            metadata.ModuleCount != snapshot.Modules.Count ||
            metadata.HandleCount != snapshot.Handles.Count ||
            metadata.MemoryDumpCount != snapshot.MemoryDumps.Count ||
            metadata.PeAnalysisCount != snapshot.PeAnalyses.Count ||
            metadata.NetworkCaptureCount != snapshot.NetworkCaptures.Count ||
            metadata.ZeekNetworkArtifactCount != snapshot.ZeekNetworkArtifacts.Count)
        {
            throw new InvalidDataException("The archive metadata counts do not match the telemetry records.");
        }
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = false
        };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    private sealed class TelemetryArchiveMetadata
    {
        public string Format { get; set; } = ArchiveFormat;
        public int Version { get; set; } = CurrentVersion;
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public int ProcessCount { get; set; }
        public int EventCount { get; set; }
        public int ModuleCount { get; set; }
        public int HandleCount { get; set; }
        public int MemoryDumpCount { get; set; }
        public int PeAnalysisCount { get; set; }
        public int NetworkCaptureCount { get; set; }
        public int ZeekNetworkArtifactCount { get; set; }

    }
}

public sealed class TelemetryArchiveImportResult
{
    public string ArchivePath { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; }
    public int ProcessCount { get; set; }
    public int EventCount { get; set; }
    public int ModuleCount { get; set; }
    public int HandleCount { get; set; }
    public int MemoryDumpCount { get; set; }
    public int PeAnalysisCount { get; set; }
    public int NetworkCaptureCount { get; set; }
    public int ZeekNetworkArtifactCount { get; set; }
}
