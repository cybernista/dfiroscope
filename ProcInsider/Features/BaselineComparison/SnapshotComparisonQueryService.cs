using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class SnapshotComparisonQueryService
{
    private const int MaxNetworkRows = 10000;
    private const int MaxFilesystemRows = 10000;
    private const int MaxMemoryRows = 10000;
    private const int MaxPeRowsPerProcess = 1000;

    public SnapshotComparisonEvidence LoadEvidence(string snapshotDatabasePath)
    {
        if (string.IsNullOrWhiteSpace(snapshotDatabasePath))
        {
            throw new ArgumentException("A snapshot SQLite path is required.", nameof(snapshotDatabasePath));
        }

        var fullPath = Path.GetFullPath(snapshotDatabasePath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("The selected snapshot SQLite database does not exist.", fullPath);
        }

        var queryService = new SqliteStagingQueryService(
            fullPath,
            openContext: CaptureOpenContext.ViewerLiveSnapshot);
        var snapshot = queryService.CreateSnapshotForAnalysis();
        var peAnalyses = snapshot.Processes
            .Where(process => !string.IsNullOrWhiteSpace(process.ProcessKey))
            .SelectMany(process => queryService.GetPeAnalysesForProcess(
                process.ProcessKey,
                MaxPeRowsPerProcess,
                process.ProcessEntityId))
            .GroupBy(analysis => analysis.AnalysisId, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToList();

        return new SnapshotComparisonEvidence
        {
            SnapshotPath = fullPath,
            Processes = snapshot.Processes,
            Modules = snapshot.Modules,
            PeAnalyses = peAnalyses,
            Events = snapshot.Events,
            NetworkCaptures = queryService.GetNetworkCaptures(MaxNetworkRows),
            ZeekNetworkArtifacts = queryService.GetZeekNetworkArtifacts(MaxNetworkRows),
            FilesystemArtifacts = queryService.GetFilesystemArtifacts(MaxFilesystemRows),
            MemoryImages = queryService.GetMemoryImages(MaxMemoryRows),
            VolatilityPluginRuns = queryService.GetVolatilityPluginRuns(maxCount: MaxMemoryRows),
            MemoryProcesses = queryService.GetMemoryProcesses(maxCount: MaxMemoryRows),
            Stats = queryService.GetStats()
        };
    }
}

public sealed class SnapshotComparisonEvidence
{
    public string SnapshotPath { get; set; } = string.Empty;
    public IReadOnlyList<ProcessRecord> Processes { get; set; } = Array.Empty<ProcessRecord>();
    public IReadOnlyList<ModuleObservationRecord> Modules { get; set; } = Array.Empty<ModuleObservationRecord>();
    public IReadOnlyList<PeAnalysisRecord> PeAnalyses { get; set; } = Array.Empty<PeAnalysisRecord>();
    public IReadOnlyList<TelemetryEventRecord> Events { get; set; } = Array.Empty<TelemetryEventRecord>();
    public IReadOnlyList<NetworkCaptureRecord> NetworkCaptures { get; set; } = Array.Empty<NetworkCaptureRecord>();
    public IReadOnlyList<ZeekNetworkRecord> ZeekNetworkArtifacts { get; set; } = Array.Empty<ZeekNetworkRecord>();
    public IReadOnlyList<FilesystemArtifactRecord> FilesystemArtifacts { get; set; } = Array.Empty<FilesystemArtifactRecord>();
    public IReadOnlyList<MemoryImageRecord> MemoryImages { get; set; } = Array.Empty<MemoryImageRecord>();
    public IReadOnlyList<VolatilityPluginRunRecord> VolatilityPluginRuns { get; set; } = Array.Empty<VolatilityPluginRunRecord>();
    public IReadOnlyList<MemoryProcessRecord> MemoryProcesses { get; set; } = Array.Empty<MemoryProcessRecord>();
    public TelemetryStoreStats Stats { get; set; } = new();
}
