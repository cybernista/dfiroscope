using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Narrow read contract for process dumps/PE, network/Zeek, filesystem, and
/// system-memory/Volatility evidence.
/// </summary>
public interface IArtifactEvidenceQueryService
{
    ArtifactEvidenceReadPage ReadPage(ArtifactEvidenceReadQuery query, CancellationToken cancellationToken = default);
    IReadOnlyList<MemoryDumpRecord> GetMemoryDumpsForProcess(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "");

    Task<IReadOnlyList<MemoryDumpRecord>> GetMemoryDumpsForProcessAsync(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "");

    IReadOnlyList<PeAnalysisRecord> GetPeAnalysesForProcess(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "");

    Task<IReadOnlyList<PeAnalysisRecord>> GetPeAnalysesForProcessAsync(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "");

    IReadOnlyDictionary<string, PeAnalysisRecord> GetLatestProcessImagePeAnalysesByProcessKey();

    IReadOnlyList<AuthenticodeVerificationRecord> GetAuthenticodeVerificationsForProcess(
        string processKey,
        int maxCount = 100,
        string processEntityId = "");

    AuthenticodeVerificationRecord? GetLatestAuthenticodeVerificationForProcess(
        string processKey,
        string processEntityId = "");

    IReadOnlyList<NetworkCaptureRecord> GetNetworkCaptures(int maxCount = 1000);

    Task<IReadOnlyList<NetworkCaptureRecord>> GetNetworkCapturesAsync(int maxCount = 1000);

    NetworkCaptureRecord? GetNetworkCaptureById(string captureId);

    IReadOnlyList<ZeekNetworkRecord> GetZeekNetworkArtifacts(int maxCount = 1000);

    Task<IReadOnlyList<ZeekNetworkRecord>> GetZeekNetworkArtifactsAsync(int maxCount = 1000);

    SqliteStagingQueryService.ZeekProcessCorrelation ResolveZeekProcessCorrelation(
        ZeekNetworkRecord artifact);

    IReadOnlyList<FilesystemArtifactRecord> GetFilesystemArtifacts(int maxCount = 1000);

    IReadOnlyList<FilesystemArtifactRecord> GetFilesystemArtifacts(
        ExplorerScope? scope,
        bool includeDescendants,
        int maxCount = 1000);

    Task<IReadOnlyList<FilesystemArtifactRecord>> GetFilesystemArtifactsAsync(int maxCount = 1000);

    Task<IReadOnlyList<FilesystemArtifactRecord>> GetFilesystemArtifactsAsync(
        ExplorerScope? scope,
        bool includeDescendants,
        int maxCount = 1000);

    ForensicArtifactResultPage QueryForensicArtifactResults(
        ForensicArtifactResultQuery query,
        CancellationToken cancellationToken = default);

    ColumnFilterValuePage GetForensicArtifactResultValues(
        ForensicArtifactResultQuery query,
        ForensicArtifactResultColumn column,
        string? search,
        ColumnFilterValueSort sort,
        CancellationToken cancellationToken = default,
        bool retainColumnFilter = false);

    ForensicArtifactResultDetail GetForensicArtifactResultDetail(
        string artifactId,
        CancellationToken cancellationToken = default);

    ForensicArtifactResultDetail GetForensicArtifactResultReadOccurrences(
        string artifactId, long offset = 0, int pageSize = 50,
        CancellationToken cancellationToken = default);

    ForensicArtifactResultPropertiesPage GetForensicArtifactResultProperties(
        string artifactId,
        ForensicArtifactResultPropertyQuery query,
        CancellationToken cancellationToken = default);

    IReadOnlyList<MemoryImageRecord> GetMemoryImages(int maxCount = 1000);

    Task<IReadOnlyList<MemoryImageRecord>> GetMemoryImagesAsync(int maxCount = 1000);

    MemoryImageRecord? GetMemoryImageById(string imageId);

    IReadOnlyList<VolatilityPluginRunRecord> GetVolatilityPluginRuns(
        string imageId = "",
        int maxCount = 1000);

    Task<IReadOnlyList<VolatilityPluginRunRecord>> GetVolatilityPluginRunsAsync(
        string imageId = "",
        int maxCount = 1000);

    IReadOnlyList<MemoryProcessRecord> GetMemoryProcesses(
        string imageId = "",
        int maxCount = 5000);

    Task<IReadOnlyList<MemoryProcessRecord>> GetMemoryProcessesAsync(
        string imageId = "",
        int maxCount = 5000);

    IReadOnlyList<SqliteQueryPlanRecord> GetRepresentativeQueryPlans();
}

/// <summary>
/// Focused SQLite owner for independently captured/imported artifact evidence
/// reads. The validated <see cref="SqliteStagingQueryService"/> remains the
/// compatibility facade and database-open authority.
/// </summary>
internal sealed partial class ArtifactEvidenceQueryService : IArtifactEvidenceQueryService
{
    private const int MaximumForensicFacetValues = 256;
    private const long MaximumForensicOffset = 1_000_000;
    private readonly SqliteReadQueryContext _readContext;

    internal ArtifactEvidenceQueryService(SqliteReadQueryContext readContext)
    {
        _readContext = readContext;
    }

    public IReadOnlyList<MemoryDumpRecord> GetMemoryDumpsForProcess(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "")
    {
        if (!HasProcessIdentity(processKey, processEntityId))
        {
            return Array.Empty<MemoryDumpRecord>();
        }

        return _readContext.MeasureRead(
            "GetMemoryDumpsForProcess",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                var entity = SelectOptionalColumn(connection, "MemoryDumps", "d", "ProcessEntityId", "''");
                var sourceRun = SelectOptionalColumn(connection, "MemoryDumps", "d", "SourceRunId", "''");
                var ingestionJob = SelectOptionalColumn(connection, "MemoryDumps", "d", "IngestionJobId", "''");
                var processPredicate = BuildProcessAttachmentPredicate(
                    connection,
                    "MemoryDumps",
                    "d",
                    processEntityId,
                    processKey);
                command.CommandText = $"""
                    SELECT d.DumpId, d.JobId, d.ProcessKey, d.ProcessId, d.ProcessGuid, d.ProcessName,
                           d.DumpKind, d.Status, d.RequestedUtc, d.CompletedUtc, d.OutputDirectory,
                           d.FilePath, d.FileSizeBytes, d.Sha256Hash, d.ToolName, d.ErrorMessage,
                           d.CaseId, d.EvidenceSessionId, d.CaptureId, d.SourceIdentityId, d.HostId, d.ExecutionRootId,
                           {entity}, {sourceRun}, {ingestionJob},
                           COALESCE(s.SourceType, '') AS Source
                    FROM MemoryDumps d
                    LEFT JOIN Sources s ON s.SourceId = d.SourceId
                    WHERE {processPredicate}
                    ORDER BY d.RequestedUtc DESC
                    LIMIT $MaxCount;
                    """;
                AddIdentityParameters(command, processKey, processEntityId);
                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 10000));

                var dumps = new List<MemoryDumpRecord>();
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    dumps.Add(ReadMemoryDump(reader));
                }

                return (IReadOnlyList<MemoryDumpRecord>)dumps;
            },
            IdentityDiagnostic(processKey, processEntityId, maxCount),
            rows => rows.Count);
    }

    public Task<IReadOnlyList<MemoryDumpRecord>> GetMemoryDumpsForProcessAsync(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "")
        => Task.Run(() => GetMemoryDumpsForProcess(processKey, maxCount, processEntityId));

    public IReadOnlyList<PeAnalysisRecord> GetPeAnalysesForProcess(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "")
    {
        if (!HasProcessIdentity(processKey, processEntityId))
        {
            return Array.Empty<PeAnalysisRecord>();
        }

        return _readContext.MeasureRead(
            "GetPeAnalysesForProcess",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                var processPredicate = BuildProcessAttachmentPredicate(
                    connection,
                    "PeAnalyses",
                    "p",
                    processEntityId,
                    processKey);
                command.CommandText = BuildPeAnalysisSelect(connection, processPredicate) + "\n" + """
                    ORDER BY p.AnalyzedUtc DESC
                    LIMIT $MaxCount;
                    """;
                AddIdentityParameters(command, processKey, processEntityId);
                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 10000));

                var analyses = new List<PeAnalysisRecord>();
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        analyses.Add(ReadPeAnalysis(reader));
                    }
                }

                AttachLatestAuthenticodeVerifications(connection, analyses);

                return (IReadOnlyList<PeAnalysisRecord>)analyses;
            },
            IdentityDiagnostic(processKey, processEntityId, maxCount),
            rows => rows.Count);
    }

    public Task<IReadOnlyList<PeAnalysisRecord>> GetPeAnalysesForProcessAsync(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "")
        => Task.Run(() => GetPeAnalysesForProcess(processKey, maxCount, processEntityId));

    public IReadOnlyDictionary<string, PeAnalysisRecord> GetLatestProcessImagePeAnalysesByProcessKey()
    {
        return _readContext.MeasureRead<IReadOnlyDictionary<string, PeAnalysisRecord>>(
            "GetLatestProcessImagePeAnalysesByProcessKey",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                var fileLastWriteUtc = SelectOptionalColumn(connection, "PeAnalyses", "p", "FileLastWriteUtc", "NULL");
                var stringAnalysisStatus = SelectOptionalColumn(connection, "PeAnalyses", "p", "StringAnalysisStatus", "'Completed'");
                var performanceJson = SelectOptionalColumn(connection, "PeAnalyses", "p", "PerformanceJson", "'{}'");
                var entity = SelectOptionalColumn(connection, "PeAnalyses", "p", "ProcessEntityId", "''");
                var sourceRun = SelectOptionalColumn(connection, "PeAnalyses", "p", "SourceRunId", "''");
                var ingestionJob = SelectOptionalColumn(connection, "PeAnalyses", "p", "IngestionJobId", "''");
                var ownership = ColumnExists(connection, "PeAnalyses", "ProcessEntityId")
                    ? "COALESCE(NULLIF(p.ProcessEntityId, ''), p.ProcessKey)"
                    : "p.ProcessKey";
                command.CommandText = $"""
                    SELECT *
                    FROM (
                        SELECT p.AnalysisId, p.ProcessKey, p.ProcessId, p.ProcessGuid, p.ProcessName,
                               p.SourceKind, p.SourceArtifactId, p.FilePath, p.Status, p.AnalyzedUtc,
                               p.FileSizeBytes, {fileLastWriteUtc}, p.Sha256Hash, p.Md5Hash, p.Machine, p.Subsystem,
                               p.PeKind, p.LinkerTimestampUtc, p.EntryPoint, p.ImageBase,
                               p.SectionCount, p.ImportCount, p.ExportCount, p.PrintableStringCount, {stringAnalysisStatus},
                               p.SectionsJson, p.ImportsJson, p.ExportsJson, p.VersionInfoJson,
                               p.StringSummaryJson, p.ErrorMessage, {performanceJson}, p.CaseId, p.EvidenceSessionId, p.CaptureId,
                               p.SourceIdentityId, p.HostId, p.ExecutionRootId,
                               {entity}, {sourceRun}, {ingestionJob},
                               COALESCE(s.DisplayName, '') AS Source,
                               ROW_NUMBER() OVER (
                                   PARTITION BY {ownership}
                                   ORDER BY p.AnalyzedUtc DESC, p.AnalysisId DESC
                               ) AS RowNumber
                        FROM PeAnalyses p
                        LEFT JOIN Sources s ON s.SourceId = p.SourceId
                        WHERE p.SourceKind = $SourceKind
                          AND p.ProcessKey IS NOT NULL
                          AND p.ProcessKey <> ''
                    )
                    WHERE RowNumber = 1;
                    """;
                command.Parameters.AddWithValue("$SourceKind", PeAnalysisSourceKind.ProcessImage.ToString());

                var latest = new Dictionary<string, PeAnalysisRecord>(StringComparer.Ordinal);
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var analysis = ReadPeAnalysis(reader);
                        var identityKey = string.IsNullOrWhiteSpace(analysis.ProcessEntityId)
                            ? analysis.ProcessKey
                            : analysis.ProcessEntityId;
                        if (!string.IsNullOrWhiteSpace(identityKey))
                        {
                            latest[identityKey] = analysis;
                        }

                        if (!string.IsNullOrWhiteSpace(analysis.ProcessKey))
                        {
                            latest.TryAdd(analysis.ProcessKey, analysis);
                        }
                    }
                }

                AttachLatestAuthenticodeVerifications(
                    connection,
                    latest.Values.DistinctBy(analysis => analysis.AnalysisId).ToList());

                return latest;
            },
            "latest process-image analysis per durable entity with ProcessKey compatibility aliases",
            rows => rows.Count);
    }

    public IReadOnlyList<AuthenticodeVerificationRecord> GetAuthenticodeVerificationsForProcess(
        string processKey,
        int maxCount = 100,
        string processEntityId = "")
    {
        if (!HasProcessIdentity(processKey, processEntityId))
        {
            return Array.Empty<AuthenticodeVerificationRecord>();
        }

        return _readContext.MeasureRead(
            "GetAuthenticodeVerificationsForProcess",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                if (!ColumnExists(connection, "AuthenticodeVerifications", "VerificationId"))
                {
                    return (IReadOnlyList<AuthenticodeVerificationRecord>)Array.Empty<AuthenticodeVerificationRecord>();
                }

                using var command = connection.CreateCommand();
                var processPredicate = BuildProcessAttachmentPredicate(
                    connection,
                    "AuthenticodeVerifications",
                    "a",
                    processEntityId,
                    processKey);
                command.CommandText = BuildAuthenticodeSelect() + $"\nWHERE {processPredicate}\n" + """
                    ORDER BY a.VerificationTimeUtc DESC, a.VerificationId DESC
                    LIMIT $MaxCount;
                    """;
                AddIdentityParameters(command, processKey, processEntityId);
                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 1000));
                var rows = new List<AuthenticodeVerificationRecord>();
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    rows.Add(ReadAuthenticodeVerification(reader));
                }

                return (IReadOnlyList<AuthenticodeVerificationRecord>)rows;
            },
            IdentityDiagnostic(processKey, processEntityId, maxCount),
            rows => rows.Count);
    }

    public AuthenticodeVerificationRecord? GetLatestAuthenticodeVerificationForProcess(
        string processKey,
        string processEntityId = "")
        => GetAuthenticodeVerificationsForProcess(processKey, 1, processEntityId).FirstOrDefault();

    public IReadOnlyList<MemoryImageRecord> GetMemoryImages(int maxCount = 1000)
    {
        return _readContext.MeasureRead(
            "GetMemoryImages",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var sourceRunId = SelectOptionalColumn(connection, "MemoryImages", "m", "SourceRunId", "''");
                var ingestionJobId = SelectOptionalColumn(connection, "MemoryImages", "m", "IngestionJobId", "''");
                using var command = connection.CreateCommand();
                command.CommandText = BuildMemoryImageSelect(sourceRunId, ingestionJobId) + "\n" + """
                    ORDER BY m.ImportedUtc DESC
                    LIMIT $MaxCount;
                    """;
                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 10000));

                var images = new List<MemoryImageRecord>();
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    images.Add(ReadMemoryImage(reader));
                }

                return (IReadOnlyList<MemoryImageRecord>)images;
            },
            $"max={maxCount}",
            rows => rows.Count);
    }

    public Task<IReadOnlyList<MemoryImageRecord>> GetMemoryImagesAsync(int maxCount = 1000)
        => Task.Run(() => GetMemoryImages(maxCount));

    public MemoryImageRecord? GetMemoryImageById(string imageId)
    {
        if (string.IsNullOrWhiteSpace(imageId))
        {
            return null;
        }

        return _readContext.MeasureRead(
            "GetMemoryImageById",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var sourceRunId = SelectOptionalColumn(connection, "MemoryImages", "m", "SourceRunId", "''");
                var ingestionJobId = SelectOptionalColumn(connection, "MemoryImages", "m", "IngestionJobId", "''");
                using var command = connection.CreateCommand();
                command.CommandText = BuildMemoryImageSelect(sourceRunId, ingestionJobId) + "\n" + """
                    WHERE m.ImageId = $ImageId
                    LIMIT 1;
                    """;
                command.Parameters.AddWithValue("$ImageId", imageId);
                using var reader = command.ExecuteReader();
                return reader.Read() ? ReadMemoryImage(reader) : null;
            },
            "exact memory image id",
            row => row == null ? 0 : 1);
    }

    public IReadOnlyList<VolatilityPluginRunRecord> GetVolatilityPluginRuns(
        string imageId = "",
        int maxCount = 1000)
    {
        return _readContext.MeasureRead(
            "GetVolatilityPluginRuns",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var sourceRunId = SelectOptionalColumn(connection, "VolatilityPluginRuns", "v", "SourceRunId", "''");
                var ingestionJobId = SelectOptionalColumn(connection, "VolatilityPluginRuns", "v", "IngestionJobId", "''");
                using var command = connection.CreateCommand();
                var imageWhere = string.IsNullOrWhiteSpace(imageId) ? string.Empty : "WHERE v.ImageId = $ImageId";
                command.CommandText = $"""
                    SELECT v.RunId, v.ImageId, v.JobId, v.PluginName, v.Status, v.RequestedUtc,
                           v.StartedUtc, v.CompletedUtc, v.VolatilityPath, v.VolatilityVersion,
                           v.CommandLine, v.OutputDirectory, v.StdoutPath, v.StderrPath, v.RawOutputHash,
                           v.SymbolsPath, v.ProfileOrLayer, v.NormalizedRowCount, v.ErrorMessage,
                           v.CaseId, v.EvidenceSessionId, v.CaptureId, v.SourceIdentityId, v.HostId,
                           v.ExecutionRootId, {sourceRunId}, {ingestionJobId}, COALESCE(s.DisplayName, '')
                    FROM VolatilityPluginRuns v
                    LEFT JOIN Sources s ON s.SourceId = v.SourceId
                    {imageWhere}
                    ORDER BY COALESCE(v.CompletedUtc, v.StartedUtc, v.RequestedUtc) DESC
                    LIMIT $MaxCount;
                    """;
                if (!string.IsNullOrWhiteSpace(imageId))
                {
                    command.Parameters.AddWithValue("$ImageId", imageId);
                }

                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 10000));
                var runs = new List<VolatilityPluginRunRecord>();
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    runs.Add(ReadVolatilityPluginRun(reader));
                }

                return (IReadOnlyList<VolatilityPluginRunRecord>)runs;
            },
            $"image={(string.IsNullOrWhiteSpace(imageId) ? "all" : "exact")}; max={maxCount}",
            rows => rows.Count);
    }

    public Task<IReadOnlyList<VolatilityPluginRunRecord>> GetVolatilityPluginRunsAsync(
        string imageId = "",
        int maxCount = 1000)
        => Task.Run(() => GetVolatilityPluginRuns(imageId, maxCount));

    public IReadOnlyList<MemoryProcessRecord> GetMemoryProcesses(
        string imageId = "",
        int maxCount = 5000)
    {
        return _readContext.MeasureRead(
            "GetMemoryProcesses",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var sourceRunId = SelectOptionalColumn(connection, "MemoryProcesses", "p", "SourceRunId", "''");
                var ingestionJobId = SelectOptionalColumn(connection, "MemoryProcesses", "p", "IngestionJobId", "''");
                using var command = connection.CreateCommand();
                var imageWhere = string.IsNullOrWhiteSpace(imageId) ? string.Empty : "WHERE p.ImageId = $ImageId";
                command.CommandText = $"""
                    SELECT p.ArtifactId, p.ImageId, p.PluginRunId, p.PluginName, p.EvidenceKind,
                           p.RowNumber, p.ObjectOffset, p.ProcessId, p.ParentProcessId, p.ProcessName,
                           p.ImagePath, p.CommandLine, p.CreateTimeUtc, p.ExitTimeUtc, p.SessionId,
                           p.ThreadCount, p.HandleCount, p.Wow64, p.ProcessKey, p.CorrelationState,
                           p.CorrelationMethod, p.CorrelationConfidence, p.RawRowHash, p.RawJson,
                           p.CaseId, p.EvidenceSessionId, p.CaptureId, p.SourceIdentityId, p.HostId,
                           p.ExecutionRootId, {sourceRunId}, {ingestionJobId}, COALESCE(s.DisplayName, '')
                    FROM MemoryProcesses p
                    LEFT JOIN Sources s ON s.SourceId = p.SourceId
                    {imageWhere}
                    ORDER BY p.ProcessId, p.RowNumber
                    LIMIT $MaxCount;
                    """;
                if (!string.IsNullOrWhiteSpace(imageId))
                {
                    command.Parameters.AddWithValue("$ImageId", imageId);
                }

                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 100000));
                var processes = new List<MemoryProcessRecord>();
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    processes.Add(ReadMemoryProcess(reader));
                }

                return (IReadOnlyList<MemoryProcessRecord>)processes;
            },
            $"image={(string.IsNullOrWhiteSpace(imageId) ? "all" : "exact")}; max={maxCount}",
            rows => rows.Count);
    }

    public Task<IReadOnlyList<MemoryProcessRecord>> GetMemoryProcessesAsync(
        string imageId = "",
        int maxCount = 5000)
        => Task.Run(() => GetMemoryProcesses(imageId, maxCount));

    public IReadOnlyList<NetworkCaptureRecord> GetNetworkCaptures(int maxCount = 1000)
    {
        return _readContext.MeasureRead(
            "GetNetworkCaptures",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var sourceRunId = SelectOptionalColumn(connection, "NetworkCaptures", "n", "SourceRunId", "''");
                var ingestionJobId = SelectOptionalColumn(connection, "NetworkCaptures", "n", "IngestionJobId", "''");
                using var command = connection.CreateCommand();
                command.CommandText = BuildNetworkCaptureSelect(sourceRunId, ingestionJobId) + "\n" + """
                    ORDER BY n.RequestedUtc DESC
                    LIMIT $MaxCount;
                    """;
                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 10000));

                var captures = new List<NetworkCaptureRecord>();
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    captures.Add(ReadNetworkCapture(reader));
                }

                return (IReadOnlyList<NetworkCaptureRecord>)captures;
            },
            $"max={maxCount}",
            rows => rows.Count);
    }

    public Task<IReadOnlyList<NetworkCaptureRecord>> GetNetworkCapturesAsync(int maxCount = 1000)
        => Task.Run(() => GetNetworkCaptures(maxCount));

    public NetworkCaptureRecord? GetNetworkCaptureById(string captureId)
    {
        if (string.IsNullOrWhiteSpace(captureId))
        {
            return null;
        }

        return _readContext.MeasureRead(
            "GetNetworkCaptureById",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var sourceRunId = SelectOptionalColumn(connection, "NetworkCaptures", "n", "SourceRunId", "''");
                var ingestionJobId = SelectOptionalColumn(connection, "NetworkCaptures", "n", "IngestionJobId", "''");
                using var command = connection.CreateCommand();
                command.CommandText = BuildNetworkCaptureSelect(sourceRunId, ingestionJobId) + "\n" + """
                    WHERE n.CaptureId = $CaptureId
                    LIMIT 1;
                    """;
                command.Parameters.AddWithValue("$CaptureId", captureId);
                using var reader = command.ExecuteReader();
                return reader.Read() ? ReadNetworkCapture(reader) : null;
            },
            "exact network capture id",
            row => row == null ? 0 : 1);
    }

    public IReadOnlyList<ZeekNetworkRecord> GetZeekNetworkArtifacts(int maxCount = 1000)
    {
        return _readContext.MeasureRead(
            "GetZeekNetworkArtifacts",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                command.CommandText = BuildZeekSelect(connection) + "\n" + """
                    ORDER BY z.TimestampUtc DESC, z.RawLineNumber DESC
                    LIMIT $MaxCount;
                    """;
                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 10000));

                var artifacts = new List<ZeekNetworkRecord>();
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    artifacts.Add(ReadZeekNetworkArtifact(reader));
                }

                return (IReadOnlyList<ZeekNetworkRecord>)artifacts;
            },
            $"max={maxCount}",
            rows => rows.Count);
    }

    public Task<IReadOnlyList<ZeekNetworkRecord>> GetZeekNetworkArtifactsAsync(int maxCount = 1000)
        => Task.Run(() => GetZeekNetworkArtifacts(maxCount));

    public IReadOnlyList<FilesystemArtifactRecord> GetFilesystemArtifacts(int maxCount = 1000)
        => GetFilesystemArtifacts(scope: null, includeDescendants: true, maxCount);

    public IReadOnlyList<FilesystemArtifactRecord> GetFilesystemArtifacts(
        ExplorerScope? scope,
        bool includeDescendants,
        int maxCount = 1000)
    {
        return _readContext.MeasureRead(
            "GetFilesystemArtifacts",
            () =>
            {
                var pending = new List<FilesystemArtifactRecord>();
                using var connection = _readContext.OpenReadOnlyConnection();
                var sourceRunId = SelectOptionalColumn(connection, "Artifacts", "a", "SourceRunId", "''");
                var ingestionJobId = SelectOptionalColumn(connection, "Artifacts", "a", "IngestionJobId", "''");
                var parentArtifactId = SelectOptionalColumn(connection, "Artifacts", "a", "ParentArtifactId", "''");
                using var command = connection.CreateCommand();
                var identityWhere = scope == null
                    ? string.Empty
                    : ExplorerScopeQuerySql.BuildIdentityWhereClause(
                        scope,
                        "a",
                        command.Parameters,
                        "FilesystemArtifactIdentity");
                var pathWhere = scope == null
                    ? string.Empty
                    : FilesystemQueryPath.BuildWhereClause(
                        scope.FilesystemPath,
                        recursive: true,
                        "a",
                        command.Parameters,
                        "FilesystemArtifactPath");
                command.CommandText = $"""
                    SELECT a.ArtifactId, a.ArtifactType, a.TimestampUtc, a.Name, a.Path, a.Summary, a.Hash,
                           r.RawRecordId, r.PayloadHash, r.PayloadText, a.CaseId, a.EvidenceSessionId,
                           a.CaptureId, a.SourceIdentityId, a.HostId, a.ExecutionRootId,
                           {sourceRunId}, {ingestionJobId}, {parentArtifactId}
                    FROM Artifacts a
                    LEFT JOIN RawRecords r ON r.RawRecordId = a.RawRecordId
                    WHERE a.ArtifactType IN ('NtfsMft', 'NtfsUsnJournal', 'NtfsLogFile', 'Prefetch', 'FileMetadata')
                          {(ColumnExists(connection, "Artifacts", "StructuredPayloadVersion") ? "AND a.StructuredPayloadVersion IS NULL" : string.Empty)}
                          {identityWhere}
                          {pathWhere}
                    ORDER BY COALESCE(a.TimestampUtc, a.UpdatedUtc) DESC
                    LIMIT $MaxCount;
                    """;
                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 10000));
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        pending.Add(ReadFilesystemArtifact(reader));
                    }
                }

                var visiblePending = pending
                    .Where(artifact => scope == null ||
                                       includeDescendants ||
                                       FilesystemQueryPath.MatchesImmediateArtifact(
                                           artifact.SourcePath,
                                           scope.FilesystemPath))
                    .ToList();
                var propertiesByArtifactId = ReadArtifactProperties(
                    connection,
                    visiblePending.Select(artifact => artifact.ArtifactId));
                foreach (var artifact in visiblePending)
                {
                    if (!propertiesByArtifactId.TryGetValue(artifact.ArtifactId, out var properties))
                    {
                        properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    }

                    artifact.Status = GetPropertyEnum(properties, "Status", FilesystemArtifactStatus.Imported);
                    artifact.FileSizeBytes = GetPropertyLong(properties, "FileSizeBytes");
                    artifact.CreatedUtc = GetPropertyDate(properties, "CreatedUtc");
                    artifact.LastModifiedUtc = GetPropertyDate(properties, "LastModifiedUtc");
                    artifact.ProcessName = GetProperty(properties, "ProcessName");
                    artifact.RunCount = (int)GetPropertyLong(properties, "RunCount");
                    artifact.LastRunUtc = GetPropertyDate(properties, "LastRunUtc");
                    artifact.ErrorMessage = GetProperty(properties, "ErrorMessage");
                    artifact.Properties = properties;
                }

                return (IReadOnlyList<FilesystemArtifactRecord>)visiblePending;
            },
            $"scope={(scope == null ? "all" : scope.ScopeId)}; descendants={includeDescendants}; max={maxCount}",
            rows => rows.Count);
    }

    public Task<IReadOnlyList<FilesystemArtifactRecord>> GetFilesystemArtifactsAsync(int maxCount = 1000)
        => Task.Run(() => GetFilesystemArtifacts(maxCount));

    public Task<IReadOnlyList<FilesystemArtifactRecord>> GetFilesystemArtifactsAsync(
        ExplorerScope? scope,
        bool includeDescendants,
        int maxCount = 1000)
        => Task.Run(() => GetFilesystemArtifacts(scope, includeDescendants, maxCount));

    public ForensicArtifactResultPage QueryForensicArtifactResults(
        ForensicArtifactResultQuery query,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        return _readContext.MeasureRead(
            "QueryForensicArtifactResults",
            () => QueryForensicArtifactResultsCore(query, cancellationToken),
            $"sort={query.Sort}; descending={query.Descending}; offset={query.Offset}; page={query.PageSize}",
            page => page.Rows.Count);
    }

    public ColumnFilterValuePage GetForensicArtifactResultValues(
        ForensicArtifactResultQuery query,
        ForensicArtifactResultColumn column,
        string? search,
        ColumnFilterValueSort sort,
        CancellationToken cancellationToken = default,
        bool retainColumnFilter = false)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (!Enum.IsDefined(column) || !Enum.IsDefined(sort)) throw new ArgumentOutOfRangeException(nameof(column));
        return _readContext.MeasureRead(
            "GetForensicArtifactResultValues",
            () => GetForensicArtifactResultValuesCore(query, column, search, sort, cancellationToken, retainColumnFilter),
            $"column={column}; sort={sort}",
            page => page.Entries.Count);
    }

    public ForensicArtifactResultDetail GetForensicArtifactResultDetail(
        string artifactId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(artifactId)) return new(null, [], 0, ForensicArtifactResultAvailability.Available, "No structured forensic result was selected.");
        return _readContext.MeasureRead(
            "GetForensicArtifactResultDetail",
            () => GetForensicArtifactResultDetailCore(artifactId, cancellationToken),
            "exact-id",
            detail => detail.ReadOccurrences.Count);
    }

    public ForensicArtifactResultPropertiesPage GetForensicArtifactResultProperties(
        string artifactId,
        ForensicArtifactResultPropertyQuery query,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (string.IsNullOrWhiteSpace(artifactId)) return new([], 0, ForensicArtifactResultAvailability.Available, "No structured forensic result was selected.");
        return _readContext.MeasureRead(
            "GetForensicArtifactResultProperties",
            () => GetForensicArtifactResultPropertiesCore(artifactId, query, cancellationToken),
            $"sort={query.Sort}; descending={query.Descending}; offset={query.Offset}; page={query.PageSize}",
            page => page.Rows.Count);
    }

    private ForensicArtifactResultPage QueryForensicArtifactResultsCore(ForensicArtifactResultQuery query, CancellationToken token)
    {
        try
        {
            token.ThrowIfCancellationRequested();
            using var connection = _readContext.OpenReadOnlyConnection();
            if (!SupportsForensicResults(connection)) return UnavailableForensicResultsPage();
            // Pin every count, facet and page statement to one WAL-friendly read version.
            // An Agent commit between independent SELECTs must not make an Available page self-contradictory.
            using var snapshot = connection.BeginTransaction(deferred: true);
            using var command = connection.CreateCommand();
            command.Transaction = snapshot;
            var where = BuildForensicResultWhere(connection, command, query, token);
            var rootCount = ScalarLong(connection, snapshot, "SELECT COUNT(*) FROM Artifacts WHERE StructuredPayloadVersion IS NOT NULL;");
            command.CommandText = "SELECT COUNT(*) FROM Artifacts a WHERE " + where;
            var viewCount = Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
            var categoryEntries = ReadForensicCounts(connection, command, where, "COALESCE(a.Category, '')", token);
            if (categoryEntries.Count > MaximumForensicFacetValues) return ForensicFacetLimitFailure();
            var categoryCounts = categoryEntries.ToDictionary(entry => entry.Value, entry => entry.Count, StringComparer.Ordinal);
            var facetCounts = new Dictionary<ForensicArtifactResultScopeFacet, IReadOnlyList<ForensicArtifactResultFacetCount>>();
            foreach (var facet in Enum.GetValues<ForensicArtifactResultScopeFacet>())
            {
                var entries = ReadForensicCounts(connection, command, where, ScopeExpression(facet), token);
                if (entries.Count > MaximumForensicFacetValues) return ForensicFacetLimitFailure();
                facetCounts[facet] = entries;
            }

            command.CommandText = $"""
                SELECT a.ArtifactId, a.CaseId, a.EvidenceSessionId, a.CaptureId, a.SourceIdentityId, a.HostId, a.ExecutionRootId,
                       a.SourceRunId, a.IngestionJobId, a.RawRecordId, a.TimestampUtc, a.ArtifactType, a.Category,
                       a.ParserId, a.ParserVersion, a.Name, a.Path, a.Summary, a.InputSha256, a.InputByteCount,
                       a.ResultSha256, a.OutputKey, a.OriginalFileRetained, a.SourcePathSemantics, a.ParserSettingsJson,
                       a.StructuredPayloadVersion, a.PropertiesJson
                FROM Artifacts a
                WHERE {where}
                ORDER BY {ForensicResultOrderExpression(query.Sort)} {(query.Descending ? "DESC" : "ASC")}, a.ArtifactId ASC
                LIMIT $ForensicLimit OFFSET $ForensicOffset;
                """;
            command.Parameters.AddWithValue("$ForensicLimit", Math.Clamp(query.PageSize, 1, 512));
            command.Parameters.AddWithValue("$ForensicOffset", query.Offset);
            using var registration = token.Register(command.Cancel);
            using var reader = command.ExecuteReader();
            var rows = new List<ForensicArtifactResultRow>();
            while (reader.Read()) { token.ThrowIfCancellationRequested(); rows.Add(ReadForensicArtifactResult(reader).Result); }
            return new(rows, rootCount, viewCount, categoryCounts, facetCounts, ForensicArtifactResultAvailability.Available, string.Empty);
        }
        catch (Exception exception) when (exception is SqliteException or JsonException or InvalidDataException)
        {
            return new([], 0, 0, EmptyCategoryCounts, EmptyFacetCounts(), ForensicArtifactResultAvailability.Failed,
                exception is SqliteException sqlite
                    ? "Structured forensic-result query failed: " + sqlite.SqliteErrorCode.ToString(CultureInfo.InvariantCulture)
                    : "Structured forensic-result body is malformed or unreadable.");
        }
    }

    private ColumnFilterValuePage GetForensicArtifactResultValuesCore(ForensicArtifactResultQuery query, ForensicArtifactResultColumn column, string? search, ColumnFilterValueSort sort, CancellationToken token, bool retainColumnFilter)
    {
        token.ThrowIfCancellationRequested();
        using var connection = _readContext.OpenReadOnlyConnection();
        if (!SupportsForensicResults(connection)) return new([], false);
        var filters = (query.Filters ?? []).Where(filter => retainColumnFilter || filter.Column != column).ToArray();
        using var command = connection.CreateCommand();
        var where = BuildForensicResultWhere(connection, command, query with { Filters = filters }, token);
        connection.CreateFunction<string?, bool>("forensic_value_search", value => ColumnTextFilter.Matches(value, search), true);
        var value = ForensicResultColumnExpression(column);
        var order = sort switch
        {
            ColumnFilterValueSort.ValueAscending => "Value ASC",
            ColumnFilterValueSort.ValueDescending => "Value DESC",
            ColumnFilterValueSort.CountAscending => "Occurrences ASC, Value ASC",
            ColumnFilterValueSort.CountDescending => "Occurrences DESC, Value ASC",
            _ => throw new ArgumentOutOfRangeException(nameof(sort))
        };
        command.CommandText = $"SELECT {value} AS Value, COUNT(*) AS Occurrences FROM Artifacts a WHERE {where} GROUP BY Value HAVING forensic_value_search(Value) ORDER BY {order} LIMIT 257;";
        using var registration = token.Register(command.Cancel);
        using var reader = command.ExecuteReader();
        var entries = new List<ColumnFilterValue>();
        while (reader.Read()) { token.ThrowIfCancellationRequested(); entries.Add(new(reader.IsDBNull(0) ? null : reader.GetString(0), reader.GetInt64(1))); }
        return new(entries.Take(256).ToArray(), entries.Count > 256);
    }

    public ForensicArtifactResultDetail GetForensicArtifactResultReadOccurrences(
        string artifactId, long offset = 0, int pageSize = 50, CancellationToken cancellationToken = default)
    {
        if (offset is < 0 or > MaximumForensicOffset || pageSize is < 1 or > 50)
            throw new ArgumentOutOfRangeException(nameof(offset));
        return _readContext.MeasureRead("GetForensicArtifactResultReadOccurrences",
            () => GetForensicArtifactResultDetailCore(artifactId, cancellationToken, offset, pageSize),
            $"exact-id; offset={offset}; page={pageSize}", detail => detail.ReadOccurrences.Count);
    }

    private ForensicArtifactResultDetail GetForensicArtifactResultDetailCore(string artifactId, CancellationToken token, long offset = 0, int pageSize = 256)
    {
        try
        {
            token.ThrowIfCancellationRequested();
            using var connection = _readContext.OpenReadOnlyConnection();
            if (!SupportsForensicResults(connection)) return new(null, [], 0, ForensicArtifactResultAvailability.Unavailable, "This capture has no structured forensic-result schema.");
            using var snapshot = connection.BeginTransaction(deferred: true);
            var body = ReadForensicArtifactResultById(connection, artifactId, token, snapshot);
            if (body == null) return new(null, [], 0, ForensicArtifactResultAvailability.Available, "The structured forensic result was not found.");
            var result = body.Result;
            using var count = connection.CreateCommand();
            count.Transaction = snapshot;
            count.CommandText = """
                SELECT COUNT(*) FROM EvidenceRelations e JOIN RawRecords r ON CAST(r.RawRecordId AS TEXT)=e.FromId
                WHERE e.Status='Active' AND e.FromKind='RawRecord' AND e.ToKind='GenericArtifact' AND e.ToId=$id
                  AND e.RelationType='DerivedFrom' AND e.CorrelationMethod='ParserResultForRead' AND r.RecordType='ForensicSourceReadV1';
                """;
            count.Parameters.AddWithValue("$id", artifactId);
            var occurrenceCount = Convert.ToInt64(count.ExecuteScalar(), CultureInfo.InvariantCulture);
            ValidateOriginalForensicResult(connection, snapshot, body, token);
            using var command = connection.CreateCommand();
            command.Transaction = snapshot;
            command.CommandText = """
                SELECT r.RawRecordId, e.RelationId, r.CaseId, r.EvidenceSessionId, r.CaptureId, r.SourceIdentityId, r.HostId, r.ExecutionRootId,
                       r.SourceRunId, r.IngestionJobId, r.TimestampUtc, r.PayloadJson, r.PayloadHash,
                       e.CaseId, e.EvidenceSessionId, e.CaptureId, e.SourceIdentityId, e.HostId, e.ExecutionRootId,
                       e.SourceRunId, e.IngestionJobId, e.FromKind, e.ToKind, e.RelationType, e.CorrelationMethod, e.Confidence, e.CandidateCount,
                       e.CorrelationState, e.RawInputId, e.ResolverName, e.ResolverVersion, s.MetadataJson, s.Status
                FROM EvidenceRelations e JOIN RawRecords r ON CAST(r.RawRecordId AS TEXT)=e.FromId
                LEFT JOIN SourceRuns s ON s.SourceRunId=r.SourceRunId AND s.IngestionJobId=r.IngestionJobId
                  AND COALESCE(s.CaseId,'')=COALESCE(r.CaseId,'') AND s.EvidenceSessionId=r.EvidenceSessionId
                  AND s.CaptureId=r.CaptureId AND s.SourceIdentityId=r.SourceIdentityId AND s.HostId=r.HostId AND s.ExecutionRootId=r.ExecutionRootId
                WHERE e.Status='Active' AND e.FromKind='RawRecord' AND e.ToKind='GenericArtifact' AND e.ToId=$id
                  AND e.RelationType='DerivedFrom' AND e.CorrelationMethod='ParserResultForRead' AND r.RecordType='ForensicSourceReadV1'
                ORDER BY r.TimestampUtc DESC, r.RawRecordId DESC LIMIT $page OFFSET $offset;
                """;
            command.Parameters.AddWithValue("$id", artifactId);
            command.Parameters.AddWithValue("$page", pageSize);
            command.Parameters.AddWithValue("$offset", offset);
            using var registration = token.Register(command.Cancel);
            using var reader = command.ExecuteReader();
            var occurrences = new List<ForensicArtifactResultReadOccurrence>();
            while (reader.Read()) { token.ThrowIfCancellationRequested(); occurrences.Add(ReadForensicOccurrence(reader, body)); }
            return new(result, occurrences, occurrenceCount, ForensicArtifactResultAvailability.Available, string.Empty);
        }
        catch (Exception exception) when (exception is SqliteException or JsonException or InvalidDataException)
        {
            return new(null, [], 0, ForensicArtifactResultAvailability.Failed, "Structured forensic-result lineage is malformed or unreadable.");
        }
    }

    private ForensicArtifactResultPropertiesPage GetForensicArtifactResultPropertiesCore(string artifactId, ForensicArtifactResultPropertyQuery query, CancellationToken token)
    {
        try
        {
            token.ThrowIfCancellationRequested();
            if (!Enum.IsDefined(query.Sort) || query.Offset is < 0 or > MaximumForensicOffset) throw new ArgumentOutOfRangeException(nameof(query));
            using var connection = _readContext.OpenReadOnlyConnection();
            if (!SupportsForensicResults(connection)) return new([], 0, ForensicArtifactResultAvailability.Unavailable, "This capture has no structured forensic-result schema.");
            using var snapshot = connection.BeginTransaction(deferred: true);
            var body = ReadForensicArtifactResultById(connection, artifactId, token, snapshot);
            if (body == null) return new([], 0, ForensicArtifactResultAvailability.Available, "The structured forensic result was not found.");
            ValidateOriginalForensicResult(connection, snapshot, body, token);
            using var document = JsonDocument.Parse(body.PropertiesJson, new JsonDocumentOptions { MaxDepth = 32 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            var properties = document.RootElement.EnumerateObject().Select(property => new ForensicArtifactResultProperty(
                property.Name,
                property.Value.ValueKind == JsonValueKind.Null ? null : property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : property.Value.GetRawText(),
                property.Value.ValueKind.ToString())).ToArray();
            foreach (var filter in query.Filters ?? []) { if (!Enum.IsDefined(filter.Column)) throw new ArgumentOutOfRangeException(nameof(query)); filter.Criteria.Validate(); }
            var filtered = properties.Where(property => (query.Filters ?? []).All(filter => filter.Criteria.Matches(ForensicPropertyValue(property, filter.Column)))).ToArray();
            var ordered = query.Sort switch
            {
                ForensicArtifactResultPropertyColumn.Name => query.Descending ? filtered.OrderByDescending(property => property.Name, StringComparer.Ordinal) : filtered.OrderBy(property => property.Name, StringComparer.Ordinal),
                ForensicArtifactResultPropertyColumn.Value => query.Descending
                    ? filtered.OrderBy(property => property.Value == null ? 1 : 0).ThenByDescending(property => property.Value, StringComparer.Ordinal)
                    : filtered.OrderBy(property => property.Value == null ? 1 : 0).ThenBy(property => property.Value, StringComparer.Ordinal),
                ForensicArtifactResultPropertyColumn.ValueType => query.Descending ? filtered.OrderByDescending(property => property.ValueType, StringComparer.Ordinal) : filtered.OrderBy(property => property.ValueType, StringComparer.Ordinal),
                _ => throw new ArgumentOutOfRangeException(nameof(query))
            };
            var rows = ordered.ThenBy(property => property.Name, StringComparer.Ordinal).Skip((int)Math.Min(query.Offset, int.MaxValue)).Take(Math.Clamp(query.PageSize, 1, 512)).ToArray();
            return new(rows, filtered.LongLength, ForensicArtifactResultAvailability.Available, string.Empty);
        }
        catch (Exception exception) when (exception is SqliteException or JsonException or InvalidDataException)
        {
            return new([], 0, ForensicArtifactResultAvailability.Failed, "Structured forensic-result properties are malformed or unreadable.");
        }
    }

    private static readonly IReadOnlyDictionary<string, long> EmptyCategoryCounts =
        new Dictionary<string, long>(StringComparer.Ordinal);

    private static ForensicArtifactResultPage UnavailableForensicResultsPage()
        => new([], 0, 0, EmptyCategoryCounts, EmptyFacetCounts(), ForensicArtifactResultAvailability.Unavailable,
            "This capture has no structured forensic-result schema.");

    private static ForensicArtifactResultPage ForensicFacetLimitFailure()
        => new([], 0, 0, EmptyCategoryCounts, EmptyFacetCounts(), ForensicArtifactResultAvailability.Failed,
            "Structured forensic-result facet cardinality exceeds the 256-value exact-query bound.");

    private static IReadOnlyDictionary<ForensicArtifactResultScopeFacet, IReadOnlyList<ForensicArtifactResultFacetCount>> EmptyFacetCounts()
        => Enum.GetValues<ForensicArtifactResultScopeFacet>().ToDictionary(
            facet => facet,
            _ => (IReadOnlyList<ForensicArtifactResultFacetCount>)[],
            EqualityComparer<ForensicArtifactResultScopeFacet>.Default);

    private static bool SupportsForensicResults(SqliteConnection connection)
        => new[] { "Artifacts", "RawRecords", "EvidenceRelations" }.All(table => TableExists(connection, table)) &&
           new[] { "StructuredPayloadVersion", "Category", "ParserId", "ParserVersion", "PropertiesJson", "InputByteCount", "InputSha256", "ResultSha256", "OriginalFileRetained", "OutputKey", "SourcePathSemantics", "SourceRunId", "IngestionJobId" }
               .All(column => ColumnExists(connection, "Artifacts", column)) &&
           new[] { "SourceRunId", "IngestionJobId" }.All(column => ColumnExists(connection, "RawRecords", column));

    private static string BuildForensicResultWhere(SqliteConnection connection, SqliteCommand command, ForensicArtifactResultQuery query, CancellationToken token)
    {
        if (!Enum.IsDefined(query.Sort) || query.Offset is < 0 or > MaximumForensicOffset || query.PageSize is < 1 or > 512) throw new ArgumentOutOfRangeException(nameof(query));
        var selectors = query.GreenSelectors ?? [];
        var filters = query.Filters ?? [];
        if (selectors.Count > 64 || filters.Count > Enum.GetValues<ForensicArtifactResultColumn>().Length ||
            filters.Select(filter => filter.Column).Distinct().Count() != filters.Count) throw new ArgumentOutOfRangeException(nameof(query));
        var clauses = new List<string> { "a.StructuredPayloadVersion IS NOT NULL" };
        var selectorIndex = 0;
        foreach (var group in selectors.Where(selector => !selector.IsExcluded).GroupBy(selector => selector.Facet))
        {
            if (!Enum.IsDefined(group.Key)) throw new ArgumentOutOfRangeException(nameof(query));
            var alternatives = new List<string>();
            foreach (var selector in group)
            {
                if (selector.Value == null) throw new ArgumentOutOfRangeException(nameof(query));
                var parameter = "$ForensicGreen" + selectorIndex++.ToString(CultureInfo.InvariantCulture);
                command.Parameters.AddWithValue(parameter, selector.Value);
                alternatives.Add(ScopeExpression(selector.Facet) + "=" + parameter);
            }
            clauses.Add("(" + string.Join(" OR ", alternatives) + ")");
        }
        foreach (var selector in selectors.Where(selector => selector.IsExcluded))
        {
            if (!Enum.IsDefined(selector.Facet) || selector.Value == null) throw new ArgumentOutOfRangeException(nameof(query));
            var parameter = "$ForensicGreen" + selectorIndex++.ToString(CultureInfo.InvariantCulture);
            command.Parameters.AddWithValue(parameter, selector.Value);
            clauses.Add("NOT (" + ScopeExpression(selector.Facet) + "=" + parameter + ")");
        }
        for (var index = 0; index < filters.Count; index++)
        {
            token.ThrowIfCancellationRequested();
            var filter = filters[index];
            if (!Enum.IsDefined(filter.Column) || filter.Criteria == null) throw new ArgumentOutOfRangeException(nameof(query));
            filter.Criteria.Validate();
            var function = "forensic_filter_" + index.ToString(CultureInfo.InvariantCulture);
            var column = filter.Column;
            connection.CreateFunction<string?, bool>(function, value => filter.Criteria.Matches(value, timestampUtc: column == ForensicArtifactResultColumn.ObservedUtc && DateTimeOffset.TryParse(value, out var parsed) ? parsed.UtcDateTime : null), true);
            clauses.Add(function + "(" + ForensicResultColumnExpression(column) + ")");
        }
        return string.Join(" AND ", clauses);
    }

    private static IReadOnlyList<ForensicArtifactResultFacetCount> ReadForensicCounts(SqliteConnection connection, SqliteCommand command, string where, string expression, CancellationToken token)
    {
        command.CommandText = "SELECT " + expression + " AS Value, COUNT(*) AS Occurrences FROM Artifacts a WHERE " + where + " GROUP BY Value ORDER BY Occurrences DESC, Value ASC LIMIT 257;";
        using var reader = command.ExecuteReader();
        var counts = new List<ForensicArtifactResultFacetCount>();
        while (reader.Read()) { token.ThrowIfCancellationRequested(); counts.Add(new(GetString(reader, 0), reader.GetInt64(1))); }
        return counts;
    }

    private static long ScalarLong(SqliteConnection connection, SqliteTransaction transaction, string statement)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = statement;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static string ScopeExpression(ForensicArtifactResultScopeFacet facet) => facet switch
    {
        ForensicArtifactResultScopeFacet.Case => "COALESCE(a.CaseId, '')",
        ForensicArtifactResultScopeFacet.EvidenceSession => "COALESCE(a.EvidenceSessionId, '')",
        ForensicArtifactResultScopeFacet.Capture => "COALESCE(a.CaptureId, '')",
        ForensicArtifactResultScopeFacet.SourceIdentity => "COALESCE(a.SourceIdentityId, '')",
        ForensicArtifactResultScopeFacet.Host => "COALESCE(a.HostId, '')",
        ForensicArtifactResultScopeFacet.ExecutionRoot => "COALESCE(a.ExecutionRootId, '')",
        ForensicArtifactResultScopeFacet.ArtifactType => "COALESCE(a.ArtifactType, '')",
        ForensicArtifactResultScopeFacet.Category => "COALESCE(a.Category, '')",
        _ => throw new ArgumentOutOfRangeException(nameof(facet))
    };

    private static string ForensicResultColumnExpression(ForensicArtifactResultColumn column) => column switch
    {
        ForensicArtifactResultColumn.ObservedUtc => "a.TimestampUtc",
        ForensicArtifactResultColumn.ArtifactType => "a.ArtifactType",
        ForensicArtifactResultColumn.Category => "a.Category",
        ForensicArtifactResultColumn.ParserId => "a.ParserId",
        ForensicArtifactResultColumn.ParserVersion => "a.ParserVersion",
        ForensicArtifactResultColumn.Name => "a.Name",
        ForensicArtifactResultColumn.Summary => "a.Summary",
        ForensicArtifactResultColumn.SourcePath => "a.Path",
        ForensicArtifactResultColumn.Host => "a.HostId",
        ForensicArtifactResultColumn.InputSha256 => "a.InputSha256",
        ForensicArtifactResultColumn.SourceRunId => "a.SourceRunId",
        ForensicArtifactResultColumn.IngestionJobId => "a.IngestionJobId",
        _ => throw new ArgumentOutOfRangeException(nameof(column))
    };

    private static string ForensicResultOrderExpression(ForensicArtifactResultColumn column)
    {
        var expression = ForensicResultColumnExpression(column);
        return "CASE WHEN " + expression + " IS NULL THEN 1 ELSE 0 END, " + expression + " COLLATE NOCASE";
    }

    private static ForensicArtifactResultBody? ReadForensicArtifactResultById(SqliteConnection connection, string artifactId, CancellationToken token, SqliteTransaction? transaction = null)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT a.ArtifactId, a.CaseId, a.EvidenceSessionId, a.CaptureId, a.SourceIdentityId, a.HostId, a.ExecutionRootId,
                   a.SourceRunId, a.IngestionJobId, a.RawRecordId, a.TimestampUtc, a.ArtifactType, a.Category,
                   a.ParserId, a.ParserVersion, a.Name, a.Path, a.Summary, a.InputSha256, a.InputByteCount,
                   a.ResultSha256, a.OutputKey, a.OriginalFileRetained, a.SourcePathSemantics, a.ParserSettingsJson,
                   a.StructuredPayloadVersion, a.PropertiesJson
            FROM Artifacts a WHERE a.ArtifactId=$id AND a.StructuredPayloadVersion IS NOT NULL;
            """;
        command.Parameters.AddWithValue("$id", artifactId);
        using var registration = token.Register(command.Cancel);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadForensicArtifactResult(reader) : null;
    }

    private static ForensicArtifactResultBody ReadForensicArtifactResult(SqliteDataReader reader)
    {
        var result = new ForensicArtifactResultRow(
            GetString(reader, 0),
            new EvidenceIdentity { CaseId = GetString(reader, 1), EvidenceSessionId = GetString(reader, 2), CaptureId = GetString(reader, 3), SourceIdentityId = GetString(reader, 4), HostId = GetString(reader, 5), ExecutionRootId = GetString(reader, 6) },
            GetString(reader, 7), GetString(reader, 8), GetLong(reader, 9), GetStructuredBodyTimestamp(reader, 10), GetString(reader, 11), GetString(reader, 12),
            GetString(reader, 13), GetString(reader, 14), GetString(reader, 15), GetString(reader, 16), GetString(reader, 17), GetString(reader, 18),
            reader.IsDBNull(19) ? null : GetLong(reader, 19), GetString(reader, 20), GetString(reader, 21), reader.IsDBNull(22) ? null : GetBool(reader, 22));
        if (reader.IsDBNull(23) || !Enum.IsDefined((ForensicSourcePathSemantics)GetInt(reader, 23))) throw new InvalidDataException();
        var body = new ForensicArtifactResultBody(result, (ForensicSourcePathSemantics)GetInt(reader, 23), GetString(reader, 24), GetInt(reader, 25), GetString(reader, 26));
        ValidateForensicResultBody(body);
        return body;
    }

    private static void ValidateForensicResultBody(ForensicArtifactResultBody body)
    {
        var result = body.Result;
        if (result.OriginalFileRetained != false || body.PayloadVersion < 1 || string.IsNullOrWhiteSpace(body.ParserSettingsJson)) throw new InvalidDataException();
        _ = ForensicArtifactContract.CanonicalJson(body.PropertiesJson);
        _ = ForensicArtifactContract.CanonicalJson(body.ParserSettingsJson);
        var output = new ForensicArtifactOutput
        {
            OutputKey = result.OutputKey, ArtifactType = result.ArtifactType, Category = result.Category,
            PrimaryTimeUtc = result.PrimaryTimeUtc, Name = result.Name, Summary = result.Summary,
            PayloadVersion = body.PayloadVersion, PropertiesJson = body.PropertiesJson
        };
        if (ForensicArtifactContract.Hash(JsonSerializer.Serialize(output)) != result.ResultSha256) throw new InvalidDataException();
    }

    private static void ValidateOriginalForensicResult(SqliteConnection connection, SqliteTransaction transaction, ForensicArtifactResultBody body, CancellationToken token)
    {
        var result = body.Result;
        using var original = connection.CreateCommand();
        original.Transaction = transaction;
        original.CommandText = """
            SELECT r.RawRecordId, e.RelationId, r.CaseId, r.EvidenceSessionId, r.CaptureId, r.SourceIdentityId, r.HostId, r.ExecutionRootId,
                   r.SourceRunId, r.IngestionJobId, r.TimestampUtc, r.PayloadJson, r.PayloadHash,
                   e.CaseId, e.EvidenceSessionId, e.CaptureId, e.SourceIdentityId, e.HostId, e.ExecutionRootId,
                   e.SourceRunId, e.IngestionJobId, e.FromKind, e.ToKind, e.RelationType, e.CorrelationMethod, e.Confidence, e.CandidateCount,
                   e.CorrelationState, e.RawInputId, e.ResolverName, e.ResolverVersion
            FROM EvidenceRelations e JOIN RawRecords r ON CAST(r.RawRecordId AS TEXT)=e.FromId
            WHERE e.Status='Active' AND e.FromKind='RawRecord' AND e.ToKind='GenericArtifact' AND e.ToId=$id
              AND e.RelationType='DerivedFrom' AND e.CorrelationMethod='ParserResultForRead' AND r.RecordType='ForensicSourceReadV1'
              AND r.RawRecordId=$rawId;
            """;
        original.Parameters.AddWithValue("$id", result.ArtifactId);
        original.Parameters.AddWithValue("$rawId", result.RawRecordId);
        using var reader = original.ExecuteReader();
        token.ThrowIfCancellationRequested();
        if (!reader.Read()) throw new InvalidDataException("The structured result body has no exact active parser-result receipt lineage.");
        _ = ReadForensicOccurrence(reader, body, original: true);
        if (reader.Read()) throw new InvalidDataException("The structured result body has ambiguous parser-result receipt lineage.");
    }

    private static ForensicArtifactResultReadOccurrence ReadForensicOccurrence(SqliteDataReader reader, ForensicArtifactResultBody body, bool original = false)
    {
        var result = body.Result;
        var scope = new EvidenceIdentity { CaseId = GetString(reader, 2), EvidenceSessionId = GetString(reader, 3), CaptureId = GetString(reader, 4), SourceIdentityId = GetString(reader, 5), HostId = GetString(reader, 6), ExecutionRootId = GetString(reader, 7) };
        var relationScope = new EvidenceIdentity { CaseId = GetString(reader, 13), EvidenceSessionId = GetString(reader, 14), CaptureId = GetString(reader, 15), SourceIdentityId = GetString(reader, 16), HostId = GetString(reader, 17), ExecutionRootId = GetString(reader, 18) };
        var sourceRunId = GetString(reader, 8); var ingestionJobId = GetString(reader, 9); var completedUtc = GetStructuredBodyTimestamp(reader, 10); var payload = GetString(reader, 11); var payloadHash = GetString(reader, 12);
        if (scope != result.Scope || relationScope != result.Scope || sourceRunId != GetString(reader, 19) || ingestionJobId != GetString(reader, 20) ||
            GetString(reader, 21) != EvidenceReferenceKind.RawRecord.ToString() || GetString(reader, 22) != EvidenceReferenceKind.GenericArtifact.ToString() ||
            GetString(reader, 23) != EvidenceRelationType.DerivedFrom.ToString() || GetString(reader, 24) != "ParserResultForRead" || reader.GetDouble(25) != 1.0 || reader.GetInt32(26) != 1 ||
            GetString(reader, 27) != EvidenceCorrelationState.Exact.ToString() || GetString(reader, 28) != GetLong(reader, 0).ToString(CultureInfo.InvariantCulture) ||
            GetString(reader, 29) != result.ParserId || GetString(reader, 30) != result.ParserVersion || ForensicArtifactContract.Hash(payload) != payloadHash) throw new InvalidDataException();
        var receipt = JsonSerializer.Deserialize<ForensicReadReceipt>(payload) ?? throw new InvalidDataException();
        var read = ForensicArtifactContract.Freeze([receipt.Read]).Single();
        if (completedUtc != read.ReadCompletedUtc || read.Scope != scope || read.SourceRunId != sourceRunId || read.IngestionJobId.ToString("D") != ingestionJobId || read.OriginalFileRetained || read.Outputs.Count != 0 ||
            read.Status != ForensicReadStatus.Succeeded || read.ParserStatus is not (ForensicParseStatus.Succeeded or ForensicParseStatus.Partial) || read.Consistency == ForensicReadConsistency.ChangedDuringRead ||
            read.PathSemantics != body.PathSemantics || ForensicArtifactContract.PathKey(read.SourcePath, read.PathSemantics) != ForensicArtifactContract.PathKey(result.SourcePath, body.PathSemantics) ||
            read.InputByteCount != result.InputByteCount || read.InputSha256 != result.InputSha256 || read.Parser.ParserId != result.ParserId || read.Parser.ParserVersion != result.ParserVersion || read.Parser.SettingsJson != body.ParserSettingsJson ||
            !receipt.Results.Any(reference => reference.ArtifactId == result.ArtifactId && reference.OutputKey == result.OutputKey && reference.ResultSha256 == result.ResultSha256) ||
            JsonSerializer.Serialize(new ForensicReadReceipt(read, receipt.Results)) != payload) throw new InvalidDataException();
        if (original &&
            (read.SourceRunId != result.SourceRunId || read.IngestionJobId.ToString("D") != result.IngestionJobId || read.SourcePath != result.SourcePath)) throw new InvalidDataException();
        return new(GetLong(reader, 0), GetString(reader, 1), scope, sourceRunId, ingestionJobId, read.ReadCompletedUtc, payloadHash, false)
        {
            ReadMetadata = read,
            SourceRunMetadataJson = reader.FieldCount > 31 && !reader.IsDBNull(31) ? GetString(reader, 31) : "{}",
            SourceRunStatus = reader.FieldCount > 32 && !reader.IsDBNull(32) ? GetString(reader, 32) : "Unknown"
        };
    }

    private sealed record ForensicArtifactResultBody(ForensicArtifactResultRow Result, ForensicSourcePathSemantics PathSemantics, string ParserSettingsJson, int PayloadVersion, string PropertiesJson);

    private static string? ForensicPropertyValue(ForensicArtifactResultProperty property, ForensicArtifactResultPropertyColumn column) => column switch
    {
        ForensicArtifactResultPropertyColumn.Name => property.Name,
        ForensicArtifactResultPropertyColumn.Value => property.Value,
        ForensicArtifactResultPropertyColumn.ValueType => property.ValueType,
        _ => throw new ArgumentOutOfRangeException(nameof(column))
    };

    private sealed record ForensicReadReceipt(ForensicReadAttempt Read, IReadOnlyList<ForensicResultReference> Results);
    private sealed record ForensicResultReference(string ArtifactId, string OutputKey, string ResultSha256);

    public SqliteStagingQueryService.ZeekProcessCorrelation ResolveZeekProcessCorrelation(
        ZeekNetworkRecord artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        return _readContext.MeasureRead(
            "ResolveZeekProcessCorrelation",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var tuple = FindTupleCorrelation(connection, artifact);
                if (tuple.HasValue)
                {
                    return tuple.Value;
                }

                if (!string.IsNullOrWhiteSpace(artifact.DnsQuery))
                {
                    var dns = FindCorrelation(
                        connection,
                        "Category = 'Dns' AND Target = $Target",
                        artifact.DnsQuery,
                        artifact.TimestampUtc,
                        confidence: 0.70,
                        method: "Staged DNS event target match");
                    if (dns.HasValue)
                    {
                        return dns.Value;
                    }
                }

                foreach (var endpoint in BuildEndpointCandidates(artifact))
                {
                    var network = FindCorrelation(
                        connection,
                        "Category = 'Network' AND (Target = $Target OR Details LIKE $DetailsTarget)",
                        endpoint,
                        artifact.TimestampUtc,
                        confidence: 0.80,
                        method: "Staged network endpoint match");
                    if (network.HasValue)
                    {
                        return network.Value;
                    }
                }

                return default;
            },
            $"artifact={artifact.ArtifactId}; tuple={artifact.SourceIp}:{artifact.SourcePort}->{artifact.DestinationIp}:{artifact.DestinationPort}",
            result => string.IsNullOrWhiteSpace(result.ProcessKey) ? 0 : 1);
    }

    public IReadOnlyList<SqliteQueryPlanRecord> GetRepresentativeQueryPlans()
    {
        return _readContext.MeasureRead<IReadOnlyList<SqliteQueryPlanRecord>>(
            "GetArtifactEvidenceRepresentativeQueryPlans",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var plans = new List<SqliteQueryPlanRecord>();
                var dumpHasEntity = ColumnExists(connection, "MemoryDumps", "ProcessEntityId");
                var dumpAttachment = dumpHasEntity
                    ? "ProcessEntityId = $ProcessEntityId"
                    : "ProcessKey = $ProcessKey";
                AddQueryPlan(plans, connection, "process memory dumps", $"""
                    SELECT DumpId FROM MemoryDumps
                    WHERE {dumpAttachment}
                    ORDER BY RequestedUtc DESC LIMIT $MaxCount;
                    """, command => AddPlanParameters(
                        command,
                        includeProcessKey: !dumpHasEntity,
                        includeProcessEntityId: dumpHasEntity));
                if (dumpHasEntity)
                {
                    AddQueryPlan(plans, connection, "process memory dumps legacy fallback", """
                        SELECT DumpId FROM MemoryDumps
                        WHERE ProcessKey = $ProcessKey
                        ORDER BY RequestedUtc DESC LIMIT $MaxCount;
                        """, command => AddPlanParameters(command, includeProcessKey: true));
                }

                var peHasEntity = ColumnExists(connection, "PeAnalyses", "ProcessEntityId");
                var peAttachment = peHasEntity
                    ? "ProcessEntityId = $ProcessEntityId"
                    : "ProcessKey = $ProcessKey";
                AddQueryPlan(plans, connection, "process PE analyses", $"""
                    SELECT AnalysisId FROM PeAnalyses
                    WHERE {peAttachment}
                    ORDER BY AnalyzedUtc DESC LIMIT $MaxCount;
                    """, command => AddPlanParameters(
                        command,
                        includeProcessKey: !peHasEntity,
                        includeProcessEntityId: peHasEntity));
                if (peHasEntity)
                {
                    AddQueryPlan(plans, connection, "process PE analyses legacy fallback", """
                        SELECT AnalysisId FROM PeAnalyses
                        WHERE ProcessKey = $ProcessKey
                        ORDER BY AnalyzedUtc DESC LIMIT $MaxCount;
                        """, command => AddPlanParameters(command, includeProcessKey: true));
                }

                AddQueryPlan(plans, connection, "latest process-image PE analyses", """
                    SELECT AnalysisId FROM PeAnalyses
                    WHERE SourceKind = $SourceKind AND ProcessKey <> ''
                    ORDER BY AnalyzedUtc DESC, AnalysisId DESC;
                    """, command => command.Parameters.AddWithValue("$SourceKind", PeAnalysisSourceKind.ProcessImage.ToString()));
                AddQueryPlan(plans, connection, "network captures page", """
                    SELECT CaptureId FROM NetworkCaptures
                    ORDER BY RequestedUtc DESC LIMIT $MaxCount;
                    """, AddLimitParameter);
                AddQueryPlan(plans, connection, "network capture exact lookup", """
                    SELECT CaptureId FROM NetworkCaptures WHERE CaptureId = $CaptureId LIMIT 1;
                    """, command => command.Parameters.AddWithValue("$CaptureId", string.Empty));
                AddQueryPlan(plans, connection, "Zeek artifacts page", """
                    SELECT ArtifactId FROM ZeekNetworkArtifacts
                    ORDER BY TimestampUtc DESC, RawLineNumber DESC LIMIT $MaxCount;
                    """, AddLimitParameter);
                AddQueryPlan(plans, connection, "filesystem artifacts page", $"""
                    SELECT a.ArtifactId, r.RawRecordId
                    FROM Artifacts a
                    LEFT JOIN RawRecords r ON r.RawRecordId = a.RawRecordId
                    WHERE a.ArtifactType IN ('NtfsMft', 'NtfsUsnJournal', 'NtfsLogFile', 'Prefetch', 'FileMetadata')
                          {(ColumnExists(connection, "Artifacts", "StructuredPayloadVersion") ? "AND a.StructuredPayloadVersion IS NULL" : string.Empty)}
                    ORDER BY COALESCE(a.TimestampUtc, a.UpdatedUtc) DESC LIMIT $MaxCount;
                    """, AddLimitParameter);
                AddQueryPlan(plans, connection, "artifact properties batch", """
                    SELECT ArtifactId, Name, Value FROM ArtifactProperties
                    WHERE ArtifactId IN ($ArtifactId) ORDER BY ArtifactId, Name;
                    """, command => command.Parameters.AddWithValue("$ArtifactId", string.Empty));
                AddQueryPlan(plans, connection, "memory images page", """
                    SELECT ImageId FROM MemoryImages
                    ORDER BY ImportedUtc DESC LIMIT $MaxCount;
                    """, AddLimitParameter);
                AddQueryPlan(plans, connection, "memory image exact lookup", """
                    SELECT ImageId FROM MemoryImages WHERE ImageId = $ImageId LIMIT 1;
                    """, command => command.Parameters.AddWithValue("$ImageId", string.Empty));
                AddQueryPlan(plans, connection, "Volatility plugin runs", """
                    SELECT RunId FROM VolatilityPluginRuns
                    WHERE ImageId = $ImageId
                    ORDER BY COALESCE(CompletedUtc, StartedUtc, RequestedUtc) DESC LIMIT $MaxCount;
                    """, command => AddPlanParameters(command, includeImageId: true));
                AddQueryPlan(plans, connection, "memory processes", """
                    SELECT ArtifactId FROM MemoryProcesses
                    WHERE ImageId = $ImageId
                    ORDER BY ProcessId, RowNumber LIMIT $MaxCount;
                    """, command => AddPlanParameters(command, includeImageId: true));
                AddQueryPlan(plans, connection, "Zeek tuple correlation", """
                    SELECT ProcessKey FROM ProcessEvents
                    WHERE Category = 'Network'
                      AND ABS(strftime('%s', TimestampUtc) - strftime('%s', $TimestampUtc)) <= $WindowSeconds
                    ORDER BY ABS(strftime('%s', TimestampUtc) - strftime('%s', $TimestampUtc)) ASC
                    LIMIT 1;
                    """, command =>
                    {
                        command.Parameters.AddWithValue("$TimestampUtc", DateTime.UnixEpoch.ToString("O"));
                        command.Parameters.AddWithValue("$WindowSeconds", 600);
                    });
                return plans;
            },
            "artifact-family EXPLAIN QUERY PLAN reads",
            plans => plans.Count);
    }

    private static string BuildPeAnalysisSelect(SqliteConnection connection, string processPredicate)
    {
        var fileLastWriteUtc = SelectOptionalColumn(connection, "PeAnalyses", "p", "FileLastWriteUtc", "NULL");
        var stringAnalysisStatus = SelectOptionalColumn(connection, "PeAnalyses", "p", "StringAnalysisStatus", "'Completed'");
        var performanceJson = SelectOptionalColumn(connection, "PeAnalyses", "p", "PerformanceJson", "'{}'");
        var entity = SelectOptionalColumn(connection, "PeAnalyses", "p", "ProcessEntityId", "''");
        var sourceRun = SelectOptionalColumn(connection, "PeAnalyses", "p", "SourceRunId", "''");
        var ingestionJob = SelectOptionalColumn(connection, "PeAnalyses", "p", "IngestionJobId", "''");
        return $"""
            SELECT p.AnalysisId, p.ProcessKey, p.ProcessId, p.ProcessGuid, p.ProcessName,
                   p.SourceKind, p.SourceArtifactId, p.FilePath, p.Status, p.AnalyzedUtc,
                   p.FileSizeBytes, {fileLastWriteUtc}, p.Sha256Hash, p.Md5Hash, p.Machine, p.Subsystem,
                   p.PeKind, p.LinkerTimestampUtc, p.EntryPoint, p.ImageBase,
                   p.SectionCount, p.ImportCount, p.ExportCount, p.PrintableStringCount, {stringAnalysisStatus},
                   p.SectionsJson, p.ImportsJson, p.ExportsJson, p.VersionInfoJson,
                   p.StringSummaryJson, p.ErrorMessage, {performanceJson}, p.CaseId, p.EvidenceSessionId, p.CaptureId,
                   p.SourceIdentityId, p.HostId, p.ExecutionRootId,
                   {entity}, {sourceRun}, {ingestionJob},
                   COALESCE(s.DisplayName, '') AS Source
            FROM PeAnalyses p
            LEFT JOIN Sources s ON s.SourceId = p.SourceId
            WHERE {processPredicate}
            """;
    }

    private static string BuildAuthenticodeSelect() => """
        SELECT a.VerificationId, a.AnalysisId,
               a.CaseId, a.EvidenceSessionId, a.CaptureId, a.SourceIdentityId, a.HostId, a.ExecutionRootId,
               a.ProcessEntityId, a.SourceRunId, a.IngestionJobId,
               a.ProcessKey, a.ProcessId, a.ProcessGuid, a.ProcessName, a.FilePath, a.Sha256Hash,
               a.SignatureKind, a.VerificationStatus, a.SignerSubject, a.Publisher,
               a.CertificateThumbprint, a.Issuer, a.HasTimestamp, a.TimestampSubject, a.TimestampUtc,
               a.VerificationPolicy, a.VerificationTimeUtc, a.RevocationMode, a.RevocationStatus,
               a.NativeStatusCode, a.DiagnosticCode, a.DiagnosticText,
               COALESCE(s.DisplayName, '') AS Source
        FROM AuthenticodeVerifications a
        LEFT JOIN Sources s ON s.SourceId = a.SourceId
        """;

    private static void AttachLatestAuthenticodeVerifications(
        SqliteConnection connection,
        IReadOnlyList<PeAnalysisRecord> analyses)
    {
        if (analyses.Count == 0 || !ColumnExists(connection, "AuthenticodeVerifications", "VerificationId"))
        {
            return;
        }

        const int batchSize = 400;
        var analysesById = analyses
            .Where(analysis => !string.IsNullOrWhiteSpace(analysis.AnalysisId))
            .GroupBy(analysis => analysis.AnalysisId, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToList(), StringComparer.Ordinal);
        var ids = analysesById.Keys.ToList();
        for (var offset = 0; offset < ids.Count; offset += batchSize)
        {
            var batch = ids.Skip(offset).Take(batchSize).ToList();
            using var command = connection.CreateCommand();
            var parameters = new List<string>(batch.Count);
            for (var index = 0; index < batch.Count; index++)
            {
                var parameter = $"$AnalysisId{index}";
                parameters.Add(parameter);
                command.Parameters.AddWithValue(parameter, batch[index]);
            }

            command.CommandText = BuildAuthenticodeSelect() + $"\nWHERE a.AnalysisId IN ({string.Join(", ", parameters)})\n" + """
                ORDER BY a.AnalysisId, a.VerificationTimeUtc DESC, a.VerificationId DESC;
                """;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var verification = ReadAuthenticodeVerification(reader);
                if (!seen.Add(verification.AnalysisId) ||
                    !analysesById.TryGetValue(verification.AnalysisId, out var matchingAnalyses))
                {
                    continue;
                }

                foreach (var analysis in matchingAnalyses)
                {
                    analysis.AuthenticodeVerification = verification;
                }
            }
        }
    }

    private static string BuildMemoryImageSelect(string sourceRunId, string ingestionJobId)
        => $"""
            SELECT m.ImageId, m.JobId, m.Status, m.ImportedUtc, m.SourcePath, m.FilePath,
                   m.DisplayName, m.ImageFormat, m.FileSizeBytes, m.Sha256Hash, m.HostName,
                   m.OsBuild, m.AcquisitionTool, m.AcquisitionToolVersion, m.AcquisitionCommandLine,
                   m.PrivilegeState, m.ErrorMessage, m.CaseId, m.EvidenceSessionId, m.CaptureId,
                   m.SourceIdentityId, m.HostId, m.ExecutionRootId, {sourceRunId}, {ingestionJobId},
                   COALESCE(s.DisplayName, '')
            FROM MemoryImages m
            LEFT JOIN Sources s ON s.SourceId = m.SourceId
            """;

    private static string BuildNetworkCaptureSelect(string sourceRunId, string ingestionJobId)
        => $"""
            SELECT n.CaptureId, n.JobId, n.SegmentIndex, n.Status, n.RequestedUtc,
                   n.StartedUtc, n.CompletedUtc, n.OutputDirectory, n.EtlFilePath,
                   n.FilePath, n.FileSizeBytes, n.Sha256Hash, n.ToolName,
                   n.CaptureSource, n.FilterDescription, n.ErrorMessage,
                   n.CaseId, n.EvidenceSessionId, n.SourceIdentityId, n.HostId, n.ExecutionRootId,
                   {sourceRunId}, {ingestionJobId}, COALESCE(s.DisplayName, '')
            FROM NetworkCaptures n
            LEFT JOIN Sources s ON s.SourceId = n.SourceId
            """;

    private static string BuildZeekSelect(SqliteConnection connection)
    {
        var durationSeconds = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "DurationSeconds", "0");
        var origPackets = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "OrigPackets", "0");
        var respPackets = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "RespPackets", "0");
        var origIpBytes = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "OrigIpBytes", "0");
        var respIpBytes = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "RespIpBytes", "0");
        var connectionState = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "ConnectionState", "''");
        var history = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "History", "''");
        var serverName = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "ServerName", "''");
        var clientProtocol = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "ClientProtocol", "''");
        var tlsVersion = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "TlsVersion", "''");
        var tlsCipher = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "TlsCipher", "''");
        var tlsEstablished = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "TlsEstablished", "0");
        var weirdName = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "WeirdName", "''");
        var weirdAdditional = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "WeirdAdditional", "''");
        var sourceRunId = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "SourceRunId", "''");
        var ingestionJobId = SelectOptionalColumn(connection, "ZeekNetworkArtifacts", "z", "IngestionJobId", "''");
        return $"""
            SELECT z.ArtifactId, z.CaptureId, z.JobId, z.Status, z.TimestampUtc,
                   z.LogType, z.ZeekUid, z.SourceIp, z.SourcePort, z.DestinationIp,
                   z.DestinationPort, z.Protocol, z.Service, z.DnsQuery, z.HttpMethod,
                   z.HttpHost, z.HttpUri, {durationSeconds}, z.OrigBytes, z.RespBytes,
                   {origPackets}, {respPackets}, {origIpBytes}, {respIpBytes},
                   {connectionState}, {history}, {serverName}, {clientProtocol},
                   {tlsVersion}, {tlsCipher}, {tlsEstablished}, {weirdName}, {weirdAdditional},
                   z.Summary, z.ProcessKey, z.ProcessId, z.ProcessName, z.CorrelationMethod,
                   z.CorrelationConfidence, z.RawLogPath, z.RawLineNumber,
                   z.RawLineHash, z.RawText, z.ErrorMessage,
                   z.CaseId, z.EvidenceSessionId, z.SourceIdentityId, z.HostId, z.ExecutionRootId,
                   {sourceRunId}, {ingestionJobId}, COALESCE(s.DisplayName, '')
            FROM ZeekNetworkArtifacts z
            LEFT JOIN Sources s ON s.SourceId = z.SourceId
            """;
    }

    private static IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> ReadArtifactProperties(
        SqliteConnection connection,
        IEnumerable<string> artifactIds)
    {
        const int batchSize = 500;
        var ids = artifactIds
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        var result = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal);
        for (var offset = 0; offset < ids.Count; offset += batchSize)
        {
            var batch = ids.Skip(offset).Take(batchSize).ToList();
            using var command = connection.CreateCommand();
            var parameterNames = new List<string>(batch.Count);
            for (var index = 0; index < batch.Count; index++)
            {
                var parameterName = $"$ArtifactId{index}";
                parameterNames.Add(parameterName);
                command.Parameters.AddWithValue(parameterName, batch[index]);
            }

            command.CommandText = $"""
                SELECT ArtifactId, Name, Value
                FROM ArtifactProperties
                WHERE ArtifactId IN ({string.Join(", ", parameterNames)})
                ORDER BY ArtifactId, Name;
                """;
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var artifactId = GetString(reader, 0);
                if (!result.TryGetValue(artifactId, out var existing))
                {
                    existing = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    result[artifactId] = existing;
                }

                if (existing is Dictionary<string, string> properties)
                {
                    properties[GetString(reader, 1)] = GetString(reader, 2);
                }
            }
        }

        return result;
    }

    private static MemoryDumpRecord ReadMemoryDump(SqliteDataReader reader)
    {
        var record = new MemoryDumpRecord
        {
            DumpId = GetString(reader, 0),
            JobId = Guid.TryParse(GetString(reader, 1), out var jobId) ? jobId : null,
            ProcessKey = GetString(reader, 2),
            ProcessId = GetInt(reader, 3),
            ProcessGuid = GetString(reader, 4),
            ProcessName = GetString(reader, 5),
            DumpKind = GetEnum(reader, 6, MemoryDumpKind.Full),
            Status = GetEnum(reader, 7, MemoryDumpStatus.Requested),
            RequestedUtc = GetDateTime(reader, 8) ?? DateTime.UtcNow,
            CompletedUtc = GetDateTime(reader, 9),
            OutputDirectory = GetString(reader, 10),
            FilePath = GetString(reader, 11),
            FileSizeBytes = GetLong(reader, 12),
            Sha256Hash = GetString(reader, 13),
            ToolName = GetString(reader, 14),
            ErrorMessage = GetString(reader, 15),
            Source = reader.FieldCount >= 26 ? GetString(reader, 25) : reader.FieldCount >= 23 ? GetString(reader, 22) : GetString(reader, 16)
        };
        if (reader.FieldCount >= 23)
        {
            record.CaseId = GetString(reader, 16);
            record.EvidenceSessionId = GetString(reader, 17);
            record.CaptureId = GetString(reader, 18);
            record.SourceIdentityId = GetString(reader, 19);
            record.HostId = GetString(reader, 20);
            record.ExecutionRootId = GetString(reader, 21);
        }

        if (reader.FieldCount >= 26)
        {
            record.ProcessEntityId = GetString(reader, 22);
            record.SourceRunId = GetString(reader, 23);
            record.IngestionJobId = GetString(reader, 24);
        }

        return record;
    }

    private static PeAnalysisRecord ReadPeAnalysis(SqliteDataReader reader)
    {
        int Ordinal(string name) => reader.GetOrdinal(name);
        return new PeAnalysisRecord
        {
            AnalysisId = GetString(reader, Ordinal("AnalysisId")),
            ProcessKey = GetString(reader, Ordinal("ProcessKey")),
            ProcessId = GetInt(reader, Ordinal("ProcessId")),
            ProcessGuid = GetString(reader, Ordinal("ProcessGuid")),
            ProcessName = GetString(reader, Ordinal("ProcessName")),
            SourceKind = GetEnum(reader, Ordinal("SourceKind"), PeAnalysisSourceKind.ProcessImage),
            SourceArtifactId = GetString(reader, Ordinal("SourceArtifactId")),
            FilePath = GetString(reader, Ordinal("FilePath")),
            Status = GetEnum(reader, Ordinal("Status"), PeAnalysisStatus.Completed),
            AnalyzedUtc = GetDateTime(reader, Ordinal("AnalyzedUtc")) ?? DateTime.UtcNow,
            FileSizeBytes = GetLong(reader, Ordinal("FileSizeBytes")),
            FileLastWriteUtc = GetDateTime(reader, Ordinal("FileLastWriteUtc")),
            Sha256Hash = GetString(reader, Ordinal("Sha256Hash")),
            Md5Hash = GetString(reader, Ordinal("Md5Hash")),
            Machine = GetString(reader, Ordinal("Machine")),
            Subsystem = GetString(reader, Ordinal("Subsystem")),
            PeKind = GetString(reader, Ordinal("PeKind")),
            LinkerTimestampUtc = GetDateTime(reader, Ordinal("LinkerTimestampUtc")),
            EntryPoint = GetString(reader, Ordinal("EntryPoint")),
            ImageBase = GetString(reader, Ordinal("ImageBase")),
            SectionCount = GetInt(reader, Ordinal("SectionCount")),
            ImportCount = GetInt(reader, Ordinal("ImportCount")),
            ExportCount = GetInt(reader, Ordinal("ExportCount")),
            PrintableStringCount = GetInt(reader, Ordinal("PrintableStringCount")),
            StringAnalysisStatus = GetEnum(reader, Ordinal("StringAnalysisStatus"), PeStringAnalysisStatus.Completed),
            SectionsJson = GetString(reader, Ordinal("SectionsJson")),
            ImportsJson = GetString(reader, Ordinal("ImportsJson")),
            ExportsJson = GetString(reader, Ordinal("ExportsJson")),
            VersionInfoJson = GetString(reader, Ordinal("VersionInfoJson")),
            StringSummaryJson = GetString(reader, Ordinal("StringSummaryJson")),
            ErrorMessage = GetString(reader, Ordinal("ErrorMessage")),
            PerformanceJson = GetString(reader, Ordinal("PerformanceJson")),
            CaseId = GetString(reader, Ordinal("CaseId")),
            EvidenceSessionId = GetString(reader, Ordinal("EvidenceSessionId")),
            CaptureId = GetString(reader, Ordinal("CaptureId")),
            SourceIdentityId = GetString(reader, Ordinal("SourceIdentityId")),
            HostId = GetString(reader, Ordinal("HostId")),
            ExecutionRootId = GetString(reader, Ordinal("ExecutionRootId")),
            ProcessEntityId = GetOptionalString(reader, "ProcessEntityId"),
            SourceRunId = GetOptionalString(reader, "SourceRunId"),
            IngestionJobId = GetOptionalString(reader, "IngestionJobId"),
            Source = GetString(reader, Ordinal("Source"))
        };
    }

    private static AuthenticodeVerificationRecord ReadAuthenticodeVerification(SqliteDataReader reader)
    {
        int Ordinal(string name) => reader.GetOrdinal(name);
        return new AuthenticodeVerificationRecord
        {
            VerificationId = GetString(reader, Ordinal("VerificationId")),
            AnalysisId = GetString(reader, Ordinal("AnalysisId")),
            CaseId = GetString(reader, Ordinal("CaseId")),
            EvidenceSessionId = GetString(reader, Ordinal("EvidenceSessionId")),
            CaptureId = GetString(reader, Ordinal("CaptureId")),
            SourceIdentityId = GetString(reader, Ordinal("SourceIdentityId")),
            HostId = GetString(reader, Ordinal("HostId")),
            ExecutionRootId = GetString(reader, Ordinal("ExecutionRootId")),
            ProcessEntityId = GetString(reader, Ordinal("ProcessEntityId")),
            SourceRunId = GetString(reader, Ordinal("SourceRunId")),
            IngestionJobId = GetString(reader, Ordinal("IngestionJobId")),
            ProcessKey = GetString(reader, Ordinal("ProcessKey")),
            ProcessId = GetInt(reader, Ordinal("ProcessId")),
            ProcessGuid = GetString(reader, Ordinal("ProcessGuid")),
            ProcessName = GetString(reader, Ordinal("ProcessName")),
            FilePath = GetString(reader, Ordinal("FilePath")),
            Sha256Hash = GetString(reader, Ordinal("Sha256Hash")),
            SignatureKind = GetEnum(reader, Ordinal("SignatureKind"), AuthenticodeSignatureKind.Unknown),
            VerificationStatus = GetEnum(reader, Ordinal("VerificationStatus"), AuthenticodeVerificationStatus.Unknown),
            SignerSubject = GetString(reader, Ordinal("SignerSubject")),
            Publisher = GetString(reader, Ordinal("Publisher")),
            CertificateThumbprint = GetString(reader, Ordinal("CertificateThumbprint")),
            Issuer = GetString(reader, Ordinal("Issuer")),
            HasTimestamp = GetInt(reader, Ordinal("HasTimestamp")) != 0,
            TimestampSubject = GetString(reader, Ordinal("TimestampSubject")),
            TimestampUtc = GetDateTime(reader, Ordinal("TimestampUtc")),
            VerificationPolicy = GetString(reader, Ordinal("VerificationPolicy")),
            VerificationTimeUtc = GetDateTime(reader, Ordinal("VerificationTimeUtc")) ?? DateTime.UtcNow,
            RevocationMode = GetEnum(reader, Ordinal("RevocationMode"), AuthenticodeRevocationMode.Unknown),
            RevocationStatus = GetEnum(reader, Ordinal("RevocationStatus"), AuthenticodeRevocationStatus.Unknown),
            NativeStatusCode = GetString(reader, Ordinal("NativeStatusCode")),
            DiagnosticCode = GetString(reader, Ordinal("DiagnosticCode")),
            DiagnosticText = GetString(reader, Ordinal("DiagnosticText")),
            Source = GetString(reader, Ordinal("Source"))
        };
    }

    private static MemoryImageRecord ReadMemoryImage(SqliteDataReader reader)
    {
        var record = new MemoryImageRecord
        {
            ImageId = GetString(reader, 0),
            JobId = Guid.TryParse(GetString(reader, 1), out var jobId) ? jobId : null,
            Status = GetEnum(reader, 2, MemoryImageStatus.Imported),
            ImportedUtc = GetDateTime(reader, 3) ?? DateTime.UtcNow,
            SourcePath = GetString(reader, 4),
            FilePath = GetString(reader, 5),
            DisplayName = GetString(reader, 6),
            ImageFormat = GetString(reader, 7),
            FileSizeBytes = GetLong(reader, 8),
            Sha256Hash = GetString(reader, 9),
            HostName = GetString(reader, 10),
            OsBuild = GetString(reader, 11),
            AcquisitionTool = GetString(reader, 12),
            AcquisitionToolVersion = GetString(reader, 13),
            AcquisitionCommandLine = GetString(reader, 14),
            PrivilegeState = GetString(reader, 15),
            ErrorMessage = GetString(reader, 16),
            Source = reader.FieldCount >= 26 ? GetString(reader, 25) : "AgentMemoryImageImport"
        };
        if (reader.FieldCount >= 24)
        {
            record.CaseId = GetString(reader, 17);
            record.EvidenceSessionId = GetString(reader, 18);
            record.CaptureId = GetString(reader, 19);
            record.SourceIdentityId = GetString(reader, 20);
            record.HostId = GetString(reader, 21);
            record.ExecutionRootId = GetString(reader, 22);
            if (reader.FieldCount >= 26)
            {
                record.SourceRunId = GetString(reader, 23);
                record.IngestionJobId = GetString(reader, 24);
            }
        }

        return record;
    }

    private static VolatilityPluginRunRecord ReadVolatilityPluginRun(SqliteDataReader reader)
    {
        var record = new VolatilityPluginRunRecord
        {
            RunId = GetString(reader, 0),
            ImageId = GetString(reader, 1),
            JobId = Guid.TryParse(GetString(reader, 2), out var jobId) ? jobId : null,
            PluginName = GetString(reader, 3),
            Status = GetEnum(reader, 4, VolatilityPluginRunStatus.Queued),
            RequestedUtc = GetDateTime(reader, 5) ?? DateTime.UtcNow,
            StartedUtc = GetDateTime(reader, 6),
            CompletedUtc = GetDateTime(reader, 7),
            VolatilityPath = GetString(reader, 8),
            VolatilityVersion = GetString(reader, 9),
            CommandLine = GetString(reader, 10),
            OutputDirectory = GetString(reader, 11),
            StdoutPath = GetString(reader, 12),
            StderrPath = GetString(reader, 13),
            RawOutputHash = GetString(reader, 14),
            SymbolsPath = GetString(reader, 15),
            ProfileOrLayer = GetString(reader, 16),
            NormalizedRowCount = GetInt(reader, 17),
            ErrorMessage = GetString(reader, 18),
            Source = reader.FieldCount >= 28 ? GetString(reader, 27) : "AgentVolatility"
        };
        if (reader.FieldCount >= 26)
        {
            record.CaseId = GetString(reader, 19);
            record.EvidenceSessionId = GetString(reader, 20);
            record.CaptureId = GetString(reader, 21);
            record.SourceIdentityId = GetString(reader, 22);
            record.HostId = GetString(reader, 23);
            record.ExecutionRootId = GetString(reader, 24);
            if (reader.FieldCount >= 28)
            {
                record.SourceRunId = GetString(reader, 25);
                record.IngestionJobId = GetString(reader, 26);
            }
        }

        return record;
    }

    private static MemoryProcessRecord ReadMemoryProcess(SqliteDataReader reader)
    {
        var record = new MemoryProcessRecord
        {
            ArtifactId = GetString(reader, 0),
            ImageId = GetString(reader, 1),
            PluginRunId = GetString(reader, 2),
            PluginName = GetString(reader, 3),
            EvidenceKind = GetEnum(reader, 4, MemoryProcessEvidenceKind.Unknown),
            RowNumber = GetInt(reader, 5),
            ObjectOffset = GetString(reader, 6),
            ProcessId = GetInt(reader, 7),
            ParentProcessId = GetInt(reader, 8),
            ProcessName = GetString(reader, 9),
            ImagePath = GetString(reader, 10),
            CommandLine = GetString(reader, 11),
            CreateTimeUtc = GetDateTime(reader, 12),
            ExitTimeUtc = GetDateTime(reader, 13),
            SessionId = GetInt(reader, 14),
            ThreadCount = GetInt(reader, 15),
            HandleCount = GetInt(reader, 16),
            Wow64 = GetString(reader, 17),
            ProcessKey = GetString(reader, 18),
            CorrelationState = GetEnum(reader, 19, MemoryProcessCorrelationState.Unknown),
            CorrelationMethod = GetString(reader, 20),
            CorrelationConfidence = GetDouble(reader, 21),
            RawRowHash = GetString(reader, 22),
            RawJson = GetString(reader, 23),
            Source = reader.FieldCount >= 33 ? GetString(reader, 32) : "AgentVolatility"
        };
        if (reader.FieldCount >= 31)
        {
            record.CaseId = GetString(reader, 24);
            record.EvidenceSessionId = GetString(reader, 25);
            record.CaptureId = GetString(reader, 26);
            record.SourceIdentityId = GetString(reader, 27);
            record.HostId = GetString(reader, 28);
            record.ExecutionRootId = GetString(reader, 29);
            if (reader.FieldCount >= 33)
            {
                record.SourceRunId = GetString(reader, 30);
                record.IngestionJobId = GetString(reader, 31);
            }
        }

        return record;
    }

    private static NetworkCaptureRecord ReadNetworkCapture(SqliteDataReader reader)
    {
        var record = new NetworkCaptureRecord
        {
            CaptureId = GetString(reader, 0),
            JobId = Guid.TryParse(GetString(reader, 1), out var jobId) ? jobId : null,
            SegmentIndex = GetInt(reader, 2),
            Status = GetEnum(reader, 3, NetworkCaptureStatus.Requested),
            RequestedUtc = GetDateTime(reader, 4) ?? DateTime.UtcNow,
            StartedUtc = GetDateTime(reader, 5),
            CompletedUtc = GetDateTime(reader, 6),
            OutputDirectory = GetString(reader, 7),
            EtlFilePath = GetString(reader, 8),
            FilePath = GetString(reader, 9),
            FileSizeBytes = GetLong(reader, 10),
            Sha256Hash = GetString(reader, 11),
            ToolName = GetString(reader, 12),
            CaptureSource = GetString(reader, 13),
            FilterDescription = GetString(reader, 14),
            ErrorMessage = GetString(reader, 15),
            Source = reader.FieldCount >= 24 ? GetString(reader, 23) : GetString(reader, 16)
        };
        if (reader.FieldCount >= 22)
        {
            record.CaseId = GetString(reader, 16);
            record.EvidenceSessionId = GetString(reader, 17);
            record.SourceIdentityId = GetString(reader, 18);
            record.HostId = GetString(reader, 19);
            record.ExecutionRootId = GetString(reader, 20);
            if (reader.FieldCount >= 24)
            {
                record.SourceRunId = GetString(reader, 21);
                record.IngestionJobId = GetString(reader, 22);
            }
        }

        return record;
    }

    private static ZeekNetworkRecord ReadZeekNetworkArtifact(SqliteDataReader reader)
    {
        var record = new ZeekNetworkRecord
        {
            ArtifactId = GetString(reader, 0),
            CaptureId = GetString(reader, 1),
            JobId = Guid.TryParse(GetString(reader, 2), out var jobId) ? jobId : null,
            Status = GetEnum(reader, 3, ZeekArtifactStatus.Imported),
            TimestampUtc = GetDateTime(reader, 4) ?? DateTime.UtcNow,
            LogType = GetString(reader, 5),
            ZeekUid = GetString(reader, 6),
            SourceIp = GetString(reader, 7),
            SourcePort = GetInt(reader, 8),
            DestinationIp = GetString(reader, 9),
            DestinationPort = GetInt(reader, 10),
            Protocol = GetString(reader, 11),
            Service = GetString(reader, 12),
            DnsQuery = GetString(reader, 13),
            HttpMethod = GetString(reader, 14),
            HttpHost = GetString(reader, 15),
            HttpUri = GetString(reader, 16),
            DurationSeconds = GetDouble(reader, 17),
            OrigBytes = GetLong(reader, 18),
            RespBytes = GetLong(reader, 19),
            OrigPackets = GetLong(reader, 20),
            RespPackets = GetLong(reader, 21),
            OrigIpBytes = GetLong(reader, 22),
            RespIpBytes = GetLong(reader, 23),
            ConnectionState = GetString(reader, 24),
            History = GetString(reader, 25),
            ServerName = GetString(reader, 26),
            ClientProtocol = GetString(reader, 27),
            TlsVersion = GetString(reader, 28),
            TlsCipher = GetString(reader, 29),
            TlsEstablished = GetBool(reader, 30),
            WeirdName = GetString(reader, 31),
            WeirdAdditional = GetString(reader, 32),
            Summary = GetString(reader, 33),
            ProcessKey = GetString(reader, 34),
            ProcessId = GetInt(reader, 35),
            ProcessName = GetString(reader, 36),
            CorrelationMethod = GetString(reader, 37),
            CorrelationConfidence = GetDouble(reader, 38),
            RawLogPath = GetString(reader, 39),
            RawLineNumber = GetLong(reader, 40),
            RawLineHash = GetString(reader, 41),
            RawText = GetString(reader, 42),
            ErrorMessage = GetString(reader, 43),
            Source = reader.FieldCount >= 52 ? GetString(reader, 51) : string.Empty
        };
        if (reader.FieldCount >= 50)
        {
            record.CaseId = GetString(reader, 44);
            record.EvidenceSessionId = GetString(reader, 45);
            record.SourceIdentityId = GetString(reader, 46);
            record.HostId = GetString(reader, 47);
            record.ExecutionRootId = GetString(reader, 48);
            if (reader.FieldCount >= 52)
            {
                record.SourceRunId = GetString(reader, 49);
                record.IngestionJobId = GetString(reader, 50);
            }
        }

        return record;
    }

    private static FilesystemArtifactRecord ReadFilesystemArtifact(SqliteDataReader reader)
        => new()
        {
            ArtifactId = GetString(reader, 0),
            Kind = GetEnum(reader, 1, FilesystemArtifactKind.Unknown),
            TimestampUtc = GetDateTime(reader, 2) ?? DateTime.UtcNow,
            Name = GetString(reader, 3),
            SourcePath = GetString(reader, 4),
            Summary = GetString(reader, 5),
            Sha256Hash = GetString(reader, 6),
            RawRecordId = GetLong(reader, 7).ToString(),
            RawPayloadHash = GetString(reader, 8),
            RawText = GetString(reader, 9),
            CaseId = GetString(reader, 10),
            EvidenceSessionId = GetString(reader, 11),
            CaptureId = GetString(reader, 12),
            SourceIdentityId = GetString(reader, 13),
            HostId = GetString(reader, 14),
            ExecutionRootId = GetString(reader, 15),
            SourceRunId = GetString(reader, 16),
            IngestionJobId = GetString(reader, 17),
            ParentArtifactId = GetString(reader, 18)
        };

    private static SqliteStagingQueryService.ZeekProcessCorrelation? FindTupleCorrelation(
        SqliteConnection connection,
        ZeekNetworkRecord artifact)
    {
        if (string.IsNullOrWhiteSpace(artifact.SourceIp) ||
            artifact.SourcePort <= 0 ||
            string.IsNullOrWhiteSpace(artifact.DestinationIp) ||
            artifact.DestinationPort <= 0)
        {
            return null;
        }

        var sourceEndpoint = $"{artifact.SourceIp}:{artifact.SourcePort}";
        var destinationEndpoint = $"{artifact.DestinationIp}:{artifact.DestinationPort}";
        var protocol = artifact.Protocol.Trim().ToLowerInvariant();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ProcessKey, ProcessId, ProcessName
            FROM ProcessEvents
            WHERE Category = 'Network'
              AND (ProcessStartTimeUtc IS NULL OR ProcessStartTimeUtc <= $TimestampUtc)
              AND ABS(strftime('%s', TimestampUtc) - strftime('%s', $TimestampUtc)) <= $WindowSeconds
              AND (
                    Target = $DestinationEndpoint
                    OR Target = $DestinationIp
                    OR Summary LIKE $DestinationEndpointLike
                    OR Details LIKE $DestinationEndpointLike
                    OR Details LIKE $DestinationIpLike
                  )
              AND (
                    Summary LIKE $SourceEndpointLike
                    OR Details LIKE $SourceEndpointLike
                  )
              AND (
                    $Protocol = ''
                    OR LOWER(Summary) LIKE $ProtocolLike
                    OR LOWER(Details) LIKE $ProtocolLike
                  )
            ORDER BY ABS(strftime('%s', TimestampUtc) - strftime('%s', $TimestampUtc)) ASC
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$TimestampUtc", FormatDate(artifact.TimestampUtc));
        command.Parameters.AddWithValue("$WindowSeconds", 600);
        command.Parameters.AddWithValue("$SourceEndpointLike", $"%{sourceEndpoint}%");
        command.Parameters.AddWithValue("$DestinationEndpoint", destinationEndpoint);
        command.Parameters.AddWithValue("$DestinationEndpointLike", $"%{destinationEndpoint}%");
        command.Parameters.AddWithValue("$DestinationIp", artifact.DestinationIp);
        command.Parameters.AddWithValue("$DestinationIpLike", $"%{artifact.DestinationIp}%");
        command.Parameters.AddWithValue("$Protocol", protocol);
        command.Parameters.AddWithValue("$ProtocolLike", $"%{protocol}%");
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new SqliteStagingQueryService.ZeekProcessCorrelation(
                GetString(reader, 0),
                GetInt(reader, 1),
                GetString(reader, 2),
                "Staged network 5-tuple/time match",
                0.95)
            : null;
    }

    private static IEnumerable<string> BuildEndpointCandidates(ZeekNetworkRecord artifact)
    {
        if (!string.IsNullOrWhiteSpace(artifact.DestinationIp) && artifact.DestinationPort > 0)
        {
            yield return $"{artifact.DestinationIp}:{artifact.DestinationPort}";
        }

        if (!string.IsNullOrWhiteSpace(artifact.SourceIp) && artifact.SourcePort > 0)
        {
            yield return $"{artifact.SourceIp}:{artifact.SourcePort}";
        }
    }

    private static SqliteStagingQueryService.ZeekProcessCorrelation? FindCorrelation(
        SqliteConnection connection,
        string predicate,
        string target,
        DateTime timestampUtc,
        double confidence,
        string method)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT ProcessKey, ProcessId, ProcessName
            FROM ProcessEvents
            WHERE {predicate}
            ORDER BY ABS(strftime('%s', TimestampUtc) - strftime('%s', $TimestampUtc)) ASC
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$Target", target);
        command.Parameters.AddWithValue("$DetailsTarget", $"%{target}%");
        command.Parameters.AddWithValue("$TimestampUtc", FormatDate(timestampUtc));
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new SqliteStagingQueryService.ZeekProcessCorrelation(
                GetString(reader, 0),
                GetInt(reader, 1),
                GetString(reader, 2),
                method,
                confidence)
            : null;
    }

    private static void AddIdentityParameters(
        SqliteCommand command,
        string processKey,
        string processEntityId)
    {
        command.Parameters.AddWithValue("$ProcessKey", processKey ?? string.Empty);
        command.Parameters.AddWithValue("$ProcessEntityId", processEntityId ?? string.Empty);
    }

    private static bool HasProcessIdentity(string processKey, string processEntityId)
        => !string.IsNullOrWhiteSpace(processKey) || !string.IsNullOrWhiteSpace(processEntityId);

    private static string IdentityDiagnostic(string processKey, string processEntityId, int maxCount)
        => $"identity={(string.IsNullOrWhiteSpace(processEntityId) ? "process-key compatibility" : "process-entity")}; max={maxCount}";

    private static string BuildProcessAttachmentPredicate(
        SqliteConnection connection,
        string tableName,
        string alias,
        string processEntityId,
        string processKey)
        => !string.IsNullOrWhiteSpace(processEntityId) && ColumnExists(connection, tableName, "ProcessEntityId")
            ? $"{alias}.ProcessEntityId = $ProcessEntityId"
            : !string.IsNullOrWhiteSpace(processKey)
                ? $"{alias}.ProcessKey = $ProcessKey"
                : "1 = 0";

    private static string SelectOptionalColumn(
        SqliteConnection connection,
        string tableName,
        string alias,
        string columnName,
        string fallbackExpression)
        => ColumnExists(connection, tableName, columnName)
            ? $"{alias}.{columnName}"
            : $"{fallbackExpression} AS {columnName}";

    private static bool ColumnExists(SqliteConnection connection, string tableName, string columnName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({tableName});";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (string.Equals(GetString(reader, 1), columnName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$name;";
        command.Parameters.AddWithValue("$name", tableName);
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;
    }

    private static string GetProperty(IReadOnlyDictionary<string, string> properties, string name)
        => properties.TryGetValue(name, out var value) ? value : string.Empty;

    private static long GetPropertyLong(IReadOnlyDictionary<string, string> properties, string name)
        => long.TryParse(GetProperty(properties, name), out var value) ? value : 0;

    private static DateTime? GetPropertyDate(IReadOnlyDictionary<string, string> properties, string name)
        => DateTimeOffset.TryParse(GetProperty(properties, name), out var value) ? value.UtcDateTime : null;

    private static TEnum GetPropertyEnum<TEnum>(
        IReadOnlyDictionary<string, string> properties,
        string name,
        TEnum fallback)
        where TEnum : struct
        => Enum.TryParse<TEnum>(GetProperty(properties, name), out var value) ? value : fallback;

    private static string GetOptionalString(SqliteDataReader reader, string columnName)
    {
        for (var index = 0; index < reader.FieldCount; index++)
        {
            if (string.Equals(reader.GetName(index), columnName, StringComparison.OrdinalIgnoreCase))
            {
                return GetString(reader, index);
            }
        }

        return string.Empty;
    }

    private static string GetString(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private static int GetInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt32(ordinal);

    private static long GetLong(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt64(ordinal);

    private static double GetDouble(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetDouble(ordinal);

    private static bool GetBool(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return false;
        }

        if (reader.GetFieldType(ordinal) == typeof(string))
        {
            var value = GetString(reader, ordinal);
            return value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("T", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("1", StringComparison.OrdinalIgnoreCase);
        }

        return reader.GetInt64(ordinal) != 0;
    }

    private static DateTime? GetDateTime(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) || !DateTimeOffset.TryParse(reader.GetString(ordinal), out var value)
            ? null
            : value.UtcDateTime;

    // Structured bodies bind this nullable timestamp into ResultSha256. Unlike legacy projections,
    // malformed non-null text must therefore fail rather than being treated as an absent primary time.
    private static DateTime? GetStructuredBodyTimestamp(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal)) return null;
        var stored = reader.GetString(ordinal);
        if (!DateTimeOffset.TryParse(stored, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var value) ||
            !string.Equals(stored, value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture), StringComparison.Ordinal)) throw new InvalidDataException();
        return value.UtcDateTime;
    }

    private static string FormatDate(DateTime value)
        => value.Kind == DateTimeKind.Utc
            ? value.ToString("O")
            : value.ToUniversalTime().ToString("O");

    private static TEnum GetEnum<TEnum>(SqliteDataReader reader, int ordinal, TEnum fallback)
        where TEnum : struct
        => !reader.IsDBNull(ordinal) && Enum.TryParse<TEnum>(reader.GetString(ordinal), out var value)
            ? value
            : fallback;

    private static void AddLimitParameter(SqliteCommand command)
        => command.Parameters.AddWithValue("$MaxCount", 250);

    private static void AddPlanParameters(
        SqliteCommand command,
        bool includeProcessKey = false,
        bool includeProcessEntityId = false,
        bool includeImageId = false)
    {
        if (includeProcessKey)
        {
            command.Parameters.AddWithValue("$ProcessKey", string.Empty);
        }

        if (includeProcessEntityId)
        {
            command.Parameters.AddWithValue("$ProcessEntityId", string.Empty);
        }

        if (includeImageId)
        {
            command.Parameters.AddWithValue("$ImageId", string.Empty);
        }

        AddLimitParameter(command);
    }

    private static void AddQueryPlan(
        ICollection<SqliteQueryPlanRecord> plans,
        SqliteConnection connection,
        string operation,
        string sql,
        Action<SqliteCommand>? configure = null)
    {
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"EXPLAIN QUERY PLAN {sql.Trim().TrimEnd(';')};";
            configure?.Invoke(command);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                plans.Add(new SqliteQueryPlanRecord(
                    operation,
                    GetInt(reader, 0),
                    GetInt(reader, 1),
                    GetInt(reader, 2),
                    GetString(reader, 3)));
            }
        }
        catch (Exception ex) when (ex is SqliteException or InvalidOperationException)
        {
            plans.Add(new SqliteQueryPlanRecord(
                operation,
                -1,
                -1,
                -1,
                $"query plan unavailable: {ex.Message}"));
        }
    }
}
