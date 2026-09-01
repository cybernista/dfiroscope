using System;
using System.Collections.Generic;
using System.Linq;
using ProcInsider.Models;

namespace ProcInsider.Services;

public enum EvidenceReadPath
{
    Unavailable = 0,
    ViewerSnapshotSqlite = 1,
    ArchivedCaptureSqlite = 2
}

public sealed record EvidencePathDiagnostics(
    EvidenceReadPath ReadPath,
    string WritePath,
    string DatabasePath,
    DateTime ActivatedUtc)
{
    public const string AgentWritePath = "ProcInsider.Agent/AgentStagingWriter";

    public bool IsReadable => ReadPath != EvidenceReadPath.Unavailable;

    public string StatusCode => ReadPath switch
    {
        EvidenceReadPath.ViewerSnapshotSqlite => "evidence.path.viewer-snapshot-sqlite",
        EvidenceReadPath.ArchivedCaptureSqlite => "evidence.path.archived-readonly-sqlite",
        _ => "evidence.path.unavailable"
    };

    public string StatusMessage => IsReadable
        ? $"Evidence reads: {ReadPath} ({DatabasePath}); live writes: {WritePath}."
        : $"Evidence reads: unavailable until a snapshot or archived capture is loaded; live writes: {WritePath}.";

    public static EvidencePathDiagnostics Unavailable() =>
        new(EvidenceReadPath.Unavailable, AgentWritePath, string.Empty, DateTime.UtcNow);
}

/// <summary>
/// Viewer evidence read facade. Published viewer surfaces read one active SQLite
/// projection only; this service never falls back to a mutable in-memory evidence store.
/// </summary>
public sealed class TelemetryProjectionService : IApplicationComparisonEvidenceReader
{
    private SqliteStagingQueryService? _sqliteStagingQueryService;
    private EvidencePathDiagnostics _pathDiagnostics = EvidencePathDiagnostics.Unavailable();

    public EvidencePathDiagnostics PathDiagnostics => _pathDiagnostics;

    public void SetSqliteStagingQueryService(
        SqliteStagingQueryService? sqliteStagingQueryService,
        EvidenceReadPath readPath = EvidenceReadPath.Unavailable,
        string databasePath = "")
    {
        if (sqliteStagingQueryService == null)
        {
            _sqliteStagingQueryService = null;
            _pathDiagnostics = EvidencePathDiagnostics.Unavailable();
            return;
        }

        if (readPath == EvidenceReadPath.Unavailable)
        {
            throw new ArgumentOutOfRangeException(
                nameof(readPath),
                readPath,
                "A bound SQLite projection requires an explicit viewer-snapshot or archived-capture read path.");
        }

        _sqliteStagingQueryService = sqliteStagingQueryService;
        _pathDiagnostics = new EvidencePathDiagnostics(
            readPath,
            EvidencePathDiagnostics.AgentWritePath,
            databasePath,
            DateTime.UtcNow);
    }

    public IReadOnlyList<ProcessInfo> GetProcessList(ProcessProjectionQuery query) =>
        _sqliteStagingQueryService?
            .GetProcesses(query)
            .Select(process => process.ToProcessInfo())
            .ToList()
        ?? [];

    public TelemetryStoreStats GetStats()
    {
        if (_sqliteStagingQueryService != null)
        {
            var stats = _sqliteStagingQueryService.GetStats();
            stats.StatusMessage = $"{stats.StatusMessage} {_pathDiagnostics.StatusMessage}".Trim();
            return stats;
        }

        return new TelemetryStoreStats { StatusMessage = _pathDiagnostics.StatusMessage };
    }

    public IReadOnlyList<ProcessStatisticsRecord> GetLatestProcessStatistics(int maxCount = 100000) =>
        _sqliteStagingQueryService?.GetLatestProcessStatistics(maxCount) ?? [];

    public IReadOnlyList<ProcessStatisticsRecord> GetProcessStatisticsSamples(
        string processKey,
        int maxCount = 100000,
        string processEntityId = "") =>
        _sqliteStagingQueryService?.GetProcessStatisticsSamples(processKey, maxCount, processEntityId) ?? [];

    public ProcessArtifactCounts GetArtifactCounts(string processKey, string processEntityId = "") =>
        _sqliteStagingQueryService?.GetArtifactCounts(processKey, processEntityId) ?? new ProcessArtifactCounts();

    public ProcessSourceEventCounts GetEventCounts(string processKey, string processEntityId = "") =>
        _sqliteStagingQueryService?.GetEventCounts(processKey, processEntityId) ?? new ProcessSourceEventCounts();

    public IReadOnlyDictionary<string, ProcessSourceEventCounts> GetEventCountsByProcess() =>
        _sqliteStagingQueryService?.CountEventsByProcessAndSource()
        ?? new Dictionary<string, ProcessSourceEventCounts>(StringComparer.Ordinal);

    public IReadOnlyDictionary<string, int> GetModuleCountsByProcess() =>
        _sqliteStagingQueryService?.CountModulesByProcess(includeUnloaded: true)
        ?? new Dictionary<string, int>(StringComparer.Ordinal);

    public IReadOnlyDictionary<string, int> GetHandleCountsByProcess() =>
        _sqliteStagingQueryService?.CountHandlesByProcess(includeClosed: true)
        ?? new Dictionary<string, int>(StringComparer.Ordinal);

    public IReadOnlyList<ProcessEventInfo> GetEventsForProcess(EventProjectionQuery query)
    {
        if (_sqliteStagingQueryService == null ||
            (string.IsNullOrWhiteSpace(query.ProcessKey) && string.IsNullOrWhiteSpace(query.ProcessEntityId)))
        {
            return [];
        }

        return _sqliteStagingQueryService
            .GetEventsForProcess(query.ProcessKey, query.Source, query.MaxCount, query.ProcessEntityId)
            .Select(processEvent => processEvent.ToProcessEventInfo())
            .ToList();
    }

    public IReadOnlyList<SystemActivityRecord> GetSystemActivities(SystemActivityQuery query) =>
        _sqliteStagingQueryService?.GetSystemActivities(query) ?? [];

    public IReadOnlyDictionary<SystemActivityScopeKind, int> GetSystemActivityScopeCounts() =>
        _sqliteStagingQueryService?.GetSystemActivityScopeCounts()
        ?? new Dictionary<SystemActivityScopeKind, int>();

    public IReadOnlyList<SystemActivityAccountSummary> GetSystemActivityAccounts(
        SystemActivityQuery query,
        int maxCount = 100) =>
        _sqliteStagingQueryService?.GetSystemActivityAccounts(query, maxCount) ?? [];

    public IReadOnlyList<ModuleInfo> GetModulesForProcess(ModuleProjectionQuery query)
    {
        if (_sqliteStagingQueryService == null || query.MaxCount <= 0 ||
            (string.IsNullOrWhiteSpace(query.ProcessKey) && string.IsNullOrWhiteSpace(query.ProcessEntityId)))
        {
            return [];
        }

        return _sqliteStagingQueryService
            .GetModulesForProcess(
                query.ProcessKey,
                query.IncludeUnloaded,
                Math.Clamp(query.MaxCount, 1, 10000),
                query.ProcessEntityId)
            .Select(module => module.ToModuleInfo())
            .ToList();
    }

    public IReadOnlyList<HandleInfo> GetHandlesForProcess(HandleProjectionQuery query)
    {
        if (_sqliteStagingQueryService == null || query.MaxCount <= 0 ||
            (string.IsNullOrWhiteSpace(query.ProcessKey) && string.IsNullOrWhiteSpace(query.ProcessEntityId)))
        {
            return [];
        }

        return _sqliteStagingQueryService
            .GetHandlesForProcess(
                query.ProcessKey,
                query.IncludeClosed,
                Math.Clamp(query.MaxCount, 1, 10000),
                query.ProcessEntityId)
            .Select(handle => handle.ToHandleInfo())
            .ToList();
    }

    public IReadOnlyList<MemoryDumpRecord> GetMemoryDumpsForProcess(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "") =>
        _sqliteStagingQueryService?.GetMemoryDumpsForProcess(processKey, maxCount, processEntityId) ?? [];

    public IReadOnlyList<PeAnalysisRecord> GetPeAnalysesForProcess(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "") =>
        _sqliteStagingQueryService?.GetPeAnalysesForProcess(processKey, maxCount, processEntityId) ?? [];

    public IReadOnlyList<AuthenticodeVerificationRecord> GetAuthenticodeVerificationsForProcess(
        string processKey,
        int maxCount = 100,
        string processEntityId = "") =>
        _sqliteStagingQueryService?.GetAuthenticodeVerificationsForProcess(processKey, maxCount, processEntityId) ?? [];

    public AuthenticodeVerificationRecord? GetLatestAuthenticodeVerificationForProcess(
        string processKey,
        string processEntityId = "") =>
        _sqliteStagingQueryService?.GetLatestAuthenticodeVerificationForProcess(processKey, processEntityId);

    public IReadOnlyList<NetworkCaptureRecord> GetNetworkCaptures(int maxCount = 1000) =>
        _sqliteStagingQueryService?.GetNetworkCaptures(maxCount) ?? [];

    public IReadOnlyList<MemoryImageRecord> GetMemoryImages(int maxCount = 1000) =>
        _sqliteStagingQueryService?.GetMemoryImages(maxCount) ?? [];

    public IReadOnlyList<VolatilityPluginRunRecord> GetVolatilityPluginRuns(string imageId = "", int maxCount = 1000) =>
        _sqliteStagingQueryService?.GetVolatilityPluginRuns(imageId, maxCount) ?? [];

    public IReadOnlyList<MemoryProcessRecord> GetMemoryProcesses(string imageId = "", int maxCount = 5000) =>
        _sqliteStagingQueryService?.GetMemoryProcesses(imageId, maxCount) ?? [];

    public IReadOnlyList<ZeekNetworkRecord> GetZeekNetworkArtifacts(int maxCount = 1000) =>
        _sqliteStagingQueryService?.GetZeekNetworkArtifacts(maxCount) ?? [];

    public IReadOnlyList<EvidenceRelation> GetEvidenceRelationsForProcess(string processEntityId, int maxCount = 200) =>
        _sqliteStagingQueryService?.GetEvidenceRelationsForProcess(processEntityId, maxCount) ?? [];

    public IReadOnlyList<EvidenceRelation> GetEvidenceRelationsForArtifact(
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        int maxCount = 200) =>
        _sqliteStagingQueryService?.GetEvidenceRelationsForArtifact(evidenceKind, evidenceId, maxCount) ?? [];

    public IReadOnlyList<FilesystemArtifactRecord> GetFilesystemArtifacts(int maxCount = 1000) =>
        _sqliteStagingQueryService?.GetFilesystemArtifacts(maxCount) ?? [];

    public IReadOnlyList<FilesystemArtifactRecord> GetFilesystemArtifacts(
        ExplorerScope? scope,
        bool includeDescendants,
        int maxCount = 1000) =>
        _sqliteStagingQueryService?.GetFilesystemArtifacts(scope, includeDescendants, maxCount) ?? [];

    public IReadOnlyList<TelemetrySearchResult> Search(TelemetrySearchQuery query) =>
        _sqliteStagingQueryService?.Search(query) ?? [];

    public IReadOnlyList<SigmaFinding> RunSigmaRule(SigmaRunQuery query) =>
        _sqliteStagingQueryService?
            .RunSigmaRulesWithDiagnostics([query.Rule], query.MaxFindings)
            .Findings
        ?? [];

    public IReadOnlyList<SigmaFinding> RunSigmaRules(IReadOnlyList<SigmaRule> rules, int maxFindings) =>
        _sqliteStagingQueryService?.RunSigmaRulesWithDiagnostics(rules, maxFindings).Findings ?? [];

    public SigmaRunResult RunSigmaRulesWithDiagnostics(IReadOnlyList<SigmaRule> rules, int maxFindings) =>
        _sqliteStagingQueryService?.RunSigmaRulesWithDiagnostics(rules, maxFindings) ?? new SigmaRunResult();

    public SigmaEvaluationInput CreateSigmaEvaluationInput() =>
        _sqliteStagingQueryService?.CreateSigmaEvaluationInput() ?? new SigmaEvaluationInput();

    public IReadOnlyList<ProcessObservation> GetProcessObservations(int maxCount = 10000) =>
        _sqliteStagingQueryService?.GetProcessObservations(maxCount) ?? [];

    public ProcessInfo? GetProcessForSearchResult(TelemetrySearchResult result)
    {
        if (_sqliteStagingQueryService == null)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(result.ProcessEntityId))
        {
            var entityLookup = _sqliteStagingQueryService.GetProcessByEntityId(result.ProcessEntityId);
            if (entityLookup.IsFound && entityLookup.Process != null)
            {
                return entityLookup.Process.ToProcessInfo();
            }
        }

        if (!string.IsNullOrWhiteSpace(result.ProcessKey))
        {
            var keyLookup = _sqliteStagingQueryService.GetProcessByKey(result.ProcessKey);
            if (keyLookup.IsFound && keyLookup.Process != null)
            {
                return keyLookup.Process.ToProcessInfo();
            }
        }

        return null;
    }
}
