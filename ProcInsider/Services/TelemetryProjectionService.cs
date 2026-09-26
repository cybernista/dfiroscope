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

    public static EvidencePathDiagnostics Unavailable() {
        return new(EvidenceReadPath.Unavailable, AgentWritePath, string.Empty, DateTime.UtcNow);
    }
}

public sealed record ImmediateChildProcessProjectionResult(
    IReadOnlyList<ProcessInfo> Processes,
    bool IsComplete,
    bool IsAmbiguous);

/// <summary>
/// Viewer evidence read facade. Published viewer surfaces read one active SQLite
/// projection only; this service never falls back to a mutable in-memory evidence store.
/// </summary>
public sealed class TelemetryProjectionService : IApplicationComparisonEvidenceReader
{
    private const int ChildRelationshipScanLimit = 500;
    private sealed record ReadBinding(SqliteStagingQueryService? Queries, EvidencePathDiagnostics Diagnostics);
    private ReadBinding _binding = new(null, EvidencePathDiagnostics.Unavailable());
    private readonly System.Threading.AsyncLocal<ReadScope?> _readScope = new();
    private readonly object _readGate = new();
    private bool _readAdmissionSuspended;
    private int _activeReadScopes;
    private ReadBinding CurrentBinding => _readScope.Value is { } scope ? scope.Binding : System.Threading.Volatile.Read(ref _binding);
    private SqliteStagingQueryService? _sqliteStagingQueryService => CurrentBinding.Queries;
    private EvidencePathDiagnostics _pathDiagnostics => CurrentBinding.Diagnostics;
    internal int ActiveReadScopes => System.Threading.Volatile.Read(ref _activeReadScopes);

    /// <summary>Async descendants retain the exact validated binding captured at admission.</summary>
    internal IDisposable BeginReadScope()
    {
        lock (_readGate)
        {
            var previous = _readScope.Value;
            if (previous?.IsDisposed == true || (_readAdmissionSuspended && previous == null))
                throw new OperationCanceledException("The captured evidence read generation is no longer admitted.");
            var scope = new ReadScope(this, CurrentBinding, previous);
            _readScope.Value = scope;
            System.Threading.Interlocked.Increment(ref _activeReadScopes);
            return scope;
        }
    }

    internal void SuspendReadAdmission() { lock (_readGate) _readAdmissionSuspended = true; }
    internal void ResumeReadAdmission() { lock (_readGate) _readAdmissionSuspended = false; }

    private sealed class ReadScope(TelemetryProjectionService owner, ReadBinding binding, ReadScope? previous) : IDisposable
    {
        public ReadBinding Binding { get; } = binding;
        public bool IsDisposed { get; private set; }
        public void Dispose()
        {
            lock (owner._readGate)
            {
                if (IsDisposed) return;
                IsDisposed = true;
                owner._readScope.Value = previous;
                System.Threading.Interlocked.Decrement(ref owner._activeReadScopes);
            }
        }
    }

    public EvidencePathDiagnostics PathDiagnostics => _pathDiagnostics;

    public void SetSqliteStagingQueryService(
        SqliteStagingQueryService? sqliteStagingQueryService,
        EvidenceReadPath readPath = EvidenceReadPath.Unavailable,
        string databasePath = "")
    {
        if (sqliteStagingQueryService == null)
        {
            System.Threading.Volatile.Write(ref _binding, new ReadBinding(null, EvidencePathDiagnostics.Unavailable()));
            return;
        }

        if (readPath == EvidenceReadPath.Unavailable)
        {
            throw new ArgumentOutOfRangeException(
                nameof(readPath),
                readPath,
                "A bound SQLite projection requires an explicit viewer-snapshot or archived-capture read path.");
        }

        System.Threading.Volatile.Write(ref _binding, new ReadBinding(sqliteStagingQueryService, new EvidencePathDiagnostics(
            readPath,
            EvidencePathDiagnostics.AgentWritePath,
            databasePath,
            DateTime.UtcNow)));
    }

    public IReadOnlyList<ProcessInfo> GetProcessList(ProcessProjectionQuery query) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?
            .GetProcesses(query)
            .Select(process => process.ToProcessInfo())
            .ToList()
        ?? [];
    }

    public ProcessInfo? GetProcessByEntityId(string processEntityId)
    {
        using var readScope = BeginReadScope();
        if (_sqliteStagingQueryService == null || string.IsNullOrWhiteSpace(processEntityId))
        {
            return null;
        }

        var lookup = _sqliteStagingQueryService.GetProcessByEntityId(processEntityId);
        return lookup.IsFound ? lookup.Process?.ToProcessInfo() : null;
    }

    public IReadOnlyList<ProcessInfo> GetProcessesByExactScope(ExplorerScope scope, int maxCount = 2)
    {
        ArgumentNullException.ThrowIfNull(scope);
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?
            .GetProcessesByExactScope(scope, maxCount)
            .Select(process => process.ToProcessInfo())
            .ToArray()
            ?? [];
    }

    public ImmediateChildProcessProjectionResult GetImmediateChildProcesses(ProcessInfo parent, int maxCount = 100)
    {
        ArgumentNullException.ThrowIfNull(parent);
        using var readScope = BeginReadScope();
        if (_sqliteStagingQueryService == null ||
            string.IsNullOrWhiteSpace(parent.GetUniqueKey()) ||
            maxCount <= 0)
        {
            return new([], true, false);
        }

        var scope = new ExplorerScope
        {
            Kind = ExplorerScopeKind.ProcessBranch,
            ProcessKey = parent.GetUniqueKey(),
            CaseId = parent.CaseId,
            EvidenceSessionId = parent.EvidenceSessionId,
            CaptureId = parent.CaptureId,
            SourceIdentityId = parent.SourceIdentityId,
            HostId = parent.HostId,
            ExecutionRootId = parent.ExecutionRootId
        };
        var parentMatches = _sqliteStagingQueryService.GetProcessesByExactScope(new ExplorerScope
        {
            Kind = ExplorerScopeKind.AllProcesses,
            ProcessKey = parent.GetUniqueKey(),
            CaseId = parent.CaseId,
            EvidenceSessionId = parent.EvidenceSessionId,
            CaptureId = parent.CaptureId,
            SourceIdentityId = parent.SourceIdentityId,
            HostId = parent.HostId,
            ExecutionRootId = parent.ExecutionRootId
        }, 2);
        var parentKeyIsUnambiguous = parentMatches.Count == 1 &&
            string.Equals(
                parentMatches[0].ProcessEntityId,
                parent.ProcessEntityId,
                StringComparison.Ordinal);
        var summaries = _sqliteStagingQueryService.GetExplorerProcessChildren(
            scope,
            ChildRelationshipScanLimit);
        if (summaries.Count == 0)
        {
            return new([], true, false);
        }

        // Explorer hierarchy intentionally retains legacy key compatibility.  AI context
        // cannot infer that a key-selected child belongs to this durable parent when the
        // key is reused, so a saturated scan fails closed rather than reporting a partial
        // relationship set as complete.
        if (summaries.Count == ChildRelationshipScanLimit)
        {
            return new([], false, false);
        }

        var children = new List<ProcessInfo>(summaries.Count);
        foreach (var summary in summaries)
        {
            var matches = _sqliteStagingQueryService.GetProcessesByExactScope(new ExplorerScope
            {
                Kind = ExplorerScopeKind.AllProcesses,
                ProcessKey = summary.ProcessKey,
                CaseId = summary.CaseId,
                EvidenceSessionId = summary.EvidenceSessionId,
                CaptureId = summary.CaptureId,
                SourceIdentityId = summary.SourceIdentityId,
                HostId = summary.HostId,
                ExecutionRootId = summary.ExecutionRootId
            }, 2);
            if (matches.Count != 1)
            {
                return new(children, false, matches.Count > 1);
            }

            var child = matches[0].ToProcessInfo();
            if (!string.IsNullOrWhiteSpace(child.ParentProcessEntityId))
            {
                if (string.Equals(
                    child.ParentProcessEntityId,
                    parent.ProcessEntityId,
                    StringComparison.Ordinal))
                {
                    children.Add(child);
                }

                continue;
            }

            if (!parentKeyIsUnambiguous)
            {
                return new(children, false, true);
            }

            if (!string.Equals(child.ParentProcessKey, parent.GetUniqueKey(), StringComparison.Ordinal))
            {
                return new(children, false, false);
            }

            children.Add(child);
        }

        return new(children.Take(Math.Clamp(maxCount, 1, ChildRelationshipScanLimit)).ToArray(), true, false);
    }

    public TelemetryStoreStats GetStats()
    {
        using var readScope = BeginReadScope();
        if (_sqliteStagingQueryService != null)
        {
            var stats = _sqliteStagingQueryService.GetStats();
            stats.StatusMessage = $"{stats.StatusMessage} {_pathDiagnostics.StatusMessage}".Trim();
            return stats;
        }

        return new TelemetryStoreStats { StatusMessage = _pathDiagnostics.StatusMessage };
    }

    public IReadOnlyList<ProcessStatisticsRecord> GetLatestProcessStatistics(int maxCount = 100000) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetLatestProcessStatistics(maxCount) ?? [];
    }

    public IReadOnlyList<ProcessStatisticsRecord> GetProcessStatisticsSamples(
        string processKey,
        int maxCount = 100000,
        string processEntityId = "") {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetProcessStatisticsSamples(processKey, maxCount, processEntityId) ?? [];
    }

    public ProcessArtifactCounts GetArtifactCounts(string processKey, string processEntityId = "") {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetArtifactCounts(processKey, processEntityId) ?? new ProcessArtifactCounts();
    }

    public ProcessSourceEventCounts GetEventCounts(string processKey, string processEntityId = "") {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetEventCounts(processKey, processEntityId) ?? new ProcessSourceEventCounts();
    }

    public IReadOnlyDictionary<string, ProcessSourceEventCounts> GetEventCountsByProcess() {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.CountEventsByProcessAndSource()
        ?? new Dictionary<string, ProcessSourceEventCounts>(StringComparer.Ordinal);
    }

    public IReadOnlyDictionary<string, int> GetModuleCountsByProcess() {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.CountModulesByProcess(includeUnloaded: true)
        ?? new Dictionary<string, int>(StringComparer.Ordinal);
    }

    public IReadOnlyDictionary<string, int> GetHandleCountsByProcess() {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.CountHandlesByProcess(includeClosed: true)
        ?? new Dictionary<string, int>(StringComparer.Ordinal);
    }

    public IReadOnlyList<ProcessEventInfo> GetEventsForProcess(EventProjectionQuery query)
    {
        using var readScope = BeginReadScope();
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

    public IReadOnlyList<SystemActivityRecord> GetSystemActivities(SystemActivityQuery query) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetSystemActivities(query) ?? [];
    }

    public IReadOnlyDictionary<SystemActivityScopeKind, int> GetSystemActivityScopeCounts() {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetSystemActivityScopeCounts()
        ?? new Dictionary<SystemActivityScopeKind, int>();
    }

    public IReadOnlyList<SystemActivityAccountSummary> GetSystemActivityAccounts(
        SystemActivityQuery query,
        int maxCount = 100) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetSystemActivityAccounts(query, maxCount) ?? [];
    }

    public IReadOnlyList<ModuleInfo> GetModulesForProcess(ModuleProjectionQuery query)
    {
        using var readScope = BeginReadScope();
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
        using var readScope = BeginReadScope();
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
        string processEntityId = "") {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetMemoryDumpsForProcess(processKey, maxCount, processEntityId) ?? [];
    }

    public IReadOnlyList<PeAnalysisRecord> GetPeAnalysesForProcess(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "") {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetPeAnalysesForProcess(processKey, maxCount, processEntityId) ?? [];
    }

    public IReadOnlyList<AuthenticodeVerificationRecord> GetAuthenticodeVerificationsForProcess(
        string processKey,
        int maxCount = 100,
        string processEntityId = "") {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetAuthenticodeVerificationsForProcess(processKey, maxCount, processEntityId) ?? [];
    }

    public AuthenticodeVerificationRecord? GetLatestAuthenticodeVerificationForProcess(
        string processKey,
        string processEntityId = "") {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetLatestAuthenticodeVerificationForProcess(processKey, processEntityId);
    }

    public IReadOnlyList<NetworkCaptureRecord> GetNetworkCaptures(int maxCount = 1000) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetNetworkCaptures(maxCount) ?? [];
    }

    public IReadOnlyList<MemoryImageRecord> GetMemoryImages(int maxCount = 1000) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetMemoryImages(maxCount) ?? [];
    }

    public IReadOnlyList<VolatilityPluginRunRecord> GetVolatilityPluginRuns(string imageId = "", int maxCount = 1000) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetVolatilityPluginRuns(imageId, maxCount) ?? [];
    }

    public IReadOnlyList<MemoryProcessRecord> GetMemoryProcesses(string imageId = "", int maxCount = 5000) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetMemoryProcesses(imageId, maxCount) ?? [];
    }

    public IReadOnlyList<ZeekNetworkRecord> GetZeekNetworkArtifacts(int maxCount = 1000) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetZeekNetworkArtifacts(maxCount) ?? [];
    }

    public IReadOnlyList<EvidenceRelation> GetEvidenceRelationsForProcess(string processEntityId, int maxCount = 200) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetEvidenceRelationsForProcess(processEntityId, maxCount) ?? [];
    }

    public IReadOnlyList<EvidenceRelation> GetEvidenceRelationsForArtifact(
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        int maxCount = 200) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetEvidenceRelationsForArtifact(evidenceKind, evidenceId, maxCount) ?? [];
    }

    public IReadOnlyList<FilesystemArtifactRecord> GetFilesystemArtifacts(int maxCount = 1000) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetFilesystemArtifacts(maxCount) ?? [];
    }

    public IReadOnlyList<FilesystemArtifactRecord> GetFilesystemArtifacts(
        ExplorerScope? scope,
        bool includeDescendants,
        int maxCount = 1000) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetFilesystemArtifacts(scope, includeDescendants, maxCount) ?? [];
    }

    public IReadOnlyList<TelemetrySearchResult> Search(TelemetrySearchQuery query) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.Search(query) ?? [];
    }

    public IReadOnlyList<SigmaFinding> RunSigmaRule(SigmaRunQuery query) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?
            .RunSigmaRulesWithDiagnostics([query.Rule], query.MaxFindings)
            .Findings
        ?? [];
    }

    public IReadOnlyList<SigmaFinding> RunSigmaRules(IReadOnlyList<SigmaRule> rules, int maxFindings) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.RunSigmaRulesWithDiagnostics(rules, maxFindings).Findings ?? [];
    }

    public SigmaRunResult RunSigmaRulesWithDiagnostics(IReadOnlyList<SigmaRule> rules, int maxFindings) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.RunSigmaRulesWithDiagnostics(rules, maxFindings) ?? new SigmaRunResult();
    }

    public SigmaEvaluationInput CreateSigmaEvaluationInput() {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.CreateSigmaEvaluationInput() ?? new SigmaEvaluationInput();
    }

    public IReadOnlyList<ProcessObservation> GetProcessObservations(int maxCount = 10000) {
        using var readScope = BeginReadScope();
        return _sqliteStagingQueryService?.GetProcessObservations(maxCount) ?? [];
    }

    public ProcessInfo? GetProcessForSearchResult(TelemetrySearchResult result)
    {
        using var readScope = BeginReadScope();
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

            return null;
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
