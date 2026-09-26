using System.IO;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.Features.BaselineComparison;

public enum BaselineRiskProjectionUpdateState
{
    Completed = 0,
    Unavailable = 1,
    Rejected = 2,
    Superseded = 3,
    Failed = 4
}

public sealed record BaselineRiskProjectionUpdateResult(
    BaselineRiskProjectionUpdateState State,
    string DatabasePath,
    int SupportedCurrentProcessFindingCount,
    int AcceptedFindingCount,
    int RejectedFindingCount,
    ProcessRiskProjectionRebuildResult? Rebuild,
    IReadOnlyList<BaselineRiskEvidenceMaterializationDiagnostic> Diagnostics,
    string Diagnostic)
{
    public bool Completed => State == BaselineRiskProjectionUpdateState.Completed;
}

public sealed record BaselineRiskProjectionWorkspaceContext(
    EvidencePathDiagnostics Path,
    string EvidenceSessionId,
    long WorkspaceGeneration,
    long SnapshotGeneration);

public interface IBaselineRiskProjectionMaintenance : IDisposable
{
    ProcessRiskProjectionRebuildResult ReplaceBaselineRiskEvidenceAndRebuild(
        IReadOnlyList<ProcInsider.Models.Analysis.LocalProcessBaselineComparisonEvidence> evidence,
        CancellationToken cancellationToken);
}

public interface IBaselineRiskProjectionUpdateRuntime
{
    BaselineRiskProjectionWorkspaceContext CaptureContext();

    IReadOnlyList<ProcessObservation> ReadCurrentProcessObservations(
        int maximumCount,
        CancellationToken cancellationToken);

    IBaselineRiskProjectionMaintenance OpenMaintenance(
        string databasePath,
        string evidenceSessionId);
}

public sealed class BaselineRiskProjectionUpdateRuntime : IBaselineRiskProjectionUpdateRuntime
{
    private readonly TelemetryProjectionService _projectionService;
    private readonly Func<string> _evidenceSessionIdProvider;
    private readonly Func<long> _workspaceGenerationProvider;
    private readonly Func<long> _snapshotGenerationProvider;

    public BaselineRiskProjectionUpdateRuntime(
        TelemetryProjectionService projectionService,
        Func<string> evidenceSessionIdProvider,
        Func<long> workspaceGenerationProvider,
        Func<long> snapshotGenerationProvider)
    {
        _projectionService = projectionService ?? throw new ArgumentNullException(nameof(projectionService));
        _evidenceSessionIdProvider = evidenceSessionIdProvider ??
                                     throw new ArgumentNullException(nameof(evidenceSessionIdProvider));
        _workspaceGenerationProvider = workspaceGenerationProvider ??
                                       throw new ArgumentNullException(nameof(workspaceGenerationProvider));
        _snapshotGenerationProvider = snapshotGenerationProvider ??
                                      throw new ArgumentNullException(nameof(snapshotGenerationProvider));
    }

    public BaselineRiskProjectionWorkspaceContext CaptureContext() => new(
        _projectionService.PathDiagnostics,
        _evidenceSessionIdProvider()?.Trim() ?? string.Empty,
        _workspaceGenerationProvider(),
        _snapshotGenerationProvider());

    public IReadOnlyList<ProcessObservation> ReadCurrentProcessObservations(
        int maximumCount,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var observations = _projectionService.GetProcessObservations(maximumCount);
        cancellationToken.ThrowIfCancellationRequested();
        return observations;
    }

    public IBaselineRiskProjectionMaintenance OpenMaintenance(
        string databasePath,
        string evidenceSessionId)
    {
        var store = SqliteAnalysisIndexMaintenanceStoreFactory.Create(databasePath, evidenceSessionId);
        try
        {
            store.OpenExistingForViewerSnapshot();
            return new BaselineRiskProjectionMaintenance(store);
        }
        catch
        {
            store.Dispose();
            throw;
        }
    }

    private sealed class BaselineRiskProjectionMaintenance(
        SqliteStagingStore store) : IBaselineRiskProjectionMaintenance
    {
        public ProcessRiskProjectionRebuildResult ReplaceBaselineRiskEvidenceAndRebuild(
            IReadOnlyList<ProcInsider.Models.Analysis.LocalProcessBaselineComparisonEvidence> evidence,
            CancellationToken cancellationToken) =>
            store.ReplaceBaselineRiskEvidenceAndRebuild(evidence, progress: null, cancellationToken);

        public void Dispose() => store.Dispose();
    }
}

/// <summary>
/// Binds one hash-stable Baseline completion to the exact active live viewer
/// snapshot, materializes #373 inputs, and delegates the only write to #374's
/// atomic maintenance transaction.
/// </summary>
public sealed class BaselineRiskProjectionUpdateService
{
    private readonly IBaselineRiskProjectionUpdateRuntime _runtime;

    public BaselineRiskProjectionUpdateService(IBaselineRiskProjectionUpdateRuntime runtime)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
    }

    public BaselineRiskProjectionUpdateService(
        TelemetryProjectionService projectionService,
        Func<string> evidenceSessionIdProvider,
        Func<long> workspaceGenerationProvider,
        Func<long> snapshotGenerationProvider)
        : this(new BaselineRiskProjectionUpdateRuntime(
            projectionService,
            evidenceSessionIdProvider,
            workspaceGenerationProvider,
            snapshotGenerationProvider))
    {
    }

    public BaselineRiskProjectionUpdateResult Update(
        BaselineComparisonCompletion completion,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(completion);
        cancellationToken.ThrowIfCancellationRequested();
        var comparison = completion.CreateComparisonResult();
        var supportedCurrentProcessFindings = comparison.Findings.Count(finding =>
            finding.ArtifactKind == SnapshotComparisonArtifactKind.Process &&
            finding.Verdict != SnapshotComparisonVerdict.Missing &&
            !string.IsNullOrWhiteSpace(finding.CurrentFingerprint));
        var initial = _runtime.CaptureContext();
        if (initial.Path.ReadPath != EvidenceReadPath.ViewerSnapshotSqlite ||
            string.IsNullOrWhiteSpace(initial.Path.DatabasePath))
        {
            return Result(
                BaselineRiskProjectionUpdateState.Unavailable,
                initial.Path.DatabasePath,
                supportedCurrentProcessFindings,
                "Baseline Process Risk publication is available only for the active compatible live viewer snapshot.");
        }

        if (!SamePath(initial.Path.DatabasePath, completion.CurrentSnapshotPath))
        {
            return Result(
                BaselineRiskProjectionUpdateState.Rejected,
                initial.Path.DatabasePath,
                supportedCurrentProcessFindings,
                "The completed comparison current file is not the exact active live viewer snapshot; the prior generation was preserved.");
        }

        try
        {
            var observations = _runtime.ReadCurrentProcessObservations(
                BaselineRiskEvidenceMaterializer.MaximumCurrentProcessObservations,
                cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsCurrent(initial))
            {
                return Superseded(initial.Path.DatabasePath, supportedCurrentProcessFindings);
            }

            var materialized = BaselineRiskEvidenceMaterializer.Materialize(
                new BaselineRiskEvidenceMaterializationRequest
                {
                    ComparisonResult = comparison,
                    ComparisonId = completion.ComparisonId,
                    ComparisonVersion = completion.ComparisonVersion,
                    BaselineId = completion.BaselineId,
                    BaselineSnapshotHashSha256 = completion.BaselineSnapshotHashSha256,
                    CurrentSnapshotHashSha256 = completion.CurrentSnapshotHashSha256,
                    EvaluatedUtc = completion.EvaluatedUtc,
                    CurrentProcessObservations = observations.ToArray()
                });
            if (supportedCurrentProcessFindings > 0 && materialized.AcceptedFindingCount == 0)
            {
                return new BaselineRiskProjectionUpdateResult(
                    BaselineRiskProjectionUpdateState.Rejected,
                    initial.Path.DatabasePath,
                    supportedCurrentProcessFindings,
                    0,
                    materialized.RejectedFindingCount,
                    null,
                    materialized.Diagnostics,
                    "No supported current-side Process finding resolved to one exact persisted observation; the prior Baseline and Process Risk generations were preserved.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (!IsCurrent(initial))
            {
                return Superseded(initial.Path.DatabasePath, supportedCurrentProcessFindings);
            }

            using var maintenance = _runtime.OpenMaintenance(
                initial.Path.DatabasePath,
                initial.EvidenceSessionId);
            if (!IsCurrent(initial))
            {
                return Superseded(initial.Path.DatabasePath, supportedCurrentProcessFindings);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var rebuild = maintenance.ReplaceBaselineRiskEvidenceAndRebuild(
                materialized.Evidence,
                cancellationToken);
            if (rebuild.State != ProcessRiskProjectionRebuildState.Completed)
            {
                return new BaselineRiskProjectionUpdateResult(
                    BaselineRiskProjectionUpdateState.Unavailable,
                    initial.Path.DatabasePath,
                    supportedCurrentProcessFindings,
                    materialized.AcceptedFindingCount,
                    materialized.RejectedFindingCount,
                    rebuild,
                    materialized.Diagnostics,
                    rebuild.Diagnostic);
            }

            if (!IsCurrent(initial))
            {
                return Superseded(initial.Path.DatabasePath, supportedCurrentProcessFindings);
            }

            return new BaselineRiskProjectionUpdateResult(
                BaselineRiskProjectionUpdateState.Completed,
                initial.Path.DatabasePath,
                supportedCurrentProcessFindings,
                materialized.AcceptedFindingCount,
                materialized.RejectedFindingCount,
                rebuild,
                materialized.Diagnostics,
                $"Persisted {materialized.AcceptedFindingCount} exact Baseline input(s) and rebuilt {rebuild.ReadyProjections} Process Risk projection(s).");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Result(
                BaselineRiskProjectionUpdateState.Failed,
                initial.Path.DatabasePath,
                supportedCurrentProcessFindings,
                $"Baseline Process Risk publication failed; the prior complete generation was preserved: {ex.Message}");
        }
    }

    private bool IsCurrent(BaselineRiskProjectionWorkspaceContext expected)
    {
        var current = _runtime.CaptureContext();
        return current.Path.ReadPath == EvidenceReadPath.ViewerSnapshotSqlite &&
               current.WorkspaceGeneration == expected.WorkspaceGeneration &&
               current.SnapshotGeneration == expected.SnapshotGeneration &&
               string.Equals(current.EvidenceSessionId, expected.EvidenceSessionId, StringComparison.Ordinal) &&
               SamePath(current.Path.DatabasePath, expected.Path.DatabasePath);
    }

    private static bool SamePath(string left, string right)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(left) &&
                   !string.IsNullOrWhiteSpace(right) &&
                   string.Equals(
                       Path.GetFullPath(left),
                       Path.GetFullPath(right),
                       StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static BaselineRiskProjectionUpdateResult Result(
        BaselineRiskProjectionUpdateState state,
        string databasePath,
        int supportedCurrentProcessFindings,
        string diagnostic) =>
        new(state, databasePath, supportedCurrentProcessFindings, 0, 0, null, [], diagnostic);

    private static BaselineRiskProjectionUpdateResult Superseded(
        string databasePath,
        int supportedCurrentProcessFindings) =>
        Result(
            BaselineRiskProjectionUpdateState.Superseded,
            databasePath,
            supportedCurrentProcessFindings,
            "The active workspace or viewer snapshot changed before Baseline Process Risk publication completed.");
}
