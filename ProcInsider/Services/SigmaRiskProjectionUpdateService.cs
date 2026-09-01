using System.IO;
using ProcInsider.Models;

namespace ProcInsider.Services;

public enum SigmaRiskProjectionUpdateState
{
    Completed = 0,
    Unavailable = 1,
    Rejected = 2,
    Superseded = 3,
    Failed = 4
}

public sealed record SigmaRiskProjectionUpdateResult(
    SigmaRiskProjectionUpdateState State,
    string DatabasePath,
    int AcceptedFindingCount,
    int RejectedFindingCount,
    ProcessRiskProjectionRebuildResult? Rebuild,
    IReadOnlyList<SigmaRiskEvidenceMaterializationDiagnostic> Diagnostics,
    string Diagnostic)
{
    public bool Completed => State == SigmaRiskProjectionUpdateState.Completed;
}

/// <summary>
/// Binds one completed analyst-triggered Sigma run to the still-current live
/// viewer snapshot. Exact normalized rows and the Process Risk generation are
/// replaced through the existing viewer-owned analysis-maintenance transaction.
/// </summary>
public sealed class SigmaRiskProjectionUpdateService
{
    private readonly TelemetryProjectionService _projectionService;
    private readonly Func<string> _evidenceSessionIdProvider;
    private readonly Func<long> _workspaceGenerationProvider;

    public SigmaRiskProjectionUpdateService(
        TelemetryProjectionService projectionService,
        Func<string> evidenceSessionIdProvider,
        Func<long> workspaceGenerationProvider)
    {
        _projectionService = projectionService ??
                             throw new ArgumentNullException(nameof(projectionService));
        _evidenceSessionIdProvider = evidenceSessionIdProvider ??
                                     throw new ArgumentNullException(nameof(evidenceSessionIdProvider));
        _workspaceGenerationProvider = workspaceGenerationProvider ??
                                       throw new ArgumentNullException(nameof(workspaceGenerationProvider));
    }

    public SigmaRiskProjectionUpdateResult Update(
        IReadOnlyList<SigmaRule> rules,
        SigmaRunResult run,
        DateTime evaluatedUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(run);
        cancellationToken.ThrowIfCancellationRequested();
        if (evaluatedUtc.Kind != DateTimeKind.Utc)
        {
            return Rejected("A UTC Sigma evaluation boundary is required.");
        }

        var initialPath = _projectionService.PathDiagnostics;
        var initialGeneration = _workspaceGenerationProvider();
        if (initialPath.ReadPath != EvidenceReadPath.ViewerSnapshotSqlite ||
            string.IsNullOrWhiteSpace(initialPath.DatabasePath))
        {
            return new SigmaRiskProjectionUpdateResult(
                SigmaRiskProjectionUpdateState.Unavailable,
                initialPath.DatabasePath,
                0,
                run.Findings.Count,
                null,
                [],
                "Sigma Process Risk integration is available only for the active live viewer snapshot.");
        }

        try
        {
            var input = _projectionService.CreateSigmaEvaluationInput();
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsCurrent(initialPath.DatabasePath, initialGeneration))
            {
                return Superseded(initialPath.DatabasePath);
            }

            var materialized = SigmaRiskEvidenceMaterializer.Materialize(
                new SigmaRiskEvidenceMaterializationRequest
                {
                    EvaluatedUtc = evaluatedUtc,
                    RuleIdentities = rules.Select(rule => new SigmaRiskRuleIdentity
                    {
                        RuleId = rule.Id,
                        RuleVersion = rule.RuleVersion,
                        RuleContentHashSha256 = rule.RuleContentHashSha256
                    }).ToArray(),
                    Findings = run.Findings.ToArray(),
                    Events = input.Events.ToArray(),
                    ProcessObservations = input.ProcessObservations.ToArray(),
                    ModuleObservations = input.Modules.ToArray(),
                    HandleObservations = input.Handles.ToArray()
                });
            if (run.Findings.Count > 0 && materialized.AcceptedFindingCount == 0)
            {
                return new SigmaRiskProjectionUpdateResult(
                    SigmaRiskProjectionUpdateState.Rejected,
                    initialPath.DatabasePath,
                    0,
                    materialized.RejectedFindingCount,
                    null,
                    materialized.Diagnostics,
                    "No Sigma finding passed exact normalized source resolution; the prior Process Risk generation was preserved.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (!IsCurrent(initialPath.DatabasePath, initialGeneration))
            {
                return Superseded(initialPath.DatabasePath);
            }

            var evidenceSessionId = _evidenceSessionIdProvider()?.Trim() ?? string.Empty;
            using var store = SqliteAnalysisIndexMaintenanceStoreFactory.Create(
                initialPath.DatabasePath,
                evidenceSessionId);
            store.OpenExistingForViewerSnapshot();
            if (!IsCurrent(initialPath.DatabasePath, initialGeneration))
            {
                return Superseded(initialPath.DatabasePath);
            }

            var rebuild = store.ReplaceSigmaRiskEvidenceAndRebuild(
                materialized.Evidence,
                progress: null,
                cancellationToken);
            if (rebuild.State != ProcessRiskProjectionRebuildState.Completed)
            {
                return new SigmaRiskProjectionUpdateResult(
                    SigmaRiskProjectionUpdateState.Unavailable,
                    initialPath.DatabasePath,
                    materialized.AcceptedFindingCount,
                    materialized.RejectedFindingCount,
                    rebuild,
                    materialized.Diagnostics,
                    rebuild.Diagnostic);
            }

            if (!IsCurrent(initialPath.DatabasePath, initialGeneration))
            {
                return Superseded(initialPath.DatabasePath);
            }

            return new SigmaRiskProjectionUpdateResult(
                SigmaRiskProjectionUpdateState.Completed,
                initialPath.DatabasePath,
                materialized.AcceptedFindingCount,
                materialized.RejectedFindingCount,
                rebuild,
                materialized.Diagnostics,
                $"Persisted {materialized.AcceptedFindingCount} exact normalized Sigma input(s) and rebuilt {rebuild.ReadyProjections} Process Risk projection(s).");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new SigmaRiskProjectionUpdateResult(
                SigmaRiskProjectionUpdateState.Failed,
                initialPath.DatabasePath,
                0,
                run.Findings.Count,
                null,
                [],
                $"Sigma Process Risk update failed; the prior complete generation was preserved: {ex.Message}");
        }
    }

    private bool IsCurrent(string databasePath, long generation)
    {
        var current = _projectionService.PathDiagnostics;
        return current.ReadPath == EvidenceReadPath.ViewerSnapshotSqlite &&
               _workspaceGenerationProvider() == generation &&
               !string.IsNullOrWhiteSpace(current.DatabasePath) &&
               string.Equals(
                   Path.GetFullPath(current.DatabasePath),
                   Path.GetFullPath(databasePath),
                   StringComparison.OrdinalIgnoreCase);
    }

    private static SigmaRiskProjectionUpdateResult Rejected(string diagnostic) =>
        new(
            SigmaRiskProjectionUpdateState.Rejected,
            string.Empty,
            0,
            0,
            null,
            [],
            diagnostic);

    private static SigmaRiskProjectionUpdateResult Superseded(string databasePath) =>
        new(
            SigmaRiskProjectionUpdateState.Superseded,
            databasePath,
            0,
            0,
            null,
            [],
            "The active workspace changed before the Sigma Process Risk generation could publish.");
}
