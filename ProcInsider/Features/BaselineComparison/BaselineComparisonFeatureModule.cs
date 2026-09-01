using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.BaselineComparison;

/// <summary>
/// Slice-owned activation, presentation, and workspace-lifecycle adapter for Baseline Comparison.
/// Shared session, feature-catalog, and SQLite services stay outside the slice.
/// </summary>
public sealed class BaselineComparisonFeatureModule : IDisposable
{
    private readonly EventHandler<BaselineRiskProjectionUpdateResult>? _riskProjectionUpdatedHandler;
    private bool _disposed;

    public BaselineComparisonFeatureModule(
        InvestigationSessionPaths sessionPaths,
        BaselineRiskProjectionUpdateService? riskProjectionUpdateService = null,
        Action<BaselineRiskProjectionUpdateResult>? riskProjectionUpdated = null)
    {
        ArgumentNullException.ThrowIfNull(sessionPaths);
        var comparisonService = new SnapshotComparisonService(new SnapshotComparisonQueryService());
        ViewModel = new SnapshotComparisonViewModel(
            new SnapshotComparisonCompletionService(
                new SnapshotComparisonCompletionRuntime(comparisonService)),
            new BaselinePolicyService(sessionPaths.BaselinePolicyPath),
            sessionPaths,
            riskProjectionUpdateService);
        if (riskProjectionUpdated != null)
        {
            _riskProjectionUpdatedHandler = (_, result) => riskProjectionUpdated(result);
            ViewModel.RiskProjectionUpdated += _riskProjectionUpdatedHandler;
        }
    }

    public SnapshotComparisonViewModel ViewModel { get; }

    public static ViewerFeatureDefinition<BaselineComparisonFeatureModule> CreateDefinition(
        Func<InvestigationSessionPaths> sessionPathsAccessor,
        Func<BaselineRiskProjectionUpdateService>? riskProjectionUpdateServiceFactory = null,
        Action<BaselineRiskProjectionUpdateResult>? riskProjectionUpdated = null)
    {
        ArgumentNullException.ThrowIfNull(sessionPathsAccessor);
        return new ViewerFeatureDefinition<BaselineComparisonFeatureModule>(
            FeatureIds.BaselineComparison,
            [FeatureIds.ProcessListing],
            () => new BaselineComparisonFeatureModule(
                sessionPathsAccessor(),
                riskProjectionUpdateServiceFactory?.Invoke(),
                riskProjectionUpdated),
            [
                new ViewerFeatureTabDefinition<BaselineComparisonFeatureModule>(
                    DataTabKeys.Baseline,
                    "Baseline",
                    1900,
                    module => module.CreateView())
            ],
            module => module.Dispose());
    }

    public DataBaselineComparisonView CreateView()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new DataBaselineComparisonView { DataContext = ViewModel };
    }

    public void SetWorkspace(InvestigationSessionPaths sessionPaths, string? activeSnapshotPath = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(sessionPaths);
        ViewModel.SetSessionPaths(sessionPaths);
        if (!string.IsNullOrWhiteSpace(activeSnapshotPath))
        {
            ViewModel.SetActiveSnapshotPath(activeSnapshotPath);
        }
    }

    public void SetActiveSnapshotPath(string snapshotPath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ViewModel.SetActiveSnapshotPath(snapshotPath);
    }

    public void DetachWorkspace()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ViewModel.ClearSessionState();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_riskProjectionUpdatedHandler != null)
        {
            ViewModel.RiskProjectionUpdated -= _riskProjectionUpdatedHandler;
        }

        ViewModel.Dispose();
    }
}
