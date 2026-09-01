using ProcInsider.Models;

namespace ProcInsider.Services;

internal interface ISqliteAnalysisIndexMaintenanceService
{
    void Disable();

    void Enable(string databaseRole, string maintenanceMode);

    void EnsureAnalysisIndexes(
        IProgress<SqliteAnalysisIndexBuildProgress>? progress,
        CancellationToken cancellationToken);

    void Upsert(SearchIndexRow row);

    void UpsertProcess(ProcessRecord process);

    void UpsertCorrelation(EvidenceCorrelationInput input, EvidenceRelation decision);
}

internal sealed class UnavailableSqliteAnalysisIndexMaintenanceService : ISqliteAnalysisIndexMaintenanceService
{
    private const string MissingOwnerMessage =
        "Analysis-index maintenance requires the viewer-owned SqliteAnalysisIndexMaintenanceStoreFactory.";

    public void Disable()
    {
    }

    public void Enable(string databaseRole, string maintenanceMode)
    {
    }

    public void EnsureAnalysisIndexes(
        IProgress<SqliteAnalysisIndexBuildProgress>? progress,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException(MissingOwnerMessage);

    public void Upsert(SearchIndexRow row)
    {
    }

    public void UpsertProcess(ProcessRecord process)
    {
    }

    public void UpsertCorrelation(EvidenceCorrelationInput input, EvidenceRelation decision)
    {
    }
}
