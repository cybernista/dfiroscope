namespace ProcInsider.Services;

public static class SqliteAnalysisIndexMaintenanceStoreFactory
{
    public static SqliteStagingStore Create(
        string databasePath,
        string expectedEvidenceSessionId = "")
    {
        var store = new SqliteStagingStore(databasePath, expectedEvidenceSessionId);
        Attach(store);
        return store;
    }

    public static void Attach(SqliteStagingStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        var processRiskMaintenance = new SqliteProcessRiskProjectionMaintenanceService(
            new SqliteProcessRiskProjectionMaintenanceContext(store));
        store.AttachProcessRiskProjectionMaintenance(processRiskMaintenance);
        store.AttachAnalysisIndexMaintenance(
            new SqliteAnalysisIndexMaintenanceService(
                new SqliteAnalysisIndexMaintenanceContext(store),
                processRiskMaintenance));
    }
}
