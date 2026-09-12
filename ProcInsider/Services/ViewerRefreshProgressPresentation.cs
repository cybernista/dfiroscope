using System.Globalization;

namespace ProcInsider.Services;

public sealed record ViewerRefreshProgressPresentation(string Title, string Detail,
    double Completed, double Maximum, bool IsIndeterminate)
{
    public static ViewerRefreshProgressPresentation Create(SqliteWorkProgress progress, int stageNumber)
    {
        var known = progress.Total.HasValue;
        var count = known
            ? $"{progress.Completed:N0} / {progress.Total:N0} {progress.Unit}"
            : progress.Completed > 0
                ? $"{progress.Completed:N0} {progress.Unit}; total unknown"
                : "Total unknown";
        var operations = progress.DatabaseOperations > 0
            ? $" · {progress.DatabaseOperations:N0} SQLite instructions executed"
            : string.Empty;
        var elapsed = progress.Elapsed.TotalSeconds.ToString("N1", CultureInfo.CurrentCulture);
        return new($"Stage {stageNumber}: {FriendlyStage(progress.Stage)}",
            $"{count}{operations} · {elapsed} s",
            progress.Completed, Math.Max(1, progress.Total ?? 1), !known);
    }

    private static string FriendlyStage(string name) => name switch
    {
        "CountProcesses" => "Counting matching processes",
        "GetProcessPage" => "Querying and sorting process page",
        "GetProcessRowIndex" => "Restoring selected process / scroll position",
        "CountEventsForProcesses" => "Counting events for this process page",
        "GetExplorerScopeCounts" => "Counting Explorer scopes",
        "GetStats" => "Counting evidence tables",
        "GetEvidenceRoots" => "Loading evidence roots",
        "GetLatestProcessStatistics" => "Loading process statistics",
        _ => name
    };
}
