using System.Globalization;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class MainViewModel
{
    private IReadOnlyDictionary<string, ColumnFilterViewModel>? _headerFilters;
    private int _activeHeaderQueryCount;
    private int _headerQuerySuspensionCount;
    public IReadOnlyDictionary<string, ColumnFilterViewModel> HeaderFilters => _headerFilters ??= CreateHeaderFilters();

    private static ProcessListingSortColumn HeaderColumn(string key) => key switch
    {
        "TotalProcessorTimeTicks" => ProcessListingSortColumn.TotalProcessorTime,
        "MemoryUsageBytes" => ProcessListingSortColumn.MemoryUsage,
        "RiskScore" => ProcessListingSortColumn.ProcessRisk,
        _ => Enum.Parse<ProcessListingSortColumn>(key)
    };

    private IReadOnlyDictionary<string, ColumnFilterViewModel> CreateHeaderFilters()
    {
        var filters = new Dictionary<string, ColumnFilterViewModel>(StringComparer.Ordinal);
        void Add(ColumnFilterKind kind, params string[] keys)
        {
            foreach (var key in keys)
                filters.Add(key, new ColumnFilterViewModel(key, kind, (search, token) => LoadHeaderValuesAsync(key, search, token), ApplyHeaderFilters));
        }
        Add(ColumnFilterKind.Values, "Tree", "ParentProcessName", "UserName", "SessionId", "Architecture", "Status", "CompanyName", "FileDescription");
        Add(ColumnFilterKind.Text, "ProcessId", "ParentProcessId", "ProcessPath", "CommandLine", "Sha256Hash");
        Add(ColumnFilterKind.Timestamp, "StartTime", "EndTime");
        Add(ColumnFilterKind.Duration, "TotalProcessorTimeTicks");
        Add(ColumnFilterKind.Bytes, "MemoryUsageBytes", "ReadBytes", "WrittenBytes");
        Add(ColumnFilterKind.Number, "RiskScore", "ModuleCount", "HandleCount", "RuntimeEventCount", "EtwEventCount", "SecurityEventCount", "PowerShellEventCount", "OtherWindowsEventCount", "SysmonEventCount");
        return filters;
    }

    private async Task<ColumnFilterValuePage> LoadHeaderValuesAsync(string key, string search, CancellationToken token)
    {
        if (Volatile.Read(ref _headerQuerySuspensionCount) > 0)
            throw new OperationCanceledException("Evidence is changing. Reopen this filter after the refresh.", token);
        Interlocked.Increment(ref _activeHeaderQueryCount);
        try
        {
            var queryService = _sqliteStagingQueryService;
            var workspaceGeneration = _captureWorkspaceCoordinator.Generation;
            var queryGeneration = _processListingQueryGeneration;
            if (queryService != null)
            {
                var result = await queryService.ProcessListingQueries.GetColumnValuesAsync(BuildCurrentListingQuery().Filters, HeaderColumn(key), search, 256, token);
                token.ThrowIfCancellationRequested();
                if (!ReferenceEquals(queryService, _sqliteStagingQueryService) || workspaceGeneration != _captureWorkspaceCoordinator.Generation || queryGeneration != _processListingQueryGeneration)
                    throw new OperationCanceledException("The Listing scope changed.", token);
                return result;
            }
            token.ThrowIfCancellationRequested();
            var values = _processViewModels.Values.Where(row => FilterProcess(row, key))
                .Select(row => HeaderValue(row, key).Text).Where(value => ColumnTextFilter.Matches(value, search))
                .Distinct(StringComparer.Ordinal).OrderBy(value => value, StringComparer.Ordinal).Take(257).ToArray();
            return new ColumnFilterValuePage(values.Take(256).ToArray(), values.Length > 256);
        }
        finally { Interlocked.Decrement(ref _activeHeaderQueryCount); }

    }

    private IReadOnlyDictionary<ProcessListingSortColumn, ColumnFilterCriteria> GetAppliedHeaderFilters()
        => _headerFilters?.Where(pair => pair.Value.IsActive).ToDictionary(pair => HeaderColumn(pair.Key), pair => pair.Value.Criteria)
           ?? new Dictionary<ProcessListingSortColumn, ColumnFilterCriteria>();

    // Admission, suspension and popup state changes run on the Viewer dispatcher.
    // Nesting lets a workspace detach overlap a cancelled snapshot refresh safely.
    private void SuspendHeaderQueries()
    {
        Interlocked.Increment(ref _headerQuerySuspensionCount);
        CloseHeaderFilters();
    }

    private void ResumeHeaderQueries() => Interlocked.Decrement(ref _headerQuerySuspensionCount);

    private void CloseHeaderFilters()
    {
        if (_headerFilters != null) foreach (var filter in _headerFilters.Values) filter.Close();
    }

    private void ApplyHeaderFilters()
    {
        ScheduleDbRefresh();
        if (_processListingService == null)
        {
            ProcessesView?.Refresh();
            if (SelectedProcess != null && !FilterProcess(SelectedProcess)) SelectedProcess = null;
        }
    }

    private bool MatchesHeaderFilters(ProcessRowViewModel row, string? excludedKey)
        => _headerFilters == null || _headerFilters.All(pair =>
        {
            if (pair.Key == excludedKey || !pair.Value.IsActive) return true;
            var value = HeaderValue(row, pair.Key);
            return pair.Value.Criteria.Matches(value.Text, value.Number, value.Time);
        });

    private static (string? Text, long? Number, DateTime? Time) HeaderValue(ProcessRowViewModel row, string key)
    {
        object? value = key switch
        {
            "Tree" => row.ProcessName, "ProcessId" => row.ProcessId, "ParentProcessId" => row.ParentProcessId,
            "ParentProcessName" => row.ParentProcessName, "ProcessPath" => row.ProcessPath, "CommandLine" => row.CommandLine,
            "UserName" => row.UserName, "SessionId" => row.SessionId, "Architecture" => row.Architecture,
            "Status" => row.StatusDisplay, "CompanyName" => row.CompanyName, "FileDescription" => row.FileDescription,
            "Sha256Hash" => row.Sha256Hash, "StartTime" => row.StartTime, "EndTime" => row.EndTime,
            "MemoryUsageBytes" => row.MemoryUsageBytes, "TotalProcessorTimeTicks" => row.TotalProcessorTimeTicks,
            "ReadBytes" => row.ReadBytes, "WrittenBytes" => row.WrittenBytes, "RiskScore" => row.RiskScore,
            "ModuleCount" => row.ModuleCount, "HandleCount" => row.HandleCount, "RuntimeEventCount" => row.RuntimeEventCount,
            "EtwEventCount" => row.EtwEventCount, "SecurityEventCount" => row.SecurityEventCount,
            "PowerShellEventCount" => row.PowerShellEventCount, "OtherWindowsEventCount" => row.OtherWindowsEventCount,
            "SysmonEventCount" => row.SysmonEventCount, _ => throw new ArgumentOutOfRangeException(nameof(key))
        };
        return (value == null ? null : Convert.ToString(value, CultureInfo.InvariantCulture), value is int or long ? Convert.ToInt64(value, CultureInfo.InvariantCulture) : null,
            value is DateTime time ? time.ToUniversalTime() : null);
    }
}
