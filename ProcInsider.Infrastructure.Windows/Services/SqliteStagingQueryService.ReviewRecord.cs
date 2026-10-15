using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed partial class SqliteStagingQueryService
{
    /// <summary>Complete stored fields of an already resolved process original; never a PID lookup.</summary>
    public IReadOnlyDictionary<string, object?>? GetProcessRecordFields(ProcessRecord resolved,
        CancellationToken cancellationToken = default) =>
        _processListingQueries.GetProcessRecordFields(resolved, cancellationToken);
}
