using ProcInsider.Features.WindowsSecurityDetails;
using System.Threading;
using System.Windows.Threading;

namespace ProcInsider.ViewModels;

public partial class EventsViewModel
{
    private SecurityDetailsStore? _detailsStore;
    private CancellationTokenSource? _detailsCancellation;
    private readonly Dispatcher _detailsDispatcher = Dispatcher.CurrentDispatcher;
    public Task DetailsFormattingTask { get; private set; } = Task.CompletedTask;

    public void ConfigureSecurityDetails(SecurityDetailsStore store)
    {
        if (_eventSource != "Security") throw new InvalidOperationException("Security definitions require the Security projection.");
        _detailsStore = store;
        BeginDetailsFormatting();
    }

    public void RefreshSecurityDetails()
    {
        if (!_detailsDispatcher.CheckAccess()) { _detailsDispatcher.BeginInvoke(RefreshSecurityDetails); return; }
        BeginDetailsFormatting();
    }

    private void CancelDetailsFormatting()
    {
        _detailsCancellation?.Cancel();
        _detailsCancellation?.Dispose();
        _detailsCancellation = null;
    }

    private void BeginDetailsFormatting()
    {
        CancelDetailsFormatting();
        if (_detailsStore is null || Events.Count == 0) return;
        var cancellation = _detailsCancellation = new CancellationTokenSource();
        var rows = Events.ToArray();
        var definitions = _detailsStore.Snapshot();
        DetailsFormattingTask = FormatDetailsAsync(rows, definitions, cancellation.Token);
    }

    private async Task FormatDetailsAsync(EventRowViewModel[] rows, SecurityDetailsDefinition[] definitions, CancellationToken token)
    {
        try
        {
            // One bounded parse per immutable loaded row/revision; repaint and filter/sort only read strings.
            var summaries = await Task.Run(() =>
            {
                var compiled = definitions.ToDictionary(d => d.EventId, d => (Definition: d, Formatter: SecurityDetailsTemplate.Compile(d.Template)));
                var values = new string[rows.Length];
                for (var i = 0; i < rows.Length; i++)
                {
                    token.ThrowIfCancellationRequested();
                    var row = rows[i];
                    values[i] = row.EventCode.HasValue && compiled.TryGetValue(row.EventCode.Value, out var definition)
                        ? definition.Formatter.Format(SecurityDetailsTemplate.Parse(row.Details, row.EventCode), definition.Definition.Layouts)
                        : "No details definition";
                }
                return values;
            }, token);
            token.ThrowIfCancellationRequested();
            await _detailsDispatcher.InvokeAsync(() =>
            {
                if (token.IsCancellationRequested) return;
                using (EventsView?.DeferRefresh())
                    for (var i = 0; i < rows.Length; i++) rows[i].DetailsSummary = summaries[i];
                ApplyFilters();
            });
        }
        catch (OperationCanceledException) { }
    }
}
