using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class MainViewModel
{
    public IReadOnlyDictionary<string, ColumnFilterViewModel> HeaderFilters => _activeProcessPresentation?.HeaderFilters ?? new Dictionary<string, ColumnFilterViewModel>();
    private int _emptyHeaderQueryCount;
    private ref int _activeHeaderQueryCount => ref (_activeProcessPresentation is { } p ? ref p._activeHeaderQueryCount : ref _emptyHeaderQueryCount);
    private void SuspendHeaderQueries() => _activeProcessPresentation?.SuspendHeaderQueries();
    private void ResumeHeaderQueries() => _activeProcessPresentation?.ResumeHeaderQueries();
    private void CloseHeaderFilters() => _activeProcessPresentation?.CloseHeaderFilters();
}
