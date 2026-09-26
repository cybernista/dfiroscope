namespace ProcInsider.ViewModels;

public sealed class ApplicationInfoDraftDifferenceViewModel
{
    public string FieldName { get; init; } = string.Empty;
    public string ResolvedValue { get; init; } = string.Empty;
    public string DraftValue { get; init; } = string.Empty;
    public bool IsChanged { get; init; }
    public string DifferenceDisplay => IsChanged ? "Changed" : "Unchanged";
}
