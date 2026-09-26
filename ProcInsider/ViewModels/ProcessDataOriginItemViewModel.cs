namespace ProcInsider.ViewModels;

/// <summary>
/// Formats one process-projection winner for the Properties tab's data-origin section.
/// </summary>
public sealed class ProcessDataOriginItemViewModel
{
    public ProcessDataOriginItemViewModel(
        string fieldName,
        string sourceRunId,
        string observationId,
        string selectionRule)
    {
        FieldName = fieldName;
        SourceRunId = sourceRunId;
        ObservationId = observationId;
        SelectionRule = selectionRule;
    }

    public string FieldName { get; }

    public string SourceRunId { get; }

    public string ObservationId { get; }

    public string SelectionRule { get; }
}
