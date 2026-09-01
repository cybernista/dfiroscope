using ProcInsider.Models.ApplicationCatalog;

namespace ProcInsider.ViewModels;

public sealed class ApplicationComparisonRowViewModel
{
    private readonly ApplicationComparisonRow _row;

    public ApplicationComparisonRowViewModel(ApplicationComparisonRow row)
    {
        _row = row ?? throw new ArgumentNullException(nameof(row));
    }

    public ApplicationComparisonPropertyKind PropertyKind => _row.PropertyKind;

    public string PropertyDisplay => _row.PropertyKind switch
    {
        ApplicationComparisonPropertyKind.ExecutableFilename => "Executable filename",
        ApplicationComparisonPropertyKind.ProcessPath => "Process path",
        ApplicationComparisonPropertyKind.OriginalFilename => "Original filename",
        ApplicationComparisonPropertyKind.FileDescription => "File description",
        ApplicationComparisonPropertyKind.ParentProcess => "Parent process",
        ApplicationComparisonPropertyKind.SignerPublisher => "Signer / publisher",
        _ => _row.PropertyKind.ToString()
    };

    public string OperatorDisplay => _row.Operator switch
    {
        ApplicationComparisonOperator.NormalizedFilename => "Normalized filename",
        ApplicationComparisonOperator.PathPatternAny => "Any allowed path pattern",
        ApplicationComparisonOperator.ExactValueAny => "Any expected value",
        ApplicationComparisonOperator.AccountContext => "Account context",
        ApplicationComparisonOperator.SessionContext => "Session context",
        ApplicationComparisonOperator.CommandLineMarkers => "Typed command-line markers",
        ApplicationComparisonOperator.EvidenceAvailability => "Evidence availability",
        _ => _row.Operator.ToString()
    };

    public string ResultDisplay => _row.Result switch
    {
        ApplicationComparisonResult.NotApplicable => "Not applicable",
        _ => _row.Result.ToString()
    };

    public string ImportanceDisplay => _row.Importance.ToString();

    public string ExpectedValue => _row.ExpectedValue;

    public string ActualValue => _row.ActualValue;

    public string Rationale => _row.Rationale;

    public string EvidenceSource => _row.EvidenceSource;

    public string SourceAvailability => _row.SourceAvailability;
}
