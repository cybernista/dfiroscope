using ProcInsider.Models;

namespace ProcInsider.Services;

internal sealed record SqliteLegacyBookmarkWrite(
    string BookmarkId,
    string TargetKind,
    string TargetId,
    string ProcessKey,
    int ProcessId,
    string ProcessName,
    string Label,
    string Notes,
    string Tags,
    DateTime CreatedUtc,
    DateTime UpdatedUtc);

internal sealed record CorrelationSearchIndexEntry(
    EvidenceCorrelationInput Input,
    EvidenceRelation Decision);

internal sealed class SearchIndexRow
{
    public string Kind { get; init; } = string.Empty;
    public string RecordKey { get; init; } = string.Empty;
    public string ProcessKey { get; init; } = string.Empty;
    public string ProcessId { get; init; } = string.Empty;
    public string ProcessName { get; init; } = string.Empty;
    public string TimestampUtc { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Subtitle { get; init; } = string.Empty;
    public string StatusText { get; init; } = string.Empty;
    public string SourceText { get; init; } = string.Empty;
    public string ProcessNameText { get; init; } = string.Empty;
    public string PathText { get; init; } = string.Empty;
    public string CommandLineText { get; init; } = string.Empty;
    public string UserText { get; init; } = string.Empty;
    public string CompanyText { get; init; } = string.Empty;
    public string DescriptionText { get; init; } = string.Empty;
    public string Sha256Text { get; init; } = string.Empty;
    public string ParentText { get; init; } = string.Empty;
    public string TargetText { get; init; } = string.Empty;
    public string SummaryText { get; init; } = string.Empty;
    public string DetailsText { get; init; } = string.Empty;
    public string RiskFlagsText { get; init; } = string.Empty;
    public string EventCodeText { get; init; } = string.Empty;
    public string ActionText { get; init; } = string.Empty;
    public string CategoryText { get; init; } = string.Empty;
    public string ProcessGuidText { get; init; } = string.Empty;
    public string ModuleNameText { get; init; } = string.Empty;
    public string FileVersionText { get; init; } = string.Empty;
    public string BaseAddressText { get; init; } = string.Empty;
    public string ObjectTypeText { get; init; } = string.Empty;
    public string ObjectNameText { get; init; } = string.Empty;
    public string GrantedAccessText { get; init; } = string.Empty;
    public string HandleText { get; init; } = string.Empty;
    public string SearchText { get; private init; } = string.Empty;

    public SearchIndexRow WithSearchText()
        => new()
        {
            Kind = Kind,
            RecordKey = RecordKey,
            ProcessKey = ProcessKey,
            ProcessId = ProcessId,
            ProcessName = ProcessName,
            TimestampUtc = TimestampUtc,
            Source = Source,
            Title = Title,
            Subtitle = Subtitle,
            StatusText = StatusText,
            SourceText = SourceText,
            ProcessNameText = ProcessNameText,
            PathText = PathText,
            CommandLineText = CommandLineText,
            UserText = UserText,
            CompanyText = CompanyText,
            DescriptionText = DescriptionText,
            Sha256Text = Sha256Text,
            ParentText = ParentText,
            TargetText = TargetText,
            SummaryText = SummaryText,
            DetailsText = DetailsText,
            RiskFlagsText = RiskFlagsText,
            EventCodeText = EventCodeText,
            ActionText = ActionText,
            CategoryText = CategoryText,
            ProcessGuidText = ProcessGuidText,
            ModuleNameText = ModuleNameText,
            FileVersionText = FileVersionText,
            BaseAddressText = BaseAddressText,
            ObjectTypeText = ObjectTypeText,
            ObjectNameText = ObjectNameText,
            GrantedAccessText = GrantedAccessText,
            HandleText = HandleText,
            SearchText = string.Join(
                ' ',
                new[]
                {
                    Kind, Source, Title, Subtitle, StatusText, SourceText, ProcessNameText, PathText,
                    CommandLineText, UserText, CompanyText, DescriptionText, Sha256Text, ParentText,
                    TargetText, SummaryText, DetailsText, RiskFlagsText, EventCodeText, ActionText,
                    CategoryText, ProcessGuidText, ModuleNameText, FileVersionText, BaseAddressText,
                    ObjectTypeText, ObjectNameText, GrantedAccessText, HandleText
                }.Where(value => !string.IsNullOrWhiteSpace(value)))
        };
}
