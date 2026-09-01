using CommunityToolkit.Mvvm.ComponentModel;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public partial class SnapshotComparisonFindingRowViewModel : ViewModelBase
{
    public SnapshotComparisonFindingRowViewModel(SnapshotComparisonFinding finding)
    {
        Finding = finding;
        verdict = finding.Verdict;
        policyRuleId = finding.PolicyRuleId;
    }

    public SnapshotComparisonFinding Finding { get; }

    public SnapshotComparisonArtifactKind ArtifactKind => Finding.ArtifactKind;
    public string StableKey => Finding.StableKey;
    public string Title => Finding.Title;
    public string BaselineSummary => Finding.BaselineSummary;
    public string CurrentSummary => Finding.CurrentSummary;
    public string Explanation => Finding.Explanation;
    public string ChangedFields => Finding.ChangedFields;

    [ObservableProperty]
    private SnapshotComparisonVerdict verdict;

    [ObservableProperty]
    private string policyRuleId;

    public void MarkAccepted(string ruleId)
    {
        Finding.Verdict = SnapshotComparisonVerdict.Accepted;
        Finding.PolicyRuleId = ruleId;
        Verdict = SnapshotComparisonVerdict.Accepted;
        PolicyRuleId = ruleId;
    }
}
