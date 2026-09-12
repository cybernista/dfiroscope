using ProcInsider.Models.Agent;

namespace ProcInsider.ViewModels;

public sealed record AgentMonitoringSectionViewModel(string Heading, string Body)
{
    public AgentMonitoringFindingViewModel[] Findings { get; init; } = [];
}

public sealed record AgentMonitoringComparisonRow(string Setting, string Expected, string Current);

public sealed record AgentMonitoringPolicyRow(string PolicyName, string Success, string Failure);

public sealed record AgentMonitoringFindingViewModel(string Summary, string Detail, string Remediation,
    AgentMonitoringComparisonRow[] Comparisons, AgentMonitoringPolicyRow[] PolicyStates)
{
    public bool HasComparisons => Comparisons.Length > 0;
    public bool HasPolicyStates => PolicyStates.Length > 0;
    public static AgentMonitoringFindingViewModel Create(AgentConfigurationFinding finding) => new(
        finding.Severity == AgentConfigurationFindingSeverity.Info ? finding.Message : $"[{finding.Severity}] {finding.Message}",
        finding.TechnicalDetail ?? string.Empty,
        string.IsNullOrWhiteSpace(finding.SuggestedRemediation) ? string.Empty : "Suggested action: " + finding.SuggestedRemediation,
        ParseComparisons(finding),
        (finding.AuditPolicyStates ?? []).Select(state => new AgentMonitoringPolicyRow(
            state.PolicyName,
            FormatBoolean(state.Success),
            FormatBoolean(state.Failure))).ToArray());

    private static string FormatBoolean(bool? value) => value.HasValue ? value.Value.ToString() : "Unavailable";

    // Presentation of the existing exact Agent audit-drift grammar only. Any unknown
    // text stays verbatim; this projection never supplies policy or restore authority.
    private static AgentMonitoringComparisonRow[] ParseComparisons(AgentConfigurationFinding finding)
    {
        if (finding.Area != AgentConfigurationAreaKind.WindowsSecurityAuditPolicy || string.IsNullOrEmpty(finding.TechnicalDetail)) return [];
        var parts = finding.TechnicalDetail.Split("; ", StringSplitOptions.None);
        if (parts.Length > 256) return [];
        string[] states = ["No Auditing", "Success", "Failure", "Success and Failure"];
        var rows = new List<AgentMonitoringComparisonRow>();
        foreach (var part in parts)
        {
            var expected = part.IndexOf(": expected ", StringComparison.Ordinal);
            var current = part.IndexOf(", effective ", StringComparison.Ordinal);
            if (expected <= 0 || current <= expected + 11) return [];
            var expectedValue = part[(expected + 11)..current];
            var currentValue = part[(current + 12)..];
            if (!states.Contains(expectedValue) || !states.Contains(currentValue) || part[..expected].Contains('\n')) return [];
            rows.Add(new(part[..expected], expectedValue, currentValue));
        }
        return rows.ToArray();
    }
}
