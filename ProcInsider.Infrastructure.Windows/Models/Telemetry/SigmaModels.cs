using System;

namespace ProcInsider.Models;

public sealed class SigmaRule
{
    public string SourcePath { get; set; } = string.Empty;
    public string Id { get; set; } = string.Empty;
    public string RuleVersion { get; set; } = string.Empty;
    public string RuleContentHashSha256 { get; set; } = string.Empty;
    public string Title { get; set; } = "Untitled Sigma rule";
    public string Description { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public string Level { get; set; } = string.Empty;
    public string Condition { get; set; } = string.Empty;
    public SigmaLogSource LogSource { get; set; } = new();
    public IReadOnlyList<string> Tags { get; set; } = Array.Empty<string>();
    public IReadOnlyList<SigmaRuleSelection> Selections { get; set; } = Array.Empty<SigmaRuleSelection>();
    public IReadOnlyList<string> ParseWarnings { get; set; } = Array.Empty<string>();
}

public sealed class SigmaLogSource
{
    public string Product { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Service { get; set; } = string.Empty;
}

public sealed class SigmaRuleSelection
{
    public string Name { get; set; } = string.Empty;
    public IReadOnlyList<SigmaConditionGroup> Groups { get; set; } = Array.Empty<SigmaConditionGroup>();
}

public sealed class SigmaConditionGroup
{
    public IReadOnlyList<SigmaFieldCondition> Conditions { get; set; } = Array.Empty<SigmaFieldCondition>();
}

public sealed class SigmaFieldCondition
{
    public string Field { get; set; } = string.Empty;
    public IReadOnlyList<string> Modifiers { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> Values { get; set; } = Array.Empty<string>();
}

public enum SigmaCompatibilityStatus
{
    Runnable,
    PartiallyRunnable,
    Unsupported
}

public enum SigmaEvidenceKind
{
    Process,
    Event,
    Module,
    Handle
}

public sealed class SigmaCompatibilityAnalysis
{
    public SigmaCompatibilityStatus Status { get; set; } = SigmaCompatibilityStatus.Unsupported;
    public IReadOnlyList<SigmaEvidenceKind> SupportedEvidenceKinds { get; set; } = Array.Empty<SigmaEvidenceKind>();
    public IReadOnlyList<SigmaRuleDiagnostic> Diagnostics { get; set; } = Array.Empty<SigmaRuleDiagnostic>();
}

public sealed class SigmaRunQuery
{
    public SigmaRule Rule { get; set; } = new();
    public int MaxFindings { get; set; } = 1000;
}

public sealed class SigmaRunResult
{
    public IReadOnlyList<SigmaFinding> Findings { get; set; } = Array.Empty<SigmaFinding>();
    public IReadOnlyList<SigmaRuleDiagnostic> Diagnostics { get; set; } = Array.Empty<SigmaRuleDiagnostic>();
    public bool ReachedMaxFindings { get; set; }
    public int RunnableRuleCount { get; set; }
    public int PartiallyRunnableRuleCount { get; set; }
    public int UnsupportedRuleCount { get; set; }
}

public sealed class SigmaRuleDiagnostic
{
    public string Severity { get; set; } = "Warning";
    public string RuleId { get; set; } = string.Empty;
    public string RuleTitle { get; set; } = string.Empty;
    public string SourcePath { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;

    public string DisplayText
    {
        get
        {
            var ruleLabel = !string.IsNullOrWhiteSpace(RuleTitle)
                ? RuleTitle
                : !string.IsNullOrWhiteSpace(SourcePath)
                    ? System.IO.Path.GetFileName(SourcePath)
                    : "Sigma rule";
            return $"{Severity}: {ruleLabel} - {Message}";
        }
    }
}

public sealed class SigmaFinding
{
    public string RuleId { get; set; } = string.Empty;
    public string RuleTitle { get; set; } = string.Empty;
    public string Level { get; set; } = string.Empty;
    public string SourceKind { get; set; } = string.Empty;
    public DateTime? TimestampUtc { get; set; }
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "<unknown>";
    public string MatchedSelector { get; set; } = string.Empty;
    public string MatchedField { get; set; } = string.Empty;
    public string MatchedValue { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string ProcessEntityId { get; set; } = string.Empty;
    public string SourceEvidenceId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public EvidenceCorrelationState CorrelationState { get; set; } = EvidenceCorrelationState.Unresolved;
    public string CorrelationMethod { get; set; } = string.Empty;
    public int CorrelationCandidateCount { get; set; }
}

public sealed class SigmaMatchDetails
{
    public string Selector { get; set; } = string.Empty;
    public string Field { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}
