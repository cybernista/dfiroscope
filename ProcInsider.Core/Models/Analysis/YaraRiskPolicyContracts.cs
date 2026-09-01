using System.Collections.ObjectModel;

namespace ProcInsider.Models.Analysis;

public enum YaraRiskPolicyFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    InvalidIdentity = 2,
    InvalidRulesetIdentity = 3,
    InvalidReview = 4,
    RuleLimitExceeded = 5,
    InvalidRule = 6,
    UnknownSeverity = 7,
    InvalidScoreDelta = 8,
    DuplicateRule = 9,
    InvalidScanResult = 10,
    RulesetMismatch = 11
}

/// <summary>
/// One explicitly reviewed disposition for an exact rule in one hash-bound
/// YARA ruleset. Informational rows are coverage-only; other rows may carry a
/// bounded positive delta for a later, separately authorized risk mapper.
/// </summary>
public sealed record YaraRiskRuleDisposition
{
    public string RuleNamespace { get; init; } = string.Empty;

    public string RuleId { get; init; } = string.Empty;

    public AnalysisFindingSeverity Severity { get; init; }

    public int ScoreDelta { get; init; }
}

/// <summary>
/// Package-free review gate for YARA risk semantics. This contract ships no
/// policy content and grants no authority to execute YARA, persist results, or
/// create a Process Risk signal.
/// </summary>
public sealed record YaraRiskPolicy
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string PolicyId { get; init; } = string.Empty;

    public string PolicyVersion { get; init; } = string.Empty;

    public YaraRulesetIdentity Ruleset { get; init; } = new();

    public string ReviewerId { get; init; } = string.Empty;

    public string ReviewPolicyId { get; init; } = string.Empty;

    public string ReviewPolicyVersion { get; init; } = string.Empty;

    public DateTime ReviewedUtc { get; init; }

    public IReadOnlyList<YaraRiskRuleDisposition> Rules { get; init; } =
        Array.Empty<YaraRiskRuleDisposition>();
}

public sealed record YaraRiskPolicyValidationDecision
{
    public bool Accepted { get; init; }

    public YaraRiskPolicyFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public YaraRiskPolicy? Policy { get; init; }
}

/// <summary>
/// Canonical interpretation of one exact normalized match. An unmatched rule
/// remains visible as unclassified coverage and never receives a score delta.
/// </summary>
public sealed record YaraRiskMatchDisposition
{
    public string MatchId { get; init; } = string.Empty;

    public string RuleNamespace { get; init; } = string.Empty;

    public string RuleId { get; init; } = string.Empty;

    public bool IsPolicyMatched { get; init; }

    public AnalysisFindingSeverity Severity { get; init; }

    public int? ScoreDelta { get; init; }
}

public sealed record YaraRiskResolution
{
    public string ScanId { get; init; } = string.Empty;

    public AnalysisSourceAvailability Availability { get; init; }

    public string PolicyId { get; init; } = string.Empty;

    public string PolicyVersion { get; init; } = string.Empty;

    public YaraRulesetIdentity Ruleset { get; init; } = new();

    public bool IsTruncated { get; init; }

    public IReadOnlyList<YaraRiskMatchDisposition> Dispositions { get; init; } =
        Array.Empty<YaraRiskMatchDisposition>();
}

public sealed record YaraRiskResolutionDecision
{
    public bool Accepted { get; init; }

    public YaraRiskPolicyFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public YaraRiskResolution? Resolution { get; init; }
}

/// <summary>
/// Pure fail-closed validation and exact match resolution for reviewed YARA
/// risk semantics. Tags, metadata, string matches, target content, and display
/// text are deliberately outside the decision inputs.
/// </summary>
public static class YaraRiskPolicyContract
{
    public const int MaximumRuleDispositions = 4096;

    private const int MaximumIdentityLength = 512;
    private const int MaximumVersionLength = 256;

    public static YaraRiskPolicyValidationDecision Validate(YaraRiskPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        if (policy.SchemaVersion != YaraRiskPolicy.CurrentSchemaVersion)
        {
            return RejectPolicy(YaraRiskPolicyFailure.InvalidSchemaVersion,
                "The YARA risk-policy schema version is unsupported.");
        }

        if (!Required(policy.PolicyId, MaximumIdentityLength) ||
            !Required(policy.PolicyVersion, MaximumVersionLength))
        {
            return RejectPolicy(YaraRiskPolicyFailure.InvalidIdentity,
                "The YARA risk-policy identity is incomplete or exceeds the contract bound.");
        }

        if (!ValidRuleset(policy.Ruleset))
        {
            return RejectPolicy(YaraRiskPolicyFailure.InvalidRulesetIdentity,
                "The YARA risk policy requires one complete hash-bound scanner/ruleset identity.");
        }

        if (!Required(policy.ReviewerId, MaximumIdentityLength) ||
            !Required(policy.ReviewPolicyId, MaximumIdentityLength) ||
            !Required(policy.ReviewPolicyVersion, MaximumVersionLength) ||
            policy.ReviewedUtc.Kind != DateTimeKind.Utc)
        {
            return RejectPolicy(YaraRiskPolicyFailure.InvalidReview,
                "The YARA risk policy requires complete bounded review identity and UTC time.");
        }

        var rules = policy.Rules;
        if (rules == null || rules.Count == 0)
        {
            return RejectPolicy(YaraRiskPolicyFailure.InvalidRule,
                "The YARA risk policy requires at least one explicit rule disposition.");
        }

        if (rules.Count > MaximumRuleDispositions)
        {
            return RejectPolicy(YaraRiskPolicyFailure.RuleLimitExceeded,
                $"The YARA risk policy exceeds the bounded maximum of {MaximumRuleDispositions} rules.");
        }

        var acceptedRules = new List<YaraRiskRuleDisposition>(rules.Count);
        var keys = new HashSet<(string RuleNamespace, string RuleId)>();
        foreach (var rule in rules)
        {
            if (rule == null || !Required(rule.RuleNamespace, MaximumIdentityLength) ||
                !Required(rule.RuleId, MaximumIdentityLength))
            {
                return RejectPolicy(YaraRiskPolicyFailure.InvalidRule,
                    "A YARA risk rule requires an exact bounded namespace and rule identity.");
            }

            if (!Enum.IsDefined(rule.Severity) || rule.Severity == AnalysisFindingSeverity.Unknown)
            {
                return RejectPolicy(YaraRiskPolicyFailure.UnknownSeverity,
                    "A YARA risk rule uses an unknown or unsupported severity.");
            }

            if (!ValidScoreDelta(rule.Severity, rule.ScoreDelta))
            {
                return RejectPolicy(YaraRiskPolicyFailure.InvalidScoreDelta,
                    "A YARA risk rule score contradicts the positive-only severity bound.");
            }

            if (!keys.Add((rule.RuleNamespace, rule.RuleId)))
            {
                return RejectPolicy(YaraRiskPolicyFailure.DuplicateRule,
                    "The YARA risk policy contains a duplicate exact namespace/rule identity.");
            }

            acceptedRules.Add(rule with { });
        }

        return new YaraRiskPolicyValidationDecision
        {
            Accepted = true,
            Failure = YaraRiskPolicyFailure.None,
            Policy = policy with
            {
                Ruleset = policy.Ruleset with { },
                Rules = new ReadOnlyCollection<YaraRiskRuleDisposition>(acceptedRules
                    .OrderBy(rule => rule.RuleNamespace, StringComparer.Ordinal)
                    .ThenBy(rule => rule.RuleId, StringComparer.Ordinal)
                    .ToArray())
            }
        };
    }

    public static YaraRiskResolutionDecision Resolve(
        YaraRiskPolicy policy,
        YaraScanResult scanResult)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(scanResult);

        var policyDecision = Validate(policy);
        if (!policyDecision.Accepted || policyDecision.Policy == null)
        {
            return RejectResolution(policyDecision.Failure, policyDecision.Diagnostic);
        }

        var scanDecision = YaraAnalysisContractPolicy.Validate(scanResult);
        if (!scanDecision.Accepted || scanDecision.Result == null)
        {
            return RejectResolution(YaraRiskPolicyFailure.InvalidScanResult,
                $"The normalized YARA scan result failed validation: {scanDecision.Failure}.");
        }

        var acceptedPolicy = policyDecision.Policy;
        var acceptedScan = scanDecision.Result;
        if (acceptedPolicy.Ruleset != acceptedScan.Ruleset)
        {
            return RejectResolution(YaraRiskPolicyFailure.RulesetMismatch,
                "The normalized YARA scan does not use the policy's exact scanner/ruleset identity.");
        }

        var policyByRule = acceptedPolicy.Rules.ToDictionary(
            rule => (rule.RuleNamespace, rule.RuleId));
        var dispositions = new List<YaraRiskMatchDisposition>(acceptedScan.Matches.Count);
        foreach (var match in acceptedScan.Matches)
        {
            if (policyByRule.TryGetValue((match.RuleNamespace, match.RuleId), out var rule))
            {
                dispositions.Add(new YaraRiskMatchDisposition
                {
                    MatchId = match.MatchId,
                    RuleNamespace = match.RuleNamespace,
                    RuleId = match.RuleId,
                    IsPolicyMatched = true,
                    Severity = rule.Severity,
                    ScoreDelta = rule.ScoreDelta == 0 ? null : rule.ScoreDelta
                });
            }
            else
            {
                dispositions.Add(new YaraRiskMatchDisposition
                {
                    MatchId = match.MatchId,
                    RuleNamespace = match.RuleNamespace,
                    RuleId = match.RuleId,
                    IsPolicyMatched = false,
                    Severity = AnalysisFindingSeverity.Informational
                });
            }
        }

        return new YaraRiskResolutionDecision
        {
            Accepted = true,
            Failure = YaraRiskPolicyFailure.None,
            Resolution = new YaraRiskResolution
            {
                ScanId = acceptedScan.ScanId,
                Availability = acceptedScan.Availability,
                PolicyId = acceptedPolicy.PolicyId,
                PolicyVersion = acceptedPolicy.PolicyVersion,
                Ruleset = acceptedPolicy.Ruleset with { },
                IsTruncated = acceptedScan.IsTruncated,
                Dispositions = new ReadOnlyCollection<YaraRiskMatchDisposition>(dispositions)
            }
        };
    }

    private static bool ValidRuleset(YaraRulesetIdentity? ruleset) =>
        ruleset != null && Required(ruleset.ScannerId, MaximumIdentityLength) &&
        Required(ruleset.ScannerVersion, MaximumVersionLength) &&
        Required(ruleset.RulesetId, MaximumIdentityLength) &&
        Required(ruleset.RulesetVersion, MaximumVersionLength) &&
        ruleset.RulesetHashSha256 is { Length: 64 } &&
        ruleset.RulesetHashSha256.All(Uri.IsHexDigit);

    private static bool ValidScoreDelta(AnalysisFindingSeverity severity, int scoreDelta)
    {
        if (severity == AnalysisFindingSeverity.Informational)
        {
            return scoreDelta == 0;
        }

        var bound = ProcessRiskAggregationPolicy.LocalFirstVersion1.SeverityDeltaBounds
            .SingleOrDefault(item => item.Severity == severity);
        return bound != null && scoreDelta > 0 && scoreDelta <= bound.MaximumAbsoluteDelta;
    }

    private static bool Required(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;

    private static YaraRiskPolicyValidationDecision RejectPolicy(
        YaraRiskPolicyFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = diagnostic
        };

    private static YaraRiskResolutionDecision RejectResolution(
        YaraRiskPolicyFailure failure,
        string diagnostic) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = diagnostic
        };
}
