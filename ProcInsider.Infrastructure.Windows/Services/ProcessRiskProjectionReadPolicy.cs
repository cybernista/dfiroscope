using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

/// <summary>
/// Shared fail-closed read policy for persisted Process Risk projection summaries.
/// The focused risk query owner validates returned DTOs, while the process-listing
/// owner reuses this policy only to derive a safe global sort key.
/// </summary>
internal static class ProcessRiskProjectionReadPolicy
{
    internal static ProcessRiskAggregationPolicy CurrentPolicy =>
        ProcessRiskAggregationPolicy.LocalFirstVersion1;

    internal static ProcessRiskAggregationPolicy? GetSupportedPolicy(
        string? policyId,
        string? policyVersion)
    {
        var policy = CurrentPolicy;
        return string.Equals(policyId, policy.PolicyId, StringComparison.Ordinal) &&
               string.Equals(policyVersion, policy.PolicyVersion, StringComparison.Ordinal)
            ? policy
            : null;
    }

    internal static bool HasStaleContract(
        string? mapperId,
        string? mapperVersion,
        string? aggregationVersion,
        string? policyId,
        string? policyVersion)
    {
        return !string.Equals(mapperId, LocalProcessRiskMapper.MapperId, StringComparison.Ordinal) ||
               !string.Equals(mapperVersion, LocalProcessRiskMapper.MapperVersion, StringComparison.Ordinal) ||
               !string.Equals(
                   aggregationVersion,
                   ProcessRiskScoreProjection.CurrentSchemaVersion.ToString(CultureInfo.InvariantCulture),
                   StringComparison.Ordinal) ||
               GetSupportedPolicy(policyId, policyVersion) == null;
    }

    internal static bool HasValidEvaluationIdentity(
        string? evaluationId,
        string? inputIdentityHash,
        string? mapperId,
        string? mapperVersion,
        string? aggregationVersion,
        string? policyId,
        string? policyVersion)
    {
        if (string.IsNullOrEmpty(inputIdentityHash) ||
            inputIdentityHash.Length != 64 ||
            inputIdentityHash.Any(character => !Uri.IsHexDigit(character)))
        {
            return false;
        }

        var canonical = string.Join('\n',
            inputIdentityHash,
            mapperId ?? string.Empty,
            mapperVersion ?? string.Empty,
            policyId ?? string.Empty,
            policyVersion ?? string.Empty,
            aggregationVersion ?? string.Empty);
        var computed = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))
            .ToLowerInvariant();
        return string.Equals(
            evaluationId,
            $"risk-evaluation-{computed[..32]}",
            StringComparison.Ordinal);
    }

    internal static bool IsValidSummaryValues(
        ProcessRiskProjectionState state,
        int? score,
        ProcessRiskBand band,
        double confidence,
        double coverage,
        ProcessRiskAggregationPolicy policy)
    {
        if (!double.IsFinite(confidence) ||
            confidence < 0 ||
            confidence > 1 ||
            !double.IsFinite(coverage) ||
            coverage < 0 ||
            coverage > 1)
        {
            return false;
        }

        if (state == ProcessRiskProjectionState.Unknown)
        {
            return score == null && band == ProcessRiskBand.Unknown;
        }

        if (!score.HasValue || score is < 0 or > 100 || band == ProcessRiskBand.Unknown)
        {
            return false;
        }

        var expectedBand = policy.BandThresholds
            .OrderByDescending(threshold => threshold.MinimumScore)
            .First(threshold => score.Value >= threshold.MinimumScore)
            .Band;
        return band == expectedBand;
    }

    internal static bool IsValidPersistedSummarySource(
        string? policyId,
        string? policyVersion,
        int sourceOrder,
        string? sourceKind,
        string? sourceId,
        string? availability)
    {
        var policy = GetSupportedPolicy(policyId, policyVersion);
        if (policy == null ||
            sourceOrder < 0 ||
            sourceOrder >= policy.Sources.Count ||
            !Enum.TryParse<ProcessRiskSourceKind>(sourceKind, out var parsedKind) ||
            !Enum.TryParse<AnalysisSourceAvailability>(availability, out var parsedAvailability) ||
            parsedAvailability == AnalysisSourceAvailability.Unknown ||
            !Enum.IsDefined(parsedAvailability))
        {
            return false;
        }

        var expected = policy.Sources
            .OrderBy(source => source.SourceKind)
            .ElementAt(sourceOrder);
        return parsedKind == expected.SourceKind &&
               string.Equals(sourceId, expected.SourceId, StringComparison.Ordinal);
    }

    internal static int GetExpectedSourceCount(string? policyId, string? policyVersion) =>
        GetSupportedPolicy(policyId, policyVersion)?.Sources.Count ?? -1;
}
