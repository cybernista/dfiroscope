using System;
using System.Collections.Generic;
using System.Linq;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Pure, versioned process-correlation decision engine. Persistence and bounded scheduling
/// remain owned by <see cref="SqliteStagingStore"/>.
/// </summary>
public sealed class EvidenceReCorrelationService
{
    public const string ResolverName = "DeterministicProcessCorrelation";
    public const string Version = "process-correlation-v1";

    private readonly EvidenceRelationService _relationService = new();

    public EvidenceCorrelationResolution Resolve(
        EvidenceCorrelationInput input,
        IReadOnlyList<ProcessCorrelationCandidate> candidates,
        DateTime resolvedUtc)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(candidates);
        if (string.IsNullOrWhiteSpace(input.EvidenceId))
        {
            throw new ArgumentException("A correlation input must reference evidence.", nameof(input));
        }

        var compatible = candidates
            .Where(candidate => IsCompatibleScope(input.Identity, candidate.Identity))
            .Where(candidate => !string.IsNullOrWhiteSpace(candidate.ProcessEntityId))
            .DistinctBy(candidate => candidate.ProcessEntityId, StringComparer.Ordinal)
            .ToList();
        var rejectedScopeCount = candidates.Count - compatible.Count;

        MatchTier tier;
        if (!string.IsNullOrWhiteSpace(input.ProcessGuid))
        {
            tier = SelectTier(
                "ProcessGuid",
                EvidenceCorrelationState.Exact,
                1.0,
                compatible.Where(candidate =>
                    EqualsIdentifier(candidate.ProcessGuid, input.ProcessGuid) ||
                    candidate.Aliases.Any(alias =>
                        alias.Kind == ProcessAliasKind.SysmonProcessGuid &&
                        EqualsIdentifier(alias.Value, input.ProcessGuid))));
            if (tier.HasMatches)
            {
                return CreateResolution(input, tier, compatible.Count, rejectedScopeCount, resolvedUtc);
            }
        }

        if (!string.IsNullOrWhiteSpace(input.SourceNativeId))
        {
            tier = SelectTier(
                "SourceNativeAlias",
                EvidenceCorrelationState.Exact,
                0.99,
                compatible.Where(candidate =>
                    string.Equals(candidate.ProcessKey, input.SourceNativeId, StringComparison.Ordinal) ||
                    candidate.Aliases.Any(alias => string.Equals(alias.Value, input.SourceNativeId, StringComparison.Ordinal))));
            if (tier.HasMatches)
            {
                return CreateResolution(input, tier, compatible.Count, rejectedScopeCount, resolvedUtc);
            }
        }

        if (input.ProcessId > 0 && input.ProcessStartTimeUtc.HasValue)
        {
            var expectedStart = input.ProcessStartTimeUtc.Value.ToUniversalTime();
            tier = SelectTier(
                "ScopedPidStartTime",
                EvidenceCorrelationState.Exact,
                1.0,
                compatible.Where(candidate =>
                    candidate.ProcessId == input.ProcessId &&
                    candidate.StartTimeUtc.HasValue &&
                    candidate.StartTimeUtc.Value.ToUniversalTime() == expectedStart));
            if (tier.HasMatches)
            {
                return CreateResolution(input, tier, compatible.Count, rejectedScopeCount, resolvedUtc);
            }
        }

        var temporalCandidates = compatible
            .Where(candidate => input.ProcessId > 0 && candidate.ProcessId == input.ProcessId)
            .Where(candidate => IsTemporallyCompatible(input.ObservedUtc, candidate))
            .ToList();
        tier = SelectTier(
            "TemporalPid",
            EvidenceCorrelationState.Inferred,
            0.85,
            temporalCandidates);
        if (tier.HasMatches)
        {
            return CreateResolution(input, tier, compatible.Count, rejectedScopeCount, resolvedUtc);
        }

        if (IsUsableProcessText(input.ProcessPath))
        {
            tier = SelectTier(
                "TemporalExactPath",
                EvidenceCorrelationState.Inferred,
                0.70,
                compatible.Where(candidate =>
                    IsTemporallyCompatible(input.ObservedUtc, candidate) &&
                    string.Equals(candidate.ProcessPath, input.ProcessPath, StringComparison.OrdinalIgnoreCase)));
            if (tier.HasMatches)
            {
                return CreateResolution(input, tier, compatible.Count, rejectedScopeCount, resolvedUtc);
            }
        }

        if (IsUsableProcessText(input.ProcessName))
        {
            tier = SelectTier(
                "TemporalProcessName",
                EvidenceCorrelationState.Inferred,
                0.55,
                compatible.Where(candidate =>
                    IsTemporallyCompatible(input.ObservedUtc, candidate) &&
                    string.Equals(candidate.ProcessName, input.ProcessName, StringComparison.OrdinalIgnoreCase)));
            if (tier.HasMatches)
            {
                return CreateResolution(input, tier, compatible.Count, rejectedScopeCount, resolvedUtc);
            }
        }

        var diagnostics = rejectedScopeCount > 0
            ? $"No compatible process candidate matched; {rejectedScopeCount} candidate(s) were rejected by case/session/host/execution scope."
            : "No compatible process candidate matched the versioned exact, temporal, or fallback rules.";
        var unresolved = CreateDecision(
            input,
            string.Empty,
            EvidenceCorrelationState.Unresolved,
            "NoScopedCandidate",
            0,
            0,
            diagnostics,
            resolvedUtc);
        return new EvidenceCorrelationResolution(unresolved, compatible.Count, rejectedScopeCount);
    }

    private EvidenceCorrelationResolution CreateResolution(
        EvidenceCorrelationInput input,
        MatchTier tier,
        int compatibleCount,
        int rejectedScopeCount,
        DateTime resolvedUtc)
    {
        var state = tier.Matches.Count == 1 ? tier.UniqueState : EvidenceCorrelationState.Ambiguous;
        var targetId = tier.Matches.Count == 1 ? tier.Matches[0].ProcessEntityId : string.Empty;
        var confidence = tier.Matches.Count == 1 ? tier.UniqueConfidence : Math.Min(tier.UniqueConfidence, 0.49);
        var diagnostics = tier.Matches.Count == 1
            ? $"One scoped process candidate matched by {tier.Method}."
            : $"{tier.Matches.Count} scoped process candidates matched by {tier.Method}; no target was selected.";
        if (rejectedScopeCount > 0)
        {
            diagnostics += $" {rejectedScopeCount} cross-scope candidate(s) were rejected.";
        }

        var decision = CreateDecision(
            input,
            targetId,
            state,
            tier.Method,
            confidence,
            tier.Matches.Count,
            diagnostics,
            resolvedUtc);
        return new EvidenceCorrelationResolution(decision, compatibleCount, rejectedScopeCount);
    }

    private EvidenceRelation CreateDecision(
        EvidenceCorrelationInput input,
        string processEntityId,
        EvidenceCorrelationState state,
        string method,
        double confidence,
        int candidateCount,
        string diagnostics,
        DateTime resolvedUtc)
    {
        var decision = _relationService.CreateDecision(
            new EvidenceReference(input.EvidenceKind, input.EvidenceId),
            new EvidenceReference(EvidenceReferenceKind.ProcessEntity, processEntityId),
            input.RelationType,
            state,
            method,
            confidence,
            input.Identity,
            ResolverName,
            input.DecisionKey,
            input.ObservedUtc,
            input.SourceRunId,
            input.IngestionJobId,
            input.RawInputId,
            resolverVersion: Version,
            candidateCount: candidateCount,
            correlationDiagnostics: diagnostics);
        decision.UpdatedUtc = resolvedUtc;
        return decision;
    }

    private static MatchTier SelectTier(
        string method,
        EvidenceCorrelationState uniqueState,
        double uniqueConfidence,
        IEnumerable<ProcessCorrelationCandidate> candidates)
        => new(
            method,
            uniqueState,
            uniqueConfidence,
            candidates
                .DistinctBy(candidate => candidate.ProcessEntityId, StringComparer.Ordinal)
                .OrderBy(candidate => candidate.ProcessEntityId, StringComparer.Ordinal)
                .ToList());

    private static bool IsTemporallyCompatible(DateTime observedUtc, ProcessCorrelationCandidate candidate)
    {
        var observed = observedUtc == default ? DateTime.MinValue : observedUtc.ToUniversalTime();
        if (candidate.StartTimeUtc.HasValue && observed < candidate.StartTimeUtc.Value.ToUniversalTime())
        {
            return false;
        }

        return !candidate.EndTimeUtc.HasValue || observed <= candidate.EndTimeUtc.Value.ToUniversalTime();
    }

    private static bool IsCompatibleScope(EvidenceIdentity input, EvidenceIdentity candidate)
        => MatchesScope(input.CaseId, candidate.CaseId) &&
           MatchesScope(input.EvidenceSessionId, candidate.EvidenceSessionId) &&
           MatchesScope(input.HostId, candidate.HostId) &&
           MatchesScope(input.ExecutionRootId, candidate.ExecutionRootId);

    private static bool MatchesScope(string expected, string actual)
        => string.IsNullOrWhiteSpace(expected) ||
           string.IsNullOrWhiteSpace(actual) ||
           string.Equals(expected, actual, StringComparison.Ordinal);

    private static bool EqualsIdentifier(string left, string right)
        => string.Equals(left?.Trim(), right?.Trim(), StringComparison.OrdinalIgnoreCase);

    private static bool IsUsableProcessText(string value)
        => !string.IsNullOrWhiteSpace(value) &&
           value is not "<unknown>" and not "<not available>" and not "Access denied";

    private sealed record MatchTier(
        string Method,
        EvidenceCorrelationState UniqueState,
        double UniqueConfidence,
        IReadOnlyList<ProcessCorrelationCandidate> Matches)
    {
        public bool HasMatches => Matches.Count > 0;
    }
}
