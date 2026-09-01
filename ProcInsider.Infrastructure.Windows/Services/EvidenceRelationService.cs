using System;
using System.Security.Cryptography;
using System.Text;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class EvidenceRelationService
{
    public const string Version = "evidence-relation-v1";

    public EvidenceRelation CreateDecision(
        EvidenceReference from,
        EvidenceReference to,
        EvidenceRelationType relationType,
        EvidenceCorrelationState state,
        string method,
        double confidence,
        EvidenceIdentity identity,
        string resolverName,
        string decisionKey = "",
        DateTime? observedUtc = null,
        string sourceRunId = "",
        string ingestionJobId = "",
        string rawInputId = "",
        string analystAnnotationId = "",
        string resolverVersion = "",
        int candidateCount = 0,
        string correlationDiagnostics = "")
    {
        if (from.IsEmpty)
        {
            throw new ArgumentException("The relation source reference is required.", nameof(from));
        }

        if (state is not (EvidenceCorrelationState.Unresolved or EvidenceCorrelationState.Ambiguous) && to.IsEmpty)
        {
            throw new ArgumentException("Only unresolved or ambiguous decisions may omit a target reference.", nameof(to));
        }

        if (state == EvidenceCorrelationState.Unresolved && !to.IsEmpty)
        {
            throw new ArgumentException("An unresolved decision cannot claim a target reference.", nameof(to));
        }

        var normalizedConfidence = Math.Clamp(confidence, 0d, 1d);
        var normalizedDecisionKey = string.IsNullOrWhiteSpace(decisionKey)
            ? $"{from.Kind}:{from.Id}:{relationType}"
            : decisionKey.Trim();
        var normalizedResolverVersion = string.IsNullOrWhiteSpace(resolverVersion)
            ? Version
            : resolverVersion.Trim();
        var normalizedMethod = method?.Trim() ?? string.Empty;
        var normalizedCandidateCount = Math.Max(0, candidateCount);
        var normalizedDiagnostics = correlationDiagnostics?.Trim() ?? string.Empty;
        var timestamp = observedUtc ?? DateTime.UtcNow;
        var relationId = CreateStableId(string.Join("|",
            identity.CaseId,
            identity.EvidenceSessionId,
            identity.HostId,
            identity.ExecutionRootId,
            normalizedDecisionKey,
            to.Kind,
            to.Id,
            state,
            resolverName,
            normalizedResolverVersion,
            normalizedMethod,
            normalizedCandidateCount,
            normalizedDiagnostics));

        return new EvidenceRelation
        {
            RelationId = relationId,
            DecisionKey = normalizedDecisionKey,
            FromKind = from.Kind,
            FromId = from.Id,
            ToKind = to.Kind,
            ToId = to.Id,
            RelationType = relationType,
            State = state,
            CorrelationMethod = normalizedMethod,
            Confidence = normalizedConfidence,
            CandidateCount = normalizedCandidateCount,
            CorrelationDiagnostics = normalizedDiagnostics,
            CaseId = identity.CaseId,
            EvidenceSessionId = identity.EvidenceSessionId,
            CaptureId = identity.CaptureId,
            SourceIdentityId = identity.SourceIdentityId,
            HostId = identity.HostId,
            ExecutionRootId = identity.ExecutionRootId,
            SourceRunId = sourceRunId,
            IngestionJobId = ingestionJobId,
            RawInputId = rawInputId,
            ObservedFromUtc = timestamp,
            ResolverName = resolverName?.Trim() ?? string.Empty,
            ResolverVersion = normalizedResolverVersion,
            CreatedUtc = timestamp,
            UpdatedUtc = timestamp,
            AnalystAnnotationId = analystAnnotationId?.Trim() ?? string.Empty
        };
    }

    public static bool IsCanonicalProcessLink(EvidenceCorrelationState state)
        => state is EvidenceCorrelationState.Exact or EvidenceCorrelationState.Asserted or EvidenceCorrelationState.Confirmed;

    public static void EnsureCompatibleScopes(EvidenceIdentity from, EvidenceIdentity to)
    {
        EnsureSame("case", from.CaseId, to.CaseId);
        EnsureSame("evidence session", from.EvidenceSessionId, to.EvidenceSessionId);
        EnsureSame("host", from.HostId, to.HostId);
        EnsureSame("execution root", from.ExecutionRootId, to.ExecutionRootId);
    }

    private static void EnsureSame(string label, string left, string right)
    {
        if (!string.IsNullOrWhiteSpace(left) &&
            !string.IsNullOrWhiteSpace(right) &&
            !string.Equals(left, right, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Evidence relation rejected across incompatible {label} scopes.");
        }
    }

    private static string CreateStableId(string value)
        => $"rel_{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant()}";
}
