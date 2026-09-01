using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ProcInsider.Models.Analysis;

public enum ReputationProviderExecutionFailure
{
    None = 0,
    InvalidSchemaVersion = 1,
    InvalidAuthorization = 2,
    InvalidLookupResult = 3,
    RequestMismatch = 4,
    ProviderMismatch = 5,
    InvalidAttemptTimestamp = 6,
    RequestTimeoutExceeded = 7,
    InvalidResponseLength = 8,
    InvalidReceiptHash = 9
}

/// <summary>
/// Canonical completion receipt for one future provider attempt. It composes
/// the exact authorization and normalized result without carrying transport
/// content, credentials, paths, evidence bytes, or scoring authority.
/// </summary>
public sealed record ReputationProviderExecutionReceipt
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public ReputationProviderAuthorization Authorization { get; init; } = new();

    public ReputationLookupResult Result { get; init; } = new();

    public DateTime StartedUtc { get; init; }

    public DateTime CompletedUtc { get; init; }

    public int ResponseLength { get; init; }

    public string ReceiptHashSha256 { get; init; } = string.Empty;
}

public sealed record ReputationProviderExecutionDecision
{
    public bool Accepted { get; init; }

    public ReputationProviderExecutionFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public ReputationProviderExecutionReceipt? Receipt { get; init; }
}

/// <summary>
/// Pure fail-closed validation for one execution receipt. Actual provider I/O,
/// credential loading, concurrency, and rate enforcement remain separate.
/// </summary>
public static class ReputationProviderExecutionPolicy
{
    public static ReputationProviderExecutionDecision Validate(
        ReputationProviderExecutionReceipt candidate) =>
        ValidateInternal(candidate, requireHash: true);

    public static string ComputeReceiptHash(ReputationProviderExecutionReceipt candidate)
    {
        var decision = ValidateInternal(candidate, requireHash: false);
        return decision.Accepted && decision.Receipt != null
            ? decision.Receipt.ReceiptHashSha256
            : string.Empty;
    }

    private static ReputationProviderExecutionDecision ValidateInternal(
        ReputationProviderExecutionReceipt? candidate,
        bool requireHash)
    {
        if (candidate == null ||
            candidate.SchemaVersion != ReputationProviderExecutionReceipt.CurrentSchemaVersion)
        {
            return Reject(ReputationProviderExecutionFailure.InvalidSchemaVersion);
        }

        var authorizationDecision =
            ReputationProviderAuthorizationPolicy.ValidateAuthorization(candidate.Authorization);
        if (!authorizationDecision.Accepted || authorizationDecision.Authorization == null)
        {
            return Reject(ReputationProviderExecutionFailure.InvalidAuthorization);
        }

        var resultDecision = ReputationLookupContractPolicy.Validate(candidate.Result);
        if (!resultDecision.Accepted || resultDecision.Result == null)
        {
            return Reject(ReputationProviderExecutionFailure.InvalidLookupResult);
        }

        var authorization = authorizationDecision.Authorization;
        var result = resultDecision.Result;
        if (!RequestsEqual(authorization.LookupRequest, result.Request))
        {
            return Reject(ReputationProviderExecutionFailure.RequestMismatch);
        }

        if (!ProvidersEqual(authorization.Admission.Provider, result.Provider))
        {
            return Reject(ReputationProviderExecutionFailure.ProviderMismatch);
        }

        if (!IsUtc(candidate.StartedUtc) || !IsUtc(candidate.CompletedUtc) ||
            candidate.StartedUtc < authorization.AuthorizedUtc ||
            candidate.CompletedUtc < candidate.StartedUtc ||
            result.RetrievedUtc < candidate.StartedUtc ||
            result.RetrievedUtc > candidate.CompletedUtc)
        {
            return Reject(ReputationProviderExecutionFailure.InvalidAttemptTimestamp);
        }

        if (candidate.CompletedUtc - candidate.StartedUtc >
            TimeSpan.FromSeconds(authorization.Admission.Limits.RequestTimeoutSeconds))
        {
            return Reject(ReputationProviderExecutionFailure.RequestTimeoutExceeded);
        }

        if (candidate.ResponseLength < 0 ||
            candidate.ResponseLength > authorization.Admission.Limits.MaximumResponseLength)
        {
            return Reject(ReputationProviderExecutionFailure.InvalidResponseLength);
        }

        var canonical = candidate with
        {
            Authorization = authorization,
            Result = result,
            ReceiptHashSha256 = string.Empty
        };
        var expectedHash = ComputeCanonicalHash(canonical);
        if (requireHash &&
            (!IsLowerSha256(candidate.ReceiptHashSha256) ||
             !string.Equals(candidate.ReceiptHashSha256, expectedHash, StringComparison.Ordinal)))
        {
            return Reject(ReputationProviderExecutionFailure.InvalidReceiptHash);
        }

        return new ReputationProviderExecutionDecision
        {
            Accepted = true,
            Failure = ReputationProviderExecutionFailure.None,
            Receipt = canonical with { ReceiptHashSha256 = expectedHash }
        };
    }

    private static bool RequestsEqual(
        ReputationLookupRequest left,
        ReputationLookupRequest right)
    {
        if (left.SchemaVersion != right.SchemaVersion ||
            !string.Equals(left.RequestId, right.RequestId, StringComparison.Ordinal) ||
            left.Initiation != right.Initiation ||
            left.Indicator.Kind != right.Indicator.Kind ||
            !string.Equals(left.Indicator.Value, right.Indicator.Value, StringComparison.Ordinal) ||
            !EvidenceIdentitiesEqual(left.EvidenceIdentity, right.EvidenceIdentity) ||
            !string.Equals(left.SourceRunId, right.SourceRunId, StringComparison.Ordinal) ||
            left.RequestedUtc != right.RequestedUtc ||
            left.EvidenceReferences.Count != right.EvidenceReferences.Count)
        {
            return false;
        }

        for (var index = 0; index < left.EvidenceReferences.Count; index++)
        {
            var leftReference = left.EvidenceReferences[index];
            var rightReference = right.EvidenceReferences[index];
            if (leftReference.Kind != rightReference.Kind ||
                !string.Equals(leftReference.Id, rightReference.Id, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static bool EvidenceIdentitiesEqual(EvidenceIdentity left, EvidenceIdentity right) =>
        string.Equals(left.CaseId, right.CaseId, StringComparison.Ordinal) &&
        string.Equals(left.EvidenceSessionId, right.EvidenceSessionId, StringComparison.Ordinal) &&
        string.Equals(left.CaptureId, right.CaptureId, StringComparison.Ordinal) &&
        string.Equals(left.SourceIdentityId, right.SourceIdentityId, StringComparison.Ordinal) &&
        string.Equals(left.HostId, right.HostId, StringComparison.Ordinal) &&
        string.Equals(left.ExecutionRootId, right.ExecutionRootId, StringComparison.Ordinal);

    private static bool ProvidersEqual(
        ReputationProviderIdentity left,
        ReputationProviderIdentity right) =>
        string.Equals(left.ProviderId, right.ProviderId, StringComparison.Ordinal) &&
        string.Equals(left.ProviderVersion, right.ProviderVersion, StringComparison.Ordinal) &&
        string.Equals(left.DatasetId, right.DatasetId, StringComparison.Ordinal) &&
        string.Equals(left.DatasetVersion, right.DatasetVersion, StringComparison.Ordinal) &&
        left.QueryMode == right.QueryMode;

    private static string ComputeCanonicalHash(ReputationProviderExecutionReceipt receipt)
    {
        var builder = new StringBuilder();
        Append(builder, receipt.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(builder, receipt.Authorization.AuthorizationHashSha256);
        Append(builder, receipt.Result.ContentHashSha256);
        Append(builder, receipt.StartedUtc.ToString("O", CultureInfo.InvariantCulture));
        Append(builder, receipt.CompletedUtc.ToString("O", CultureInfo.InvariantCulture));
        Append(builder, receipt.ResponseLength.ToString(CultureInfo.InvariantCulture));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())))
            .ToLowerInvariant();
    }

    private static void Append(StringBuilder builder, string value) =>
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture))
            .Append(':')
            .Append(value)
            .Append('\n');

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static bool IsUtc(DateTime value) =>
        value != default && value.Kind == DateTimeKind.Utc;

    private static ReputationProviderExecutionDecision Reject(
        ReputationProviderExecutionFailure failure) =>
        new()
        {
            Accepted = false,
            Failure = failure,
            Diagnostic = failure switch
            {
                ReputationProviderExecutionFailure.InvalidSchemaVersion =>
                    "The reputation provider execution receipt schema version is unsupported.",
                ReputationProviderExecutionFailure.InvalidAuthorization =>
                    "The reputation provider execution receipt authorization is invalid.",
                ReputationProviderExecutionFailure.InvalidLookupResult =>
                    "The reputation provider execution receipt lookup result is invalid.",
                ReputationProviderExecutionFailure.RequestMismatch =>
                    "The reputation provider result does not match the exact authorized request.",
                ReputationProviderExecutionFailure.ProviderMismatch =>
                    "The reputation provider result does not match the exact admitted provider and dataset.",
                ReputationProviderExecutionFailure.InvalidAttemptTimestamp =>
                    "The reputation provider execution timestamps are invalid or out of order.",
                ReputationProviderExecutionFailure.RequestTimeoutExceeded =>
                    "The reputation provider execution exceeded its admitted request timeout.",
                ReputationProviderExecutionFailure.InvalidResponseLength =>
                    "The reputation provider response length is invalid or exceeds its admitted ceiling.",
                ReputationProviderExecutionFailure.InvalidReceiptHash =>
                    "The reputation provider execution receipt identity is missing or mismatched.",
                _ => "The reputation provider execution receipt violates the portable policy."
            }
        };
}
