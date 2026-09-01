using System.Security.Cryptography;
using System.Text;
using System.IO;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.Features.BaselineComparison;

public enum SnapshotComparisonExecutionState
{
    Completed = 0,
    MetadataUnavailable = 1,
    Rejected = 2
}

public sealed record SnapshotComparisonExecutionResult(
    SnapshotComparisonExecutionState State,
    SnapshotComparisonResult? ComparisonResult,
    BaselineComparisonCompletion? Completion,
    string Diagnostic)
{
    public bool CanPublish => State == SnapshotComparisonExecutionState.Completed && Completion != null;
}

public interface ISnapshotComparisonCompletionRuntime
{
    Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken);

    Task<SnapshotComparisonResult> CompareAsync(
        string baselineSnapshotPath,
        string currentSnapshotPath,
        BaselinePolicyDocument policy,
        CancellationToken cancellationToken);
}

public sealed class SnapshotComparisonCompletionRuntime : ISnapshotComparisonCompletionRuntime
{
    private readonly SnapshotComparisonService _comparisonService;

    public SnapshotComparisonCompletionRuntime(SnapshotComparisonService comparisonService)
    {
        _comparisonService = comparisonService ?? throw new ArgumentNullException(nameof(comparisonService));
    }

    public async Task<string> ComputeSha256Async(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(
                await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false))
            .ToLowerInvariant();
    }

    public Task<SnapshotComparisonResult> CompareAsync(
        string baselineSnapshotPath,
        string currentSnapshotPath,
        BaselinePolicyDocument policy,
        CancellationToken cancellationToken) =>
        _comparisonService.CompareAsync(
            baselineSnapshotPath,
            currentSnapshotPath,
            policy,
            cancellationToken);
}

/// <summary>
/// Immutable identity for one hash-stable completed Baseline comparison. Rich
/// findings are retained only as a defensive snapshot and are copied again for
/// every materialization attempt.
/// </summary>
public sealed class BaselineComparisonCompletion
{
    private readonly SnapshotComparisonFinding[] _findings;

    internal BaselineComparisonCompletion(
        SnapshotComparisonResult comparison,
        string comparisonId,
        string comparisonVersion,
        string baselineId,
        string baselineSnapshotHashSha256,
        string currentSnapshotHashSha256,
        DateTime evaluatedUtc)
    {
        ArgumentNullException.ThrowIfNull(comparison);
        BaselineSnapshotPath = Path.GetFullPath(comparison.BaselineSnapshotPath);
        CurrentSnapshotPath = Path.GetFullPath(comparison.CurrentSnapshotPath);
        ComparedUtc = comparison.ComparedUtc;
        EvaluatedUtc = evaluatedUtc;
        BaselineProcessCount = comparison.BaselineProcessCount;
        CurrentProcessCount = comparison.CurrentProcessCount;
        ComparisonId = comparisonId;
        ComparisonVersion = comparisonVersion;
        BaselineId = baselineId;
        BaselineSnapshotHashSha256 = baselineSnapshotHashSha256.ToLowerInvariant();
        CurrentSnapshotHashSha256 = currentSnapshotHashSha256.ToLowerInvariant();
        _findings = comparison.Findings.Select(CloneFinding).ToArray();
    }

    public string BaselineSnapshotPath { get; }

    public string CurrentSnapshotPath { get; }

    public DateTime ComparedUtc { get; }

    public DateTime EvaluatedUtc { get; }

    public int BaselineProcessCount { get; }

    public int CurrentProcessCount { get; }

    public string ComparisonId { get; }

    public string ComparisonVersion { get; }

    public string BaselineId { get; }

    public string BaselineSnapshotHashSha256 { get; }

    public string CurrentSnapshotHashSha256 { get; }

    public int FindingCount => _findings.Length;

    public SnapshotComparisonResult CreateComparisonResult() => new()
    {
        BaselineSnapshotPath = BaselineSnapshotPath,
        CurrentSnapshotPath = CurrentSnapshotPath,
        ComparedUtc = ComparedUtc,
        BaselineProcessCount = BaselineProcessCount,
        CurrentProcessCount = CurrentProcessCount,
        Findings = _findings.Select(CloneFinding).ToArray()
    };

    public BaselineComparisonCompletion WithFindings(
        IEnumerable<SnapshotComparisonFinding> findings,
        DateTime evaluatedUtc)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var comparison = CreateComparisonResult();
        comparison.Findings = findings.Select(CloneFinding).ToArray();
        return new BaselineComparisonCompletion(
            comparison,
            ComparisonId,
            ComparisonVersion,
            BaselineId,
            BaselineSnapshotHashSha256,
            CurrentSnapshotHashSha256,
            evaluatedUtc);
    }

    internal static SnapshotComparisonFinding CloneFinding(SnapshotComparisonFinding source) => new()
    {
        FindingId = source.FindingId,
        ArtifactKind = source.ArtifactKind,
        Verdict = source.Verdict,
        StableKey = source.StableKey,
        Fingerprint = source.Fingerprint,
        BaselineFingerprint = source.BaselineFingerprint,
        CurrentFingerprint = source.CurrentFingerprint,
        Title = source.Title,
        BaselineSummary = source.BaselineSummary,
        CurrentSummary = source.CurrentSummary,
        Explanation = source.Explanation,
        ChangedFields = source.ChangedFields,
        PolicyRuleId = source.PolicyRuleId
    };
}

/// <summary>
/// Hashes both selected files before and after the read-only comparison and
/// binds the result to exactly one saved Baseline metadata identity.
/// </summary>
public sealed class SnapshotComparisonCompletionService
{
    private readonly ISnapshotComparisonCompletionRuntime _runtime;

    public SnapshotComparisonCompletionService(ISnapshotComparisonCompletionRuntime runtime)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
    }

    public async Task<SnapshotComparisonExecutionResult> CompareAsync(
        string baselineSnapshotPath,
        string currentSnapshotPath,
        BaselinePolicyDocument policy,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        string baselinePath;
        string currentPath;
        try
        {
            baselinePath = Path.GetFullPath(baselineSnapshotPath);
            currentPath = Path.GetFullPath(currentSnapshotPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return Rejected($"Snapshot paths could not be canonicalized: {ex.Message}");
        }

        if (!File.Exists(baselinePath) || !File.Exists(currentPath))
        {
            return Rejected("Both selected snapshot files must exist before comparison.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var baselineHashBefore = NormalizeSha256(
            await _runtime.ComputeSha256Async(baselinePath, cancellationToken).ConfigureAwait(false));
        var currentHashBefore = NormalizeSha256(
            await _runtime.ComputeSha256Async(currentPath, cancellationToken).ConfigureAwait(false));
        if (baselineHashBefore == null || currentHashBefore == null)
        {
            return Rejected("Snapshot hashing did not return two valid SHA-256 byte identities.");
        }

        var comparison = await _runtime.CompareAsync(
                baselinePath,
                currentPath,
                policy,
                cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        var baselineHashAfter = NormalizeSha256(
            await _runtime.ComputeSha256Async(baselinePath, cancellationToken).ConfigureAwait(false));
        var currentHashAfter = NormalizeSha256(
            await _runtime.ComputeSha256Async(currentPath, cancellationToken).ConfigureAwait(false));
        if (!string.Equals(baselineHashBefore, baselineHashAfter, StringComparison.Ordinal) ||
            !string.Equals(currentHashBefore, currentHashAfter, StringComparison.Ordinal))
        {
            return Rejected(
                "A selected snapshot changed while it was being compared; no completion identity or Process Risk update was produced.");
        }

        if (comparison == null ||
            comparison.ComparedUtc.Kind != DateTimeKind.Utc ||
            !SamePath(comparison.BaselineSnapshotPath, baselinePath) ||
            !SamePath(comparison.CurrentSnapshotPath, currentPath))
        {
            return Rejected(
                "The comparison result did not retain the exact canonical selected paths and UTC completion boundary.");
        }

        var displayResult = CloneComparison(comparison);
        var matchingMetadata = (policy.Baselines ?? [])
            .Where(metadata => metadata != null && SamePath(metadata.SnapshotPath, baselinePath))
            .ToArray();
        if (matchingMetadata.Length != 1 || string.IsNullOrWhiteSpace(matchingMetadata[0].BaselineId))
        {
            return new SnapshotComparisonExecutionResult(
                SnapshotComparisonExecutionState.MetadataUnavailable,
                displayResult,
                null,
                matchingMetadata.Length == 0
                    ? "Comparison completed, but Process Risk publication requires exactly one saved Baseline metadata row for the selected baseline path."
                    : "Comparison completed, but the selected baseline metadata identity is ambiguous or incomplete; Process Risk was preserved.");
        }

        var evaluatedUtc = DateTime.UtcNow;
        if (evaluatedUtc < comparison.ComparedUtc)
        {
            evaluatedUtc = comparison.ComparedUtc;
        }

        var baselineId = matchingMetadata[0].BaselineId.Trim();
        var comparisonId = CreateComparisonId(
            SnapshotComparisonService.CurrentComparisonVersion,
            baselineId,
            baselineHashBefore,
            currentHashBefore);
        var completion = new BaselineComparisonCompletion(
            comparison,
            comparisonId,
            SnapshotComparisonService.CurrentComparisonVersion,
            baselineId,
            baselineHashBefore,
            currentHashBefore,
            evaluatedUtc);
        return new SnapshotComparisonExecutionResult(
            SnapshotComparisonExecutionState.Completed,
            displayResult,
            completion,
            "Comparison completed with stable pre/post hashes and one exact saved Baseline identity.");
    }

    private static string CreateComparisonId(
        string version,
        string baselineId,
        string baselineHash,
        string currentHash)
    {
        var canonical = string.Join("\n",
            $"version:{version.Length}:{version}",
            $"baseline-id:{baselineId.Length}:{baselineId}",
            $"baseline-sha256:{baselineHash}",
            $"current-sha256:{currentHash}");
        return $"baseline-comparison-{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant()}";
    }

    private static SnapshotComparisonResult CloneComparison(SnapshotComparisonResult source) => new()
    {
        BaselineSnapshotPath = source.BaselineSnapshotPath,
        CurrentSnapshotPath = source.CurrentSnapshotPath,
        ComparedUtc = source.ComparedUtc,
        BaselineProcessCount = source.BaselineProcessCount,
        CurrentProcessCount = source.CurrentProcessCount,
        Findings = source.Findings.Select(BaselineComparisonCompletion.CloneFinding).ToArray()
    };

    private static bool SamePath(string left, string right)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(left) &&
                   !string.IsNullOrWhiteSpace(right) &&
                   string.Equals(
                       Path.GetFullPath(left),
                       Path.GetFullPath(right),
                       StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static string? NormalizeSha256(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 64)
        {
            return null;
        }

        try
        {
            _ = Convert.FromHexString(value);
            return value.ToLowerInvariant();
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static SnapshotComparisonExecutionResult Rejected(string diagnostic) =>
        new(SnapshotComparisonExecutionState.Rejected, null, null, diagnostic);
}
