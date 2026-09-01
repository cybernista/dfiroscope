namespace ProcInsider.Models.Infrastructure;

/// <summary>
/// Durable Agent-side progress for one publication-eligible local evidence transaction.
/// The outbox stores identity and receipt metadata only; package bytes remain in the
/// machine-owned transfer spool and primary evidence remains in its source tables.
/// </summary>
public enum InfrastructureEvidenceOutboxState
{
    Pending = 1,
    Spooled = 2,
    AcknowledgedCleanupPending = 3,
    Completed = 4,
    Quarantined = 5
}

public static class InfrastructureEvidenceOutboxPolicy
{
    public const int CurrentSchemaVersion = 1;
    public const int MaxPageSize = 256;
    public const int MaxOperationNameLength = 128;
    public const int MaxErrorCodeLength = 128;
    public const int MaxRetryCount = 1_000_000;

    public static string NormalizeOperationName(string value)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length == 0 || normalized.Length > MaxOperationNameLength ||
            normalized.Any(character => char.IsControl(character)))
        {
            throw new InvalidDataException("The evidence outbox operation name is invalid.");
        }

        return normalized;
    }

    public static string NormalizeErrorCode(string value)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length > MaxErrorCodeLength ||
            normalized.Any(character => char.IsControl(character)))
        {
            throw new InvalidDataException("The evidence outbox error code is invalid.");
        }

        return normalized;
    }

    public static int NormalizePageSize(int value)
        => value is > 0 and <= MaxPageSize
            ? value
            : throw new ArgumentOutOfRangeException(nameof(value));

    public static void RequireUtc(DateTime value, string fieldName)
    {
        if (value.Kind != DateTimeKind.Utc)
        {
            throw new InvalidDataException($"The evidence outbox {fieldName} must be UTC.");
        }
    }
}

public sealed record InfrastructureEvidenceOutboxEntry
{
    public int SchemaVersion { get; init; } = InfrastructureEvidenceOutboxPolicy.CurrentSchemaVersion;

    public long Sequence { get; init; }

    public Guid OutboxId { get; init; }

    public Guid WriterInstanceId { get; init; }

    public long WriterCommitGeneration { get; init; }

    public string OperationName { get; init; } = string.Empty;

    public long ApproximateRowCount { get; init; }

    public DateTime CommittedAtUtc { get; init; }

    public InfrastructureEvidenceOutboxState State { get; init; }

    public string BatchId { get; init; } = string.Empty;

    public string ManifestSha256 { get; init; } = string.Empty;

    public string PackageSha256 { get; init; } = string.Empty;

    public InfrastructureEvidenceTransferOutcome AcknowledgementOutcome { get; init; }

    public string ServerCommitId { get; init; } = string.Empty;

    public DateTime? ServerReceiptTimeUtc { get; init; }

    public DateTime StateChangedAtUtc { get; init; }

    public int RetryCount { get; init; }

    public string LastErrorCode { get; init; } = string.Empty;
}

public sealed record InfrastructureEvidenceOutboxCommit
{
    public Guid OutboxId { get; init; }

    public Guid WriterInstanceId { get; init; }

    public long WriterCommitGeneration { get; init; }

    public string OperationName { get; init; } = string.Empty;

    public long ApproximateRowCount { get; init; }

    public DateTime CommittedAtUtc { get; init; }
}

public sealed record InfrastructureEvidenceOutboxPackageBinding
{
    public Guid OutboxId { get; init; }

    public string BatchId { get; init; } = string.Empty;

    public string ManifestSha256 { get; init; } = string.Empty;

    public string PackageSha256 { get; init; } = string.Empty;

    public DateTime BoundAtUtc { get; init; }
}

public sealed record InfrastructureEvidenceOutboxAcknowledgement
{
    public Guid OutboxId { get; init; }

    public string BatchId { get; init; } = string.Empty;

    public string ManifestSha256 { get; init; } = string.Empty;

    public string PackageSha256 { get; init; } = string.Empty;

    public InfrastructureEvidenceTransferOutcome Outcome { get; init; }

    public string ServerCommitId { get; init; } = string.Empty;

    public DateTime ServerReceiptTimeUtc { get; init; }

    public DateTime RecordedAtUtc { get; init; }
}
