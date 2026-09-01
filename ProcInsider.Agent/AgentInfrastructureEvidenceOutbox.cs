using ProcInsider.Models.Infrastructure;

namespace ProcInsider.Agent;

/// <summary>
/// Narrow Agent-side owner for the transactional SQLite evidence outbox. Reads use the
/// already-open live store; every state mutation is serialized through AgentStagingWriter.
/// </summary>
internal sealed class AgentInfrastructureEvidenceOutbox
{
    private readonly AgentStagingWriter _writer;
    private readonly Guid _ownerId;

    internal AgentInfrastructureEvidenceOutbox(AgentStagingWriter writer, Guid ownerId)
    {
        _writer = writer ?? throw new ArgumentNullException(nameof(writer));
        _ownerId = ownerId == Guid.Empty
            ? throw new ArgumentException("The evidence outbox owner is required.", nameof(ownerId))
            : ownerId;
    }

    public IReadOnlyList<InfrastructureEvidenceOutboxEntry> List(
        InfrastructureEvidenceOutboxState state,
        int maxCount = InfrastructureEvidenceOutboxPolicy.MaxPageSize)
    {
        try
        {
            return _writer.ListInfrastructureEvidenceOutbox(_ownerId, state, maxCount);
        }
        catch (Exception ex) when (IsSqliteFailure(ex))
        {
            throw new InvalidOperationException("The transactional evidence outbox could not be read.", ex);
        }
    }

    public InfrastructureEvidenceOutboxEntry? GetByBatchId(string batchId)
    {
        try
        {
            return _writer.GetInfrastructureEvidenceOutboxByBatchId(_ownerId, batchId);
        }
        catch (Exception ex) when (IsSqliteFailure(ex))
        {
            throw new InvalidOperationException("The transactional evidence outbox could not be read.", ex);
        }
    }

    public async ValueTask<InfrastructureEvidenceOutboxEntry> BindPackageAsync(
        InfrastructureEvidenceOutboxPackageBinding binding,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _writer.BindInfrastructureEvidenceOutboxPackageAsync(
                _ownerId,
                binding,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsSqliteFailure(ex))
        {
            throw new InvalidOperationException("The transactional package binding could not be recorded.", ex);
        }
    }

    public async ValueTask<InfrastructureEvidenceOutboxEntry> RecordAcknowledgementAsync(
        InfrastructureEvidenceOutboxAcknowledgement acknowledgement,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _writer.RecordInfrastructureEvidenceOutboxAcknowledgementAsync(
                _ownerId,
                acknowledgement,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsSqliteFailure(ex))
        {
            throw new InvalidOperationException("The durable Server acknowledgement could not be recorded.", ex);
        }
    }

    public async ValueTask<InfrastructureEvidenceOutboxEntry> CompleteCleanupAsync(
        Guid outboxId,
        DateTime completedAtUtc,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _writer.CompleteInfrastructureEvidenceOutboxCleanupAsync(
                _ownerId,
                outboxId,
                completedAtUtc,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsSqliteFailure(ex))
        {
            throw new InvalidOperationException("The evidence acknowledgement cleanup could not be completed.", ex);
        }
    }

    public async ValueTask<InfrastructureEvidenceOutboxEntry> QuarantineAsync(
        Guid outboxId,
        string errorCode,
        DateTime quarantinedAtUtc,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _writer.QuarantineInfrastructureEvidenceOutboxAsync(
                _ownerId,
                outboxId,
                errorCode,
                quarantinedAtUtc,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsSqliteFailure(ex))
        {
            throw new InvalidOperationException("The evidence outbox quarantine could not be recorded.", ex);
        }
    }

    private static bool IsSqliteFailure(Exception exception)
        => string.Equals(
            exception.GetType().FullName,
            "Microsoft.Data.Sqlite.SqliteException",
            StringComparison.Ordinal);
}
