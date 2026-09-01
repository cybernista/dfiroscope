using ProcInsider.Models.Infrastructure;

namespace ProcInsider.Agent;

internal sealed record AgentInfrastructureEvidenceConnectivitySnapshot(
    InfrastructureEvidenceSpoolState State,
    bool SessionConnected,
    bool RemoteCommandEligible,
    int ConsecutiveFailures,
    DateTime? NextAttemptUtc,
    string LastErrorCode);

internal sealed class AgentInfrastructureEvidenceConnectivity
{
    private readonly object _gate = new();
    private int _failures;
    private bool _connected;
    private InfrastructureEvidenceSpoolState _state = InfrastructureEvidenceSpoolState.Offline;
    private DateTime? _nextAttemptUtc;
    private string _lastErrorCode = string.Empty;

    public AgentInfrastructureEvidenceConnectivitySnapshot Snapshot
    {
        get
        {
            lock (_gate)
            {
                return new(_state, _connected, _connected, _failures, _nextAttemptUtc, _lastErrorCode);
            }
        }
    }

    public void RecordConnected()
    {
        lock (_gate)
        {
            _connected = true;
            _failures = 0;
            _state = InfrastructureEvidenceSpoolState.Healthy;
            _nextAttemptUtc = null;
            _lastErrorCode = string.Empty;
        }
    }

    public TimeSpan RecordDisconnected(DateTime nowUtc, double fullJitterFraction, string errorCode)
    {
        lock (_gate)
        {
            _connected = false;
            _state = InfrastructureEvidenceSpoolState.Offline;
            _lastErrorCode = errorCode;
            _failures = checked(_failures + 1);
            var delay = InfrastructureReconnectBackoffPolicy.GetDelay(_failures, fullJitterFraction);
            _nextAttemptUtc = nowUtc + delay;
            return delay;
        }
    }

    public void RecordBackpressure(string errorCode)
    {
        lock (_gate)
        {
            _state = InfrastructureEvidenceSpoolState.Backpressured;
            _lastErrorCode = errorCode;
        }
    }

    public void RecordSpoolBlocked(string errorCode)
    {
        lock (_gate)
        {
            _state = InfrastructureEvidenceSpoolState.QuotaBlocked;
            _lastErrorCode = errorCode;
        }
    }
}

internal static class InfrastructureReconnectBackoffPolicy
{
    public static TimeSpan GetDelay(int consecutiveFailures, double fullJitterFraction)
    {
        if (consecutiveFailures <= 0 || double.IsNaN(fullJitterFraction) ||
            fullJitterFraction < 0 || fullJitterFraction > 1)
        {
            throw new ArgumentOutOfRangeException();
        }

        var exponent = Math.Min(consecutiveFailures - 1, 20);
        var ceilingSeconds = Math.Min(
            InfrastructureEvidenceInterchange.MaximumReconnectDelay.TotalSeconds,
            Math.Pow(2, exponent));
        var seconds = Math.Max(
            InfrastructureEvidenceInterchange.MinimumReconnectDelay.TotalSeconds,
            ceilingSeconds * fullJitterFraction);
        return TimeSpan.FromSeconds(Math.Min(
            seconds,
            InfrastructureEvidenceInterchange.MaximumReconnectDelay.TotalSeconds));
    }
}

internal interface IAgentInfrastructureEvidenceTransport
{
    Task<InfrastructureEvidenceAcknowledgementPayload> UploadAsync(
        InfrastructureEvidenceBatchPackage package,
        CancellationToken cancellationToken);
}

internal sealed record AgentInfrastructureEvidenceUploadResult(
    bool Completed,
    bool Retained,
    InfrastructureEvidenceFailure Failure,
    string ErrorCode,
    InfrastructureEvidenceAcknowledgementPayload? Acknowledgement = null);

internal sealed class AgentInfrastructureEvidenceUploader
{
    private readonly AgentInfrastructureEvidenceSpool _spool;
    private readonly AgentInfrastructureEvidenceOutbox? _outbox;
    private readonly IAgentInfrastructureEvidenceTransport _transport;
    private readonly AgentInfrastructureEvidenceConnectivity _connectivity;

    public AgentInfrastructureEvidenceUploader(
        AgentInfrastructureEvidenceSpool spool,
        IAgentInfrastructureEvidenceTransport transport,
        AgentInfrastructureEvidenceConnectivity connectivity)
    {
        _spool = spool ?? throw new ArgumentNullException(nameof(spool));
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _connectivity = connectivity ?? throw new ArgumentNullException(nameof(connectivity));
    }

    public AgentInfrastructureEvidenceUploader(
        AgentInfrastructureEvidenceSpool spool,
        AgentInfrastructureEvidenceOutbox outbox,
        IAgentInfrastructureEvidenceTransport transport,
        AgentInfrastructureEvidenceConnectivity connectivity)
    {
        _spool = spool ?? throw new ArgumentNullException(nameof(spool));
        _outbox = outbox ?? throw new ArgumentNullException(nameof(outbox));
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _connectivity = connectivity ?? throw new ArgumentNullException(nameof(connectivity));
    }

    public async Task<AgentInfrastructureEvidenceUploadResult> UploadNextAsync(
        CancellationToken cancellationToken)
    {
        if (_outbox == null)
        {
            return _spool.ListPending().Count == 0
                ? new(true, false, InfrastructureEvidenceFailure.None, "EvidenceSpoolEmpty")
                : new(false, true, InfrastructureEvidenceFailure.StoreUnavailable,
                    "EvidenceOutboxUnavailable");
        }

        var cleanupPending = _outbox.List(
            InfrastructureEvidenceOutboxState.AcknowledgedCleanupPending,
            maxCount: 1).FirstOrDefault();
        if (cleanupPending != null)
        {
            return await FinalizeDurableAcknowledgementAsync(
                    _spool,
                    _outbox,
                    _connectivity,
                    cleanupPending,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        var entry = _spool.ListPending().FirstOrDefault();
        if (entry == null)
        {
            if (_outbox.List(InfrastructureEvidenceOutboxState.Spooled, maxCount: 1).Count != 0)
            {
                return new(false, true, InfrastructureEvidenceFailure.StoreUnavailable,
                    "EvidenceSpoolPackageMissing");
            }
            return new(true, false, InfrastructureEvidenceFailure.None, "EvidenceSpoolEmpty");
        }

        var outboxEntry = _outbox.GetByBatchId(entry.Manifest.BatchId);
        if (outboxEntry?.State == InfrastructureEvidenceOutboxState.Quarantined &&
            MatchesPackage(outboxEntry, entry))
        {
            var errorCode = string.IsNullOrWhiteSpace(outboxEntry.LastErrorCode)
                ? "EvidenceUploadIdentityConflict"
                : outboxEntry.LastErrorCode;
            var quarantined = _spool.Quarantine(entry, errorCode);
            if (!quarantined)
            {
                _connectivity.RecordBackpressure("EvidenceSpoolQuarantinePending");
                return new(false, true, InfrastructureEvidenceFailure.StoreUnavailable,
                    "EvidenceSpoolQuarantinePending");
            }
            return new(false, true, InfrastructureEvidenceFailure.DuplicateConflict, errorCode);
        }
        if (outboxEntry == null ||
            outboxEntry.State != InfrastructureEvidenceOutboxState.Spooled ||
            !MatchesPackage(outboxEntry, entry))
        {
            return new(false, true, InfrastructureEvidenceFailure.StoreUnavailable,
                "EvidenceSpoolOutboxMismatch");
        }

        if (!_connectivity.Snapshot.SessionConnected)
        {
            return new(false, true, InfrastructureEvidenceFailure.SessionStale, "EvidenceSessionOffline");
        }

        InfrastructureEvidenceAcknowledgementPayload acknowledgement;
        try
        {
            acknowledgement = await _transport.UploadAsync(_spool.Load(entry), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new(false, true, InfrastructureEvidenceFailure.Canceled, "EvidenceUploadCanceled");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
        {
            _connectivity.RecordBackpressure("EvidenceUploadTransportFailed");
            return new(false, true, InfrastructureEvidenceFailure.StoreUnavailable, "EvidenceUploadTransportFailed");
        }

        if (acknowledgement.Outcome is InfrastructureEvidenceTransferOutcome.Committed or
            InfrastructureEvidenceTransferOutcome.DuplicateCommitted)
        {
            try
            {
                outboxEntry = await _outbox.RecordAcknowledgementAsync(
                    new InfrastructureEvidenceOutboxAcknowledgement
                    {
                        OutboxId = outboxEntry.OutboxId,
                        BatchId = entry.Manifest.BatchId,
                        ManifestSha256 = entry.Manifest.ManifestSha256,
                        PackageSha256 = entry.PackageSha256,
                        Outcome = acknowledgement.Outcome,
                        ServerCommitId = acknowledgement.CommitId,
                        ServerReceiptTimeUtc = acknowledgement.ServerReceiptTimeUtc,
                        RecordedAtUtc = DateTime.UtcNow
                    },
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return new(false, true, InfrastructureEvidenceFailure.Canceled,
                    "EvidenceAcknowledgementRecordingCanceled", acknowledgement);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
            {
                _connectivity.RecordBackpressure("EvidenceAcknowledgementPersistenceFailed");
                return new(false, true, InfrastructureEvidenceFailure.StoreUnavailable,
                    "EvidenceAcknowledgementPersistenceFailed", acknowledgement);
            }

            return await FinalizeDurableAcknowledgementAsync(
                    _spool,
                    _outbox,
                    _connectivity,
                    outboxEntry,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (acknowledgement.Outcome == InfrastructureEvidenceTransferOutcome.Conflict)
        {
            var errorCode = string.IsNullOrWhiteSpace(acknowledgement.ErrorCode)
                ? "EvidenceUploadIdentityConflict"
                : acknowledgement.ErrorCode;
            try
            {
                await _outbox.QuarantineAsync(
                    outboxEntry.OutboxId,
                    errorCode,
                    DateTime.UtcNow,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return new(false, true, InfrastructureEvidenceFailure.Canceled,
                    "EvidenceQuarantineRecordingCanceled", acknowledgement);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
            {
                _connectivity.RecordBackpressure("EvidenceQuarantinePersistenceFailed");
                return new(false, true, InfrastructureEvidenceFailure.StoreUnavailable,
                    "EvidenceQuarantinePersistenceFailed", acknowledgement);
            }

            if (!_spool.Quarantine(entry, errorCode))
            {
                _connectivity.RecordBackpressure("EvidenceSpoolQuarantinePending");
                return new(false, true, InfrastructureEvidenceFailure.StoreUnavailable,
                    "EvidenceSpoolQuarantinePending", acknowledgement);
            }
            return new(false, true, InfrastructureEvidenceFailure.DuplicateConflict,
                errorCode, acknowledgement);
        }

        return new(false, true,
            acknowledgement.Failure == InfrastructureEvidenceFailure.None
                ? InfrastructureEvidenceFailure.StoreUnavailable
                : acknowledgement.Failure,
            acknowledgement.ErrorCode,
            acknowledgement);
    }

    public static async Task<int> ConvergeAcknowledgedCleanupAsync(
        AgentInfrastructureEvidenceSpool spool,
        AgentInfrastructureEvidenceOutbox outbox,
        AgentInfrastructureEvidenceConnectivity connectivity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(spool);
        ArgumentNullException.ThrowIfNull(outbox);
        ArgumentNullException.ThrowIfNull(connectivity);
        var completed = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            var pending = outbox.List(
                InfrastructureEvidenceOutboxState.AcknowledgedCleanupPending,
                maxCount: 1).SingleOrDefault();
            if (pending == null)
            {
                return completed;
            }

            var result = await FinalizeDurableAcknowledgementAsync(
                    spool,
                    outbox,
                    connectivity,
                    pending,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!result.Completed)
            {
                return completed;
            }
            completed++;
        }
        return completed;
    }

    private static async Task<AgentInfrastructureEvidenceUploadResult> FinalizeDurableAcknowledgementAsync(
        AgentInfrastructureEvidenceSpool spool,
        AgentInfrastructureEvidenceOutbox outbox,
        AgentInfrastructureEvidenceConnectivity connectivity,
        InfrastructureEvidenceOutboxEntry outboxEntry,
        CancellationToken cancellationToken)
    {
        var acknowledgement = DurableAcknowledgement(outboxEntry);
        if (!spool.FinalizeAcknowledgement(
                outboxEntry.BatchId,
                outboxEntry.ManifestSha256,
                outboxEntry.PackageSha256,
                acknowledgement))
        {
            connectivity.RecordBackpressure("EvidenceAcknowledgementCleanupPending");
            return new(false, true, InfrastructureEvidenceFailure.StoreUnavailable,
                "EvidenceAcknowledgementCleanupPending", acknowledgement);
        }

        try
        {
            await outbox.CompleteCleanupAsync(
                outboxEntry.OutboxId,
                DateTime.UtcNow,
                cancellationToken).ConfigureAwait(false);
            return new(true, false, InfrastructureEvidenceFailure.None, string.Empty, acknowledgement);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new(false, true, InfrastructureEvidenceFailure.Canceled,
                "EvidenceAcknowledgementCleanupRecordingCanceled", acknowledgement);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
        {
            connectivity.RecordBackpressure("EvidenceAcknowledgementCleanupRecordingFailed");
            return new(false, true, InfrastructureEvidenceFailure.StoreUnavailable,
                "EvidenceAcknowledgementCleanupRecordingFailed", acknowledgement);
        }
    }

    private static bool MatchesPackage(
        InfrastructureEvidenceOutboxEntry outboxEntry,
        AgentInfrastructureEvidenceSpoolEntry spoolEntry) =>
        string.Equals(outboxEntry.BatchId, spoolEntry.Manifest.BatchId, StringComparison.Ordinal) &&
        string.Equals(outboxEntry.ManifestSha256, spoolEntry.Manifest.ManifestSha256, StringComparison.Ordinal) &&
        string.Equals(outboxEntry.PackageSha256, spoolEntry.PackageSha256, StringComparison.Ordinal);

    private static InfrastructureEvidenceAcknowledgementPayload DurableAcknowledgement(
        InfrastructureEvidenceOutboxEntry entry)
    {
        if (entry.State is not (InfrastructureEvidenceOutboxState.AcknowledgedCleanupPending or
                InfrastructureEvidenceOutboxState.Completed) ||
            entry.ServerReceiptTimeUtc is not { } receiptTimeUtc)
        {
            throw new InvalidDataException("The evidence outbox entry does not contain a durable acknowledgement.");
        }

        return new InfrastructureEvidenceAcknowledgementPayload
        {
            BatchId = entry.BatchId,
            ManifestSha256 = entry.ManifestSha256,
            Outcome = entry.AcknowledgementOutcome,
            Failure = InfrastructureEvidenceFailure.None,
            CommitId = entry.ServerCommitId,
            ServerReceiptTimeUtc = receiptTimeUtc
        };
    }
}

internal sealed class AgentInfrastructureEvidenceStreamTransport : IAgentInfrastructureEvidenceTransport
{
    private readonly AgentInfrastructureSessionConnection _connection;

    public AgentInfrastructureEvidenceStreamTransport(AgentInfrastructureSessionConnection connection)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
    }

    public async Task<InfrastructureEvidenceAcknowledgementPayload> UploadAsync(
        InfrastructureEvidenceBatchPackage package,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(package);
        if (!_connection.Negotiation.NegotiatedCapabilities.Contains(
                InfrastructureSessionCapabilities.EvidenceTransferV1,
                StringComparer.Ordinal))
        {
            return Rejected(package.Manifest, Guid.NewGuid(), InfrastructureEvidenceFailure.CapabilityUnavailable,
                "EvidenceTransferCapabilityUnavailable");
        }

        var transferId = Guid.NewGuid();
        var prepare = new InfrastructureEvidenceTransferMessage
        {
            Kind = InfrastructureSessionMessageKind.EvidenceBatchManifest,
            BatchPrepare = new InfrastructureEvidenceBatchPreparePayload
            {
                TransferId = transferId,
                Manifest = package.Manifest
            }
        };
        var acknowledgement = await SendAndReadAcknowledgementAsync(prepare, cancellationToken).ConfigureAwait(false);
        if (IsTerminal(acknowledgement))
        {
            return acknowledgement;
        }

        acknowledgement = await SendContentAsync(
            package.Manifest.BatchId,
            package.Manifest.BatchId,
            InfrastructureEvidenceContentKind.BatchPayload,
            package.Payload,
            InfrastructureEvidenceInterchange.MaximumDecodedChunkBytes,
            transferId,
            acknowledgement.NextChunkIndex,
            cancellationToken).ConfigureAwait(false);
        if (IsTerminal(acknowledgement))
        {
            return acknowledgement;
        }

        foreach (var artifact in package.Artifacts)
        {
            var artifactPrepare = new InfrastructureEvidenceTransferMessage
            {
                Kind = InfrastructureSessionMessageKind.EvidenceArtifactManifest,
                ArtifactPrepare = new InfrastructureEvidenceArtifactPreparePayload
                {
                    TransferId = transferId,
                    BatchId = package.Manifest.BatchId,
                    Artifact = artifact.Reference
                }
            };
            acknowledgement = await SendAndReadAcknowledgementAsync(artifactPrepare, cancellationToken)
                .ConfigureAwait(false);
            if (IsTerminal(acknowledgement))
            {
                return acknowledgement;
            }
            acknowledgement = await SendContentAsync(
                package.Manifest.BatchId,
                artifact.Reference.ArtifactId,
                InfrastructureEvidenceContentKind.Artifact,
                artifact.Bytes,
                artifact.Reference.ChunkBytes,
                transferId,
                acknowledgement.NextChunkIndex,
                cancellationToken).ConfigureAwait(false);
            if (IsTerminal(acknowledgement))
            {
                return acknowledgement;
            }
        }

        return await SendAndReadAcknowledgementAsync(new InfrastructureEvidenceTransferMessage
        {
            Kind = InfrastructureSessionMessageKind.EvidenceCommit,
            Commit = new InfrastructureEvidenceCommitPayload
            {
                TransferId = transferId,
                BatchId = package.Manifest.BatchId,
                ManifestSha256 = package.Manifest.ManifestSha256
            }
        }, cancellationToken).ConfigureAwait(false);
    }

    private async Task<InfrastructureEvidenceAcknowledgementPayload> SendContentAsync(
        string batchId,
        string contentId,
        InfrastructureEvidenceContentKind contentKind,
        byte[] content,
        int chunkBytes,
        Guid transferId,
        int nextChunkIndex,
        CancellationToken cancellationToken)
    {
        var index = nextChunkIndex;
        var offset = checked(index * chunkBytes);
        if (offset > content.Length)
        {
            return Rejected(null, transferId, InfrastructureEvidenceFailure.ChunkOutOfOrder,
                "EvidenceResumeOffsetInvalid", batchId);
        }
        InfrastructureEvidenceAcknowledgementPayload? acknowledgement = null;
        while (offset < content.Length)
        {
            var length = Math.Min(chunkBytes, content.Length - offset);
            var bytes = content.AsSpan(offset, length).ToArray();
            acknowledgement = await SendAndReadAcknowledgementAsync(new InfrastructureEvidenceTransferMessage
            {
                Kind = InfrastructureSessionMessageKind.EvidenceContentChunk,
                Chunk = new InfrastructureEvidenceContentChunkPayload
                {
                    TransferId = transferId,
                    BatchId = batchId,
                    ContentKind = contentKind,
                    ContentId = contentId,
                    ChunkIndex = index,
                    Offset = offset,
                    IsFinal = offset + length == content.Length,
                    Sha256 = InfrastructureEvidenceBatchCodec.Hash(bytes),
                    Bytes = bytes
                }
            }, cancellationToken).ConfigureAwait(false);
            if (IsTerminal(acknowledgement) || acknowledgement.NextChunkIndex != index + 1)
            {
                return acknowledgement;
            }
            index++;
            offset += length;
        }

        return acknowledgement ?? Rejected(null, transferId, InfrastructureEvidenceFailure.TransferIncomplete,
            "EvidenceContentEmpty", batchId);
    }

    private async Task<InfrastructureEvidenceAcknowledgementPayload> SendAndReadAcknowledgementAsync(
        InfrastructureEvidenceTransferMessage message,
        CancellationToken cancellationToken)
    {
        var sent = await _connection.SendEvidenceAsync(message, cancellationToken).ConfigureAwait(false);
        if (!sent.Allowed)
        {
            return Rejected(
                message.BatchPrepare?.Manifest,
                TransferId(message),
                InfrastructureEvidenceFailure.SessionStale,
                sent.ErrorCode,
                BatchId(message));
        }

        var read = await _connection.ReadEvidenceAsync(cancellationToken).ConfigureAwait(false);
        var acknowledgement = read.Envelope?.EvidenceTransfer?.Acknowledgement;
        if (!read.Decision.Allowed || acknowledgement == null ||
            acknowledgement.TransferId != TransferId(message) ||
            !string.Equals(acknowledgement.BatchId, BatchId(message), StringComparison.Ordinal))
        {
            return Rejected(
                message.BatchPrepare?.Manifest,
                TransferId(message),
                InfrastructureEvidenceFailure.SessionStale,
                read.Decision.ErrorCode,
                BatchId(message));
        }
        return acknowledgement;
    }

    private static Guid TransferId(InfrastructureEvidenceTransferMessage message) =>
        message.BatchPrepare?.TransferId ?? message.ArtifactPrepare?.TransferId ??
        message.Chunk?.TransferId ?? message.Commit?.TransferId ?? Guid.Empty;

    private static string BatchId(InfrastructureEvidenceTransferMessage message) =>
        message.BatchPrepare?.Manifest.BatchId ?? message.ArtifactPrepare?.BatchId ??
        message.Chunk?.BatchId ?? message.Commit?.BatchId ?? string.Empty;

    private static bool IsTerminal(InfrastructureEvidenceAcknowledgementPayload acknowledgement) =>
        acknowledgement.Outcome is InfrastructureEvidenceTransferOutcome.Committed or
            InfrastructureEvidenceTransferOutcome.DuplicateCommitted or
            InfrastructureEvidenceTransferOutcome.Rejected or
            InfrastructureEvidenceTransferOutcome.Conflict or
            InfrastructureEvidenceTransferOutcome.Incomplete;

    private static InfrastructureEvidenceAcknowledgementPayload Rejected(
        InfrastructureEvidenceBatchManifest? manifest,
        Guid transferId,
        InfrastructureEvidenceFailure failure,
        string errorCode,
        string? batchId = null) => new()
    {
        TransferId = transferId,
        BatchId = batchId ?? manifest?.BatchId ?? "batch-unavailable",
        ManifestSha256 = manifest?.ManifestSha256 ?? new string('0', 64),
        Outcome = InfrastructureEvidenceTransferOutcome.Rejected,
        Failure = failure,
        ErrorCode = string.IsNullOrWhiteSpace(errorCode) ? "EvidenceTransferRejected" : errorCode,
        ServerReceiptTimeUtc = DateTime.UtcNow
    };
}
