using ProcInsider.Models.EvidenceSources;
using ProcInsider.Models;

namespace ProcInsider.Agent;

/// <summary>
/// The only durable publisher used by built-in evidence-source adapters. It
/// validates bounded output and delegates every write to AgentStagingWriter.
/// </summary>
internal sealed class AgentEvidenceSourcePublisher : IEvidenceSourcePublisher
{
    private readonly AgentStagingWriter _writer;

    public AgentEvidenceSourcePublisher(AgentStagingWriter writer)
    {
        _writer = writer ?? throw new ArgumentNullException(nameof(writer));
        MaxBatchRowCount = Math.Max(1, writer.GetSnapshot().MaxRowsPerTransaction);
    }

    public int MaxBatchRowCount { get; }

    public async ValueTask<EvidenceSourcePublishResult> PublishAsync(
        EvidenceSourceEmissionBatch batch,
        CancellationToken cancellationToken)
    {
        ValidateBatch(batch, MaxBatchRowCount);
        var persisted = 0;
        var duplicates = 0;
        try
        {
            if (batch.ProcessObservations.Count > 0 || batch.ProcessAliases.Count > 0)
            {
                var result = await _writer.AppendProcessObservationBatchAsync(
                        batch.ProcessObservations,
                        batch.ProcessAliases,
                        batch.ProcessStatistics,
                        cancellationToken)
                    .ConfigureAwait(false);
                persisted += result.PersistedRowCount;
                duplicates += result.DuplicateRowCount;
            }
            else if (batch.Processes.Count > 0 || batch.ProcessStatistics.Count > 0)
            {
                await _writer.UpsertProcessBatchAsync(
                        batch.Processes,
                        batch.ProcessStatistics,
                        cancellationToken)
                    .ConfigureAwait(false);
                persisted += batch.Processes.Count + batch.ProcessStatistics.Count;
            }

            if (batch.Events.Count > 0)
            {
                await _writer.AddEventsAsync(batch.Events, cancellationToken).ConfigureAwait(false);
                persisted += batch.Events.Count;
            }

            if (batch.FilesystemArtifacts.Count > 0)
            {
                await _writer.UpsertFilesystemArtifactsAsync(batch.FilesystemArtifacts, cancellationToken)
                    .ConfigureAwait(false);
                persisted += batch.FilesystemArtifacts.Count;
            }

            if (batch.NetworkCaptures.Count > 0)
            {
                await _writer.UpsertNetworkCapturesAsync(batch.NetworkCaptures, cancellationToken)
                    .ConfigureAwait(false);
                persisted += batch.NetworkCaptures.Count;
            }

            if (batch.ZeekNetworkArtifacts.Count > 0)
            {
                await _writer.UpsertZeekNetworkArtifactsAsync(batch.ZeekNetworkArtifacts, cancellationToken)
                    .ConfigureAwait(false);
                persisted += batch.ZeekNetworkArtifacts.Count;
            }

            if (batch.MemoryImages.Count > 0)
            {
                await _writer.UpsertMemoryImagesAsync(batch.MemoryImages, cancellationToken)
                    .ConfigureAwait(false);
                persisted += batch.MemoryImages.Count;
            }

            if (batch.VolatilityPluginRuns.Count > 0)
            {
                await _writer.UpsertVolatilityPluginRunsAsync(batch.VolatilityPluginRuns, cancellationToken)
                    .ConfigureAwait(false);
                persisted += batch.VolatilityPluginRuns.Count;
            }

            if (batch.MemoryProcesses.Count > 0)
            {
                await _writer.UpsertMemoryProcessesAsync(batch.MemoryProcesses, cancellationToken)
                    .ConfigureAwait(false);
                persisted += batch.MemoryProcesses.Count;
            }

            if (batch.Relations.Count > 0)
            {
                await _writer.UpsertEvidenceRelationsAsync(batch.Relations, cancellationToken)
                    .ConfigureAwait(false);
                persisted += batch.Relations.Count;
            }

            return new EvidenceSourcePublishResult
            {
                PersistedRowCount = persisted,
                DuplicateRowCount = duplicates
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new EvidenceSourcePublishException(
                $"Evidence source batch {batch.Sequence} failed after {persisted:N0} durable row(s): {ex.Message}",
                persisted,
                ex);
        }
    }

    internal static void ValidateBatch(EvidenceSourceEmissionBatch batch, int maxBatchRowCount)
    {
        ArgumentNullException.ThrowIfNull(batch);
        if (string.IsNullOrWhiteSpace(batch.SourceRunId) || batch.IngestionJobId == Guid.Empty)
        {
            throw new InvalidOperationException("Evidence source batches require exact source-run and ingestion-job provenance.");
        }

        if (batch.Sequence <= 0)
        {
            throw new InvalidOperationException("Evidence source batch sequence numbers must be positive.");
        }

        if (batch.RowCount > Math.Max(1, maxBatchRowCount))
        {
            throw new InvalidOperationException(
                $"Evidence source batch contains {batch.RowCount:N0} durable rows; the publisher limit is {maxBatchRowCount:N0}.");
        }

        if (batch.Identities.Any(identity =>
                string.IsNullOrWhiteSpace(identity.EvidenceId) ||
                string.IsNullOrWhiteSpace(identity.ExternalIdentity) ||
                string.IsNullOrWhiteSpace(identity.DeduplicationKey)))
        {
            throw new InvalidOperationException(
                "Every evidence source emission identity requires evidence, external, and deduplication identities.");
        }

        if (batch.Identities
            .GroupBy(identity => identity.DeduplicationKey, StringComparer.Ordinal)
            .Any(group => group.Count() > 1))
        {
            throw new InvalidOperationException("An evidence source batch emitted duplicate deduplication keys.");
        }


        if (batch.Processes.Count > 0 && batch.ProcessObservations.Count > 0)
        {
            throw new InvalidOperationException(
                "Evidence adapters cannot mix compatibility process rows with normalized process observations.");
        }

        if (batch.ProcessObservations.Any(observation =>
                string.IsNullOrWhiteSpace(observation.ObservationId) ||
                string.IsNullOrWhiteSpace(observation.AdapterId) ||
                string.IsNullOrWhiteSpace(observation.ProcessEntityId) ||
                !string.Equals(observation.SourceRunId, batch.SourceRunId, StringComparison.Ordinal) ||
                observation.IngestionJobId != batch.IngestionJobId ||
                string.IsNullOrWhiteSpace(observation.Fields.ProcessEntityId)))
        {
            throw new InvalidOperationException(
                "Normalized process observations require immutable identity and exact batch provenance.");
        }
    }
}
