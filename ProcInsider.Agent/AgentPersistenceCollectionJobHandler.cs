using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Persistence;
using ProcInsider.Services;
using ProcInsider.Services.Persistence;

namespace ProcInsider.Agent;

internal sealed class AgentPersistenceCollectionJobHandler(
    AgentStagingWriter writer, AgentPersistenceCaptureWorkflow workflow, TextWriter log,
    Func<EvidenceIdentity, IReadOnlyList<IPersistenceCollector>>? collectorFactory = null,
    Func<PersistenceCollection, CancellationToken, ValueTask<PersistenceAcceptance>>? acceptance = null,
    Func<DateTime>? utcNow = null,
    Func<EvidenceIdentity, CancellationToken, ValueTask<PersistenceAcceptedState?>>? recovery = null) : IAgentJobHandler
{
    public async Task ExecuteAsync(AgentJobContext context)
    {
        var parameters = JsonSerializer.Deserialize<AgentPersistenceCollectionParameters>(context.Request.ToParametersJson(), AgentJson.JsonOptions)
            ?? throw new InvalidDataException("Persistence collection parameters missing.");
        workflow.EnsureCurrent(context, parameters.CaptureGeneration);
        var state = workflow.GetAcceptedState(context, parameters.CaptureGeneration);
        if (state == null)
        {
            state = await RecoverAsync(context.Request.EvidenceIdentity, context.CancellationToken).ConfigureAwait(false);
            if (state != null) state = state with { BaselineRelative = PersistenceComparisonPolicy.CompareBaseline(state) };
            workflow.CacheAcceptedState(context, parameters.CaptureGeneration, state, recovered: true);
        }
        var checkpoint = state?.Checkpoint;
        var dailyBoundary = workflow.IsBoundaryDue(context, parameters.CaptureGeneration);
        var reset = parameters.Reason == PersistenceCollectionReason.Rebaseline || dailyBoundary;
        var started = (utcNow ?? (() => workflow.UtcNow))();
        var results = new List<PersistenceCollectorResult>();
        workflow.EnsureCurrent(context, parameters.CaptureGeneration);
        var collectors = (collectorFactory ?? (identity => [new RegistryRunCollector(identity), new ScheduledTasksCollector(identity), new ServicesDriversCollector(identity), new StartupFoldersCollector(identity), new WmiSubscriptionsCollector(identity), new WinlogonCollector(identity), new IfeoCollector(identity), new AppInitCollector(identity), new LsaCollector(identity)]))(context.Request.EvidenceIdentity);
        foreach (var collector in collectors)
        {
            workflow.EnsureCurrent(context, parameters.CaptureGeneration);
            foreach (var result in await collector.CollectAsync(context.Request.EvidenceIdentity, context.CancellationToken).ConfigureAwait(false))
            {
                var effective = result;
                if (result.Status == PersistenceCollectionStatus.Complete)
                {
                    try { _ = PersistenceComparisonPolicy.Inventory(result.Artifacts); }
                    catch (InvalidDataException) { effective = result with { Status = PersistenceCollectionStatus.Failed, DiagnosticSummary = "Conflicting duplicate persistence location." }; }
                }
                results.Add(effective);
            }
        }
        workflow.EnsureCurrent(context, parameters.CaptureGeneration);
        var completed = (utcNow ?? (() => workflow.UtcNow))();
        var collection = new PersistenceCollection
        {
            EvidenceIdentity = context.Request.EvidenceIdentity, SourceRunId = context.SourceRunId,
            IngestionJobId = context.Request.JobId.ToString("D"), CollectionId = "pcol_" + Guid.NewGuid().ToString("N"),
            StateGenerationId = reset || checkpoint == null ? "pgen_" + Guid.NewGuid().ToString("N") : checkpoint.StateGenerationId,
            CollectionSequence = reset || checkpoint == null ? 1 : checkpoint.CollectionSequence + 1,
            ExpectedPredecessorCollectionId = checkpoint?.CollectionId, Reason = reset ? PersistenceCollectionReason.Rebaseline : parameters.Reason,
            ResetReason = parameters.Reason == PersistenceCollectionReason.Rebaseline ? parameters.ResetReason : dailyBoundary ? "24 elapsed hours since the accepted persistence baseline." : "",
            StartedUtc = started, CompletedUtc = completed, Results = results
        };
        // Keep the exact frozen payload/run/job/predecessor through retries; never recollect a failed commit.
        collection = JsonSerializer.Deserialize<PersistenceCollection>(JsonSerializer.Serialize(collection))!;
        // Calculate against the accepted cache; the writer independently verifies P and all transitions.
        var transitions = new List<PersistenceVersion>();
        foreach (var result in collection.Results.Where(r => r.Status == PersistenceCollectionStatus.Complete))
        {
            var partition = PersistenceComparisonPolicy.PartitionKey(result.CollectorId, result.Coverage);
            transitions.AddRange(PersistenceComparisonPolicy.Diff(collection, result, state?.Previous.GetValueOrDefault(partition)));
        }
        PersistenceAcceptance accepted;
        for (var attempt = 0; ; attempt++)
        {
            workflow.EnsureCurrent(context, parameters.CaptureGeneration);
            try
            {
                accepted = acceptance != null ? await acceptance(collection, context.CancellationToken).ConfigureAwait(false)
                    : await writer.AcceptPersistenceCollectionAsync(collection, context.CancellationToken,
                        commit => workflow.CommitIfCurrent(context, parameters.CaptureGeneration, commit)).ConfigureAwait(false);
                break;
            }
            catch (OperationCanceledException)
            {
                // The writer may have committed before cancellation wins delivery of its reply.
                // Never retain a predecessor whose durable acceptance is now unknown. The next
                // admitted child recovers verified state through the serialized writer first.
                workflow.CacheAcceptedState(context, parameters.CaptureGeneration, null);
                throw;
            }
            catch (Exception ex) when (attempt < 2 && (ex is SqliteException or IOException))
            {
                // Reconciliation and retry waits can themselves be cancelled. Invalidate before
                // either await so every uncertain acceptance outcome forces verified recovery.
                workflow.CacheAcceptedState(context, parameters.CaptureGeneration, null);
                var committed = await writer.GetPersistenceCheckpointAsync(context.Request.EvidenceIdentity, context.CancellationToken).ConfigureAwait(false);
                if (committed != null && committed.CollectionId != collection.CollectionId && committed.CollectionId != checkpoint?.CollectionId)
                    throw new InvalidDataException("Persistence acceptance cannot reconcile a different committed collection.");
                log.WriteLine($"Persistence acceptance attempt {attempt + 1} reconciled; retrying the exact collection identity.");
                await Task.Delay(TimeSpan.FromMilliseconds(50 * (attempt + 1)), context.CancellationToken).ConfigureAwait(false);
            }
            catch (Exception) when (!context.CancellationToken.IsCancellationRequested)
            {
                workflow.RecordAcceptanceFailure(context, parameters.CaptureGeneration, results);
                throw;
            }
        }
        // A known commit also makes the old predecessor obsolete. Keep the cache empty across
        // reconstruction, identity verification and comparison failures until verified publication.
        workflow.CacheAcceptedState(context, parameters.CaptureGeneration, null);
        var durable = await RecoverAsync(context.Request.EvidenceIdentity, CancellationToken.None).ConfigureAwait(false);
        if (durable?.Checkpoint.CollectionId != accepted.CollectionId) throw new InvalidDataException("Persistence accepted cache identity cannot be reconciled.");
        durable = durable with { BaselineRelative = PersistenceComparisonPolicy.CompareBaseline(durable) };
        workflow.CacheAcceptedState(context, parameters.CaptureGeneration, durable);
        workflow.RecordAccepted(results, completed);
        context.SetSourceRunCompletion(accepted.Status.ToString(), JsonSerializer.Serialize(new { accepted.CollectionId, accepted.Status, accepted.VersionCount, accepted.BoundaryDeferred, ObservedTransitions = transitions.Count(v => v.Kind != PersistenceChangeKind.Baseline), BaselineRelativeDifferences = durable.BaselineRelative.Count, Counts = results.Select(result => new { result.CollectorId, result.Status, Count = result.Artifacts.Count }) }));
        await context.ReportProgressAsync(results.Sum(result => result.Artifacts.Count), results.Sum(result => result.Artifacts.Count),
            $"Persistence committed: {accepted.Status}; {accepted.VersionCount} versions; {results.Sum(result => result.Artifacts.Count)} observed artifacts. {(accepted.BoundaryDeferred ? "Baseline deferred: required coverage is incomplete." : "")}").ConfigureAwait(false);
        if (accepted.BoundaryDeferred)
            throw new InvalidOperationException("Persistence baseline deferred: required coverage is incomplete. The partial observation was durably accepted and the active baseline period was retained.");
    }
    private ValueTask<PersistenceAcceptedState?> RecoverAsync(EvidenceIdentity identity, CancellationToken token)
        => recovery != null ? recovery(identity, token) : writer.RecoverPersistenceStateAsync(identity, token);
}
