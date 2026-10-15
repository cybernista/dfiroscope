using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services;

/// <summary>History and comparison projections share the store's serialized transaction.</summary>
internal sealed class PersistenceEvidenceWriteService(SqliteWriteTransactionContext context)
{
    internal const string SchemaSql = """
        CREATE TABLE IF NOT EXISTS PersistenceCollections(
            CollectionId TEXT PRIMARY KEY, ScopeKey TEXT NOT NULL, GenerationId TEXT NOT NULL,
            Sequence INTEGER NOT NULL, PayloadHash TEXT NOT NULL, SourceRunId TEXT NOT NULL,
            IngestionJobId TEXT NOT NULL, Status TEXT NOT NULL, VersionCount INTEGER NOT NULL,
            MetadataJson TEXT NOT NULL, MetadataHash TEXT NOT NULL, UNIQUE(ScopeKey, GenerationId, Sequence));
        CREATE TABLE IF NOT EXISTS PersistenceCollectorResults(
            CollectionId TEXT NOT NULL, PartitionKey TEXT NOT NULL, ResultJson TEXT NOT NULL, ResultHash TEXT NOT NULL,
            PRIMARY KEY(CollectionId, PartitionKey));
        CREATE TABLE IF NOT EXISTS PersistenceVersions(
            CollectionId TEXT NOT NULL, PartitionKey TEXT NOT NULL, ArtifactKey TEXT NOT NULL,
            VersionJson TEXT NOT NULL, VersionHash TEXT NOT NULL, PRIMARY KEY(CollectionId, PartitionKey, ArtifactKey));
        CREATE TABLE IF NOT EXISTS PersistenceCurrent(
            ScopeKey TEXT NOT NULL, PartitionKey TEXT NOT NULL, ArtifactKey TEXT NOT NULL,
            GenerationId TEXT NOT NULL, ArtifactJson TEXT NOT NULL, Fingerprint TEXT NOT NULL,
            LastConfirmedUtc TEXT NOT NULL, Stale INTEGER NOT NULL,
            PRIMARY KEY(ScopeKey, PartitionKey, ArtifactKey));
        CREATE TABLE IF NOT EXISTS PersistenceCheckpoints(
            ScopeKey TEXT NOT NULL, GenerationId TEXT NOT NULL, PartitionKey TEXT NOT NULL,
            InventoryHash TEXT NOT NULL, PRIMARY KEY(ScopeKey, GenerationId, PartitionKey));
        CREATE TABLE IF NOT EXISTS PersistenceSequenceState(
            ScopeKey TEXT PRIMARY KEY, GenerationId TEXT NOT NULL, Sequence INTEGER NOT NULL,
            CollectionId TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS IX_PersistenceCollections_Scope ON PersistenceCollections(ScopeKey, GenerationId, Sequence);
        """;

    public PersistenceAcceptance Accept(PersistenceCollection collection, CancellationToken cancellationToken, bool boundaryUse = false)
    {
        // Freeze caller-owned lists/dictionaries before enqueue callers can mutate them.
        collection = Deserialize<PersistenceCollection>(JsonSerializer.Serialize(collection));
        Validate(collection);
        if (!boundaryUse && (collection.BoundaryAcquisitionId != null || collection.BoundaryPreviousPeriodId != null || collection.DeferredBaselineGenerationId != null))
            throw new InvalidDataException("Boundary use metadata belongs to authoritative writer acceptance.");
        var payloadHash = PersistenceComparisonPolicy.Hash(PersistenceComparisonPolicy.CanonicalJson(JsonSerializer.Serialize(collection)));
        var scope = PersistenceComparisonPolicy.ScopeKey(collection.EvidenceIdentity);
        PersistenceAcceptance? accepted = null;
        cancellationToken.ThrowIfCancellationRequested();
        context.Execute(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidateWriterProvenance(collection);
            ValidateSourceRun(collection);
            VerifyAuthoritativeHistory(scope);
            PersistenceAcceptance? replayAcceptance = null;
            using (var replay = Command("SELECT PayloadHash, Status, VersionCount,MetadataJson FROM PersistenceCollections WHERE CollectionId=$id", ("$id", collection.CollectionId)))
            using (var reader = replay.ExecuteReader())
            {
                if (reader.Read())
                {
                    if (reader.GetString(0) != payloadHash) throw new InvalidDataException("Conflicting persistence collection replay.");
                    replayAcceptance = new(collection.CollectionId, true, Enum.Parse<PersistenceCollectionStatus>(reader.GetString(1)), reader.GetInt32(2), Deserialize<PersistenceCollection>(reader.GetString(3)).DeferredBaselineGenerationId != null);
                }
            }
            if (replayAcceptance != null) { accepted = replayAcceptance; return; }
            var predecessor = ReadSequence(scope);
            if (predecessor != null && collection.Reason == PersistenceCollectionReason.Rebaseline)
            {
                if (collection.StateGenerationId == predecessor.StateGenerationId || collection.CollectionSequence != 1 ||
                    collection.ExpectedPredecessorCollectionId != predecessor.CollectionId || string.IsNullOrWhiteSpace(collection.ResetReason))
                    throw new InvalidDataException("A boundary requires a fresh period and the exact accepted predecessor.");
                if (ComparisonStateDamaged(scope, predecessor))
                    throw new InvalidDataException("Damaged comparison state requires explicit recovery before a boundary.");
                var complete = collection.Results.Where(r => r.Status == PersistenceCollectionStatus.Complete && r.Coverage.SourceAvailability == PersistenceSourceAvailability.Available)
                    .ToDictionary(r => PersistenceComparisonPolicy.PartitionKey(r.CollectorId, r.Coverage), StringComparer.Ordinal);
                var established = ReadJson("SELECT PartitionKey FROM PersistenceCheckpoints WHERE ScopeKey=$s AND GenerationId=$g", ("$s", scope), ("$g", predecessor.StateGenerationId));
                // Explicit unattempted Startup-profile exclusions remain unavailable evidence;
                // they cannot establish absence, nor veto a fully observed boundary.
                var required = collection.Results.Where(result => !PersistenceComparisonPolicy.IsUnattemptedStartupProfile(result)).ToArray();
                var eligible = required.Length > 0 && required.All(result => complete.ContainsKey(PersistenceComparisonPolicy.PartitionKey(result.CollectorId, result.Coverage))) && established.All(complete.ContainsKey);
                if (eligible)
                    try { foreach (var result in complete.Values) _ = PersistenceComparisonPolicy.Inventory(result.Artifacts); }
                    catch (InvalidDataException) { eligible = false; }
                if (!eligible)
                    collection = collection with { DeferredBaselineGenerationId = collection.StateGenerationId,
                        StateGenerationId = predecessor.StateGenerationId, CollectionSequence = predecessor.CollectionSequence + 1,
                        Reason = PersistenceCollectionReason.UserRequested };
                else
                {
                    var acquisition = collection.CollectionId;
                    var final = collection with { CollectionId = acquisition + ".final", StateGenerationId = predecessor.StateGenerationId,
                        CollectionSequence = predecessor.CollectionSequence + 1, Reason = PersistenceCollectionReason.UserRequested,
                        BoundaryAcquisitionId = acquisition, BoundaryPreviousPeriodId = predecessor.StateGenerationId };
                    Accept(final, cancellationToken, boundaryUse: true); // Nested store transaction: neither use can commit alone.
                    collection = collection with { ExpectedPredecessorCollectionId = final.CollectionId,
                        BoundaryAcquisitionId = acquisition, BoundaryPreviousPeriodId = predecessor.StateGenerationId };
                    predecessor = ReadSequence(scope);
                }
            }
            if (predecessor != null)
            {
                var priorMetadata = ReadVerifiedJson("SELECT MetadataJson,MetadataHash FROM PersistenceCollections WHERE CollectionId=$id", ("$id", predecessor.CollectionId)).Single();
                var priorCollection = Deserialize<PersistenceCollection>(priorMetadata);
                if (collection.StartedUtc < priorCollection.StartedUtc || collection.CompletedUtc < priorCollection.CompletedUtc)
                    throw new InvalidDataException("Persistence observation interval cannot move backwards.");
            }
            var newGeneration = predecessor == null || predecessor.StateGenerationId != collection.StateGenerationId;
            if (newGeneration)
            {
                if (collection.CollectionSequence != 1 || collection.ExpectedPredecessorCollectionId != predecessor?.CollectionId)
                    throw new InvalidDataException("A generation must start at sequence one with the exact predecessor.");
                if (predecessor != null)
                {
                    var stateDamaged = ComparisonStateDamaged(scope, predecessor);
                    if (collection.Reason is not (PersistenceCollectionReason.Rebaseline or PersistenceCollectionReason.ComparisonStateRecovery) || string.IsNullOrWhiteSpace(collection.ResetReason))
                        throw new InvalidDataException("A comparison reset requires an explicit reason.");
                    if (collection.Reason == PersistenceCollectionReason.ComparisonStateRecovery && !stateDamaged)
                        throw new InvalidDataException("Comparison-state recovery requires verified projection loss or corruption.");
                    RestoreLastKnown(scope);
                }
                if (Scalar("SELECT COUNT(*) FROM PersistenceCollections WHERE ScopeKey=$s AND GenerationId=$g", ("$s", scope), ("$g", collection.StateGenerationId)) != 0)
                    throw new InvalidDataException("A historical persistence generation cannot be reused.");
            }
            else if (collection.CollectionSequence != predecessor!.CollectionSequence + 1 || collection.ExpectedPredecessorCollectionId != predecessor.CollectionId)
                throw new InvalidDataException("Unexpected persistence predecessor or stale/gapped sequence.");
            else if (collection.Reason is PersistenceCollectionReason.Rebaseline or PersistenceCollectionReason.ComparisonStateRecovery)
                throw new InvalidDataException("A comparison reset requires a new generation.");
            else if (ComparisonStateDamaged(scope, predecessor))
                throw new InvalidDataException("Persistence comparison state is damaged; explicit recovery is required.");

            Execute("UPDATE PersistenceCurrent SET Stale=1 WHERE ScopeKey=$s", ("$s", scope));
            var versionCount = 0;
            var effectiveResults = new List<PersistenceCollectorResult>();
            foreach (var originalResult in collection.Results)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = originalResult;
                var partition = PersistenceComparisonPolicy.PartitionKey(result.CollectorId, result.Coverage);
                IReadOnlyDictionary<string, PersistenceArtifact>? inventory = null;
                if (result.Status == PersistenceCollectionStatus.Complete ||
                    result.Status == PersistenceCollectionStatus.Partial && result.CollectorId == "persistence.services-drivers.v1" &&
                    result.Coverage.SourceAvailability == PersistenceSourceAvailability.Unavailable)
                {
                    try { inventory = PersistenceComparisonPolicy.Inventory(result.Artifacts); }
                    catch (InvalidDataException) { result = result with { Status = PersistenceCollectionStatus.Failed, DiagnosticSummary = "Conflicting duplicate persistence location." }; }
                }
                if (inventory != null && result.Status == PersistenceCollectionStatus.Complete)
                {
                    // An accepted empty P cannot erase the representation fence established by B.
                    var baselineRepresentations = ReadVerifiedJson("SELECT v.VersionJson,v.VersionHash FROM PersistenceVersions v JOIN PersistenceCollections c ON c.CollectionId=v.CollectionId WHERE c.ScopeKey=$s AND c.GenerationId=$g AND v.PartitionKey=$p AND json_extract(v.VersionJson,'$.Kind')=0",
                        ("$s", scope), ("$g", collection.StateGenerationId), ("$p", partition))
                        .Select(json => Deserialize<PersistenceVersion>(json).After!.SourceSchemaVersion).ToHashSet();
                    if (baselineRepresentations.Count > 0 && inventory.Count > 0 && !baselineRepresentations.SetEquals(inventory.Values.Select(a => a.SourceSchemaVersion)))
                        throw new InvalidDataException("Persistence baseline collector representation differs; use a distinct collector partition.");
                    var prior = Scalar("SELECT COUNT(*) FROM PersistenceCheckpoints WHERE ScopeKey=$s AND GenerationId=$g AND PartitionKey=$p",
                        ("$s", scope), ("$g", collection.StateGenerationId), ("$p", partition)) == 0 ? null : ReadInventory(scope, partition, collection.StateGenerationId);
                    foreach (var version in PersistenceComparisonPolicy.Diff(collection, result, prior))
                    {
                        var versionJson = JsonSerializer.Serialize(version);
                        Execute("INSERT INTO PersistenceVersions VALUES($id,$p,$k,$json,$hash)", ("$id", collection.CollectionId), ("$p", partition),
                            ("$k", version.ArtifactKey), ("$json", versionJson), ("$hash", PersistenceComparisonPolicy.Hash(versionJson)));
                        versionCount++;
                    }
                    // Replace only this fully enumerated partition. Across a gap, absence is never a removal.
                    if (prior == null)
                        Execute("DELETE FROM PersistenceCurrent WHERE ScopeKey=$s AND PartitionKey=$p", ("$s", scope), ("$p", partition));
                    else
                        foreach (var key in prior.Keys.Where(key => !inventory.ContainsKey(key)))
                            Execute("DELETE FROM PersistenceCurrent WHERE ScopeKey=$s AND PartitionKey=$p AND ArtifactKey=$k", ("$s", scope), ("$p", partition), ("$k", key));
                    foreach (var (key, artifact) in inventory)
                    {
                        if (prior != null && prior.TryGetValue(key, out var previous) && PersistenceComparisonPolicy.Fingerprint(previous) == PersistenceComparisonPolicy.Fingerprint(artifact)) continue;
                        Execute("INSERT INTO PersistenceCurrent VALUES($s,$p,$k,$g,$json,$f,$utc,0) ON CONFLICT(ScopeKey,PartitionKey,ArtifactKey) DO UPDATE SET GenerationId=excluded.GenerationId,ArtifactJson=excluded.ArtifactJson,Fingerprint=excluded.Fingerprint,LastConfirmedUtc=excluded.LastConfirmedUtc,Stale=0",
                            ("$s", scope), ("$p", partition), ("$k", key), ("$g", collection.StateGenerationId),
                            ("$json", JsonSerializer.Serialize(artifact)), ("$f", PersistenceComparisonPolicy.Fingerprint(artifact)), ("$utc", collection.CompletedUtc));
                    }
                    Execute("UPDATE PersistenceCurrent SET LastConfirmedUtc=$utc,Stale=0 WHERE ScopeKey=$s AND PartitionKey=$p AND GenerationId=$g",
                        ("$utc", collection.CompletedUtc), ("$s", scope), ("$p", partition), ("$g", collection.StateGenerationId));
                    Execute("INSERT INTO PersistenceCheckpoints VALUES($s,$g,$p,$hash) ON CONFLICT(ScopeKey,GenerationId,PartitionKey) DO UPDATE SET InventoryHash=excluded.InventoryHash",
                        ("$s", scope), ("$g", collection.StateGenerationId), ("$p", partition), ("$hash", InventoryHash(inventory)));
                }
                else if (inventory != null && result.Status == PersistenceCollectionStatus.Partial)
                {
                    // A bounded partial scan establishes presence only. Its observations are
                    // immutable evidence, but never alter confirmed comparison state.
                    var observed = ReadLatestIncompleteInventory(scope, partition, collection.StateGenerationId);
                    foreach (var (key, artifact) in inventory.OrderBy(pair => pair.Key, StringComparer.Ordinal))
                    {
                        if (observed.TryGetValue(key, out var previous) &&
                            PersistenceComparisonPolicy.Fingerprint(previous) == PersistenceComparisonPolicy.Fingerprint(artifact)) continue;
                        var version = new PersistenceVersion(collection.CollectionId, collection.StateGenerationId,
                            result.CollectorId, result.Coverage, key, PersistenceChangeKind.ObservedIncomplete, null, artifact);
                        var json = JsonSerializer.Serialize(version);
                        Execute("INSERT INTO PersistenceVersions VALUES($id,$p,$k,$json,$hash)", ("$id", collection.CollectionId),
                            ("$p", partition), ("$k", key), ("$json", json), ("$hash", PersistenceComparisonPolicy.Hash(json)));
                        versionCount++;
                    }
                }
                var metadata = new { result.CollectorId, result.Coverage, result.Status, Count = result.Artifacts.Count, result.Duration, result.DiagnosticSummary };
                var resultJson = JsonSerializer.Serialize(metadata);
                Execute("INSERT INTO PersistenceCollectorResults VALUES($id,$p,$json,$hash)", ("$id", collection.CollectionId), ("$p", partition), ("$json", resultJson), ("$hash", PersistenceComparisonPolicy.Hash(resultJson)));
                effectiveResults.Add(result with { Artifacts = [] });
            }
            var status = AggregateStatus(effectiveResults);
            var metadataJson = JsonSerializer.Serialize(collection with { Results = effectiveResults });
            Execute("INSERT INTO PersistenceCollections VALUES($id,$s,$g,$seq,$hash,$run,$job,$status,$count,$json,$metadataHash)",
                ("$id", collection.CollectionId), ("$s", scope), ("$g", collection.StateGenerationId), ("$seq", collection.CollectionSequence),
                ("$hash", payloadHash), ("$run", collection.SourceRunId), ("$job", collection.IngestionJobId), ("$status", status.ToString()),
                ("$count", versionCount), ("$json", metadataJson), ("$metadataHash", PersistenceComparisonPolicy.Hash(metadataJson)));
            Execute("INSERT INTO PersistenceSequenceState VALUES($s,$g,$seq,$id) ON CONFLICT(ScopeKey) DO UPDATE SET GenerationId=excluded.GenerationId, Sequence=excluded.Sequence, CollectionId=excluded.CollectionId",
                ("$s", scope), ("$g", collection.StateGenerationId), ("$seq", collection.CollectionSequence), ("$id", collection.CollectionId));
            cancellationToken.ThrowIfCancellationRequested();
            accepted = new(collection.CollectionId, false, status, versionCount, collection.DeferredBaselineGenerationId != null);
        });
        return accepted!; // Execute returns only after the actual commit.
    }

    private bool ComparisonStateDamaged(string scope, PersistenceCheckpoint state)
    {
        VerifyAuthoritativeHistory(scope);
        var damaged = Scalar("SELECT COUNT(*) FROM PersistenceSequenceState WHERE ScopeKey=$s AND GenerationId=$g AND Sequence=$seq AND CollectionId=$id",
            ("$s", scope), ("$g", state.StateGenerationId), ("$seq", state.CollectionSequence), ("$id", state.CollectionId)) != 1;
        // Authoritative metadata and versions must decode and retain their exact identities before recovery.
        var expected = new Dictionary<string, Dictionary<string, PersistenceArtifact>>(StringComparer.Ordinal);
        foreach (var json in ReadVerifiedJson("SELECT MetadataJson,MetadataHash FROM PersistenceCollections WHERE ScopeKey=$s AND GenerationId=$g ORDER BY Sequence", ("$s", scope), ("$g", state.StateGenerationId)))
        {
            var collection = Deserialize<PersistenceCollection>(json);
            Validate(collection);
            foreach (var versionJson in ReadVerifiedJson("SELECT VersionJson,VersionHash FROM PersistenceVersions WHERE CollectionId=$id", ("$id", collection.CollectionId)))
            {
                var version = Deserialize<PersistenceVersion>(versionJson);
                if (version.Kind == PersistenceChangeKind.ObservedIncomplete) continue;
                if (version.CollectionId != collection.CollectionId || version.StateGenerationId != collection.StateGenerationId ||
                    PersistenceComparisonPolicy.ArtifactKey(version.After ?? version.Before ?? throw new InvalidDataException("Missing version evidence.")) != version.ArtifactKey)
                    throw new InvalidDataException("Authoritative persistence history is corrupt.");
                var partition = PersistenceComparisonPolicy.PartitionKey(version.CollectorId, version.Coverage);
                if (!expected.TryGetValue(partition, out var inventory)) expected[partition] = inventory = new(StringComparer.Ordinal);
                if (version.Kind == PersistenceChangeKind.Removed) inventory.Remove(version.ArtifactKey);
                else inventory[version.ArtifactKey] = version.After ?? throw new InvalidDataException("Missing version after evidence.");
            }
            // Complete-empty partitions also own a checkpoint.
            foreach (var resultJson in ReadVerifiedJson("SELECT ResultJson,ResultHash FROM PersistenceCollectorResults WHERE CollectionId=$id", ("$id", collection.CollectionId)))
            {
                using var document = JsonDocument.Parse(resultJson);
                if (document.RootElement.GetProperty("Status").GetInt32() != (int)PersistenceCollectionStatus.Complete) continue;
                var collector = document.RootElement.GetProperty("CollectorId").GetString()!;
                var coverage = document.RootElement.GetProperty("Coverage").Deserialize<PersistenceCoverage>()!;
                expected.TryAdd(PersistenceComparisonPolicy.PartitionKey(collector, coverage), new(StringComparer.Ordinal));
            }
        }
        foreach (var (partition, inventory) in expected)
        {
            var hashes = ReadJson("SELECT InventoryHash FROM PersistenceCheckpoints WHERE ScopeKey=$s AND GenerationId=$g AND PartitionKey=$p",
                ("$s", scope), ("$g", state.StateGenerationId), ("$p", partition));
            try
            {
                if (hashes.Count != 1 || hashes[0] != InventoryHash(inventory) || InventoryHash(ReadInventory(scope, partition, state.StateGenerationId)) != hashes[0]) damaged = true;
            }
            catch (JsonException) { damaged = true; }
            catch (ArgumentException) { damaged = true; }
            catch (InvalidDataException) { damaged = true; }
        }
        if (Scalar("SELECT COUNT(*) FROM PersistenceCurrent WHERE ScopeKey=$s AND GenerationId=$g", ("$s", scope), ("$g", state.StateGenerationId)) != expected.Values.Sum(inventory => inventory.Count)) damaged = true;
        if (Scalar("SELECT COUNT(*) FROM PersistenceCheckpoints WHERE ScopeKey=$s AND GenerationId=$g", ("$s", scope), ("$g", state.StateGenerationId)) != expected.Count) damaged = true;
        return damaged;
    }

    private void VerifyAuthoritativeHistory(string scope)
    {
        VerifyParentReferences(scope);
        PersistenceCollection? previous = null;
        var generations = new HashSet<string>(StringComparer.Ordinal);
        foreach (var json in ReadVerifiedJson("SELECT MetadataJson,MetadataHash FROM PersistenceCollections WHERE ScopeKey=$s ORDER BY rowid", ("$s", scope)))
        {
            var collection = Deserialize<PersistenceCollection>(json);
            Validate(collection);
            if (PersistenceComparisonPolicy.ScopeKey(collection.EvidenceIdentity) != scope || collection.ExpectedPredecessorCollectionId != previous?.CollectionId)
                throw new InvalidDataException("Authoritative persistence predecessor history is corrupt.");
            ValidateSourceRun(collection);
            if (Scalar("SELECT COUNT(*) FROM PersistenceCollections WHERE CollectionId=$id AND ScopeKey=$s AND GenerationId=$g AND Sequence=$seq AND SourceRunId=$run AND IngestionJobId=$job",
                ("$id", collection.CollectionId), ("$s", scope), ("$g", collection.StateGenerationId), ("$seq", collection.CollectionSequence), ("$run", collection.SourceRunId), ("$job", collection.IngestionJobId)) != 1)
                throw new InvalidDataException("Authoritative persistence collection indexes contradict metadata.");
            PersistenceComparisonPolicy.ValidateBoundaryUse(previous, collection);
            if (previous?.StateGenerationId != collection.StateGenerationId)
            {
                if (collection.CollectionSequence != 1 || !generations.Add(collection.StateGenerationId))
                    throw new InvalidDataException("Authoritative persistence generation history is corrupt.");
            }
            else if (collection.CollectionSequence != previous.CollectionSequence + 1)
                throw new InvalidDataException("Authoritative persistence sequence history is incomplete.");
            if (Scalar("SELECT VersionCount FROM PersistenceCollections WHERE CollectionId=$id", ("$id", collection.CollectionId)) !=
                Scalar("SELECT COUNT(*) FROM PersistenceVersions WHERE CollectionId=$id", ("$id", collection.CollectionId)) ||
                Scalar("SELECT COUNT(*) FROM PersistenceCollectorResults WHERE CollectionId=$id", ("$id", collection.CollectionId)) != collection.Results.Count)
                throw new InvalidDataException("Authoritative persistence history rows are missing.");
            foreach (var versionJson in ReadVerifiedJson("SELECT VersionJson,VersionHash FROM PersistenceVersions WHERE CollectionId=$id", ("$id", collection.CollectionId)))
            {
                var version = Deserialize<PersistenceVersion>(versionJson);
                var artifact = version.After ?? version.Before ?? throw new InvalidDataException("Missing version evidence.");
                if (!Enum.IsDefined(version.Kind) || version.CollectionId != collection.CollectionId || version.StateGenerationId != collection.StateGenerationId ||
                    artifact.EvidenceIdentity != collection.EvidenceIdentity || PersistenceComparisonPolicy.ArtifactKey(artifact) != version.ArtifactKey ||
                    artifact.CollectorId != version.CollectorId || artifact.Coverage != version.Coverage)
                    throw new InvalidDataException("Authoritative persistence version identity is corrupt.");
            }
            var resultRows = ReadVerifiedJson("SELECT ResultJson,ResultHash FROM PersistenceCollectorResults WHERE CollectionId=$id", ("$id", collection.CollectionId));
            foreach (var result in collection.Results)
            {
                var matches = resultRows.Where(json =>
                {
                    using var document = JsonDocument.Parse(json);
                    var row = document.RootElement;
                    return row.GetProperty("CollectorId").GetString() == result.CollectorId && row.GetProperty("Coverage").Deserialize<PersistenceCoverage>() == result.Coverage;
                }).ToArray();
                if (matches.Length != 1) throw new InvalidDataException("Authoritative persistence result identity is corrupt.");
                if (Scalar("SELECT COUNT(*) FROM PersistenceCollectorResults WHERE CollectionId=$id AND PartitionKey=$p", ("$id", collection.CollectionId),
                        ("$p", PersistenceComparisonPolicy.PartitionKey(result.CollectorId, result.Coverage))) != 1)
                    throw new InvalidDataException("Authoritative persistence result partition is corrupt.");
                using var acceptedResult = JsonDocument.Parse(matches[0]);
                var value = acceptedResult.RootElement;
                if (value.GetProperty("Status").GetInt32() != (int)result.Status || value.GetProperty("DiagnosticSummary").GetString() != result.DiagnosticSummary ||
                    value.GetProperty("Duration").Deserialize<TimeSpan>() != result.Duration || value.GetProperty("Count").GetInt32() < 0 || result.Artifacts.Count != 0)
                    throw new InvalidDataException("Authoritative persistence accepted results disagree.");
            }
            if (ReadJson("SELECT Status FROM PersistenceCollections WHERE CollectionId=$id", ("$id", collection.CollectionId)).Single() != AggregateStatus(collection.Results).ToString())
                throw new InvalidDataException("Authoritative persistence aggregate status disagrees.");
            previous = collection;
        }
    }

    private static PersistenceCollectionStatus AggregateStatus(IReadOnlyList<PersistenceCollectorResult> results)
        => results.Count > 0 && results.All(result => result.Status == PersistenceCollectionStatus.Complete) ? PersistenceCollectionStatus.Complete
            : results.Any(result => result.Status == PersistenceCollectionStatus.Complete) ? PersistenceCollectionStatus.Partial
            : results.Count > 0 && results.All(result => result.Status == PersistenceCollectionStatus.Cancelled) ? PersistenceCollectionStatus.Cancelled
            : PersistenceCollectionStatus.Failed;

    private void VerifyParentReferences(string scope)
    {
        if (Scalar("SELECT COUNT(*) FROM PersistenceVersions v LEFT JOIN PersistenceCollections c ON c.CollectionId=v.CollectionId WHERE c.CollectionId IS NULL") != 0 ||
            Scalar("SELECT COUNT(*) FROM PersistenceCollectorResults r LEFT JOIN PersistenceCollections c ON c.CollectionId=r.CollectionId WHERE c.CollectionId IS NULL") != 0 ||
            Scalar("SELECT COUNT(*) FROM PersistenceSequenceState s LEFT JOIN PersistenceCollections c ON c.CollectionId=s.CollectionId WHERE s.ScopeKey=$s AND (c.CollectionId IS NULL OR c.ScopeKey<>s.ScopeKey)", ("$s", scope)) != 0)
            throw new InvalidDataException("Persistence history contains orphan evidence or a dangling sequence parent.");
    }

    private static void Validate(PersistenceCollection collection)
    {
        var identity = collection.EvidenceIdentity;
        if (identity.CaseId == null || (identity.CaseId.Length != 0 && string.IsNullOrWhiteSpace(identity.CaseId)) || new[] { identity.EvidenceSessionId, identity.CaptureId, identity.SourceIdentityId,
            identity.HostId, identity.ExecutionRootId, collection.SourceRunId, collection.IngestionJobId,
            collection.CollectionId, collection.StateGenerationId }.Any(string.IsNullOrWhiteSpace) ||
            collection.CollectionSequence < 1 || collection.StartedUtc.Kind != DateTimeKind.Utc ||
            collection.CompletedUtc.Kind != DateTimeKind.Utc || collection.CompletedUtc < collection.StartedUtc || !Enum.IsDefined(collection.Reason))
            throw new InvalidDataException("Exact persistence scope, provenance, sequence and UTC interval are required.");
        var partitions = new HashSet<string>(StringComparer.Ordinal);
        foreach (var result in collection.Results)
        {
            if (string.IsNullOrWhiteSpace(result.CollectorId) || string.IsNullOrWhiteSpace(result.Coverage.PartitionId) ||
                !partitions.Add(PersistenceComparisonPolicy.PartitionKey(result.CollectorId, result.Coverage)) ||
                result.DiagnosticSummary.Length > 2048 || result.Duration < TimeSpan.Zero || !Enum.IsDefined(result.Status) ||
                !Enum.IsDefined(result.Coverage.SourceAvailability) ||
                (result.Status == PersistenceCollectionStatus.Complete && result.Coverage.SourceAvailability != PersistenceSourceAvailability.Available))
                throw new InvalidDataException("Invalid persistence collector coverage or diagnostics.");
            foreach (var artifact in result.Artifacts)
            {
                if (artifact.EvidenceIdentity != identity || artifact.CollectorId != result.CollectorId || artifact.Coverage != result.Coverage ||
                    string.IsNullOrWhiteSpace(artifact.NativeLocation) || artifact.SourceSchemaVersion < 1)
                    throw new InvalidDataException("Persistence artifact scope differs from its authoritative collector partition.");
                _ = PersistenceComparisonPolicy.Fingerprint(artifact);
                if (artifact.Configuration.Values.Any(value => !Enum.IsDefined(value.State) || string.IsNullOrWhiteSpace(value.NativeType)))
                    throw new InvalidDataException("Invalid native persistence value contract.");
            }
        }
    }

    private void RestoreLastKnown(string scope)
    {
        var known = new Dictionary<string, PersistenceCurrent>(StringComparer.Ordinal);
        var completedPartitions = new HashSet<string>(StringComparer.Ordinal);
        foreach (var json in ReadVerifiedJson("SELECT MetadataJson,MetadataHash FROM PersistenceCollections WHERE ScopeKey=$s ORDER BY rowid", ("$s", scope)))
        {
            var collection = Deserialize<PersistenceCollection>(json);
            Validate(collection);
            if (PersistenceComparisonPolicy.ScopeKey(collection.EvidenceIdentity) != scope) throw new InvalidDataException("Authoritative persistence scope is corrupt.");
            var complete = new List<string>();
            foreach (var resultJson in ReadVerifiedJson("SELECT ResultJson,ResultHash FROM PersistenceCollectorResults WHERE CollectionId=$id", ("$id", collection.CollectionId)))
            {
                using var document = JsonDocument.Parse(resultJson);
                if (document.RootElement.GetProperty("Status").GetInt32() != (int)PersistenceCollectionStatus.Complete) continue;
                var collector = document.RootElement.GetProperty("CollectorId").GetString()!;
                var coverage = document.RootElement.GetProperty("Coverage").Deserialize<PersistenceCoverage>()!;
                var partition = PersistenceComparisonPolicy.PartitionKey(collector, coverage);
                complete.Add(partition);
                if (completedPartitions.Add(collection.StateGenerationId + ":" + partition))
                    foreach (var key in known.Where(row => PersistenceComparisonPolicy.PartitionKey(row.Value.CollectorId, row.Value.Coverage) == partition).Select(row => row.Key).ToArray()) known.Remove(key);
            }
            foreach (var versionJson in ReadVerifiedJson("SELECT VersionJson,VersionHash FROM PersistenceVersions WHERE CollectionId=$id", ("$id", collection.CollectionId)))
            {
                var version = Deserialize<PersistenceVersion>(versionJson);
                if (!Enum.IsDefined(version.Kind) || version.CollectionId != collection.CollectionId || version.StateGenerationId != collection.StateGenerationId ||
                    PersistenceComparisonPolicy.ArtifactKey(version.After ?? version.Before ?? throw new InvalidDataException("Missing version evidence.")) != version.ArtifactKey)
                    throw new InvalidDataException("Authoritative persistence version is corrupt.");
                if (version.Kind == PersistenceChangeKind.ObservedIncomplete) continue;
                if (version.Kind == PersistenceChangeKind.Removed) known.Remove(version.ArtifactKey);
                else known[version.ArtifactKey] = new(collection.StateGenerationId, version.CollectorId, version.Coverage, version.ArtifactKey,
                    version.After ?? throw new InvalidDataException("Missing after evidence."), collection.CompletedUtc, true);
            }
            foreach (var key in known.Keys.ToArray())
                if (complete.Contains(PersistenceComparisonPolicy.PartitionKey(known[key].CollectorId, known[key].Coverage)))
                    known[key] = known[key] with { LastConfirmedUtc = collection.CompletedUtc };
        }
        Execute("DELETE FROM PersistenceCurrent WHERE ScopeKey=$s", ("$s", scope));
        foreach (var current in known.Values)
            Execute("INSERT INTO PersistenceCurrent VALUES($s,$p,$k,$g,$json,$f,$utc,1)",
                ("$s", scope), ("$p", PersistenceComparisonPolicy.PartitionKey(current.CollectorId, current.Coverage)),
                ("$k", current.ArtifactKey), ("$g", current.StateGenerationId), ("$json", JsonSerializer.Serialize(current.Artifact)),
                ("$f", PersistenceComparisonPolicy.Fingerprint(current.Artifact)), ("$utc", current.LastConfirmedUtc));
    }

    private void ValidateSourceRun(PersistenceCollection collection)
    {
        using var command = Command("SELECT COALESCE(CaseId,''),EvidenceSessionId,CaptureId,SourceIdentityId,HostId,ExecutionRootId,IngestionJobId FROM SourceRuns WHERE SourceRunId=$id", ("$id", collection.SourceRunId));
        using var reader = command.ExecuteReader();
        var identity = collection.EvidenceIdentity;
        if (!reader.Read() || new[] { identity.CaseId, identity.EvidenceSessionId, identity.CaptureId,
                identity.SourceIdentityId, identity.HostId, identity.ExecutionRootId, collection.IngestionJobId }.Where((value, index) => reader.IsDBNull(index) || value != reader.GetString(index)).Any())
            throw new InvalidDataException("Persistence requires an existing exact scoped source run.");
        reader.Close();
        if (Scalar("SELECT COUNT(*) FROM IngestionJobs WHERE JobId=$job AND SourceRunId=$run AND COALESCE(CaseId,'')=$case AND EvidenceSessionId=$session AND CaptureId=$capture AND HostId=$host AND ExecutionRootId=$root",
                ("$job", collection.IngestionJobId), ("$run", collection.SourceRunId), ("$case", identity.CaseId),
                ("$session", identity.EvidenceSessionId), ("$capture", identity.CaptureId), ("$host", identity.HostId), ("$root", identity.ExecutionRootId)) != 1)
            throw new InvalidDataException("Persistence requires the exact registered ingestion job.");
    }

    private void ValidateWriterProvenance(PersistenceCollection collection)
    {
        using var command = Command("SELECT SourceRunId,IngestionJobId FROM WriterProvenanceContext WHERE SingletonId=1");
        using var reader = command.ExecuteReader();
        if (reader.Read() && (reader.GetString(0) != collection.SourceRunId || reader.GetString(1) != collection.IngestionJobId))
            throw new InvalidDataException("Persistence collection conflicts with the active serialized writer provenance.");
    }

    public PersistenceCheckpoint? GetCheckpoint(EvidenceIdentity identity)
    {
        PersistenceCheckpoint? result = null;
        context.Execute(() => { var scope = PersistenceComparisonPolicy.ScopeKey(identity); VerifyAuthoritativeHistory(scope); result = ReadSequence(scope); });
        return result;
    }

    public PersistenceAcceptedState? Recover(EvidenceIdentity identity)
    {
        PersistenceAcceptedState? state = null;
        context.Execute(() =>
        {
            var scope = PersistenceComparisonPolicy.ScopeKey(identity);
            VerifyAuthoritativeHistory(scope);
            var checkpoint = ReadSequence(scope);
            if (checkpoint == null) return;
            if (ComparisonStateDamaged(scope, checkpoint)) throw new InvalidDataException("Persistence comparison state is damaged; explicit recovery is required.");
            var baseline = new Dictionary<string, IReadOnlyDictionary<string, PersistenceArtifact>>(StringComparer.Ordinal);
            var previous = new Dictionary<string, IReadOnlyDictionary<string, PersistenceArtifact>>(StringComparer.Ordinal);
            var observations = new Dictionary<string, PersistencePartitionObservation>(StringComparer.Ordinal);
            DateTime? start = null;
            foreach (var json in ReadVerifiedJson("SELECT MetadataJson,MetadataHash FROM PersistenceCollections WHERE ScopeKey=$s AND GenerationId=$g ORDER BY Sequence", ("$s", scope), ("$g", checkpoint.StateGenerationId)))
            {
                var collection = Deserialize<PersistenceCollection>(json);
                if (collection.EvidenceIdentity != identity) throw new InvalidDataException("Persistence recovery scope differs.");
                if (collection.Results.Any(r => r.Status == PersistenceCollectionStatus.Complete)) start ??= collection.CompletedUtc;
                var versions = ReadVerifiedJson("SELECT VersionJson,VersionHash FROM PersistenceVersions WHERE CollectionId=$id", ("$id", collection.CollectionId)).Select(Deserialize<PersistenceVersion>).ToArray();
                foreach (var result in collection.Results.Where(r => r.Status == PersistenceCollectionStatus.Complete))
                {
                    var partition = PersistenceComparisonPolicy.PartitionKey(result.CollectorId, result.Coverage);
                    var inventory = previous.TryGetValue(partition, out var prior) ? new Dictionary<string, PersistenceArtifact>(prior, StringComparer.Ordinal) : new(StringComparer.Ordinal);
                    foreach (var version in versions.Where(v => PersistenceComparisonPolicy.PartitionKey(v.CollectorId, v.Coverage) == partition))
                    {
                        var exists = inventory.TryGetValue(version.ArtifactKey, out var before);
                        if (version.Before == null ? exists : !exists || PersistenceComparisonPolicy.Fingerprint(before!) != PersistenceComparisonPolicy.Fingerprint(version.Before))
                            throw new InvalidDataException("Persistence recovery transition predecessor is contradictory.");
                        if (version.After == null) inventory.Remove(version.ArtifactKey); else inventory[version.ArtifactKey] = version.After;
                    }
                    if (!baseline.ContainsKey(partition)) baseline.Add(partition, new Dictionary<string, PersistenceArtifact>(inventory, StringComparer.Ordinal));
                    previous[partition] = inventory;
                    observations[partition] = new(collection.CollectionId, collection.CompletedUtc);
                }
            }
            var tailJson = ReadVerifiedJson("SELECT MetadataJson,MetadataHash FROM PersistenceCollections WHERE CollectionId=$id", ("$id", checkpoint.CollectionId)).Single();
            var tail = Deserialize<PersistenceCollection>(tailJson);
            if (tail.BoundaryAcquisitionId != null && tail.CollectionId != tail.BoundaryAcquisitionId)
                throw new InvalidDataException("Persistence recovery found an incomplete boundary.");
            var immutableBaseline = baseline.ToDictionary(pair => pair.Key, pair => (IReadOnlyDictionary<string, PersistenceArtifact>)new System.Collections.ObjectModel.ReadOnlyDictionary<string, PersistenceArtifact>(new Dictionary<string, PersistenceArtifact>(pair.Value)), StringComparer.Ordinal);
            var immutablePrevious = previous.ToDictionary(pair => pair.Key, pair => (IReadOnlyDictionary<string, PersistenceArtifact>)new System.Collections.ObjectModel.ReadOnlyDictionary<string, PersistenceArtifact>(new Dictionary<string, PersistenceArtifact>(pair.Value)), StringComparer.Ordinal);
            state = new(identity, checkpoint, start,
                new System.Collections.ObjectModel.ReadOnlyDictionary<string, IReadOnlyDictionary<string, PersistenceArtifact>>(immutableBaseline),
                new System.Collections.ObjectModel.ReadOnlyDictionary<string, IReadOnlyDictionary<string, PersistenceArtifact>>(immutablePrevious),
                new System.Collections.ObjectModel.ReadOnlyDictionary<string, PersistencePartitionObservation>(observations));
        });
        return state;
    }

    private PersistenceCheckpoint? ReadSequence(string scope)
    {
        VerifyParentReferences(scope);
        // The immutable committed tail remains authority when the mutable sequence projection is lost/corrupt.
        var tails = ReadVerifiedJson("SELECT MetadataJson,MetadataHash FROM PersistenceCollections WHERE ScopeKey=$s ORDER BY rowid DESC LIMIT 1", ("$s", scope));
        var json = tails.SingleOrDefault();
        if (json == null)
        {
            if (Scalar("SELECT COUNT(*) FROM PersistenceSequenceState WHERE ScopeKey=$s", ("$s", scope)) != 0)
                throw new InvalidDataException("Sequence state has no authoritative history.");
            return null;
        }
        var collection = Deserialize<PersistenceCollection>(json);
        Validate(collection);
        if (PersistenceComparisonPolicy.ScopeKey(collection.EvidenceIdentity) != scope)
            throw new InvalidDataException("Authoritative persistence scope is corrupt.");
        return new(collection.StateGenerationId, collection.CollectionSequence, collection.CollectionId);
    }

    private Dictionary<string, PersistenceArtifact> ReadInventory(string scope, string partition, string generation)
    {
        using var command = Command("SELECT ArtifactKey,Fingerprint,ArtifactJson FROM PersistenceCurrent WHERE ScopeKey=$s AND PartitionKey=$p AND GenerationId=$g",
            ("$s", scope), ("$p", partition), ("$g", generation));
        using var reader = command.ExecuteReader();
        var inventory = new Dictionary<string, PersistenceArtifact>(StringComparer.Ordinal);
        while (reader.Read())
        {
            var artifact = Deserialize<PersistenceArtifact>(reader.GetString(2));
            if (PersistenceComparisonPolicy.ArtifactKey(artifact) != reader.GetString(0) || PersistenceComparisonPolicy.Fingerprint(artifact) != reader.GetString(1) ||
                PersistenceComparisonPolicy.ScopeKey(artifact.EvidenceIdentity) != scope || PersistenceComparisonPolicy.PartitionKey(artifact.CollectorId, artifact.Coverage) != partition)
                throw new InvalidDataException("Persistence current projection identity is corrupt.");
            inventory.Add(reader.GetString(0), artifact);
        }
        return inventory;
    }
    private Dictionary<string, PersistenceArtifact> ReadLatestIncompleteInventory(string scope, string partition, string generation)
    {
        // Confirmed rows are deliberately excluded: the first partial poll after a
        // complete one must mark even unchanged observed entries as unconfirmed.
        var inventory = new Dictionary<string, PersistenceArtifact>(StringComparer.Ordinal);
        foreach (var json in ReadVerifiedJson("""
            SELECT v.VersionJson,v.VersionHash FROM PersistenceVersions v
            JOIN PersistenceCollections c ON c.CollectionId=v.CollectionId
            WHERE c.ScopeKey=$s AND c.GenerationId=$g AND v.PartitionKey=$p
              AND json_extract(v.VersionJson,'$.Kind')=4
              AND c.rowid>COALESCE((SELECT MAX(done.rowid) FROM PersistenceCollectorResults r
                  JOIN PersistenceCollections done ON done.CollectionId=r.CollectionId
                  WHERE done.ScopeKey=$s AND done.GenerationId=$g AND r.PartitionKey=$p
                    AND json_extract(r.ResultJson,'$.Status')=0),0)
            ORDER BY c.rowid
            """, ("$s", scope), ("$g", generation), ("$p", partition)))
        {
            var version = Deserialize<PersistenceVersion>(json);
            inventory[version.ArtifactKey] = version.After ?? throw new InvalidDataException("Incomplete observation lacks native evidence.");
        }
        return inventory;
    }
    private static string InventoryHash(IReadOnlyDictionary<string, PersistenceArtifact> inventory)
        => PersistenceComparisonPolicy.Hash(string.Join("\n", inventory.OrderBy(x => x.Key, StringComparer.Ordinal)
            .Select(x => x.Key + ":" + PersistenceComparisonPolicy.Fingerprint(x.Value))));
    private List<string> ReadJson(string sql, params (string, object?)[] values)
    {
        using var command = Command(sql, values);
        using var reader = command.ExecuteReader();
        var result = new List<string>();
        while (reader.Read()) result.Add(reader.GetString(0));
        return result;
    }
    private List<string> ReadVerifiedJson(string sql, params (string, object?)[] values)
    {
        using var command = Command(sql, values);
        using var reader = command.ExecuteReader();
        var result = new List<string>();
        while (reader.Read())
        {
            var json = reader.GetString(0);
            if (PersistenceComparisonPolicy.Hash(json) != reader.GetString(1))
                throw new InvalidDataException("Authoritative persistence history integrity failed.");
            result.Add(json);
        }
        return result;
    }
    private static T Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json) ?? throw new InvalidDataException("Missing persistence payload.");
    private SqliteCommand Command(string sql, params (string, object?)[] values)
    {
        var command = context.CreateCommand(sql);
        foreach (var (name, value) in values) SqliteWriteTransactionContext.Add(command, name, value);
        return command;
    }
    private void Execute(string sql, params (string, object?)[] values) { using var command = Command(sql, values); command.ExecuteNonQuery(); }
    private long Scalar(string sql, params (string, object?)[] values) { using var command = Command(sql, values); return Convert.ToInt64(command.ExecuteScalar()); }
}
