using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;

namespace ProcInsider.Services.EvidenceSources;

public sealed record FilesystemArtifactEvidenceSourceInput
{
    public string Path { get; init; } = string.Empty;

    public bool Recurse { get; init; } = true;

    public bool IncludeNtfs { get; init; } = true;

    public bool IncludePrefetch { get; init; } = true;

    public int MaxFiles { get; init; } = 10000;
}

/// <summary>
/// Imports NTFS/Prefetch artifacts through the common adapter contract. It
/// preserves bounded raw samples plus file/hash references and emits relations
/// to the source run without requiring a process key.
/// </summary>
public sealed class FilesystemArtifactEvidenceSourceAdapter
    : EvidenceSourceAdapterBase<FilesystemArtifactEvidenceSourceInput>
{
    public const string Id = "procinsider.filesystem-artifact-import";
    public const string Version = "1.0.0";
    public const string FilesystemReadPrerequisite = "filesystem.read";
    private const int MaxDiagnostics = 100;

    private readonly FilesystemArtifactLoaderService _loader;
    private readonly EvidenceRelationService _relationService;

    public FilesystemArtifactEvidenceSourceAdapter(
        FilesystemArtifactLoaderService loader,
        EvidenceRelationService? relationService = null)
    {
        _loader = loader ?? throw new ArgumentNullException(nameof(loader));
        _relationService = relationService ?? new EvidenceRelationService();
    }

    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id,
        AdapterVersion = Version,
        DisplayName = "Filesystem artifact import",
        Description = "Imports NTFS and Prefetch files with stable artifact identities, bounded raw samples, and source-run relations.",
        Category = EvidenceSourceCategory.Importer,
        Capabilities =
            EvidenceSourceCapability.IndependentArtifacts |
            EvidenceSourceCapability.Relationships |
            EvidenceSourceCapability.RawReferences |
            EvidenceSourceCapability.IncrementalPublication,
        MaxBatchRowCount = 512,
        RawPreservation = new EvidenceRawPreservationPolicy
        {
            Mode = EvidenceRawPreservationMode.BoundedInlineAndFileReference,
            MaxInlineBytes = 4096,
            RequireContentHash = true
        },
        Prerequisites =
        [
            new EvidenceSourcePrerequisite
            {
                PrerequisiteId = FilesystemReadPrerequisite,
                Kind = EvidenceSourcePrerequisiteKind.Capability,
                Description = "The agent can read the analyst-selected local file or directory."
            }
        ]
    };

    protected override void ValidateInput(FilesystemArtifactEvidenceSourceInput input, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(input.Path))
        {
            errors.Add("An artifact import path is required.");
        }

        if (!input.IncludeNtfs && !input.IncludePrefetch)
        {
            errors.Add("At least one filesystem artifact family must be enabled.");
        }

        if (input.MaxFiles is < 1 or > 100000)
        {
            errors.Add("MaxFiles must be between 1 and 100000.");
        }
    }

    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        FilesystemArtifactEvidenceSourceInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var records = await _loader.LoadAsync(
                new FilesystemArtifactImportOptions
                {
                    Path = input.Path,
                    Recurse = input.Recurse,
                    IncludeNtfs = input.IncludeNtfs,
                    IncludePrefetch = input.IncludePrefetch,
                    MaxFiles = input.MaxFiles
                },
                request.IngestionJobId,
                cancellationToken)
            .ConfigureAwait(false);
        var identity = request.EvidenceIdentity;
        var diagnostics = new List<EvidenceSourceDiagnostic>();
        var scopedArtifactIds = records
            .Select(record => record.ArtifactId)
            .Distinct(StringComparer.Ordinal)
            .ToDictionary(
                artifactId => artifactId,
                artifactId => IndependentArtifactAdapterLineage.CreateScopedEvidenceId(
                    "filesystem-artifact",
                    request.SourceRunId,
                    artifactId),
                StringComparer.Ordinal);
        foreach (var record in records)
        {
            var sourceNativeArtifactId = record.ArtifactId;
            record.ArtifactId = scopedArtifactIds[sourceNativeArtifactId];
            if (!string.IsNullOrWhiteSpace(record.ParentArtifactId))
            {
                record.ParentArtifactId = scopedArtifactIds.TryGetValue(record.ParentArtifactId, out var scopedParentId)
                    ? scopedParentId
                    : IndependentArtifactAdapterLineage.CreateScopedEvidenceId(
                        "filesystem-artifact",
                        request.SourceRunId,
                        record.ParentArtifactId);
            }

            ApplyIdentity(record, identity);
            record.JobId = request.IngestionJobId;
            record.SourceRunId = request.SourceRunId;
            record.IngestionJobId = request.IngestionJobId.ToString("D");
            record.RawRecordId = IndependentArtifactAdapterLineage.CreateScopedEvidenceId(
                "filesystem-raw",
                request.SourceRunId,
                string.IsNullOrWhiteSpace(record.RawRecordId) ? sourceNativeArtifactId : record.RawRecordId);
            if (record.Status == FilesystemArtifactStatus.Failed && diagnostics.Count < MaxDiagnostics)
            {
                diagnostics.Add(new EvidenceSourceDiagnostic
                {
                    Code = "ArtifactImportFailed",
                    Severity = EvidenceSourceDiagnosticSeverity.Warning,
                    Message = record.ErrorMessage,
                    EvidenceId = record.ArtifactId,
                    IsRetryable = true
                });
            }
        }

        const int rowsPerArtifact = 5;
        var artifactBatchSize = Math.Max(1, GetEffectiveBatchRowLimit(Descriptor, publisher) / rowsPerArtifact);
        var persisted = 0L;
        var duplicate = 0L;
        var sequence = 0;
        try
        {
            foreach (var chunk in records.Chunk(artifactBatchSize))
            {
                cancellationToken.ThrowIfCancellationRequested();
                sequence++;
                var artifacts = chunk.ToArray();
                var relations = artifacts
                    .SelectMany(record => CreateLineageRelations(request, record, identity))
                    .ToArray();
                var identities = artifacts
                    .SelectMany(record =>
                    {
                        var recordRelations = CreateLineageRelations(request, record, identity);
                        return new[]
                        {
                            new EvidenceSourceEmissionIdentity
                            {
                                EvidenceKind = EvidenceReferenceKind.FileArtifact,
                                EvidenceId = record.ArtifactId,
                                ExternalIdentity = record.SourcePath,
                                DeduplicationKey = $"{Id}|artifact|{request.SourceRunId}|{record.ArtifactId}",
                                RawReference = record.SourcePath
                            },
                            new EvidenceSourceEmissionIdentity
                            {
                                EvidenceKind = EvidenceReferenceKind.RawRecord,
                                EvidenceId = BuildRawRecordId(record),
                                ExternalIdentity = string.IsNullOrWhiteSpace(record.RawPayloadHash)
                                    ? record.SourcePath
                                    : record.RawPayloadHash,
                                DeduplicationKey = $"{Id}|raw|{request.SourceRunId}|{record.ArtifactId}",
                                RawReference = record.SourcePath
                            }
                        }.Concat(recordRelations.Select(relation => new EvidenceSourceEmissionIdentity
                        {
                            EvidenceKind = EvidenceReferenceKind.GenericArtifact,
                            EvidenceId = relation.RelationId,
                            ExternalIdentity = relation.DecisionKey,
                            DeduplicationKey = $"{Id}|relation|{relation.RelationId}"
                        }));
                    })
                    .ToArray();
                var batch = new EvidenceSourceEmissionBatch
                {
                    SourceRunId = request.SourceRunId,
                    IngestionJobId = request.IngestionJobId,
                    Sequence = sequence,
                    IsFinalBatch = sequence * artifactBatchSize >= records.Count,
                    FilesystemArtifacts = artifacts,
                    Relations = relations,
                    Identities = identities
                };
                var published = await publisher.PublishAsync(batch, cancellationToken).ConfigureAwait(false);
                persisted += published.PersistedRowCount;
                duplicate += published.DuplicateRowCount;
                diagnostics.AddRange(published.Diagnostics.Take(Math.Max(0, MaxDiagnostics - diagnostics.Count)));
                progress?.Report(CreateProgress(
                    request,
                    records.Count,
                    Math.Min(records.Count, sequence * artifactBatchSize),
                    persisted,
                    duplicate,
                    records.Count(record => record.Status == FilesystemArtifactStatus.Failed)));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            if (ex is EvidenceSourcePublishException publishException)
            {
                persisted += publishException.PersistedRowCount;
            }

            diagnostics.Add(new EvidenceSourceDiagnostic
            {
                Code = "ArtifactPublishFailed",
                Severity = EvidenceSourceDiagnosticSeverity.Error,
                Message = ex.Message,
                IsRetryable = true
            });
            return CreateResult(
                persisted > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Failed,
                records,
                persisted,
                duplicate,
                diagnostics);
        }

        var failed = records.Count(record => record.Status == FilesystemArtifactStatus.Failed);
        return CreateResult(
            failed > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Completed,
            records,
            persisted,
            duplicate,
            diagnostics);
    }

    private IReadOnlyList<EvidenceRelation> CreateLineageRelations(
        EvidenceSourceAdapterRequest request,
        FilesystemArtifactRecord record,
        EvidenceIdentity identity)
    {
        var rawRecordId = BuildRawRecordId(record);
        var relations = new List<EvidenceRelation>
        {
            CreateRelation(
                request,
                identity,
                new EvidenceReference(EvidenceReferenceKind.FileArtifact, record.ArtifactId),
                new EvidenceReference(EvidenceReferenceKind.SourceRun, request.SourceRunId),
                "AdapterSourceRun",
                $"filesystem:{record.ArtifactId}:source-run",
                record),
            CreateRelation(
                request,
                identity,
                new EvidenceReference(EvidenceReferenceKind.SourceRun, request.SourceRunId),
                new EvidenceReference(EvidenceReferenceKind.RawRecord, rawRecordId),
                "FilesystemRawImport",
                $"filesystem:{record.ArtifactId}:raw",
                record),
            CreateRelation(
                request,
                identity,
                new EvidenceReference(EvidenceReferenceKind.RawRecord, rawRecordId),
                new EvidenceReference(EvidenceReferenceKind.FileArtifact, record.ArtifactId),
                "FilesystemNormalization",
                $"filesystem:{record.ArtifactId}:normalized",
                record)
        };
        if (!string.IsNullOrWhiteSpace(record.ParentArtifactId))
        {
            relations.Add(CreateRelation(
                request,
                identity,
                new EvidenceReference(EvidenceReferenceKind.FileArtifact, record.ParentArtifactId),
                new EvidenceReference(EvidenceReferenceKind.FileArtifact, record.ArtifactId),
                "FilesystemParentArtifact",
                $"filesystem:{record.ArtifactId}:parent",
                record));
        }

        return relations;
    }

    private EvidenceRelation CreateRelation(
        EvidenceSourceAdapterRequest request,
        EvidenceIdentity identity,
        EvidenceReference from,
        EvidenceReference to,
        string method,
        string decisionKey,
        FilesystemArtifactRecord record)
        => _relationService.CreateDecision(
            from,
            to,
            EvidenceRelationType.DerivedFrom,
            EvidenceCorrelationState.Exact,
            method,
            1.0,
            identity,
            Id,
            decisionKey,
            record.TimestampUtc,
            sourceRunId: request.SourceRunId,
            ingestionJobId: request.IngestionJobId.ToString("D"),
            rawInputId: record.RawRecordId,
            resolverVersion: Version);

    private static string BuildRawRecordId(FilesystemArtifactRecord record)
        => $"filesystem-raw:{record.ArtifactId}";

    private static void ApplyIdentity(FilesystemArtifactRecord record, EvidenceIdentity identity)
    {
        record.CaseId = identity.CaseId;
        record.EvidenceSessionId = identity.EvidenceSessionId;
        record.CaptureId = identity.CaptureId;
        record.SourceIdentityId = identity.SourceIdentityId;
        record.HostId = identity.HostId;
        record.ExecutionRootId = identity.ExecutionRootId;
    }

    private static EvidenceSourceProgress CreateProgress(
        EvidenceSourceAdapterRequest request,
        long received,
        long normalized,
        long persisted,
        long duplicate,
        long failed)
        => new()
        {
            AdapterId = Id,
            SourceRunId = request.SourceRunId,
            ReceivedCount = received,
            NormalizedCount = normalized,
            PersistedCount = persisted,
            DuplicateCount = duplicate,
            FailedCount = failed,
            Message = $"Normalized {normalized:N0}/{received:N0} filesystem artifact(s)."
        };

    private static EvidenceSourceExecutionResult CreateResult(
        EvidenceSourceCompletionState state,
        IReadOnlyList<FilesystemArtifactRecord> records,
        long persisted,
        long duplicate,
        IReadOnlyList<EvidenceSourceDiagnostic> diagnostics)
        => new()
        {
            State = state,
            ReceivedCount = records.Count,
            NormalizedCount = records.Count,
            DuplicateCount = duplicate,
            PersistedCount = persisted,
            FailedCount = records.Count(record => record.Status == FilesystemArtifactStatus.Failed),
            Diagnostics = diagnostics.Take(MaxDiagnostics).ToArray()
        };
}
