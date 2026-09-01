using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;
using System.Security.Cryptography;
using System.Text;

namespace ProcInsider.Services.EvidenceSources;

public sealed record NetworkCaptureEvidenceSourceInput
{
    public IReadOnlyList<NetworkCaptureRecord> Captures { get; init; } =
        Array.Empty<NetworkCaptureRecord>();
}

public sealed record ZeekNetworkEvidenceSourceInput
{
    public IReadOnlyList<ZeekNetworkRecord> Artifacts { get; init; } =
        Array.Empty<ZeekNetworkRecord>();
}

public sealed record MemoryImageEvidenceSourceInput
{
    public IReadOnlyList<MemoryImageRecord> Images { get; init; } =
        Array.Empty<MemoryImageRecord>();
}

public sealed class NetworkCaptureEvidenceSourceAdapter
    : EvidenceSourceAdapterBase<NetworkCaptureEvidenceSourceInput>
{
    public const string Id = "procinsider.network-capture";
    public const string Version = "1.0.0";
    public const string CaptureResultPrerequisite = "network-capture.result";

    private readonly EvidenceRelationService _relations;

    public NetworkCaptureEvidenceSourceAdapter(EvidenceRelationService? relations = null)
    {
        _relations = relations ?? new EvidenceRelationService();
    }

    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id,
        AdapterVersion = Version,
        DisplayName = "Packet Monitor capture metadata",
        Description = "Preserves Packet Monitor segments as file-referenced evidence with exact source-run lineage.",
        Category = EvidenceSourceCategory.PrimaryAcquisition,
        Capabilities =
            EvidenceSourceCapability.IndependentArtifacts |
            EvidenceSourceCapability.Relationships |
            EvidenceSourceCapability.RawReferences |
            EvidenceSourceCapability.DerivationLineage |
            EvidenceSourceCapability.LiveCollection,
        MaxBatchRowCount = 256,
        RawPreservation = new EvidenceRawPreservationPolicy
        {
            Mode = EvidenceRawPreservationMode.HashAndFileReference,
            RequireContentHash = false
        },
        Prerequisites =
        [
            new EvidenceSourcePrerequisite
            {
                PrerequisiteId = CaptureResultPrerequisite,
                Kind = EvidenceSourcePrerequisiteKind.SourceRun,
                Description = "The scheduler-owned Packet Monitor execution produced a capture status record."
            }
        ]
    };

    protected override void ValidateInput(NetworkCaptureEvidenceSourceInput input, List<string> errors)
    {
        if (input.Captures.Count == 0)
        {
            errors.Add("At least one network capture record is required.");
        }

        if (input.Captures.Any(capture => string.IsNullOrWhiteSpace(capture.CaptureId)))
        {
            errors.Add("Every network capture record requires a stable CaptureId.");
        }
    }

    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        NetworkCaptureEvidenceSourceInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var persisted = 0L;
        var duplicates = 0L;
        var diagnostics = new List<EvidenceSourceDiagnostic>();
        for (var index = 0; index < input.Captures.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var capture = input.Captures[index];
            IndependentArtifactAdapterLineage.ApplyProvenance(capture, request, Id);
            capture.JobId = request.IngestionJobId;
            var relations = new List<EvidenceRelation>
            {
                IndependentArtifactAdapterLineage.Create(
                    _relations,
                    request,
                    new EvidenceReference(EvidenceReferenceKind.Capture, capture.CaptureId),
                    new EvidenceReference(EvidenceReferenceKind.SourceRun, request.SourceRunId),
                    EvidenceRelationType.DerivedFrom,
                    "NetworkCaptureSourceRun",
                    $"network-capture:{capture.CaptureId}:source-run",
                    capture.RequestedUtc,
                    capture.FilePath)
            };
            if (!string.IsNullOrWhiteSpace(capture.FilePath))
            {
                relations.Add(IndependentArtifactAdapterLineage.Create(
                    _relations,
                    request,
                    new EvidenceReference(EvidenceReferenceKind.Capture, capture.CaptureId),
                    new EvidenceReference(EvidenceReferenceKind.FileArtifact, capture.FilePath),
                    EvidenceRelationType.Created,
                    "PacketCaptureFileReference",
                    $"network-capture:{capture.CaptureId}:file",
                    capture.CompletedUtc ?? capture.RequestedUtc,
                    capture.Sha256Hash));
            }

            var batch = new EvidenceSourceEmissionBatch
            {
                SourceRunId = request.SourceRunId,
                IngestionJobId = request.IngestionJobId,
                Sequence = index + 1,
                IsFinalBatch = index == input.Captures.Count - 1,
                NetworkCaptures = [capture],
                Relations = relations,
                Identities =
                [
                    IndependentArtifactAdapterLineage.Identity(
                        EvidenceReferenceKind.Capture,
                        capture.CaptureId,
                        string.IsNullOrWhiteSpace(capture.FilePath) ? capture.CaptureId : capture.FilePath,
                        $"{Id}|capture|{request.SourceRunId}|{capture.CaptureId}",
                        capture.FilePath)
                ]
            };
            var result = await IndependentArtifactAdapterLineage.PublishAsync(
                    publisher,
                    batch,
                    cancellationToken,
                    diagnostics)
                .ConfigureAwait(false);
            persisted += result.PersistedRowCount;
            duplicates += result.DuplicateRowCount;
            progress?.Report(IndependentArtifactAdapterLineage.Progress(
                Id,
                request.SourceRunId,
                input.Captures.Count,
                index + 1,
                persisted,
                duplicates,
                "Network capture metadata normalized."));
            if (result.Failed)
            {
                break;
            }
        }

        return IndependentArtifactAdapterLineage.Result(
            input.Captures.Count,
            persisted,
            duplicates,
            diagnostics);
    }
}

public sealed class ZeekNetworkEvidenceSourceAdapter
    : EvidenceSourceAdapterBase<ZeekNetworkEvidenceSourceInput>
{
    public const string Id = "procinsider.zeek-network";
    public const string Version = "1.0.0";
    public const string ParserPrerequisite = "zeek.normalized-output";

    private readonly EvidenceRelationService _relations;

    public ZeekNetworkEvidenceSourceAdapter(EvidenceRelationService? relations = null)
    {
        _relations = relations ?? new EvidenceRelationService();
    }

    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id,
        AdapterVersion = Version,
        DisplayName = "Zeek network artifacts",
        Description = "Normalizes Zeek raw log rows into network artifacts with capture, source-run, and raw-record lineage.",
        Category = EvidenceSourceCategory.DerivedAnalyzer,
        Capabilities =
            EvidenceSourceCapability.IndependentArtifacts |
            EvidenceSourceCapability.Relationships |
            EvidenceSourceCapability.RawReferences |
            EvidenceSourceCapability.DerivationLineage |
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
                PrerequisiteId = ParserPrerequisite,
                Kind = EvidenceSourcePrerequisiteKind.SourceRun,
                Description = "Zeek output was produced and normalized by the scheduler-owned execution service."
            }
        ]
    };

    protected override void ValidateInput(ZeekNetworkEvidenceSourceInput input, List<string> errors)
    {
        if (input.Artifacts.Count == 0)
        {
            errors.Add("At least one Zeek artifact is required.");
        }

        if (input.Artifacts.Any(artifact => string.IsNullOrWhiteSpace(artifact.ArtifactId)))
        {
            errors.Add("Every Zeek artifact requires a stable ArtifactId.");
        }
    }

    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        ZeekNetworkEvidenceSourceInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var persisted = 0L;
        var duplicates = 0L;
        var diagnostics = new List<EvidenceSourceDiagnostic>();
        var linkedCaptures = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < input.Artifacts.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var artifact = input.Artifacts[index];
            var sourceNativeArtifactId = artifact.ArtifactId;
            artifact.ArtifactId = IndependentArtifactAdapterLineage.CreateScopedEvidenceId(
                "zeek-flow",
                request.SourceRunId,
                sourceNativeArtifactId);
            IndependentArtifactAdapterLineage.ApplyProvenance(artifact, request, Id);
            artifact.JobId = request.IngestionJobId;
            var rawId = $"zeek-raw:{artifact.ArtifactId}";
            var relations = new List<EvidenceRelation>();
            if (!string.IsNullOrWhiteSpace(artifact.CaptureId) && linkedCaptures.Add(artifact.CaptureId))
            {
                relations.Add(IndependentArtifactAdapterLineage.Create(
                    _relations,
                    request,
                    new EvidenceReference(EvidenceReferenceKind.Capture, artifact.CaptureId),
                    new EvidenceReference(EvidenceReferenceKind.SourceRun, request.SourceRunId),
                    EvidenceRelationType.DerivedFrom,
                    "ZeekRunInput",
                    $"zeek:{artifact.CaptureId}:source-run",
                    artifact.TimestampUtc,
                    request.InputHash));
            }

            relations.Add(IndependentArtifactAdapterLineage.Create(
                _relations,
                request,
                new EvidenceReference(EvidenceReferenceKind.SourceRun, request.SourceRunId),
                new EvidenceReference(EvidenceReferenceKind.RawRecord, rawId),
                EvidenceRelationType.ExtractedFrom,
                "ZeekRawLog",
                $"zeek:{artifact.ArtifactId}:raw",
                artifact.TimestampUtc,
                artifact.RawLineHash));
            relations.Add(IndependentArtifactAdapterLineage.Create(
                _relations,
                request,
                new EvidenceReference(EvidenceReferenceKind.RawRecord, rawId),
                new EvidenceReference(EvidenceReferenceKind.NetworkFlow, artifact.ArtifactId),
                EvidenceRelationType.DerivedFrom,
                "ZeekNormalization",
                $"zeek:{artifact.ArtifactId}:normalized",
                artifact.TimestampUtc,
                artifact.RawLineHash));

            var batch = new EvidenceSourceEmissionBatch
            {
                SourceRunId = request.SourceRunId,
                IngestionJobId = request.IngestionJobId,
                Sequence = index + 1,
                IsFinalBatch = index == input.Artifacts.Count - 1,
                ZeekNetworkArtifacts = [artifact],
                Relations = relations,
                Identities =
                [
                    IndependentArtifactAdapterLineage.Identity(
                        EvidenceReferenceKind.NetworkFlow,
                        artifact.ArtifactId,
                        $"{sourceNativeArtifactId}|{artifact.RawLogPath}|{artifact.RawLineNumber}|{artifact.RawLineHash}",
                        $"{Id}|flow|{request.SourceRunId}|{artifact.ArtifactId}",
                        artifact.RawLogPath),
                    IndependentArtifactAdapterLineage.Identity(
                        EvidenceReferenceKind.RawRecord,
                        rawId,
                        $"{artifact.RawLogPath}|{artifact.RawLineNumber}",
                        $"{Id}|raw|{request.SourceRunId}|{artifact.ArtifactId}",
                        artifact.RawLogPath)
                ]
            };
            var result = await IndependentArtifactAdapterLineage.PublishAsync(
                    publisher,
                    batch,
                    cancellationToken,
                    diagnostics)
                .ConfigureAwait(false);
            persisted += result.PersistedRowCount;
            duplicates += result.DuplicateRowCount;
            progress?.Report(IndependentArtifactAdapterLineage.Progress(
                Id,
                request.SourceRunId,
                input.Artifacts.Count,
                index + 1,
                persisted,
                duplicates,
                "Zeek artifacts normalized."));
            if (result.Failed)
            {
                break;
            }
        }

        return IndependentArtifactAdapterLineage.Result(
            input.Artifacts.Count,
            persisted,
            duplicates,
            diagnostics,
            input.Artifacts.Count(artifact => artifact.Status == ZeekArtifactStatus.Failed));
    }
}

public sealed class MemoryImageEvidenceSourceAdapter
    : EvidenceSourceAdapterBase<MemoryImageEvidenceSourceInput>
{
    public const string Id = "procinsider.memory-image-import";
    public const string Version = "1.0.0";
    public const string ImageMetadataPrerequisite = "memory-image.metadata";

    private readonly EvidenceRelationService _relations;

    public MemoryImageEvidenceSourceAdapter(EvidenceRelationService? relations = null)
    {
        _relations = relations ?? new EvidenceRelationService();
    }

    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id,
        AdapterVersion = Version,
        DisplayName = "System memory image import",
        Description = "Preserves memory-image metadata and external file references with exact source-run lineage.",
        Category = EvidenceSourceCategory.Importer,
        Capabilities =
            EvidenceSourceCapability.IndependentArtifacts |
            EvidenceSourceCapability.Relationships |
            EvidenceSourceCapability.RawReferences |
            EvidenceSourceCapability.DerivationLineage,
        MaxBatchRowCount = 256,
        RawPreservation = new EvidenceRawPreservationPolicy
        {
            Mode = EvidenceRawPreservationMode.HashAndFileReference,
            RequireContentHash = true
        },
        Prerequisites =
        [
            new EvidenceSourcePrerequisite
            {
                PrerequisiteId = ImageMetadataPrerequisite,
                Kind = EvidenceSourcePrerequisiteKind.SourceRun,
                Description = "The read-only memory image import service produced bounded metadata."
            }
        ]
    };

    protected override void ValidateInput(MemoryImageEvidenceSourceInput input, List<string> errors)
    {
        if (input.Images.Count == 0)
        {
            errors.Add("At least one memory image record is required.");
        }

        if (input.Images.Any(image => string.IsNullOrWhiteSpace(image.ImageId)))
        {
            errors.Add("Every memory image requires a stable ImageId.");
        }
    }

    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        MemoryImageEvidenceSourceInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var persisted = 0L;
        var duplicates = 0L;
        var diagnostics = new List<EvidenceSourceDiagnostic>();
        for (var index = 0; index < input.Images.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var image = input.Images[index];
            var sourceNativeImageId = image.ImageId;
            image.ImageId = IndependentArtifactAdapterLineage.CreateScopedEvidenceId(
                "memory-image",
                request.SourceRunId,
                sourceNativeImageId);
            IndependentArtifactAdapterLineage.ApplyProvenance(image, request, Id);
            image.JobId = request.IngestionJobId;
            var relations = new List<EvidenceRelation>
            {
                IndependentArtifactAdapterLineage.Create(
                    _relations,
                    request,
                    new EvidenceReference(EvidenceReferenceKind.MemoryImage, image.ImageId),
                    new EvidenceReference(EvidenceReferenceKind.SourceRun, request.SourceRunId),
                    EvidenceRelationType.DerivedFrom,
                    "MemoryImageSourceRun",
                    $"memory-image:{image.ImageId}:source-run",
                    image.ImportedUtc,
                    image.Sha256Hash)
            };
            if (!string.IsNullOrWhiteSpace(image.FilePath))
            {
                relations.Add(IndependentArtifactAdapterLineage.Create(
                    _relations,
                    request,
                    new EvidenceReference(EvidenceReferenceKind.FileArtifact, image.FilePath),
                    new EvidenceReference(EvidenceReferenceKind.MemoryImage, image.ImageId),
                    EvidenceRelationType.DerivedFrom,
                    "MemoryImageFileReference",
                    $"memory-image:{image.ImageId}:file",
                    image.ImportedUtc,
                    image.Sha256Hash));
            }

            var batch = new EvidenceSourceEmissionBatch
            {
                SourceRunId = request.SourceRunId,
                IngestionJobId = request.IngestionJobId,
                Sequence = index + 1,
                IsFinalBatch = index == input.Images.Count - 1,
                MemoryImages = [image],
                Relations = relations,
                Identities =
                [
                    IndependentArtifactAdapterLineage.Identity(
                        EvidenceReferenceKind.MemoryImage,
                        image.ImageId,
                        $"{sourceNativeImageId}|{image.FilePath}|{image.Sha256Hash}",
                        $"{Id}|image|{request.SourceRunId}|{image.ImageId}",
                        image.FilePath)
                ]
            };
            var result = await IndependentArtifactAdapterLineage.PublishAsync(
                    publisher,
                    batch,
                    cancellationToken,
                    diagnostics)
                .ConfigureAwait(false);
            persisted += result.PersistedRowCount;
            duplicates += result.DuplicateRowCount;
            progress?.Report(IndependentArtifactAdapterLineage.Progress(
                Id,
                request.SourceRunId,
                input.Images.Count,
                index + 1,
                persisted,
                duplicates,
                "Memory image metadata normalized."));
            if (result.Failed)
            {
                break;
            }
        }

        return IndependentArtifactAdapterLineage.Result(
            input.Images.Count,
            persisted,
            duplicates,
            diagnostics,
            input.Images.Count(image => image.Status == MemoryImageStatus.Failed));
    }
}

internal static class IndependentArtifactAdapterLineage
{
    public static string CreateScopedEvidenceId(string prefix, string sourceRunId, string sourceNativeId)
    {
        if (sourceNativeId.StartsWith($"{prefix}-", StringComparison.Ordinal) &&
            sourceNativeId.Length == prefix.Length + 33)
        {
            return sourceNativeId;
        }

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{prefix}|{sourceRunId}|{sourceNativeId}"));
        return $"{prefix}-{Convert.ToHexString(bytes).ToLowerInvariant()[..32]}";
    }

    public static void ApplyProvenance(
        IHasSourceRunEvidenceLink record,
        EvidenceSourceAdapterRequest request,
        string sourceIdentityId)
    {
        record.CaseId = request.EvidenceIdentity.CaseId;
        record.EvidenceSessionId = request.EvidenceIdentity.EvidenceSessionId;
        record.CaptureId = string.IsNullOrWhiteSpace(record.CaptureId)
            ? request.EvidenceIdentity.CaptureId
            : record.CaptureId;
        record.SourceIdentityId = string.IsNullOrWhiteSpace(request.EvidenceIdentity.SourceIdentityId)
            ? sourceIdentityId
            : request.EvidenceIdentity.SourceIdentityId;
        record.HostId = request.EvidenceIdentity.HostId;
        record.ExecutionRootId = request.EvidenceIdentity.ExecutionRootId;
        record.SourceRunId = request.SourceRunId;
        record.IngestionJobId = request.IngestionJobId.ToString("D");
    }

    public static EvidenceRelation Create(
        EvidenceRelationService service,
        EvidenceSourceAdapterRequest request,
        EvidenceReference from,
        EvidenceReference to,
        EvidenceRelationType relationType,
        string method,
        string decisionKey,
        DateTime observedUtc,
        string rawInputId)
        => service.CreateDecision(
            from,
            to,
            relationType,
            EvidenceCorrelationState.Exact,
            method,
            1.0,
            request.EvidenceIdentity,
            method,
            decisionKey,
            observedUtc,
            sourceRunId: request.SourceRunId,
            ingestionJobId: request.IngestionJobId.ToString("D"),
            rawInputId: rawInputId,
            resolverVersion: "independent-artifact-v1");

    public static EvidenceSourceEmissionIdentity Identity(
        EvidenceReferenceKind kind,
        string evidenceId,
        string externalIdentity,
        string deduplicationKey,
        string rawReference)
        => new()
        {
            EvidenceKind = kind,
            EvidenceId = evidenceId,
            ExternalIdentity = string.IsNullOrWhiteSpace(externalIdentity) ? evidenceId : externalIdentity,
            DeduplicationKey = deduplicationKey,
            RawReference = rawReference
        };

    public static async ValueTask<(int PersistedRowCount, int DuplicateRowCount, bool Failed)> PublishAsync(
        IEvidenceSourcePublisher publisher,
        EvidenceSourceEmissionBatch batch,
        CancellationToken cancellationToken,
        ICollection<EvidenceSourceDiagnostic> diagnostics)
    {
        try
        {
            var result = await publisher.PublishAsync(batch, cancellationToken).ConfigureAwait(false);
            foreach (var diagnostic in result.Diagnostics)
            {
                diagnostics.Add(diagnostic);
            }

            return (result.PersistedRowCount, result.DuplicateRowCount, false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            diagnostics.Add(new EvidenceSourceDiagnostic
            {
                Code = "IndependentArtifactPublishFailed",
                Severity = EvidenceSourceDiagnosticSeverity.Error,
                Message = ex.Message,
                IsRetryable = true
            });
            return (ex is EvidenceSourcePublishException publish ? publish.PersistedRowCount : 0, 0, true);
        }
    }

    public static EvidenceSourceProgress Progress(
        string adapterId,
        string sourceRunId,
        long received,
        long normalized,
        long persisted,
        long duplicates,
        string message)
        => new()
        {
            AdapterId = adapterId,
            SourceRunId = sourceRunId,
            ReceivedCount = received,
            NormalizedCount = normalized,
            PersistedCount = persisted,
            DuplicateCount = duplicates,
            Message = message
        };

    public static EvidenceSourceExecutionResult Result(
        long received,
        long persisted,
        long duplicates,
        IReadOnlyList<EvidenceSourceDiagnostic> diagnostics,
        long failedRows = 0)
    {
        var publishFailed = diagnostics.Any(diagnostic =>
            diagnostic.Severity == EvidenceSourceDiagnosticSeverity.Error);
        var state = publishFailed
            ? persisted > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Failed
            : failedRows > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Completed;
        return new EvidenceSourceExecutionResult
        {
            State = state,
            ReceivedCount = received,
            NormalizedCount = received,
            PersistedCount = persisted,
            DuplicateCount = duplicates,
            FailedCount = failedRows + (publishFailed ? 1 : 0),
            Diagnostics = diagnostics.ToArray()
        };
    }
}
