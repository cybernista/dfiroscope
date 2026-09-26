using ProcInsider.Models.EvidenceSources;

namespace ProcInsider.Services.EvidenceSources;

public abstract class EvidenceSourceAdapterBase<TInput> : IEvidenceSourceAdapter
    where TInput : class
{
    public abstract EvidenceSourceAdapterDescriptor Descriptor { get; }

    public Type InputType => typeof(TInput);

    public EvidenceSourceValidationResult Validate(EvidenceSourceAdapterRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(request.SourceRunId))
        {
            errors.Add("SourceRunId is required.");
        }

        if (request.IngestionJobId == Guid.Empty)
        {
            errors.Add("IngestionJobId is required.");
        }

        if (request.Payload is not TInput input)
        {
            errors.Add($"Payload must be {typeof(TInput).Name}.");
        }
        else
        {
            ValidateInput(input, errors);
        }

        foreach (var prerequisite in Descriptor.Prerequisites.Where(prerequisite => prerequisite.IsRequired))
        {
            if (!request.AvailablePrerequisiteIds.Contains(prerequisite.PrerequisiteId))
            {
                errors.Add($"Missing prerequisite '{prerequisite.PrerequisiteId}': {prerequisite.Description}");
            }
        }

        return errors.Count == 0
            ? EvidenceSourceValidationResult.Valid
            : new EvidenceSourceValidationResult { Errors = errors };
    }

    public async ValueTask<EvidenceSourceExecutionResult> ExecuteAsync(
        EvidenceSourceAdapterRequest request,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publisher);
        cancellationToken.ThrowIfCancellationRequested();
        var validation = Validate(request);
        if (!validation.IsValid)
        {
            throw new EvidenceSourceValidationException(Descriptor.AdapterId, validation.Errors);
        }

        if (publisher.MaxBatchRowCount <= 0)
        {
            throw new InvalidOperationException("Evidence source publisher must expose a positive batch-row limit.");
        }

        return await ExecuteCoreAsync(
                request,
                (TInput)request.Payload!,
                publisher,
                progress,
                cancellationToken)
            .ConfigureAwait(false);
    }

    protected virtual void ValidateInput(TInput input, List<string> errors)
    {
    }

    protected abstract ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        TInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken);

    protected static int GetEffectiveBatchRowLimit(
        EvidenceSourceAdapterDescriptor descriptor,
        IEvidenceSourcePublisher publisher)
        => Math.Max(1, Math.Min(descriptor.MaxBatchRowCount, publisher.MaxBatchRowCount));
}
