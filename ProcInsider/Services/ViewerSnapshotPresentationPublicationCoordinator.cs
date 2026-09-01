namespace ProcInsider.Services;

public enum ViewerSnapshotPresentationPublishOutcome
{
    Published,
    Superseded
}

public sealed record ViewerSnapshotPresentationPublishAttempt<TRequest>(
    ViewerSnapshotPresentationPublishOutcome Outcome,
    TRequest? CurrentRequest)
    where TRequest : class
{
    public static ViewerSnapshotPresentationPublishAttempt<TRequest> Published() =>
        new(ViewerSnapshotPresentationPublishOutcome.Published, null);

    public static ViewerSnapshotPresentationPublishAttempt<TRequest> Superseded(
        TRequest currentRequest) =>
        new(
            ViewerSnapshotPresentationPublishOutcome.Superseded,
            currentRequest ?? throw new ArgumentNullException(nameof(currentRequest)));
}

/// <summary>
/// WPF-free bounded loop for snapshot presentation publication. The caller's
/// publish attempt must compare and publish atomically on its UI dispatcher.
/// Superseded inputs are re-prepared against the already activated candidate;
/// this owner never starts another snapshot refresh.
/// </summary>
public static class ViewerSnapshotPresentationPublicationCoordinator
{
    public const int MaximumLatePreparationAttempts = 3;

    public static async Task PublishLatestAsync<TRequest, TPrepared>(
        TPrepared initialPrepared,
        Func<TPrepared, CancellationToken, Task<ViewerSnapshotPresentationPublishAttempt<TRequest>>> tryPublishAsync,
        Func<TRequest, CancellationToken, Task<TPrepared>> prepareAsync,
        CancellationToken cancellationToken = default)
        where TRequest : class
    {
        ArgumentNullException.ThrowIfNull(tryPublishAsync);
        ArgumentNullException.ThrowIfNull(prepareAsync);

        var prepared = initialPrepared;
        for (var attempt = 0; attempt <= MaximumLatePreparationAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var publication = await tryPublishAsync(prepared, cancellationToken)
                .ConfigureAwait(false);
            if (publication.Outcome == ViewerSnapshotPresentationPublishOutcome.Published)
            {
                return;
            }

            if (publication.Outcome != ViewerSnapshotPresentationPublishOutcome.Superseded ||
                publication.CurrentRequest == null)
            {
                throw new InvalidOperationException(
                    "Snapshot presentation publication returned an invalid outcome.");
            }

            if (attempt == MaximumLatePreparationAttempts)
            {
                throw new InvalidOperationException(
                    "Viewer presentation inputs kept changing during bounded publication; the previous coherent view was preserved for a later refresh.");
            }

            prepared = await prepareAsync(publication.CurrentRequest, cancellationToken)
                .ConfigureAwait(false);
        }
    }
}
