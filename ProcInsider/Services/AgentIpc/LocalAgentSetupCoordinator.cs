namespace ProcInsider.Services.AgentIpc;

public enum LocalAgentSetupOrigin
{
    Add = 0,
    SelectedRowStart = 1
}

public enum LocalAgentSetupOutcome
{
    Completed = 0,
    Partial = 1,
    Rejected = 2,
    Superseded = 3
}

public enum LocalAgentSetupStage
{
    None = 0,
    StartOrReuse = 1,
    AttachVerifiedViewer = 2,
    SaveCapture = 5,
    StartCapture = 6,
    Completed = 7
}

public sealed record LocalAgentSetupRequest(
    LocalAgentSetupOrigin Origin,
    bool HasSelectedCaptureSources);

public sealed record LocalAgentSetupAvailability(
    bool CanStart,
    string UnavailableReason);

public sealed record LocalAgentSetupResult(
    LocalAgentSetupOutcome Outcome,
    LocalAgentSetupStage Stage,
    IReadOnlyList<string> PartialFailures)
{
    public bool Succeeded => Outcome == LocalAgentSetupOutcome.Completed;
}

public interface ILocalAgentSetupRuntime
{
    bool IsCurrent();

    Task<bool> StartOrReuseAsync();

    Task<bool> AttachVerifiedViewerAsync();

    Task<bool> SaveCaptureAsync();

    LocalAgentSetupAvailability GetCaptureStartAvailability();

    Task<bool> StartCaptureAsync();
}

public sealed class DelegateLocalAgentSetupRuntime : ILocalAgentSetupRuntime
{
    private readonly Func<bool> _isCurrent;
    private readonly Func<Task<bool>> _startOrReuseAsync;
    private readonly Func<Task<bool>> _attachVerifiedViewerAsync;
    private readonly Func<Task<bool>> _saveCaptureAsync;
    private readonly Func<LocalAgentSetupAvailability> _getCaptureStartAvailability;
    private readonly Func<Task<bool>> _startCaptureAsync;

    public DelegateLocalAgentSetupRuntime(
        Func<bool> isCurrent,
        Func<Task<bool>> startOrReuseAsync,
        Func<Task<bool>> attachVerifiedViewerAsync,
        Func<Task<bool>> saveCaptureAsync,
        Func<LocalAgentSetupAvailability> getCaptureStartAvailability,
        Func<Task<bool>> startCaptureAsync)
    {
        _isCurrent = isCurrent ?? throw new ArgumentNullException(nameof(isCurrent));
        _startOrReuseAsync = startOrReuseAsync ?? throw new ArgumentNullException(nameof(startOrReuseAsync));
        _attachVerifiedViewerAsync = attachVerifiedViewerAsync ??
            throw new ArgumentNullException(nameof(attachVerifiedViewerAsync));
        _saveCaptureAsync = saveCaptureAsync ?? throw new ArgumentNullException(nameof(saveCaptureAsync));
        _getCaptureStartAvailability = getCaptureStartAvailability ??
            throw new ArgumentNullException(nameof(getCaptureStartAvailability));
        _startCaptureAsync = startCaptureAsync ?? throw new ArgumentNullException(nameof(startCaptureAsync));
    }

    public bool IsCurrent() => _isCurrent();
    public Task<bool> StartOrReuseAsync() => _startOrReuseAsync();
    public Task<bool> AttachVerifiedViewerAsync() => _attachVerifiedViewerAsync();
    public Task<bool> SaveCaptureAsync() => _saveCaptureAsync();
    public LocalAgentSetupAvailability GetCaptureStartAvailability() =>
        _getCaptureStartAvailability();
    public Task<bool> StartCaptureAsync() => _startCaptureAsync();
}

/// <summary>
/// Headless post-target workflow shared by Add Agent and selected-row Start Agent.
/// Presentation owns dialogs and status text; existing lifecycle/configuration/capture
/// services remain the owners of every security and mutation decision. This workflow
/// selects capture sources only; it has no host-monitoring save/deploy capability.
/// </summary>
public sealed class LocalAgentSetupCoordinator
{
    private readonly ILocalAgentSetupRuntime _runtime;

    public LocalAgentSetupCoordinator(ILocalAgentSetupRuntime runtime)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
    }

    public async Task<LocalAgentSetupResult> ExecuteAsync(LocalAgentSetupRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!_runtime.IsCurrent())
        {
            return Superseded(LocalAgentSetupStage.StartOrReuse);
        }

        if (!await _runtime.StartOrReuseAsync().ConfigureAwait(false))
        {
            return Rejected(LocalAgentSetupStage.StartOrReuse);
        }

        if (!_runtime.IsCurrent())
        {
            return Superseded(LocalAgentSetupStage.AttachVerifiedViewer);
        }

        if (!await _runtime.AttachVerifiedViewerAsync().ConfigureAwait(false))
        {
            return Rejected(LocalAgentSetupStage.AttachVerifiedViewer);
        }

        if (!_runtime.IsCurrent())
        {
            return Superseded(LocalAgentSetupStage.SaveCapture);
        }

        var partialFailures = new List<string>();
        var captureSaved = await _runtime.SaveCaptureAsync().ConfigureAwait(false);
        if (!_runtime.IsCurrent())
        {
            return Superseded(LocalAgentSetupStage.SaveCapture);
        }

        if (!captureSaved)
        {
            partialFailures.Add("capture configuration was not saved");
        }
        else if (request.HasSelectedCaptureSources)
        {
            var availability = _runtime.GetCaptureStartAvailability();
            if (!availability.CanStart)
            {
                partialFailures.Add(
                    $"configured capture did not start: {availability.UnavailableReason}");
            }
            else if (!await _runtime.StartCaptureAsync().ConfigureAwait(false))
            {
                partialFailures.Add("configured capture start was rejected");
            }

            if (!_runtime.IsCurrent())
            {
                return Superseded(LocalAgentSetupStage.StartCapture);
            }
        }

        return new LocalAgentSetupResult(
            partialFailures.Count == 0
                ? LocalAgentSetupOutcome.Completed
                : LocalAgentSetupOutcome.Partial,
            LocalAgentSetupStage.Completed,
            partialFailures);
    }

    private static LocalAgentSetupResult Rejected(LocalAgentSetupStage stage) =>
        new(LocalAgentSetupOutcome.Rejected, stage, []);

    private static LocalAgentSetupResult Superseded(LocalAgentSetupStage stage) =>
        new(LocalAgentSetupOutcome.Superseded, stage, []);
}
