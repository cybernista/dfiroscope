using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Serializes capture-workspace transitions and enforces their lifecycle order.
/// Target validation runs while the current workspace is still active. Once a
/// transition commits to detaching, the old workspace must be fully released
/// before the new workspace is materialized.
/// </summary>
public sealed class CaptureWorkspaceCoordinator
{
    private readonly SemaphoreSlim _switchGate = new(1, 1);
    private CaptureWorkspaceIdentity _current = CaptureWorkspaceIdentity.None;
    private long _generation;

    public event EventHandler? StateChanged;

    public CaptureWorkspaceIdentity Current => _current;

    public CaptureWorkspaceMode Mode => _current.Mode;

    public long Generation => Interlocked.Read(ref _generation);

    public void Initialize(CaptureWorkspaceIdentity identity)
    {
        if (identity.Mode is CaptureWorkspaceMode.None or CaptureWorkspaceMode.Switching)
        {
            throw new ArgumentException("An initialized workspace must be live or archived.", nameof(identity));
        }

        SetCurrent(identity);
    }

    public async Task SwitchAsync(
        CaptureWorkspaceIdentity target,
        Func<CancellationToken, Task> validateTargetAsync,
        Func<CancellationToken, Task> stopAndVerifyCurrentAsync,
        Func<CancellationToken, Task> detachAndReleaseCurrentAsync,
        Func<CancellationToken, Task> materializeTargetAsync,
        CancellationToken cancellationToken = default)
    {
        if (target.Mode is CaptureWorkspaceMode.None or CaptureWorkspaceMode.Switching)
        {
            throw new ArgumentException("A switch target must be live or archived.", nameof(target));
        }

        await _switchGate.WaitAsync(cancellationToken);
        try
        {
            // A bad target must not disturb a usable current workspace.
            await validateTargetAsync(cancellationToken);

            var previous = _current;
            var detached = false;
            SetCurrent(new CaptureWorkspaceIdentity(
                CaptureWorkspaceMode.Switching,
                previous.SessionId,
                previous.SessionRoot));

            try
            {
                await stopAndVerifyCurrentAsync(cancellationToken);
                detached = true;
                await detachAndReleaseCurrentAsync(cancellationToken);
                await materializeTargetAsync(cancellationToken);
                SetCurrent(target);
            }
            catch
            {
                // Stop/verification failures leave the old workspace intact. A
                // later materialization failure cannot safely resurrect disposed
                // services, so the coordinator exposes an explicit empty state.
                SetCurrent(detached ? CaptureWorkspaceIdentity.None : previous);
                throw;
            }
        }
        finally
        {
            _switchGate.Release();
        }
    }

    public Task SwitchCompatibleAsync(
        CaptureWorkspaceIdentity target,
        Func<CancellationToken, Task<CaptureCompatibilityAssessment>> assessTargetAsync,
        CaptureOpenCapability requiredCapability,
        Func<CancellationToken, Task> stopAndVerifyCurrentAsync,
        Func<CancellationToken, Task> detachAndReleaseCurrentAsync,
        Func<CancellationToken, Task> materializeTargetAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assessTargetAsync);
        return SwitchAsync(
            target,
            async token =>
            {
                var assessment = await assessTargetAsync(token);
                CaptureCompatibilityPolicy.EnsureAllowed(assessment, requiredCapability);
            },
            stopAndVerifyCurrentAsync,
            detachAndReleaseCurrentAsync,
            materializeTargetAsync,
            cancellationToken);
    }

    private void SetCurrent(CaptureWorkspaceIdentity identity)
    {
        _current = identity;
        Interlocked.Increment(ref _generation);
        StateChanged?.Invoke(this, EventArgs.Empty);
    }
}
