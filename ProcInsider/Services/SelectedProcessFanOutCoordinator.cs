using ProcInsider.Models.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Services;

public enum SelectedProcessFanOutPhase
{
    Empty,
    Loading,
    Clearing,
    Rebinding,
    Active,
    Disposed
}

public enum SelectedProcessFanOutOutcome
{
    None,
    Succeeded,
    PartialFailure,
    Canceled,
    Superseded,
    Disposed
}

public enum SelectedProcessConsumerOutcome
{
    Succeeded,
    Unavailable,
    Failed,
    Canceled,
    Superseded
}

public sealed record SelectedProcessContext(
    ProcessRowViewModel Row,
    string ProcessEntityId,
    string ProcessKey,
    int ProcessId,
    string ProcessName,
    DateTime? StartTime,
    long WorkspaceGeneration,
    long SelectionGeneration)
{
    public static SelectedProcessContext Create(
        ProcessRowViewModel row,
        long workspaceGeneration,
        long selectionGeneration)
    {
        ArgumentNullException.ThrowIfNull(row);
        return new SelectedProcessContext(
            row,
            row.ProcessInfo.ProcessEntityId ?? string.Empty,
            row.ProcessKey,
            row.ProcessId,
            row.ProcessName,
            row.ProcessInfo.StartTime,
            workspaceGeneration,
            selectionGeneration);
    }
}

public sealed record SelectedProcessConsumerResult(
    SelectedProcessConsumerOutcome Outcome,
    string Error = "")
{
    public static SelectedProcessConsumerResult Success { get; } = new(
        SelectedProcessConsumerOutcome.Succeeded);

    public static SelectedProcessConsumerResult Unavailable(string error) => new(
        SelectedProcessConsumerOutcome.Unavailable,
        error ?? string.Empty);
}

public sealed record SelectedProcessConsumerDiagnostic(
    string ConsumerKey,
    SelectedProcessConsumerOutcome Outcome,
    string Error = "");

public sealed record SelectedProcessFanOutState(
    SelectedProcessContext? CurrentSelection,
    long WorkspaceGeneration,
    long SelectionGeneration,
    SelectedProcessFanOutPhase Phase,
    SelectedProcessFanOutOutcome LastOutcome,
    IReadOnlyList<SelectedProcessConsumerDiagnostic> Diagnostics,
    string LastError)
{
    public static SelectedProcessFanOutState Initial(long workspaceGeneration) => new(
        null,
        workspaceGeneration,
        0,
        SelectedProcessFanOutPhase.Empty,
        SelectedProcessFanOutOutcome.None,
        [],
        string.Empty);
}

public sealed record SelectedProcessFanOutResult(
    SelectedProcessFanOutOutcome Outcome,
    SelectedProcessFanOutState State)
{
    public bool Succeeded => Outcome == SelectedProcessFanOutOutcome.Succeeded;
}

public sealed class SelectedProcessFanOutStateChangedEventArgs(
    SelectedProcessFanOutState state) : EventArgs
{
    public SelectedProcessFanOutState State { get; } = state;
}

/// <summary>
/// One independently fallible selected-process surface. Implementations must honor
/// cancellation before projecting results obtained after an asynchronous boundary.
/// </summary>
public interface ISelectedProcessFanOutConsumer
{
    string Key { get; }

    Task<SelectedProcessConsumerResult> ApplyAsync(
        SelectedProcessContext? context,
        CancellationToken cancellationToken);
}

/// <summary>
/// Composition boundary retained by MainViewModel. Optional consumers returned here
/// must already be activated; discovery must never construct a feature.
/// </summary>
public interface ISelectedProcessFanOutConsumerProvider
{
    IReadOnlyList<ISelectedProcessFanOutConsumer> GetCoreConsumers();

    IReadOnlyList<ISelectedProcessFanOutConsumer> GetActivatedOptionalConsumers();

    IReadOnlyList<ISelectedProcessFanOutConsumer> GetActivatedOptionalConsumers(
        FeatureId featureId);
}

public sealed class DelegateSelectedProcessFanOutConsumer : ISelectedProcessFanOutConsumer
{
    private readonly Func<SelectedProcessContext?, CancellationToken, Task<SelectedProcessConsumerResult>> _apply;

    public DelegateSelectedProcessFanOutConsumer(
        string key,
        Func<SelectedProcessContext?, CancellationToken, Task<SelectedProcessConsumerResult>> apply)
    {
        Key = string.IsNullOrWhiteSpace(key)
            ? throw new ArgumentException("A selected-process consumer key is required.", nameof(key))
            : key.Trim();
        _apply = apply ?? throw new ArgumentNullException(nameof(apply));
    }

    public string Key { get; }

    public Task<SelectedProcessConsumerResult> ApplyAsync(
        SelectedProcessContext? context,
        CancellationToken cancellationToken) =>
        _apply(context, cancellationToken);
}

/// <summary>
/// Headless owner for current selected-process context, generation/cancellation,
/// deterministic core and activated-optional consumer fan-out, late activation,
/// partial-failure reporting, workspace invalidation, and repeated cleanup.
/// </summary>
public sealed class SelectedProcessFanOutCoordinator : IDisposable
{
    private readonly object _gate = new();
    private readonly ISelectedProcessFanOutConsumerProvider _consumerProvider;
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly HashSet<string> _boundConsumerKeys = new(StringComparer.Ordinal);
    private CancellationTokenSource? _activeOperationCts;
    private SelectedProcessFanOutState _state;
    private bool _disposed;

    public SelectedProcessFanOutCoordinator(
        long initialWorkspaceGeneration,
        ISelectedProcessFanOutConsumerProvider consumerProvider)
    {
        if (initialWorkspaceGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(initialWorkspaceGeneration),
                initialWorkspaceGeneration,
                "Workspace generation cannot be negative.");
        }

        _consumerProvider = consumerProvider ?? throw new ArgumentNullException(nameof(consumerProvider));
        _state = SelectedProcessFanOutState.Initial(initialWorkspaceGeneration);
    }

    public event EventHandler<SelectedProcessFanOutStateChangedEventArgs>? StateChanged;

    public SelectedProcessFanOutState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    public Task<SelectedProcessFanOutResult> SelectAsync(
        ProcessRowViewModel? row,
        long workspaceGeneration,
        CancellationToken cancellationToken = default) =>
        RunSelectionAsync(
            row,
            workspaceGeneration,
            row == null ? SelectedProcessFanOutPhase.Clearing : SelectedProcessFanOutPhase.Loading,
            cancellationToken);

    public Task<SelectedProcessFanOutResult> RebindWorkspaceAsync(
        long workspaceGeneration,
        CancellationToken cancellationToken = default) =>
        RunSelectionAsync(
            null,
            workspaceGeneration,
            SelectedProcessFanOutPhase.Rebinding,
            cancellationToken);

    public async Task<SelectedProcessFanOutResult> BindActivatedConsumersAsync(
        FeatureId featureId,
        CancellationToken cancellationToken = default)
    {
        SelectedProcessFanOutState operationState;
        CancellationToken activeToken;
        lock (_gate)
        {
            if (_disposed)
            {
                return CreateDisposedResultLocked();
            }

            operationState = _state;
            activeToken = _activeOperationCts?.Token ?? _lifetimeCts.Token;
        }

        IReadOnlyList<ISelectedProcessFanOutConsumer> consumers;
        try
        {
            consumers = _consumerProvider.GetActivatedOptionalConsumers(featureId);
        }
        catch (Exception ex)
        {
            return PublishLateBindingFailure(operationState, "consumer-provider", ex);
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            activeToken,
            cancellationToken,
            _lifetimeCts.Token);
        var diagnostics = new List<SelectedProcessConsumerDiagnostic>();
        foreach (var consumer in NormalizeConsumers(consumers))
        {
            if (!TryReserveConsumer(operationState, consumer.Key))
            {
                continue;
            }

            var diagnostic = await ApplyConsumerAsync(
                consumer,
                operationState.CurrentSelection,
                operationState,
                linkedCts.Token);
            diagnostics.Add(diagnostic);
            if (!IsCurrent(operationState))
            {
                return new SelectedProcessFanOutResult(
                    SelectedProcessFanOutOutcome.Superseded,
                    State);
            }
        }

        if (diagnostics.Count == 0)
        {
            return new SelectedProcessFanOutResult(operationState.LastOutcome, State);
        }

        return PublishLateBindingDiagnostics(operationState, diagnostics);
    }

    public void Dispose()
    {
        SelectedProcessFanOutState disposedState;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _activeOperationCts?.Cancel();
            _activeOperationCts?.Dispose();
            _activeOperationCts = null;
            _lifetimeCts.Cancel();
            disposedState = _state with
            {
                Phase = SelectedProcessFanOutPhase.Disposed,
                LastOutcome = SelectedProcessFanOutOutcome.Disposed
            };
            _state = disposedState;
        }

        PublishState(disposedState);
        _lifetimeCts.Dispose();
    }

    private async Task<SelectedProcessFanOutResult> RunSelectionAsync(
        ProcessRowViewModel? row,
        long workspaceGeneration,
        SelectedProcessFanOutPhase phase,
        CancellationToken cancellationToken)
    {
        if (workspaceGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(workspaceGeneration),
                workspaceGeneration,
                "Workspace generation cannot be negative.");
        }

        SelectedProcessFanOutState operationState;
        CancellationToken operationToken;
        lock (_gate)
        {
            if (_disposed)
            {
                return CreateDisposedResultLocked();
            }

            _activeOperationCts?.Cancel();
            _activeOperationCts?.Dispose();
            _activeOperationCts = CancellationTokenSource.CreateLinkedTokenSource(
                _lifetimeCts.Token,
                cancellationToken);
            operationToken = _activeOperationCts.Token;

            var selectionGeneration = checked(_state.SelectionGeneration + 1);
            var context = row == null
                ? null
                : SelectedProcessContext.Create(row, workspaceGeneration, selectionGeneration);
            _boundConsumerKeys.Clear();
            operationState = new SelectedProcessFanOutState(
                context,
                workspaceGeneration,
                selectionGeneration,
                phase,
                SelectedProcessFanOutOutcome.None,
                [],
                string.Empty);
            _state = operationState;
        }

        PublishState(operationState);

        IReadOnlyList<ISelectedProcessFanOutConsumer> consumers;
        try
        {
            consumers = NormalizeConsumers(
                _consumerProvider.GetCoreConsumers()
                    .Concat(_consumerProvider.GetActivatedOptionalConsumers()));
        }
        catch (Exception ex)
        {
            return PublishProviderFailure(operationState, ex);
        }

        var pendingConsumers = new List<Task<SelectedProcessConsumerDiagnostic>>(consumers.Count);
        foreach (var consumer in consumers)
        {
            if (!TryReserveConsumer(operationState, consumer.Key))
            {
                continue;
            }

            pendingConsumers.Add(ApplyConsumerAsync(
                consumer,
                operationState.CurrentSelection,
                operationState,
                operationToken));
        }

        var diagnostics = new List<SelectedProcessConsumerDiagnostic>(pendingConsumers.Count);
        foreach (var pendingConsumer in pendingConsumers)
        {
            var diagnostic = await pendingConsumer;
            diagnostics.Add(diagnostic);

            if (!IsCurrent(operationState))
            {
                return new SelectedProcessFanOutResult(
                    SelectedProcessFanOutOutcome.Superseded,
                    State);
            }

            if (diagnostic.Outcome is SelectedProcessConsumerOutcome.Canceled or
                SelectedProcessConsumerOutcome.Superseded)
            {
                break;
            }
        }

        return PublishCompleted(operationState, diagnostics, cancellationToken);
    }

    private async Task<SelectedProcessConsumerDiagnostic> ApplyConsumerAsync(
        ISelectedProcessFanOutConsumer consumer,
        SelectedProcessContext? context,
        SelectedProcessFanOutState operationState,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await consumer.ApplyAsync(context, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsCurrent(operationState))
            {
                return new SelectedProcessConsumerDiagnostic(
                    consumer.Key,
                    SelectedProcessConsumerOutcome.Superseded);
            }

            return new SelectedProcessConsumerDiagnostic(
                consumer.Key,
                result.Outcome,
                result.Error ?? string.Empty);
        }
        catch (OperationCanceledException)
        {
            return new SelectedProcessConsumerDiagnostic(
                consumer.Key,
                IsCurrent(operationState)
                    ? SelectedProcessConsumerOutcome.Canceled
                    : SelectedProcessConsumerOutcome.Superseded);
        }
        catch (Exception ex)
        {
            return new SelectedProcessConsumerDiagnostic(
                consumer.Key,
                SelectedProcessConsumerOutcome.Failed,
                ex.Message);
        }
    }

    private SelectedProcessFanOutResult PublishCompleted(
        SelectedProcessFanOutState operationState,
        IReadOnlyList<SelectedProcessConsumerDiagnostic> diagnostics,
        CancellationToken callerToken)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return CreateDisposedResultLocked();
            }

            if (!IsCurrentLocked(operationState))
            {
                return new SelectedProcessFanOutResult(
                    SelectedProcessFanOutOutcome.Superseded,
                    _state);
            }

            var combinedDiagnostics = _state.Diagnostics
                .Where(existing => diagnostics.All(current =>
                    !string.Equals(existing.ConsumerKey, current.ConsumerKey, StringComparison.Ordinal)))
                .Concat(diagnostics)
                .ToArray();
            var canceled = callerToken.IsCancellationRequested ||
                           combinedDiagnostics.Any(diagnostic =>
                               diagnostic.Outcome == SelectedProcessConsumerOutcome.Canceled);
            var partialFailure = combinedDiagnostics.Any(diagnostic =>
                diagnostic.Outcome is SelectedProcessConsumerOutcome.Failed or
                    SelectedProcessConsumerOutcome.Unavailable);
            var outcome = canceled
                ? SelectedProcessFanOutOutcome.Canceled
                : partialFailure
                    ? SelectedProcessFanOutOutcome.PartialFailure
                    : SelectedProcessFanOutOutcome.Succeeded;
            var lastError = string.Join(
                "; ",
                combinedDiagnostics
                    .Where(diagnostic => !string.IsNullOrWhiteSpace(diagnostic.Error))
                    .Select(diagnostic => $"{diagnostic.ConsumerKey}: {diagnostic.Error}"));
            var completed = operationState with
            {
                Phase = operationState.CurrentSelection == null
                    ? SelectedProcessFanOutPhase.Empty
                    : SelectedProcessFanOutPhase.Active,
                LastOutcome = outcome,
                Diagnostics = combinedDiagnostics,
                LastError = lastError
            };
            _state = completed;
            operationState = completed;
        }

        PublishState(operationState);
        return new SelectedProcessFanOutResult(operationState.LastOutcome, operationState);
    }

    private SelectedProcessFanOutResult PublishProviderFailure(
        SelectedProcessFanOutState operationState,
        Exception exception)
    {
        var diagnostics = new[]
        {
            new SelectedProcessConsumerDiagnostic(
                "consumer-provider",
                SelectedProcessConsumerOutcome.Failed,
                exception.Message)
        };
        return PublishCompleted(operationState, diagnostics, CancellationToken.None);
    }

    private SelectedProcessFanOutResult PublishLateBindingFailure(
        SelectedProcessFanOutState operationState,
        string key,
        Exception exception) =>
        PublishLateBindingDiagnostics(
            operationState,
            [new SelectedProcessConsumerDiagnostic(
                key,
                SelectedProcessConsumerOutcome.Failed,
                exception.Message)]);

    private SelectedProcessFanOutResult PublishLateBindingDiagnostics(
        SelectedProcessFanOutState operationState,
        IReadOnlyList<SelectedProcessConsumerDiagnostic> diagnostics)
    {
        SelectedProcessFanOutState published;
        lock (_gate)
        {
            if (_disposed)
            {
                return CreateDisposedResultLocked();
            }

            if (!IsCurrentLocked(operationState))
            {
                return new SelectedProcessFanOutResult(
                    SelectedProcessFanOutOutcome.Superseded,
                    _state);
            }

            var combined = _state.Diagnostics
                .Where(existing => diagnostics.All(current =>
                    !string.Equals(existing.ConsumerKey, current.ConsumerKey, StringComparison.Ordinal)))
                .Concat(diagnostics)
                .ToArray();
            var hasFailure = combined.Any(diagnostic =>
                diagnostic.Outcome is SelectedProcessConsumerOutcome.Failed or
                    SelectedProcessConsumerOutcome.Unavailable);
            published = _state with
            {
                LastOutcome = hasFailure
                    ? SelectedProcessFanOutOutcome.PartialFailure
                    : _state.LastOutcome == SelectedProcessFanOutOutcome.None
                        ? SelectedProcessFanOutOutcome.Succeeded
                        : _state.LastOutcome,
                Diagnostics = combined,
                LastError = string.Join(
                    "; ",
                    combined
                        .Where(diagnostic => !string.IsNullOrWhiteSpace(diagnostic.Error))
                        .Select(diagnostic => $"{diagnostic.ConsumerKey}: {diagnostic.Error}"))
            };
            _state = published;
        }

        PublishState(published);
        return new SelectedProcessFanOutResult(published.LastOutcome, published);
    }

    private bool TryReserveConsumer(
        SelectedProcessFanOutState operationState,
        string consumerKey)
    {
        lock (_gate)
        {
            return !_disposed &&
                   IsCurrentLocked(operationState) &&
                   _boundConsumerKeys.Add(consumerKey);
        }
    }

    private bool IsCurrent(SelectedProcessFanOutState operationState)
    {
        lock (_gate)
        {
            return !_disposed && IsCurrentLocked(operationState);
        }
    }

    private bool IsCurrentLocked(SelectedProcessFanOutState operationState) =>
        _state.SelectionGeneration == operationState.SelectionGeneration &&
        _state.WorkspaceGeneration == operationState.WorkspaceGeneration &&
        ReferenceEquals(_state.CurrentSelection?.Row, operationState.CurrentSelection?.Row);

    private static IReadOnlyList<ISelectedProcessFanOutConsumer> NormalizeConsumers(
        IEnumerable<ISelectedProcessFanOutConsumer> consumers)
    {
        ArgumentNullException.ThrowIfNull(consumers);
        var normalized = new List<ISelectedProcessFanOutConsumer>();
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var consumer in consumers)
        {
            if (consumer == null)
            {
                throw new InvalidOperationException("Selected-process consumers cannot contain null entries.");
            }

            if (string.IsNullOrWhiteSpace(consumer.Key))
            {
                throw new InvalidOperationException("Selected-process consumers require stable non-empty keys.");
            }

            if (!keys.Add(consumer.Key))
            {
                throw new InvalidOperationException(
                    $"Duplicate selected-process consumer key '{consumer.Key}'.");
            }

            normalized.Add(consumer);
        }

        return normalized;
    }

    private SelectedProcessFanOutResult CreateDisposedResultLocked() => new(
        SelectedProcessFanOutOutcome.Disposed,
        _state.Phase == SelectedProcessFanOutPhase.Disposed
            ? _state
            : _state with
            {
                Phase = SelectedProcessFanOutPhase.Disposed,
                LastOutcome = SelectedProcessFanOutOutcome.Disposed
            });

    private void PublishState(SelectedProcessFanOutState state) =>
        StateChanged?.Invoke(this, new SelectedProcessFanOutStateChangedEventArgs(state));
}
