using System.Diagnostics.CodeAnalysis;
using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

public sealed class FeatureActivationRegistry : IDisposable
{
    private readonly FeatureAccessService _access;
    private readonly Dictionary<ModuleKey, IFeatureModuleRegistration> _registrations = [];
    private bool _disposed;

    public FeatureActivationRegistry(FeatureAccessService access)
    {
        _access = access;
    }

    public event EventHandler<FeatureActivationFailedEventArgs>? ActivationFailed;
    public event EventHandler<FeatureActivatedEventArgs>? Activated;
    public event EventHandler<FeatureDeactivationFailedEventArgs>? DeactivationFailed;

    public IReadOnlyCollection<FeatureId> ActivatedFeatureIds => _registrations
        .Where(pair => pair.Value.IsActivated)
        .Select(pair => pair.Key.FeatureId)
        .Distinct()
        .ToArray();

    public void Register<T>(FeatureId featureId, Func<T> factory, Action<T>? deactivate = null)
        where T : class
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var key = new ModuleKey(featureId, typeof(T));
        if (!_registrations.TryAdd(key, new FeatureModuleRegistration<T>(factory, deactivate)))
        {
            throw new InvalidOperationException($"Feature '{featureId}' already has an activation registration.");
        }
    }

    public T? GetOrActivate<T>(FeatureId featureId) where T : class
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_access.IsPublished(featureId) ||
            !_registrations.TryGetValue(new ModuleKey(featureId, typeof(T)), out var registration) ||
            registration is not FeatureModuleRegistration<T> typed)
        {
            return null;
        }

        try
        {
            var instance = typed.GetOrActivate(out var activatedNow);
            if (activatedNow)
            {
                Activated?.Invoke(this, new FeatureActivatedEventArgs(featureId, typeof(T), instance));
            }

            return instance;
        }
        catch (Exception ex)
        {
            if (typed.TryMarkFailureReported())
            {
                ActivationFailed?.Invoke(this, new FeatureActivationFailedEventArgs(featureId, ex));
            }

            return null;
        }
    }

    public bool TryGetActivated<T>(
        FeatureId featureId,
        [NotNullWhen(true)] out T? instance) where T : class
    {
        instance = null;
        if (!_registrations.TryGetValue(new ModuleKey(featureId, typeof(T)), out var registration) ||
            registration is not FeatureModuleRegistration<T> typed)
        {
            return false;
        }

        instance = typed.ActivatedInstance;
        return instance != null;
    }

    public bool IsActivated(FeatureId featureId) =>
        _registrations.Any(pair => pair.Key.FeatureId == featureId && pair.Value.IsActivated);

    public void DeactivateAll()
    {
        foreach (var pair in _registrations.Reverse())
        {
            try
            {
                pair.Value.Deactivate();
            }
            catch (Exception ex)
            {
                DeactivationFailed?.Invoke(
                    this,
                    new FeatureDeactivationFailedEventArgs(pair.Key.FeatureId, ex));
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        DeactivateAll();
        _disposed = true;
    }

    private interface IFeatureModuleRegistration
    {
        bool IsActivated { get; }
        void Deactivate();
    }

    private readonly record struct ModuleKey(FeatureId FeatureId, Type ModuleType);

    private sealed class FeatureModuleRegistration<T> : IFeatureModuleRegistration where T : class
    {
        private readonly Func<T> _factory;
        private readonly Action<T>? _deactivate;
        private T? _instance;
        private Exception? _activationFailure;
        private bool _failureReported;

        public FeatureModuleRegistration(Func<T> factory, Action<T>? deactivate)
        {
            _factory = factory ?? throw new ArgumentNullException(nameof(factory));
            _deactivate = deactivate;
        }

        public bool IsActivated => _instance != null;
        public T? ActivatedInstance => _instance;

        public T GetOrActivate(out bool activatedNow)
        {
            if (_instance != null)
            {
                activatedNow = false;
                return _instance;
            }

            if (_activationFailure != null)
            {
                activatedNow = false;
                throw _activationFailure;
            }

            try
            {
                _instance = _factory() ?? throw new InvalidOperationException(
                    $"Feature activation factory for '{typeof(T).Name}' returned null.");
                activatedNow = true;
                return _instance;
            }
            catch (Exception ex)
            {
                activatedNow = false;
                _activationFailure = ex;
                throw;
            }
        }

        public bool TryMarkFailureReported()
        {
            if (_failureReported)
            {
                return false;
            }

            _failureReported = true;
            return true;
        }

        public void Deactivate()
        {
            if (_instance == null)
            {
                return;
            }

            var instance = _instance;
            _instance = null;
            Exception? failure = null;
            try
            {
                _deactivate?.Invoke(instance);
            }
            catch (Exception ex)
            {
                failure = ex;
            }

            try
            {
                if (instance is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }
            catch (Exception ex)
            {
                failure = failure == null ? ex : new AggregateException(failure, ex);
            }

            if (failure != null)
            {
                throw failure;
            }
        }
    }
}

public sealed record FeatureActivationFailedEventArgs(FeatureId FeatureId, Exception Exception);
public sealed record FeatureActivatedEventArgs(FeatureId FeatureId, Type ModuleType, object Instance);
public sealed record FeatureDeactivationFailedEventArgs(FeatureId FeatureId, Exception Exception);
