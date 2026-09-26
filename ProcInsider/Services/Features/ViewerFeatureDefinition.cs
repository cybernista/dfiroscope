using System.Collections.ObjectModel;
using ProcInsider.Models.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Services.Features;

/// <summary>
/// Immutable metadata for one typed viewer-feature registration. Publication
/// remains authoritative in <see cref="IFeatureCatalog"/>; this definition owns
/// only viewer activation and shell presentation metadata.
/// </summary>
public interface IViewerFeatureDefinition
{
    FeatureId Id { get; }

    IReadOnlyList<FeatureId> Dependencies { get; }

    Type ModuleType { get; }

    bool HasActivationFactory { get; }

    bool HasDeactivation { get; }

    IReadOnlyList<ViewerFeatureTabMetadata> Tabs { get; }

    void RegisterActivation(FeatureActivationRegistry activationRegistry);

    IReadOnlyList<FeatureTabDescriptor> CreateTabDescriptors(
        FeatureActivationRegistry activationRegistry);
}

/// <summary>
/// Stable, factory-free tab metadata used for registration validation and
/// deterministic diagnostics.
/// </summary>
public sealed record ViewerFeatureTabMetadata
{
    public ViewerFeatureTabMetadata(
        FeatureTabKey key,
        string header,
        int order,
        bool showCount)
    {
        if (string.IsNullOrWhiteSpace(key.TabId))
        {
            throw new ArgumentException("Viewer feature tabs require a stable key.", nameof(key));
        }

        if (!Enum.IsDefined(key.Surface))
        {
            throw new ArgumentOutOfRangeException(nameof(key), key.Surface, "Unknown viewer tab surface.");
        }

        if (string.IsNullOrWhiteSpace(header))
        {
            throw new ArgumentException("Viewer feature tabs require a header.", nameof(header));
        }

        Key = key;
        Header = header.Trim();
        Order = order;
        ShowCount = showCount;
    }

    public FeatureTabKey Key { get; }

    public string Header { get; }

    public int Order { get; }

    public bool ShowCount { get; }
}

/// <summary>
/// Typed content adapter for a viewer tab. The module accessor is evaluated
/// only when the descriptor is selected, never during registration validation.
/// </summary>
public sealed class ViewerFeatureTabDefinition<TModule> where TModule : class
{
    private readonly Func<TModule, object?> _contentFactory;

    public ViewerFeatureTabDefinition(
        FeatureTabKey key,
        string header,
        int order,
        Func<TModule, object?> contentFactory,
        bool showCount = false)
    {
        Metadata = new ViewerFeatureTabMetadata(key, header, order, showCount);
        _contentFactory = contentFactory ?? throw new ArgumentNullException(nameof(contentFactory));
    }

    public ViewerFeatureTabMetadata Metadata { get; }

    internal FeatureTabDescriptor CreateDescriptor(
        FeatureId featureId,
        FeatureActivationRegistry activationRegistry)
    {
        return new FeatureTabDescriptor(
            Metadata.Key,
            Metadata.Header,
            featureId,
            Metadata.Order,
            () =>
            {
                var module = activationRegistry.GetOrActivate<TModule>(featureId);
                return module == null
                    ? throw new InvalidOperationException(
                        $"Viewer feature '{featureId}' activation is unavailable.")
                    : _contentFactory(module);
            },
            Metadata.ShowCount);
    }
}

/// <summary>
/// Typed activation and presentation definition for one optional viewer module.
/// The activation factory is optional for command-only definitions, but a
/// definition that owns tabs must provide one.
/// </summary>
public sealed class ViewerFeatureDefinition<TModule> : IViewerFeatureDefinition
    where TModule : class
{
    private readonly Func<TModule>? _activationFactory;
    private readonly Action<TModule>? _deactivate;
    private readonly IReadOnlyList<ViewerFeatureTabDefinition<TModule>> _tabDefinitions;

    public ViewerFeatureDefinition(
        FeatureId id,
        IEnumerable<FeatureId>? dependencies,
        Func<TModule>? activationFactory,
        IEnumerable<ViewerFeatureTabDefinition<TModule>>? tabs = null,
        Action<TModule>? deactivate = null)
    {
        if (id.IsEmpty)
        {
            throw new ArgumentException("Viewer feature definitions require a non-empty ID.", nameof(id));
        }

        var dependencyArray = (dependencies ?? []).ToArray();
        var tabArray = (tabs ?? []).ToArray();
        if (dependencyArray.Any(dependency => dependency.IsEmpty))
        {
            throw new ArgumentException("Viewer feature dependencies cannot contain an empty ID.", nameof(dependencies));
        }

        if (tabArray.Any(tab => tab == null))
        {
            throw new ArgumentException("Viewer feature tab definitions cannot contain null entries.", nameof(tabs));
        }

        Id = id;
        Dependencies = new ReadOnlyCollection<FeatureId>(dependencyArray);
        _activationFactory = activationFactory;
        _deactivate = deactivate;
        _tabDefinitions = new ReadOnlyCollection<ViewerFeatureTabDefinition<TModule>>(tabArray);
        Tabs = new ReadOnlyCollection<ViewerFeatureTabMetadata>(
            tabArray.Select(tab => tab.Metadata).ToArray());
    }

    public FeatureId Id { get; }

    public IReadOnlyList<FeatureId> Dependencies { get; }

    public Type ModuleType => typeof(TModule);

    public bool HasActivationFactory => _activationFactory != null;

    public bool HasDeactivation => _deactivate != null;

    public IReadOnlyList<ViewerFeatureTabMetadata> Tabs { get; }

    public void RegisterActivation(FeatureActivationRegistry activationRegistry)
    {
        ArgumentNullException.ThrowIfNull(activationRegistry);
        if (_activationFactory != null)
        {
            activationRegistry.Register(Id, _activationFactory, _deactivate);
        }
    }

    public IReadOnlyList<FeatureTabDescriptor> CreateTabDescriptors(
        FeatureActivationRegistry activationRegistry)
    {
        ArgumentNullException.ThrowIfNull(activationRegistry);
        if (_activationFactory == null && _tabDefinitions.Count > 0)
        {
            throw new InvalidOperationException(
                $"Viewer feature '{Id}' maps tabs but has no activation factory.");
        }

        return new ReadOnlyCollection<FeatureTabDescriptor>(
            _tabDefinitions
                .Select(tab => tab.CreateDescriptor(Id, activationRegistry))
                .ToArray());
    }
}
