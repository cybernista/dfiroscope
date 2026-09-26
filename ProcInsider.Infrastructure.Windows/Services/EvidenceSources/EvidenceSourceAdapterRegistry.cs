using ProcInsider.Models.EvidenceSources;

namespace ProcInsider.Services.EvidenceSources;

/// <summary>
/// In-process registry for built-in adapters. It deliberately does not discover
/// or load third-party assemblies.
/// </summary>
public sealed class EvidenceSourceAdapterRegistry
{
    private readonly IReadOnlyDictionary<string, IEvidenceSourceAdapter> _adapters;

    public EvidenceSourceAdapterRegistry(IEnumerable<IEvidenceSourceAdapter> adapters)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        var byId = new Dictionary<string, IEvidenceSourceAdapter>(StringComparer.Ordinal);
        foreach (var adapter in adapters)
        {
            ArgumentNullException.ThrowIfNull(adapter);
            ValidateDescriptor(adapter.Descriptor);
            if (!byId.TryAdd(adapter.Descriptor.AdapterId, adapter))
            {
                var existing = byId[adapter.Descriptor.AdapterId].Descriptor;
                throw new InvalidOperationException(
                    $"Duplicate evidence source adapter id '{adapter.Descriptor.AdapterId}' " +
                    $"for versions '{existing.AdapterVersion}' and '{adapter.Descriptor.AdapterVersion}'.");
            }
        }

        _adapters = byId;
        Descriptors = byId.Values
            .Select(adapter => adapter.Descriptor)
            .OrderBy(descriptor => descriptor.AdapterId, StringComparer.Ordinal)
            .ToArray();
    }

    public IReadOnlyList<EvidenceSourceAdapterDescriptor> Descriptors { get; }

    public IEvidenceSourceAdapter Resolve(string adapterId, string adapterVersion = "")
    {
        if (string.IsNullOrWhiteSpace(adapterId) || !_adapters.TryGetValue(adapterId, out var adapter))
        {
            throw new KeyNotFoundException($"Unknown evidence source adapter '{adapterId}'.");
        }

        if (!string.IsNullOrWhiteSpace(adapterVersion) &&
            !string.Equals(adapter.Descriptor.AdapterVersion, adapterVersion, StringComparison.Ordinal))
        {
            throw new KeyNotFoundException(
                $"Evidence source adapter '{adapterId}' version '{adapterVersion}' is not registered; " +
                $"available version is '{adapter.Descriptor.AdapterVersion}'.");
        }

        return adapter;
    }

    public TAdapter Resolve<TAdapter>(string adapterId, string adapterVersion = "")
        where TAdapter : class, IEvidenceSourceAdapter
        => Resolve(adapterId, adapterVersion) as TAdapter
           ?? throw new InvalidOperationException(
               $"Evidence source adapter '{adapterId}' is not a {typeof(TAdapter).Name}.");

    private static void ValidateDescriptor(EvidenceSourceAdapterDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (string.IsNullOrWhiteSpace(descriptor.AdapterId) ||
            descriptor.AdapterId.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_')) ||
            !string.Equals(descriptor.AdapterId, descriptor.AdapterId.ToLowerInvariant(), StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Evidence source adapter ids must be non-empty lowercase ASCII identifiers.");
        }

        if (!Version.TryParse(descriptor.AdapterVersion, out _))
        {
            throw new InvalidOperationException(
                $"Evidence source adapter '{descriptor.AdapterId}' has invalid version '{descriptor.AdapterVersion}'.");
        }

        if (string.IsNullOrWhiteSpace(descriptor.DisplayName) ||
            string.IsNullOrWhiteSpace(descriptor.Description) ||
            descriptor.MaxBatchRowCount <= 0)
        {
            throw new InvalidOperationException(
                $"Evidence source adapter '{descriptor.AdapterId}' must define display metadata and a positive batch limit.");
        }

        var duplicatePrerequisite = descriptor.Prerequisites
            .GroupBy(prerequisite => prerequisite.PrerequisiteId, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(group => string.IsNullOrWhiteSpace(group.Key) || group.Count() > 1);
        if (duplicatePrerequisite != null)
        {
            throw new InvalidOperationException(
                $"Evidence source adapter '{descriptor.AdapterId}' has an empty or duplicate prerequisite id.");
        }
    }
}
