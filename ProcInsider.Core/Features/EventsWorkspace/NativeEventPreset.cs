using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Services.Events;

namespace ProcInsider.Features.InvestigationWorkspaces;

/// <summary>Exact schema/path identity; an unscoped path is a merged automatic or explicitly selected manual display column.</summary>
internal sealed record NativeEventColumnIdentity(EventSort? BuiltIn, NativeEventType? EventType, string? Path)
{
    [JsonIgnore] public string Key => JsonSerializer.Serialize(this);
    [JsonIgnore] public string Description => BuiltIn?.ToString() ?? (EventType is { } t
        ? $"{t.Provider} / {t.Channel} / {t.EventId} v{t.Version} / {Path}" : $"Merged extracted path / {Path}");
    // Shared by the cell and the read-only SQL projection; labels never identify fields.
    internal string DisplayValue(EventFieldExtraction? extraction)
    {
        if (extraction == null) return "<pending>";
        if (EventType is { } type)
        {
            if (extraction.EventType?.Version == null || extraction.Status is not (EventFieldExtractionStatus.Available or EventFieldExtractionStatus.Partial)) return "<unavailable>";
            if (extraction.EventType != type) return "<not applicable>";
        }
        if (extraction.Fields.FirstOrDefault(f => f.Path == Path) is { } field) return field.Value.Length == 0 ? "<empty>" : field.Value;
        return extraction.Status == EventFieldExtractionStatus.Available ? "<missing>" : "<unavailable>";
    }
    internal void Validate()
    {
        if (BuiltIn is { } builtIn)
        {
            if (!Enum.IsDefined(builtIn) || builtIn == EventSort.Sequence || EventType != null || Path != null)
                throw new FormatException("Invalid ordinary column identity.");
        }
        else
        {
            if (string.IsNullOrWhiteSpace(Path) || Path.Length > NativeEventFieldExtractor.MaximumPathCharacters)
                throw new FormatException("An exact extracted path is required.");
            if (EventType is { } type)
                _ = new NativeEventProfile("validate", Guid.NewGuid(), "validate", type,
                    [new(Path, "validate", NativeEventFieldPriority.Medium, 0)]);
        }
    }
}

internal sealed record NativeEventPresetColumn(NativeEventColumnIdentity Identity, string Label, double Width)
{
    [JsonIgnore] public string Header => Identity.BuiltIn != null || Identity.EventType == null && Label == Identity.Path ? Label : $"{Label} — {Identity.Description}";
}
internal sealed record NativeEventPresetProfile(string Id, Guid Revision, ImmutableArray<NativeEventFieldPriority> Categories);
// Null provider/channel means the corresponding explicit filter is unset, never a wildcard match.
internal sealed record NativeEventPresetAssociation(string? Provider, string? Channel, int EventId);

/// <summary>Frozen resolved columns plus the saved profile revisions used to compose them.</summary>
internal sealed class NativeEventPreset
{
    public string Id { get; }
    public Guid Revision { get; }
    public string Name { get; }
    public ImmutableArray<NativeEventPresetProfile> Profiles { get; }
    public ImmutableArray<NativeEventPresetColumn> Columns { get; }
    public NativeEventPresetAssociation? Association { get; }
    public NativeEventPreset(string id, Guid revision, string name, IEnumerable<NativeEventPresetProfile> profiles,
        IEnumerable<NativeEventPresetColumn> columns, NativeEventPresetAssociation? association)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Length > 128 || revision == Guid.Empty || string.IsNullOrWhiteSpace(name) || name.Length > 256 || profiles == null || columns == null)
            throw new FormatException("A preset requires an ID, revision, name and columns.");
        Id = id; Revision = revision; Name = name; Profiles = profiles.ToImmutableArray(); Columns = columns.ToImmutableArray(); Association = association;
        if (Profiles.Any(p => p == null || string.IsNullOrWhiteSpace(p.Id) || p.Id.Length > 128 || p.Revision == Guid.Empty || p.Categories.IsDefaultOrEmpty || p.Categories.Any(c => !Enum.IsDefined(c)) || p.Categories.Distinct().Count() != p.Categories.Length) ||
            Profiles.Select(p => p.Id).Distinct(StringComparer.Ordinal).Count() != Profiles.Length)
            throw new FormatException("Use unique saved profiles with explicit revisions and categories.");
        foreach (var column in Columns)
        {
            if (column?.Identity == null || string.IsNullOrWhiteSpace(column.Label) || column.Label.Length > 4096 || !double.IsFinite(column.Width) || column.Width <= 0)
                throw new FormatException("Columns require a label and a positive finite pixel width.");
            column.Identity.Validate();
        }
        if (Columns.Select(c => c.Identity).Distinct().Count() != Columns.Length)
            throw new FormatException("Duplicate exact column identities.");
        if (association != null && (association.EventId is < 0 or > 65535 || association.Provider?.Length > 512 || association.Channel?.Length > 512))
            throw new FormatException("Invalid event-type filter association.");
    }
    internal static IEnumerable<NativeEventPresetColumn> Compose(NativeEventProfile profile, IEnumerable<NativeEventFieldPriority> categories) =>
        profile.Fields.Where(f => categories.Contains(f.Priority)).Select(f => new NativeEventPresetColumn(new(null, profile.EventType, f.Path), f.Label, 220));
}
