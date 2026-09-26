using System.Collections.Immutable;

namespace ProcInsider.Services.Events;

/// <summary>Investigative usefulness, never severity or suspiciousness.</summary>
public enum NativeEventFieldPriority { High, Medium, Low }
public sealed record NativeEventProfileField(string Path, string Label, NativeEventFieldPriority Priority, int Order);
public sealed record ProfiledNativeEventField(string Path, string Label, NativeEventFieldPriority Priority,
    int Order, bool IsDefaultPriority, string? Value);

/// <summary>An immutable presentation revision for one exact native schema. Labels are not identities.</summary>
public sealed class NativeEventProfile
{
    public const int ContractVersion = 1;
    public string Id { get; }
    public Guid Revision { get; }
    public string Name { get; }
    public NativeEventType EventType { get; }
    public ImmutableArray<NativeEventProfileField> Fields { get; }

    public NativeEventProfile(string id, Guid revision, string name, NativeEventType eventType,
        IEnumerable<NativeEventProfileField> fields)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Length > 128 || revision == Guid.Empty ||
            string.IsNullOrWhiteSpace(name) || name.Length > 256 || eventType is null ||
            string.IsNullOrWhiteSpace(eventType.Provider) || eventType.Provider.Length > 512 ||
            string.IsNullOrWhiteSpace(eventType.Channel) || eventType.Channel.Length > 512 ||
            eventType.EventId is < 0 or > 65535 || eventType.Version is null or < 0 or > 255)
            throw new FormatException("Profiles require an ID, revision, name and exact provider/channel/event ID/version (0–255).");
        if (fields is null) throw new FormatException("Profile fields are required.");
        var materialized = fields.Take(NativeEventFieldExtractor.MaximumFields + 1).ToArray();
        if (materialized.Length > NativeEventFieldExtractor.MaximumFields || materialized.Any(f => f is null ||
            string.IsNullOrWhiteSpace(f.Path) || f.Path.Length > NativeEventFieldExtractor.MaximumPathCharacters ||
            !(f.Path.StartsWith("System/", StringComparison.Ordinal) || f.Path.StartsWith("EventData/", StringComparison.Ordinal) ||
              f.Path.StartsWith("UserData/", StringComparison.Ordinal)) ||
            string.IsNullOrWhiteSpace(f.Label) || f.Label.Length > 256 || !Enum.IsDefined(f.Priority) || f.Order is < 0 or > 65535) ||
            materialized.Select(f => f.Path).Distinct(StringComparer.Ordinal).Count() != materialized.Length)
            throw new FormatException("Use unique exact native paths, labels up to 256 characters, High/Medium/Low and order 0–65535 (up to 512 fields).");
        Id = id; Revision = revision; Name = name; EventType = eventType;
        Fields = materialized.OrderBy(f => f.Order).ThenBy(f => f.Path, StringComparer.Ordinal).ToImmutableArray();
    }

    public bool Matches(NativeEventType? type) => type == EventType;

    /// <summary>Retains missing, empty and newly observed values. No profile can reinterpret another version.</summary>
    public static ImmutableArray<ProfiledNativeEventField> Project(EventFieldExtraction extraction,
        NativeEventProfile? profile, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        var definitions = profile?.Matches(extraction.EventType) == true ? profile.Fields : [];
        var values = extraction.Fields.ToDictionary(f => f.Path, f => f.Value, StringComparer.Ordinal);
        var result = ImmutableArray.CreateBuilder<ProfiledNativeEventField>();
        foreach (var field in definitions)
        {
            token.ThrowIfCancellationRequested();
            result.Add(new(field.Path, field.Label, field.Priority, field.Order, false, values.GetValueOrDefault(field.Path)));
            values.Remove(field.Path);
        }
        foreach (var field in extraction.Fields.Where(f => values.ContainsKey(f.Path)))
        {
            token.ThrowIfCancellationRequested();
            result.Add(new(field.Path, field.Path, NativeEventFieldPriority.Medium, 65535, true, field.Value));
        }
        return result.ToImmutable();
    }
}
