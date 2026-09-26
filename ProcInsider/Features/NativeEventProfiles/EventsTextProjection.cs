using System.Collections.Immutable;
using ProcInsider.Services.Events;
using ProcInsider.ViewModels;
using ProcInsider.Features.InvestigationWorkspaces;

namespace ProcInsider.Features.NativeEventProfiles;

/// <summary>Headless snapshot shared by SQL filtering/sorting and displayed row formatting.</summary>
internal sealed class EventsTextProjection : IEventsTextProjection
{
    internal const int MaximumSummaryCharacters = 480;
    private readonly ImmutableArray<NativeEventProfile> _profiles;
    private readonly ImmutableDictionary<NativeEventType, string> _choices;
    internal EventsTextProjection(IEnumerable<NativeEventProfile> profiles, IReadOnlyDictionary<NativeEventType, string>? choices = null)
    { _profiles = profiles.ToImmutableArray(); _choices = (choices ?? new Dictionary<NativeEventType, string>()).ToImmutableDictionary(); }
    public static string Describe(int? eventId, string? provider = null, string? channel = null)
    {
        if (string.Equals(provider, "Microsoft-Windows-Security-Auditing", StringComparison.Ordinal) &&
            string.Equals(channel, "Security", StringComparison.Ordinal))
            return WindowsSecurityEventDescriptions.GetDescription(eventId);
        var sysmon = SysmonEventTaxonomy.GetDescription(eventId, provider, channel);
        if (sysmon != null) return sysmon;
        return eventId switch
        {
            4103 when string.Equals(provider, "Microsoft-Windows-PowerShell", StringComparison.Ordinal) &&
                      string.Equals(channel, "Microsoft-Windows-PowerShell/Operational", StringComparison.Ordinal) => "PowerShell module logging",
            4104 when string.Equals(provider, "Microsoft-Windows-PowerShell", StringComparison.Ordinal) &&
                      string.Equals(channel, "Microsoft-Windows-PowerShell/Operational", StringComparison.Ordinal) => "PowerShell script block logging",
            _ => string.Empty
        };
    }
    public string Description(int? eventId, string? provider = null, string? channel = null) => Describe(eventId, provider, channel);
    public string Details(int? eventId, string nativeText, string? provider = null, string? channel = null) =>
        Project(NativeEventFieldExtractor.Extract(nativeText, eventId, provider, channel)).Summary;
    internal NativeEventPresentation Project(EventFieldExtraction extraction, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        var matches = _profiles.Where(p => p.Matches(extraction.EventType)).ToArray();
        var profile = extraction.EventType is { } type && _choices.TryGetValue(type, out var id)
            ? matches.SingleOrDefault(p => p.Id == id) : matches.Length == 1 ? matches[0] : null;
        var status = extraction.EventType?.Version == null ? "Native schema unavailable" : profile == null
            ? matches.Length > 1 ? "Multiple matching profiles; choose a Details profile" : "No matching profile"
            : $"{profile.Name} · revision {profile.Revision}";
        var fields = NativeEventProfile.Project(extraction, profile, token).Select(f => new NativeEventDisplayField(
            f.Path, f.Label, f.Priority, f.IsDefaultPriority, f.Value,
            f.Value != null ? f.Value.Length == 0 ? "<empty>" : f.Value :
            extraction.Status == EventFieldExtractionStatus.Available ? "<missing>" : "<unavailable>")).ToImmutableArray();
        var high = fields.Where(f => f.Priority == NativeEventFieldPriority.High).ToArray();
        var summary = profile == null ? status : high.Length == 0 ? "No High fields configured" :
            CreateListingPreview(string.Join("; ", high.Select(f => $"{f.Label}: {f.DisplayValue}")));
        if (extraction.Status != EventFieldExtractionStatus.Available)
        {
            status += $" · {extraction.Status}: {extraction.Diagnostic}";
            summary += $" [{extraction.Status}: {extraction.Diagnostic}]";
        }
        return new(extraction, profile, status, summary, fields);
    }

    /// <summary>Produces a bounded, one-line listing preview only; native values remain unchanged elsewhere.</summary>
    internal static string CreateListingPreview(string value)
    {
        var singleLine = string.Join(" ", value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return singleLine.Length <= MaximumSummaryCharacters ? singleLine :
            singleLine[..MaximumSummaryCharacters] + "… [truncated; inspect raw XML or native fields for the complete value]";
    }
}

internal sealed record NativeEventDisplayField(string Path, string Label, NativeEventFieldPriority Priority,
    bool IsDefaultPriority, string? Value, string DisplayValue);
internal sealed record NativeEventPresentation(EventFieldExtraction Extraction, NativeEventProfile? Profile,
    string Status, string Summary, ImmutableArray<NativeEventDisplayField> Fields);
