using System.Collections.ObjectModel;

namespace ProcInsider.Features.InvestigationWorkspaces;

/// <summary>
/// Fixed, curated Sysmon index for the Events Explorer. It classifies only these known IDs;
/// unfamiliar recorded Sysmon IDs remain available through the ordinary Events pivots.
/// </summary>
internal sealed record SysmonEventDefinition(int EventId, string Name, string Description);
internal sealed record SysmonEventCategory(string Name, string Description, IReadOnlyList<SysmonEventDefinition> Events);

internal static class SysmonEventTaxonomy
{
    internal const string Source = "Sysmon";
    internal const string Provider = "Microsoft-Windows-Sysmon";
    internal const string Channel = "Microsoft-Windows-Sysmon/Operational";
    internal static IReadOnlyList<SysmonEventCategory> Categories { get; } = Freeze(
    [
        Category("Process lifecycle", (1, "Process created"), (5, "Process terminated")),
        Category("Process interactions & tampering", (8, "Remote thread created"), (10, "Process accessed"), (25, "Process tampering")),
        Category("Network & DNS", (3, "Network connection"), (22, "DNS query")),
        Category("Files & storage", (2, "File creation time changed"), (9, "Raw disk access"), (11, "File created"), (15, "Named stream created"), (23, "File deleted and archived"), (26, "File deletion detected"), (27, "Executable creation blocked"), (28, "File shredding blocked"), (29, "Executable created")),
        Category("Registry", (12, "Object created/deleted"), (13, "Value set"), (14, "Key/value renamed")),
        Category("Modules & drivers", (6, "Driver loaded"), (7, "Image/module loaded")),
        Category("Named pipes", (17, "Pipe created"), (18, "Pipe connected")),
        Category("WMI subscriptions", (19, "Filter registered"), (20, "Consumer registered"), (21, "Consumer bound to filter")),
        Category("Clipboard", (24, "Clipboard changed")),
        Category("Sysmon health & configuration", (4, "Service state changed"), (16, "Configuration changed"), (255, "Error")),
    ]);

    internal static IReadOnlyList<int> EventIds { get; } = new ReadOnlyCollection<int>(Categories.SelectMany(category => category.Events).Select(definition => definition.EventId).ToArray());

    /// <summary>Returns a label only after the source has been proven to be the Sysmon operational channel.</summary>
    internal static string? GetDescription(int? eventId, string? provider, string? channel) =>
        eventId is { } id && string.Equals(provider, Provider, StringComparison.Ordinal) &&
        string.Equals(channel, Channel, StringComparison.Ordinal)
            ? Categories.SelectMany(category => category.Events).SingleOrDefault(definition => definition.EventId == id)?.Name
            : null;

    static SysmonEventTaxonomy()
    {
        if (Categories.Count != 10 || EventIds.Count != 30 || EventIds.Distinct().Count() != EventIds.Count ||
            Categories.Any(category => string.IsNullOrWhiteSpace(category.Name) || category.Events.Count == 0 ||
                category.Events.Any(definition => definition.EventId < 0 || string.IsNullOrWhiteSpace(definition.Name))))
            throw new InvalidOperationException("The fixed Sysmon taxonomy is incomplete or ambiguous.");
    }

    private static SysmonEventCategory Category(string name, params (int Id, string Name)[] events) =>
        new(name, $"Recorded Sysmon evidence by event type in {name}.", Freeze(events.Select(item =>
            new SysmonEventDefinition(item.Id, item.Name, $"Sysmon Event ID {item.Id}: {item.Name}. Badge is the recorded evidence-row count.")).ToArray()));
    private static IReadOnlyList<T> Freeze<T>(IReadOnlyList<T> values) => new ReadOnlyCollection<T>(values.ToArray());
}
