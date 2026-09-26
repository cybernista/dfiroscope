using System.Collections.ObjectModel;
using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace ProcInsider.Services.Events;

public enum EventFieldExtractionStatus { Available, Partial, Unavailable, Invalid, LimitExceeded }

/// <summary>Source layout identity, also suitable for future explicitly scoped extraction definitions.</summary>
public sealed record NativeEventType(string Provider, string Channel, int EventId, int? Version);
public sealed record NativeEventField(string Path, string Value);
public sealed record EventFieldExtraction(NativeEventType? EventType, EventFieldExtractionStatus Status,
    string Diagnostic, IReadOnlyList<NativeEventField> Fields)
{
    public const string ExtractorVersion = "native-windows-xml-v1";
}

/// <summary>Pure structural extraction. No rendering, type coercion, correlation, I/O or persistence.</summary>
public static class NativeEventFieldExtractor
{
    public const int MaximumCharacters = 131072, MaximumFields = 512, MaximumDepth = 32, MaximumPathCharacters = 2048, MaximumEnvelopeCandidates = 16;
    private static readonly XNamespace EventNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";

    public static EventFieldExtraction Extract(string? details, int? expectedEventId, string? expectedProvider,
        string? expectedChannel, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(details)) return Failure(EventFieldExtractionStatus.Unavailable, "Native event XML unavailable.");
        if (details.Length > MaximumCharacters) return Failure(EventFieldExtractionStatus.LimitExceeded, "Native event exceeds the extraction size limit.");
        // A marker can itself occur in a recorded command line. Only a complete XML document
        // consuming the entire remaining envelope can identify the appended native payload.
        var xml = details.Trim();
        if (!xml.StartsWith('<'))
        {
            var offsets = new List<int>();
            if (details.StartsWith("Event XML:", StringComparison.Ordinal)) offsets.Add(10);
            for (var index = 0; (index = details.IndexOf("\nEvent XML:", index, StringComparison.Ordinal)) >= 0; index += 11)
            {
                cancellationToken.ThrowIfCancellationRequested();
                offsets.Add(index + 11);
                if (offsets.Count > MaximumEnvelopeCandidates) return Failure(EventFieldExtractionStatus.LimitExceeded, "Too many native XML envelope candidates.");
            }
            var failure = Failure(EventFieldExtractionStatus.Unavailable, "No supported native XML payload.");
            foreach (var offset in offsets.AsEnumerable().Reverse())
            {
                var candidate = details[offset..].Trim();
                if (!candidate.StartsWith('<')) continue;
                var result = Extract(candidate, expectedEventId, expectedProvider, expectedChannel, cancellationToken);
                if (result.Status is EventFieldExtractionStatus.Available or EventFieldExtractionStatus.Partial) return result;
                failure = result;
            }
            return failure;
        }
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
            { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumCharacters });
            // Bound depth before allocating an XDocument or recursively visiting its elements.
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (reader.Depth > MaximumDepth) return Failure(EventFieldExtractionStatus.LimitExceeded, "Native event exceeds the extraction depth limit.");
            }
            using var boundedReader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
            { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumCharacters });
            var root = XDocument.Load(boundedReader, LoadOptions.PreserveWhitespace).Root;
            if (root?.Name != EventNamespace + "Event" || root.Elements(EventNamespace + "System").Count() != 1)
                return Failure(EventFieldExtractionStatus.Invalid, "Invalid or ambiguous native event header.");
            var system = root.Element(EventNamespace + "System")!;
            if (system.Elements().GroupBy(e => e.Name).Any(g => g.Count() != 1) || system.Elements().Any(e => e.HasElements))
                return Failure(EventFieldExtractionStatus.Invalid, "Invalid or ambiguous native System fields.");
            var provider = (string?)system.Element(EventNamespace + "Provider")?.Attribute("Name");
            var channel = (string?)system.Element(EventNamespace + "Channel");
            if (string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(channel) ||
                !int.TryParse((string?)system.Element(EventNamespace + "EventID"), NumberStyles.None, CultureInfo.InvariantCulture, out var id) || id is < 0 or > 65535)
                return Failure(EventFieldExtractionStatus.Invalid, "Native provider, channel or event ID unavailable.");
            if (expectedEventId is { } expected && expected != id ||
                !string.IsNullOrEmpty(expectedProvider) && expectedProvider != provider ||
                !string.IsNullOrEmpty(expectedChannel) && expectedChannel != channel)
                return Failure(EventFieldExtractionStatus.Invalid, "Native event identity disagrees with the recorded row.");
            var guid = (string?)system.Element(EventNamespace + "Provider")?.Attribute("Guid");
            if (guid != null && (!Guid.TryParse(guid, out var parsedGuid) ||
                provider == "Microsoft-Windows-Security-Auditing" && parsedGuid != new Guid("54849625-5478-4994-a5ba-3e3b0328c30d")))
                return Failure(EventFieldExtractionStatus.Invalid, "Invalid native provider GUID.");
            int? version = null;
            if (system.Element(EventNamespace + "Version") is { } versionElement)
            {
                if (!int.TryParse(versionElement.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) || parsed is < 0 or > 255)
                    return Failure(EventFieldExtractionStatus.Invalid, "Invalid native event version.");
                version = parsed;
            }
            var fields = new List<NativeEventField>();
            var partial = false;
            void Add(string path, string value)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (fields.Count >= MaximumFields || path.Length > MaximumPathCharacters) throw new ExtractionLimitException();
                fields.Add(new(path, value));
            }
            string Name(XName name) => name.Namespace == XNamespace.None
                ? Uri.EscapeDataString(name.LocalName) : "{" + Uri.EscapeDataString(name.NamespaceName) + "}" + Uri.EscapeDataString(name.LocalName);
            void Walk(XElement element, string path)
            {
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var attribute in element.Attributes().Where(a => !a.IsNamespaceDeclaration)) Add(path + "/@" + Name(attribute.Name), attribute.Value);
                if (!element.HasElements) Add(path, element.Value);
                else
                {
                    var text = string.Concat(element.Nodes().OfType<XText>().Select(t => t.Value));
                    if (!string.IsNullOrWhiteSpace(text)) Add(path + "/#text", text);
                    var occurrences = new Dictionary<XName, int>();
                    foreach (var child in element.Elements())
                    {
                        var occurrence = occurrences.GetValueOrDefault(child.Name) + 1;
                        occurrences[child.Name] = occurrence;
                        Walk(child, path + "/" + Name(child.Name) + "[" + occurrence + "]");
                    }
                }
            }
            foreach (var element in system.Elements()) Walk(element, "System/" + (element.Name.Namespace == EventNamespace ? element.Name.LocalName :
                "{" + Uri.EscapeDataString(element.Name.NamespaceName) + "}" + Uri.EscapeDataString(element.Name.LocalName)));
            var dataBlocks = root.Elements(EventNamespace + "EventData").ToArray();
            var userBlocks = root.Elements(EventNamespace + "UserData").ToArray();
            if (dataBlocks.Length > 1 || userBlocks.Length > 1 || dataBlocks.Length + userBlocks.Length > 1)
                return Failure(EventFieldExtractionStatus.Invalid, "Ambiguous native payload containers.");
            if (dataBlocks.FirstOrDefault() is { } data)
            {
                var occurrences = new Dictionary<string, int>(StringComparer.Ordinal);
                var position = 0;
                foreach (var element in data.Elements())
                {
                    ++position;
                    if (element.Name != EventNamespace + "Data" || element.HasElements) { partial = true; continue; }
                    var name = (string?)element.Attribute("Name");
                    var key = string.IsNullOrEmpty(name) ? "EventData/[position=" + position + "]" : "EventData/" + Uri.EscapeDataString(name);
                    var occurrence = occurrences.GetValueOrDefault(key) + 1;
                    occurrences[key] = occurrence;
                    Add(key + (string.IsNullOrEmpty(name) ? "" : "[" + occurrence + "]"), element.Value);
                    if (occurrence > 1) partial = true;
                }
            }
            if (userBlocks.FirstOrDefault() is { } user) Walk(user, "UserData");
            if (root.Elements().Any(e => e.Name != EventNamespace + "System" && e.Name != EventNamespace + "EventData" &&
                e.Name != EventNamespace + "UserData" && e.Name != EventNamespace + "RenderingInfo")) partial = true;
            return new(new(provider, channel, id, version), partial ? EventFieldExtractionStatus.Partial : EventFieldExtractionStatus.Available,
                partial ? "Repeated names retained separately or unsupported payload content present; inspect the original event." : "Native XML fields extracted.",
                new ReadOnlyCollection<NativeEventField>(fields));
        }
        catch (ExtractionLimitException) { return Failure(EventFieldExtractionStatus.LimitExceeded, "Native event exceeds field or path limits; no partial field set published."); }
        catch (XmlException) { return Failure(EventFieldExtractionStatus.Invalid, "Malformed or prohibited native event XML."); }
    }

    private static EventFieldExtraction Failure(EventFieldExtractionStatus status, string diagnostic) => new(null, status, diagnostic, Array.Empty<NativeEventField>());
    private sealed class ExtractionLimitException : Exception { }
}
