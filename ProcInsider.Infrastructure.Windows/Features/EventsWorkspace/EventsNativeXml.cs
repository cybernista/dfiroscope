using System.Xml;
using System.Xml.Linq;

namespace ProcInsider.Services;

/// <summary>Bounded native header/EventData interpretation shared by the transient Events projections.</summary>
internal sealed record EventsNativeXml(bool Available, string Computer, int? Version,
    string Channel, IReadOnlyDictionary<string, string> Fields)
{
    internal static EventsNativeXml Parse(int? eventId, string provider, string details)
    {
        try
        {
            var marker = details.IndexOf("Event XML:", StringComparison.OrdinalIgnoreCase);
            var xml = (marker >= 0 ? details[(marker + 10)..] : details).Trim();
            if (!xml.StartsWith('<') || xml.Length > EventsIdentityProjection.MaximumXmlCharacters) throw new XmlException();
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
            { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = EventsIdentityProjection.MaximumXmlCharacters });
            var doc = XDocument.Load(reader);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            if (doc.Root?.Name != ns + "Event" || doc.Root.Elements(ns + "System").Count() != 1 ||
                doc.Root.Elements(ns + "EventData").Count() > 1) throw new XmlException();
            var system = doc.Root.Element(ns + "System")!;
            foreach (var name in new[] { "Provider", "EventID", "Version", "Channel", "Computer" })
                if (system.Elements(ns + name).Count() > 1) throw new XmlException("Duplicate header.");
            if ((string?)system.Element(ns + "Provider")?.Attribute("Name") != provider || string.IsNullOrEmpty(provider) ||
                !int.TryParse(system.Element(ns + "EventID")?.Value, out var id) || id != eventId) throw new XmlException("Header mismatch.");
            var guid = (string?)system.Element(ns + "Provider")?.Attribute("Guid");
            if (provider == "Microsoft-Windows-Security-Auditing" && guid != null &&
                (!Guid.TryParse(guid, out var parsedGuid) || parsedGuid != new Guid("54849625-5478-4994-a5ba-3e3b0328c30d"))) throw new XmlException("Provider GUID mismatch.");
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var data in doc.Root.Element(ns + "EventData")?.Elements(ns + "Data") ?? [])
                if ((string?)data.Attribute("Name") is { } name && !fields.TryAdd(name, data.Value)) throw new XmlException("Duplicate field.");
            if (fields.TryGetValue("TargetSid", out var sid) && fields.TryGetValue("TargetUserSid", out var userSid) && sid != userSid)
                throw new XmlException("Conflicting target SID fields.");
            return new(true, system.Element(ns + "Computer")?.Value ?? "",
                int.TryParse(system.Element(ns + "Version")?.Value, out var version) && version is >= 0 and <= 255 ? version : null,
                system.Element(ns + "Channel")?.Value ?? "", fields);
        }
        catch (Exception ex) when (ex is XmlException or ArgumentException)
        { return new(false, "", null, "", new Dictionary<string, string>()); }
    }
}
