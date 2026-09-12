using System.Globalization;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace ProcInsider.Features.WindowsSecurityDetails;

public sealed record SecurityFieldLayout(int Version, string[] Fields);
public sealed record SecurityDetailsDefinition(int EventId, string Template, SecurityFieldLayout[] Layouts);
public sealed record SecurityEventField(string Name, string Value);
public sealed record SecurityEventPayload(int Version, SecurityEventField[] Fields);

/// <summary>Bounded, inert interpolation over the retained Security EventData payload.</summary>
public sealed class SecurityDetailsTemplate
{
    public const string Provider = "Microsoft-Windows-Security-Auditing";
    public const int MaxXmlLength = 131072, MaxFields = 256, MaxTemplateLength = 4096, MaxOutputLength = 2048;
    private readonly record struct Token(string Text, int Position, bool IsField);
    private readonly Token[] _tokens;
    private SecurityDetailsTemplate(Token[] tokens) => _tokens = tokens;
    public bool UsesPositions => _tokens.Any(t => t.Position > 0);

    public static SecurityDetailsTemplate Compile(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > MaxTemplateLength)
            throw new FormatException($"Enter a definition of 1–{MaxTemplateLength} characters.");
        var tokens = new List<Token>();
        var literal = new StringBuilder();
        void Flush() { if (literal.Length > 0) { tokens.Add(new(literal.ToString(), 0, false)); literal.Clear(); } }
        for (var i = 0; i < text.Length;)
        {
            if (text[i] != '$') { literal.Append(text[i++]); continue; }
            if (++i == text.Length) throw new FormatException("A dollar sign needs a field name, position, or another dollar sign.");
            if (text[i] == '$') { literal.Append('$'); i++; continue; }
            Flush();
            if (char.IsAsciiDigit(text[i]))
            {
                var start = i;
                while (i < text.Length && char.IsAsciiDigit(text[i])) i++;
                if (!int.TryParse(text.AsSpan(start, i - start), NumberStyles.None, CultureInfo.InvariantCulture, out var index) || index is < 1 or > MaxFields)
                    throw new FormatException($"Field positions must be between 1 and {MaxFields}.");
                tokens.Add(new(index.ToString(CultureInfo.InvariantCulture), index, true));
            }
            else
            {
                var end = text.IndexOf('$', i);
                if (end < 0) throw new FormatException("Close each named field with a dollar sign, for example $WorkstationName$.");
                var name = text[i..end];
                try { XmlConvert.VerifyNCName(name); }
                catch (XmlException) { throw new FormatException("Use an exact XML field name, for example $WorkstationName$."); }
                tokens.Add(new(name, 0, true));
                i = end + 1;
            }
            if (tokens.Count > 128) throw new FormatException("A definition may contain at most 128 tokens.");
        }
        Flush();
        if (tokens.Count > 128) throw new FormatException("A definition may contain at most 128 tokens.");
        return new(tokens.ToArray());
    }

    public static SecurityEventPayload? Parse(string? details, int? eventId)
    {
        if (eventId is null || string.IsNullOrWhiteSpace(details) || details.Length > MaxXmlLength) return null;
        var marker = details.LastIndexOf("Event XML:", StringComparison.Ordinal);
        var xml = marker >= 0 ? details[(marker + 10)..].Trim() : details.Trim();
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
                MaxCharactersInDocument = MaxXmlLength, MaxCharactersFromEntities = 0
            });
            var doc = XDocument.Load(reader, LoadOptions.None);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var root = doc.Root;
            if (root?.Name != ns + "Event" || root.Elements(ns + "System").Count() != 1 || root.Elements(ns + "EventData").Count() != 1) return null;
            var system = root.Element(ns + "System")!;
            if (system.Elements(ns + "Provider").Count() != 1 || system.Elements(ns + "EventID").Count() != 1 ||
                system.Elements(ns + "Channel").Count() != 1 || system.Elements(ns + "Version").Count() != 1 ||
                (string?)system.Element(ns + "Provider")?.Attribute("Name") != Provider ||
                (string?)system.Element(ns + "Channel") != "Security" ||
                !int.TryParse((string?)system.Element(ns + "EventID"), out var id) || id != eventId ||
                !int.TryParse((string?)system.Element(ns + "Version"), out var version) || version is < 0 or > 255) return null;
            var elements = root.Element(ns + "EventData")!.Elements().ToArray();
            if (elements.Length > MaxFields || elements.Any(e => e.Name != ns + "Data" || e.HasElements)) return null;
            return new(version, elements.Select(e => new SecurityEventField((string?)e.Attribute("Name") ?? "", e.Value)).ToArray());
        }
        catch (Exception ex) when (ex is XmlException or InvalidOperationException or ArgumentException) { return null; }
    }

    public string Format(SecurityEventPayload? payload, SecurityFieldLayout[] layouts)
    {
        if (payload is null) return "Event data unavailable";
        var positional = layouts.Any(l => l.Version == payload.Version && l.Fields.SequenceEqual(payload.Fields.Select(f => f.Name), StringComparer.Ordinal));
        var output = new StringBuilder();
        foreach (var token in _tokens)
        {
            var value = token.Text;
            if (token.IsField)
            {
                if (token.Position > 0)
                    value = positional && token.Position <= payload.Fields.Length ? payload.Fields[token.Position - 1].Value : $"<unavailable:{token.Text}>";
                else
                {
                    var matches = payload.Fields.Where(f => f.Name == token.Text).Take(2).ToArray();
                    value = matches.Length == 1 ? matches[0].Value : $"<unavailable:{token.Text}>";
                }
            }
            foreach (var c in value)
            {
                if (output.Length == MaxOutputLength) { output[^1] = '…'; return output.ToString(); }
                output.Append(char.IsControl(c) || char.GetUnicodeCategory(c) == UnicodeCategory.Format ? ' ' : c);
            }
        }
        return output.ToString();
    }
}
