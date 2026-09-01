using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class SigmaRuleParser
{
    public IReadOnlyList<SigmaRule> LoadFromFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Rule path is required.", nameof(path));
        }

        var text = File.ReadAllText(path);
        return Parse(text, path);
    }

    public IReadOnlyList<SigmaRule> Parse(string text, string sourcePath)
    {
        var documents = SplitDocuments(text);
        var rules = new List<SigmaRule>();
        foreach (var document in documents)
        {
            var lines = PrepareLines(document).ToList();
            if (lines.Count == 0)
            {
                continue;
            }

            var rule = ParseDocument(lines, sourcePath);
            rule.RuleContentHashSha256 = Convert.ToHexString(
                    SHA256.HashData(Encoding.UTF8.GetBytes(document)))
                .ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(rule.RuleVersion))
            {
                rule.RuleVersion = $"content-{rule.RuleContentHashSha256[..16]}";
            }

            if (rule.Selections.Count == 0)
            {
                var warnings = rule.ParseWarnings.ToList();
                warnings.Add("No detection selections were parsed.");
                rule.ParseWarnings = warnings;
            }

            rules.Add(rule);
        }

        return rules;
    }

    private static SigmaRule ParseDocument(IReadOnlyList<YamlLine> lines, string sourcePath)
    {
        var rule = new SigmaRule { SourcePath = sourcePath };
        var warnings = new List<string>();

        for (var index = 0; index < lines.Count;)
        {
            var line = lines[index];
            if (line.Indent != 0 || !TrySplitKeyValue(line.Text, out var key, out var value))
            {
                index++;
                continue;
            }

            switch (key.ToLowerInvariant())
            {
                case "title":
                    rule.Title = ParseScalar(value, fallback: rule.Title);
                    index++;
                    break;
                case "id":
                    rule.Id = ParseScalar(value);
                    index++;
                    break;
                case "date":
                    if (string.IsNullOrWhiteSpace(rule.RuleVersion))
                    {
                        rule.RuleVersion = ParseScalar(value);
                    }

                    index++;
                    break;
                case "modified":
                    rule.RuleVersion = ParseScalar(value, fallback: rule.RuleVersion);
                    index++;
                    break;
                case "description":
                    rule.Description = ParseScalar(value);
                    index++;
                    break;
                case "status":
                    rule.Status = ParseScalar(value);
                    index++;
                    break;
                case "author":
                    rule.Author = ParseScalar(value);
                    index++;
                    break;
                case "level":
                    rule.Level = ParseScalar(value);
                    index++;
                    break;
                case "tags":
                    rule.Tags = ParseValueList(lines, ref index, line.Indent, value);
                    break;
                case "logsource":
                    rule.LogSource = ParseLogSource(lines, ref index);
                    break;
                case "detection":
                    rule.Selections = ParseDetection(lines, ref index, rule, warnings);
                    break;
                default:
                    index++;
                    break;
            }
        }

        if (string.IsNullOrWhiteSpace(rule.Condition) && rule.Selections.Count > 0)
        {
            rule.Condition = rule.Selections.Count == 1
                ? rule.Selections[0].Name
                : string.Join(" or ", rule.Selections.Select(selection => selection.Name));
        }

        rule.ParseWarnings = warnings;
        return rule;
    }

    private static SigmaLogSource ParseLogSource(IReadOnlyList<YamlLine> lines, ref int index)
    {
        var logSource = new SigmaLogSource();
        var parentIndent = lines[index].Indent;
        index++;

        while (index < lines.Count && lines[index].Indent > parentIndent)
        {
            var line = lines[index];
            if (TrySplitKeyValue(line.Text, out var key, out var value))
            {
                switch (key.ToLowerInvariant())
                {
                    case "product":
                        logSource.Product = ParseScalar(value);
                        break;
                    case "category":
                        logSource.Category = ParseScalar(value);
                        break;
                    case "service":
                        logSource.Service = ParseScalar(value);
                        break;
                }
            }

            index++;
        }

        return logSource;
    }

    private static IReadOnlyList<SigmaRuleSelection> ParseDetection(
        IReadOnlyList<YamlLine> lines,
        ref int index,
        SigmaRule rule,
        List<string> warnings)
    {
        var selections = new List<SigmaRuleSelection>();
        var parentIndent = lines[index].Indent;
        index++;

        while (index < lines.Count && lines[index].Indent > parentIndent)
        {
            var line = lines[index];
            if (!TrySplitKeyValue(line.Text, out var key, out var value))
            {
                index++;
                continue;
            }

            if (line.Indent != parentIndent + 2)
            {
                index++;
                continue;
            }

            if (string.Equals(key, "condition", StringComparison.OrdinalIgnoreCase))
            {
                rule.Condition = ParseScalar(value);
                index++;
                continue;
            }

            var selection = ParseSelection(lines, ref index, line.Indent, key);
            if (selection.Groups.Count == 0)
            {
                warnings.Add($"Selection '{key}' did not contain supported field conditions.");
            }

            selections.Add(selection);
        }

        return selections;
    }

    private static SigmaRuleSelection ParseSelection(IReadOnlyList<YamlLine> lines, ref int index, int selectionIndent, string name)
    {
        var groups = new List<SigmaConditionGroup>();
        var conditions = new List<SigmaFieldCondition>();
        index++;

        while (index < lines.Count && lines[index].Indent > selectionIndent)
        {
            var line = lines[index];
            if (line.Text.StartsWith("- ", StringComparison.Ordinal))
            {
                if (conditions.Count > 0)
                {
                    groups.Add(new SigmaConditionGroup { Conditions = conditions });
                    conditions = new List<SigmaFieldCondition>();
                }

                var group = ParseListGroup(lines, ref index, line.Indent);
                if (group.Conditions.Count > 0)
                {
                    groups.Add(group);
                }

                continue;
            }

            var condition = ParseFieldCondition(lines, ref index, line.Indent);
            if (condition != null)
            {
                conditions.Add(condition);
            }
        }

        if (conditions.Count > 0)
        {
            groups.Add(new SigmaConditionGroup { Conditions = conditions });
        }

        return new SigmaRuleSelection
        {
            Name = name,
            Groups = groups
        };
    }

    private static SigmaConditionGroup ParseListGroup(IReadOnlyList<YamlLine> lines, ref int index, int listIndent)
    {
        var conditions = new List<SigmaFieldCondition>();
        var text = lines[index].Text[2..].Trim();
        if (TrySplitKeyValue(text, out var key, out var value))
        {
            index++;
            var values = !string.IsNullOrWhiteSpace(value)
                ? ParseInlineValues(value)
                : ParseNestedScalarList(lines, ref index, listIndent);
            conditions.Add(CreateFieldCondition(key, values));
        }
        else
        {
            index++;
        }

        while (index < lines.Count && lines[index].Indent > listIndent)
        {
            var condition = ParseFieldCondition(lines, ref index, lines[index].Indent);
            if (condition != null)
            {
                conditions.Add(condition);
            }
        }

        return new SigmaConditionGroup { Conditions = conditions };
    }

    private static SigmaFieldCondition? ParseFieldCondition(IReadOnlyList<YamlLine> lines, ref int index, int conditionIndent)
    {
        var line = lines[index];
        if (!TrySplitKeyValue(line.Text, out var key, out var value))
        {
            index++;
            return null;
        }

        var values = ParseValueList(lines, ref index, conditionIndent, value);
        return CreateFieldCondition(key, values);
    }

    private static SigmaFieldCondition CreateFieldCondition(string rawField, IReadOnlyList<string> values)
    {
        var parts = rawField.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return new SigmaFieldCondition
        {
            Field = parts.FirstOrDefault() ?? rawField,
            Modifiers = parts.Skip(1).Select(part => part.ToLowerInvariant()).ToList(),
            Values = values
        };
    }

    private static IReadOnlyList<string> ParseValueList(IReadOnlyList<YamlLine> lines, ref int index, int parentIndent, string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            index++;
            return ParseInlineValues(value);
        }

        var values = new List<string>();
        index++;
        while (index < lines.Count && lines[index].Indent > parentIndent)
        {
            var text = lines[index].Text.Trim();
            if (text.StartsWith("- ", StringComparison.Ordinal))
            {
                values.Add(ParseScalar(text[2..].Trim()));
            }
            else if (TrySplitKeyValue(text, out _, out _))
            {
                break;
            }

            index++;
        }

        return values;
    }

    private static IReadOnlyList<string> ParseInlineValues(string value)
    {
        value = value.Trim();
        if (value.Length == 0)
        {
            return Array.Empty<string>();
        }

        if (value.StartsWith("[", StringComparison.Ordinal) && value.EndsWith("]", StringComparison.Ordinal))
        {
            return SplitInlineList(value[1..^1]).Select(item => ParseScalar(item)).Where(item => item.Length > 0).ToList();
        }

        return new[] { ParseScalar(value) };
    }

    private static IReadOnlyList<string> ParseNestedScalarList(IReadOnlyList<YamlLine> lines, ref int index, int parentIndent)
    {
        var values = new List<string>();
        while (index < lines.Count && lines[index].Indent > parentIndent)
        {
            var text = lines[index].Text.Trim();
            if (!text.StartsWith("- ", StringComparison.Ordinal))
            {
                break;
            }

            var scalar = text[2..].Trim();
            if (TrySplitKeyValue(scalar, out _, out _))
            {
                break;
            }

            values.Add(ParseScalar(scalar));
            index++;
        }

        return values;
    }

    private static IEnumerable<string> SplitInlineList(string value)
    {
        var start = 0;
        var quote = '\0';
        for (var index = 0; index < value.Length; index++)
        {
            var current = value[index];
            if ((current == '\'' || current == '"') && (index == 0 || value[index - 1] != '\\'))
            {
                quote = quote == '\0' ? current : quote == current ? '\0' : quote;
            }
            else if (current == ',' && quote == '\0')
            {
                yield return value[start..index].Trim();
                start = index + 1;
            }
        }

        yield return value[start..].Trim();
    }

    private static string ParseScalar(string value, string fallback = "")
    {
        value = value.Trim();
        if (value.Length == 0)
        {
            return fallback;
        }

        if ((value.StartsWith("'", StringComparison.Ordinal) && value.EndsWith("'", StringComparison.Ordinal)) ||
            (value.StartsWith("\"", StringComparison.Ordinal) && value.EndsWith("\"", StringComparison.Ordinal)))
        {
            return value[1..^1];
        }

        return value;
    }

    private static IReadOnlyList<string> SplitDocuments(string text)
    {
        var documents = new List<string>();
        var current = new List<string>();
        foreach (var rawLine in text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            if (string.Equals(rawLine.Trim(), "---", StringComparison.Ordinal))
            {
                if (current.Count > 0)
                {
                    documents.Add(string.Join('\n', current));
                    current.Clear();
                }

                continue;
            }

            current.Add(rawLine);
        }

        if (current.Count > 0)
        {
            documents.Add(string.Join('\n', current));
        }

        return documents;
    }

    private static IEnumerable<YamlLine> PrepareLines(string text)
    {
        foreach (var rawLine in text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            var withoutComment = StripComment(rawLine).TrimEnd();
            if (string.IsNullOrWhiteSpace(withoutComment))
            {
                continue;
            }

            var indent = withoutComment.TakeWhile(char.IsWhiteSpace).Count();
            yield return new YamlLine(indent, withoutComment.Trim());
        }
    }

    private static string StripComment(string line)
    {
        var quote = '\0';
        for (var index = 0; index < line.Length; index++)
        {
            var current = line[index];
            if ((current == '\'' || current == '"') && (index == 0 || line[index - 1] != '\\'))
            {
                quote = quote == '\0' ? current : quote == current ? '\0' : quote;
            }
            else if (current == '#' && quote == '\0')
            {
                return line[..index];
            }
        }

        return line;
    }

    private static bool TrySplitKeyValue(string text, out string key, out string value)
    {
        var quote = '\0';
        for (var index = 0; index < text.Length; index++)
        {
            var current = text[index];
            if ((current == '\'' || current == '"') && (index == 0 || text[index - 1] != '\\'))
            {
                quote = quote == '\0' ? current : quote == current ? '\0' : quote;
            }
            else if (current == ':' && quote == '\0')
            {
                key = text[..index].Trim();
                value = text[(index + 1)..].Trim();
                return key.Length > 0;
            }
        }

        key = string.Empty;
        value = string.Empty;
        return false;
    }

    private readonly record struct YamlLine(int Indent, string Text);
}
