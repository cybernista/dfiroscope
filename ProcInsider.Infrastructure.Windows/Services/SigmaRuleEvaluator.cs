using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using ProcInsider.Models;

namespace ProcInsider.Services;

public static class SigmaRuleEvaluator
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    public static bool TryMatchProcess(SigmaRule rule, ProcessRecord process, out SigmaMatchDetails details)
    {
        return TryMatch(rule, field => LookupProcessField(process, field), out details);
    }

    public static bool TryMatchEvent(
        SigmaRule rule,
        TelemetryEventRecord processEvent,
        ProcessRecord? process,
        out SigmaMatchDetails details)
    {
        return TryMatch(rule, field => LookupEventField(processEvent, process, field), out details);
    }

    public static bool TryMatchModule(
        SigmaRule rule,
        ModuleObservationRecord module,
        ProcessRecord? process,
        out SigmaMatchDetails details)
    {
        return TryMatch(rule, field => LookupModuleField(module, process, field), out details);
    }

    public static bool TryMatchHandle(
        SigmaRule rule,
        HandleObservationRecord handle,
        ProcessRecord? process,
        out SigmaMatchDetails details)
    {
        return TryMatch(rule, field => LookupHandleField(handle, process, field), out details);
    }

    private static bool TryMatch(SigmaRule rule, Func<string, string?> lookup, out SigmaMatchDetails details)
    {
        details = new SigmaMatchDetails();
        if (rule.Selections.Count == 0)
        {
            return false;
        }

        var selectorMatches = new Dictionary<string, SelectorMatch>(StringComparer.OrdinalIgnoreCase);
        foreach (var selection in rule.Selections)
        {
            selectorMatches[selection.Name] = EvaluateSelection(selection, lookup);
        }

        var condition = string.IsNullOrWhiteSpace(rule.Condition)
            ? string.Join(" or ", rule.Selections.Select(selection => selection.Name))
            : rule.Condition;

        if (!SigmaConditionExpression.Evaluate(condition, selectorMatches))
        {
            return false;
        }

        var evidence = selectorMatches
            .Where(match => match.Value.Matched && !match.Key.StartsWith("filter", StringComparison.OrdinalIgnoreCase))
            .Select(match => match.Value.Details)
            .FirstOrDefault()
            ?? selectorMatches.Where(match => match.Value.Matched).Select(match => match.Value.Details).FirstOrDefault();

        if (evidence == null)
        {
            return false;
        }

        details = evidence;
        return true;
    }

    private static SelectorMatch EvaluateSelection(SigmaRuleSelection selection, Func<string, string?> lookup)
    {
        foreach (var group in selection.Groups)
        {
            var matchedDetails = new SigmaMatchDetails { Selector = selection.Name };
            var groupMatched = true;

            foreach (var condition in group.Conditions)
            {
                if (!TryMatchCondition(condition, lookup, out var value))
                {
                    groupMatched = false;
                    break;
                }

                if (string.IsNullOrWhiteSpace(matchedDetails.Field))
                {
                    matchedDetails.Field = condition.Field;
                    matchedDetails.Value = value;
                }
            }

            if (groupMatched)
            {
                return new SelectorMatch(true, matchedDetails);
            }
        }

        return new SelectorMatch(false, null);
    }

    private static bool TryMatchCondition(SigmaFieldCondition condition, Func<string, string?> lookup, out string matchedValue)
    {
        matchedValue = string.Empty;
        if (condition.Modifiers.Any(modifier => !SigmaCompatibilityAnalyzer.IsModifierSupported(modifier)))
        {
            return false;
        }

        var actual = lookup(condition.Field);
        var hasActual = !string.IsNullOrWhiteSpace(actual);

        if (condition.Modifiers.Contains("exists", StringComparer.OrdinalIgnoreCase))
        {
            var expected = condition.Values.FirstOrDefault();
            var shouldExist = !string.Equals(expected, "false", StringComparison.OrdinalIgnoreCase);
            if (hasActual == shouldExist)
            {
                matchedValue = hasActual ? TrimEvidence(actual!) : "<missing>";
                return true;
            }

            return false;
        }

        if (!hasActual || condition.Values.Count == 0)
        {
            return false;
        }

        var requireAll = condition.Modifiers.Contains("all", StringComparer.OrdinalIgnoreCase);
        var values = condition.Values.Where(value => !string.IsNullOrWhiteSpace(value)).ToList();
        if (values.Count == 0)
        {
            return false;
        }

        var matched = requireAll
            ? values.All(value => MatchValue(actual!, value, condition.Modifiers))
            : values.Any(value => MatchValue(actual!, value, condition.Modifiers));

        if (!matched)
        {
            return false;
        }

        matchedValue = TrimEvidence(actual!);
        return true;
    }

    private static bool MatchValue(string actual, string expected, IReadOnlyList<string> modifiers)
    {
        if (modifiers.Contains("re", StringComparer.OrdinalIgnoreCase) ||
            modifiers.Contains("regex", StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                return Regex.IsMatch(actual, expected, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
            }
            catch (ArgumentException)
            {
                return false;
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }

        if (modifiers.Contains("contains", StringComparer.OrdinalIgnoreCase))
        {
            return actual.Contains(expected, StringComparison.OrdinalIgnoreCase);
        }

        if (modifiers.Contains("startswith", StringComparer.OrdinalIgnoreCase))
        {
            return actual.StartsWith(expected, StringComparison.OrdinalIgnoreCase);
        }

        if (modifiers.Contains("endswith", StringComparer.OrdinalIgnoreCase))
        {
            return actual.EndsWith(expected, StringComparison.OrdinalIgnoreCase);
        }

        if (ContainsWildcard(expected))
        {
            return MatchWildcard(actual, expected);
        }

        return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsWildcard(string value)
    {
        return value.Contains('*', StringComparison.Ordinal) || value.Contains('?', StringComparison.Ordinal);
    }

    private static bool MatchWildcard(string actual, string expected)
    {
        var pattern = "^" + Regex.Escape(expected)
            .Replace("\\*", ".*", StringComparison.Ordinal)
            .Replace("\\?", ".", StringComparison.Ordinal) + "$";
        try
        {
            return Regex.IsMatch(actual, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static string? LookupProcessField(ProcessRecord process, string field)
    {
        return NormalizeField(field) switch
        {
            "image" or "processpath" or "newprocessname" or "application" => process.ProcessPath,
            "imagename" or "processname" or "process" => process.ProcessName,
            "commandline" or "cmdline" => process.CommandLine,
            "parentimage" or "parentprocessname" or "parentimagename" => process.ParentProcessName,
            "user" or "username" or "accountname" => process.UserName,
            "company" or "companyname" => process.CompanyName,
            "description" or "filedescription" => process.FileDescription,
            "originalfilename" => null,
            "sha256" or "hashes" or "hash" or "hashsha256" => process.Sha256Hash,
            "processid" or "pid" => process.ProcessId.ToString(),
            "parentprocessid" or "parentpid" => process.ParentProcessId.ToString(),
            "processguid" => process.ProcessGuid,
            "status" => process.Status.ToString(),
            _ => null
        };
    }

    private static string? LookupEventField(TelemetryEventRecord processEvent, ProcessRecord? process, string field)
    {
        var normalized = NormalizeField(field);
        return normalized switch
        {
            "eventid" or "eventcode" => processEvent.EventCode?.ToString(),
            "category" => processEvent.Category.ToString(),
            "action" => processEvent.Action.ToString(),
            "eventtype" => processEvent.Action.ToString(),
            "target" => processEvent.Target,
            "targetfilename" => FirstKnown(
                GetDetailsField(processEvent.Details, "TargetFilename", "Target Filename"),
                processEvent.Target),
            "targetobject" or "objectname" => FirstKnown(
                GetDetailsField(processEvent.Details, "TargetObject", "ObjectName", "Object Name"),
                processEvent.Target),
            "pipename" or "pipe" => FirstKnown(
                GetDetailsField(processEvent.Details, "PipeName", "Pipe Name"),
                processEvent.Target),
            "summary" => processEvent.Summary,
            "details" or "message" => processEvent.Details,
            "scriptblocktext" => FirstKnown(
                GetDetailsField(processEvent.Details, "ScriptBlockText", "Script Block Text"),
                processEvent.Action == ProcessEventAction.PowerShellScriptBlock ? processEvent.Details : null),
            "payload" => FirstKnown(GetDetailsField(processEvent.Details, "Payload"), processEvent.Details),
            "calltrace" => FirstKnown(GetDetailsField(processEvent.Details, "CallTrace", "Call Trace"), processEvent.Details),
            "path" => FirstKnown(GetDetailsField(processEvent.Details, "Path"), processEvent.Target),
            "riskflags" => processEvent.RiskFlags,
            "source" => processEvent.Source,
            "providername" or "provider" => processEvent.RawProvider,
            "logname" or "channel" => processEvent.RawLogName,
            "recordid" => processEvent.RawRecordId,
            "correlationmethod" => processEvent.CorrelationMethod,
            "correlationstate" => processEvent.CorrelationState.ToString(),
            "correlationcandidatecount" => processEvent.CorrelationCandidateCount.ToString(),
            "correlationdiagnostics" => processEvent.CorrelationDiagnostics,
            "processentityid" => processEvent.ProcessEntityId,
            "processguid" => FirstKnown(GetDetailsField(processEvent.Details, "ProcessGuid"), processEvent.ProcessGuid),
            "processid" or "pid" => processEvent.ProcessId.ToString(),
            "parentprocessid" or "parentpid" => processEvent.ParentProcessId.ToString(),
            "imagename" or "processname" or "process" => processEvent.ProcessName,
            "image" or "processpath" or "newprocessname" or "application" => FirstKnown(
                GetDetailsField(processEvent.Details, "Image", "ProcessPath", "NewProcessName"),
                process?.ProcessPath,
                processEvent.Action == ProcessEventAction.ProcessStart ? processEvent.Target : null,
                processEvent.ProcessName),
            "sourceimage" => FirstKnown(
                GetDetailsField(processEvent.Details, "SourceImage", "Source Image"),
                process?.ProcessPath,
                processEvent.ProcessName),
            "targetimage" => FirstKnown(
                GetDetailsField(processEvent.Details, "TargetImage", "Target Image"),
                processEvent.Target),
            "commandline" or "cmdline" => FirstKnown(
                GetDetailsField(processEvent.Details, "CommandLine", "Command line"),
                process?.CommandLine),
            "parentimage" or "parentprocessname" or "parentimagename" => FirstKnown(
                GetDetailsField(processEvent.Details, "ParentImage", "Parent image"),
                process?.ParentProcessName),
            "parentcommandline" => GetDetailsField(processEvent.Details, "ParentCommandLine", "Parent command line"),
            "originalfilename" => GetDetailsField(processEvent.Details, "OriginalFileName", "Original Filename"),
            "user" or "username" or "accountname" => FirstKnown(
                GetDetailsField(processEvent.Details, "User", "AccountName", "Account Name"),
                process?.UserName),
            "company" or "companyname" => FirstKnown(GetDetailsField(processEvent.Details, "Company"), process?.CompanyName),
            "description" or "filedescription" => FirstKnown(
                GetDetailsField(processEvent.Details, "Description", "FileDescription", "File Description"),
                process?.FileDescription),
            "sha256" or "hashes" or "hash" or "hashsha256" => FirstKnown(
                GetDetailsField(processEvent.Details, "Hashes", "Hash", "SHA256"),
                process?.Sha256Hash),
            "grantedaccess" or "accessmask" => FirstKnown(
                GetDetailsField(processEvent.Details, "GrantedAccess", "AccessMask", "Access Mask"),
                processEvent.Details),
            "sourceip" => GetDetailsField(processEvent.Details, "SourceIp", "Source IP"),
            "sourceport" => GetDetailsField(processEvent.Details, "SourcePort", "Source Port"),
            "destinationip" => GetDetailsField(processEvent.Details, "DestinationIp", "Destination IP"),
            "destinationport" => GetDetailsField(processEvent.Details, "DestinationPort", "Destination Port"),
            "destinationhostname" => GetDetailsField(processEvent.Details, "DestinationHostname", "Destination Hostname"),
            "protocol" => GetDetailsField(processEvent.Details, "Protocol"),
            "query" or "queryname" => FirstKnown(
                GetDetailsField(processEvent.Details, "QueryName", "Query Name"),
                processEvent.Category == ProcessEventCategory.Dns ? processEvent.Target : null),
            _ => null
        };
    }

    private static string? LookupModuleField(ModuleObservationRecord module, ProcessRecord? process, string field)
    {
        var normalized = NormalizeField(field);
        return normalized switch
        {
            "imageloaded" or "loadedmodule" or "modulepath" or "fullpath" => module.FullPath,
            "modulename" or "imagename" => module.ModuleName,
            "image" => process?.ProcessPath,
            "baseaddress" => module.BaseAddress,
            "company" or "companyname" => module.CompanyName,
            "description" or "filedescription" => module.Description,
            "originalfilename" => null,
            "fileversion" => module.FileVersion,
            "sha256" or "hashes" or "hash" or "hashsha256" => module.Sha256Hash,
            "source" => module.LastSource,
            "sources" => module.Sources,
            "state" => module.State.ToString(),
            "processid" or "pid" => module.ProcessId.ToString(),
            "processguid" => module.ProcessGuid,
            "processname" or "process" => process?.ProcessName,
            "processpath" or "application" => process?.ProcessPath,
            "commandline" or "cmdline" => process?.CommandLine,
            "user" or "username" or "accountname" => process?.UserName,
            _ => null
        };
    }

    private static string? LookupHandleField(HandleObservationRecord handle, ProcessRecord? process, string field)
    {
        var normalized = NormalizeField(field);
        return normalized switch
        {
            "objecttype" => handle.ObjectType,
            "objectname" or "targetobject" or "targetfilename" or "pipename" or "pipe" => handle.ObjectName,
            "grantedaccess" or "accessmask" => handle.GrantedAccess,
            "handleattributes" => handle.HandleAttributes,
            "objectaddress" => handle.ObjectAddress,
            "handle" or "handlevalue" => handle.HandleValue,
            "source" => handle.LastSource,
            "state" => handle.State.ToString(),
            "processid" or "pid" => handle.ProcessId.ToString(),
            "processname" or "process" or "imagename" => process?.ProcessName,
            "image" or "processpath" or "application" => process?.ProcessPath,
            "sourceimage" => process?.ProcessPath,
            "targetimage" => handle.ObjectName,
            "commandline" or "cmdline" => process?.CommandLine,
            "user" or "username" or "accountname" => process?.UserName,
            _ => null
        };
    }

    private static string NormalizeField(string field)
    {
        return field
            .Replace("_", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .Replace(".", string.Empty, StringComparison.Ordinal)
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .ToLowerInvariant();
    }

    private static string? FirstKnown(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!IsKnownValue(value))
            {
                continue;
            }

            return value!.Trim();
        }

        return null;
    }

    private static bool IsKnownValue(string? value)
    {
        return !string.IsNullOrWhiteSpace(value) &&
               !value.Equals("<not available>", StringComparison.OrdinalIgnoreCase) &&
               !value.Equals("<unknown>", StringComparison.OrdinalIgnoreCase) &&
               !value.Equals("<access denied>", StringComparison.OrdinalIgnoreCase);
    }

    private static string? GetDetailsField(string details, params string[] labels)
    {
        if (string.IsNullOrWhiteSpace(details) || labels.Length == 0)
        {
            return null;
        }

        var wantedLabels = labels.Select(NormalizeField).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var lines = details.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            var line = lines[index].Trim();
            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            var label = NormalizeField(line[..separator]);
            if (!wantedLabels.Contains(label))
            {
                continue;
            }

            var inlineValue = line[(separator + 1)..].Trim();
            if (IsKnownValue(inlineValue))
            {
                return inlineValue;
            }

            var blockLines = new List<string>();
            for (var nextIndex = index + 1; nextIndex < lines.Length; nextIndex++)
            {
                var nextLine = lines[nextIndex].TrimEnd();
                if (string.IsNullOrWhiteSpace(nextLine))
                {
                    if (blockLines.Count > 0)
                    {
                        break;
                    }

                    continue;
                }

                if (LooksLikeDetailsLabel(nextLine))
                {
                    break;
                }

                blockLines.Add(nextLine);
            }

            var blockValue = string.Join(Environment.NewLine, blockLines).Trim();
            return IsKnownValue(blockValue) ? blockValue : null;
        }

        return null;
    }

    private static bool LooksLikeDetailsLabel(string line)
    {
        var separator = line.IndexOf(':');
        if (separator <= 0 || separator > 60)
        {
            return false;
        }

        var label = line[..separator].Trim();
        return label.Length > 0 &&
               label.All(character => char.IsLetterOrDigit(character) || char.IsWhiteSpace(character) || character is '_' or '-' or '/');
    }

    private static string TrimEvidence(string value)
    {
        value = value.Replace("\r", " ").Replace("\n", " ").Trim();
        return value.Length <= 500 ? value : $"{value[..500]}...";
    }

    private readonly record struct SelectorMatch(bool Matched, SigmaMatchDetails? Details);

    private sealed class SigmaConditionExpression
    {
        private readonly IReadOnlyList<string> _tokens;
        private readonly IReadOnlyDictionary<string, SelectorMatch> _selectorMatches;
        private int _position;

        private SigmaConditionExpression(string condition, IReadOnlyDictionary<string, SelectorMatch> selectorMatches)
        {
            _tokens = Tokenize(condition);
            _selectorMatches = selectorMatches;
        }

        public static bool Evaluate(string condition, IReadOnlyDictionary<string, SelectorMatch> selectorMatches)
        {
            if (selectorMatches.Count == 0)
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(condition))
            {
                return selectorMatches.Values.Any(match => match.Matched);
            }

            var expression = new SigmaConditionExpression(condition, selectorMatches);
            return expression.ParseOr();
        }

        private bool ParseOr()
        {
            var value = ParseAnd();
            while (Match("or"))
            {
                var right = ParseAnd();
                value = value || right;
            }

            return value;
        }

        private bool ParseAnd()
        {
            var value = ParseNot();
            while (Match("and"))
            {
                var right = ParseNot();
                value = value && right;
            }

            return value;
        }

        private bool ParseNot()
        {
            if (Match("not"))
            {
                return !ParseNot();
            }

            return ParsePrimary();
        }

        private bool ParsePrimary()
        {
            if (Match("("))
            {
                var value = ParseOr();
                Match(")");
                return value;
            }

            if (Match("all"))
            {
                Match("of");
                return EvaluateSelectorPattern(NextToken(), requireAll: true);
            }

            if (Match("1") || Match("any"))
            {
                Match("of");
                return EvaluateSelectorPattern(NextToken(), requireAll: false);
            }

            var selector = NextToken();
            return EvaluateSelectorPattern(selector, requireAll: false);
        }

        private bool EvaluateSelectorPattern(string selector, bool requireAll)
        {
            if (string.IsNullOrWhiteSpace(selector))
            {
                return false;
            }

            IEnumerable<SelectorMatch> matches;
            if (string.Equals(selector, "them", StringComparison.OrdinalIgnoreCase))
            {
                matches = _selectorMatches
                    .Where(match => !match.Key.StartsWith("filter", StringComparison.OrdinalIgnoreCase))
                    .Select(match => match.Value);
            }
            else if (selector.EndsWith("*", StringComparison.Ordinal))
            {
                var prefix = selector[..^1];
                matches = _selectorMatches
                    .Where(match => match.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    .Select(match => match.Value);
            }
            else
            {
                matches = _selectorMatches.TryGetValue(selector, out var match)
                    ? new[] { match }
                    : Array.Empty<SelectorMatch>();
            }

            var materialized = matches.ToList();
            return materialized.Count > 0 && (requireAll
                ? materialized.All(match => match.Matched)
                : materialized.Any(match => match.Matched));
        }

        private bool Match(string expected)
        {
            if (_position >= _tokens.Count ||
                !string.Equals(_tokens[_position], expected, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            _position++;
            return true;
        }

        private string NextToken()
        {
            if (_position >= _tokens.Count)
            {
                return string.Empty;
            }

            return _tokens[_position++];
        }

        private static IReadOnlyList<string> Tokenize(string condition)
        {
            var tokens = new List<string>();
            var current = new List<char>();
            foreach (var character in condition)
            {
                if (char.IsWhiteSpace(character))
                {
                    Flush();
                    continue;
                }

                if (character is '(' or ')')
                {
                    Flush();
                    tokens.Add(character.ToString());
                    continue;
                }

                current.Add(character);
            }

            Flush();
            return tokens;

            void Flush()
            {
                if (current.Count == 0)
                {
                    return;
                }

                tokens.Add(new string(current.ToArray()));
                current.Clear();
            }
        }
    }
}
