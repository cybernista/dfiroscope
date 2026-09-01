using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using ProcInsider.Models;

namespace ProcInsider.Services;

public static class SigmaCompatibilityAnalyzer
{
    private static readonly HashSet<string> SupportedModifiers = new(StringComparer.OrdinalIgnoreCase)
    {
        "all",
        "contains",
        "endswith",
        "exists",
        "re",
        "regex",
        "startswith"
    };

    private static readonly HashSet<string> ProcessFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "accountname",
        "application",
        "cmdline",
        "commandline",
        "company",
        "companyname",
        "description",
        "filedescription",
        "hash",
        "hashes",
        "hashsha256",
        "image",
        "imagename",
        "newprocessname",
        "parentimage",
        "parentimagename",
        "parentpid",
        "parentprocessid",
        "parentprocessname",
        "pid",
        "process",
        "processguid",
        "processid",
        "processname",
        "processpath",
        "sha256",
        "status",
        "user",
        "username"
    };

    private static readonly HashSet<string> EventFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "accessmask",
        "accountname",
        "action",
        "application",
        "calltrace",
        "category",
        "channel",
        "cmdline",
        "commandline",
        "company",
        "companyname",
        "correlationmethod",
        "correlationstate",
        "correlationcandidatecount",
        "correlationdiagnostics",
        "description",
        "destinationhostname",
        "destinationip",
        "destinationport",
        "details",
        "eventcode",
        "eventid",
        "eventtype",
        "filedescription",
        "grantedaccess",
        "hash",
        "hashes",
        "hashsha256",
        "image",
        "imagename",
        "logname",
        "message",
        "newprocessname",
        "objectname",
        "originalfilename",
        "parentcommandline",
        "parentimage",
        "parentimagename",
        "parentpid",
        "parentprocessid",
        "parentprocessname",
        "path",
        "payload",
        "pid",
        "pipe",
        "pipename",
        "process",
        "processguid",
        "processentityid",
        "processid",
        "processname",
        "processpath",
        "protocol",
        "provider",
        "providername",
        "query",
        "queryname",
        "recordid",
        "riskflags",
        "scriptblocktext",
        "sha256",
        "source",
        "sourceimage",
        "sourceip",
        "sourceport",
        "summary",
        "target",
        "targetfilename",
        "targetimage",
        "targetobject",
        "user",
        "username"
    };

    private static readonly HashSet<string> ModuleFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "accountname",
        "application",
        "baseaddress",
        "cmdline",
        "commandline",
        "company",
        "companyname",
        "description",
        "filedescription",
        "fileversion",
        "fullpath",
        "hash",
        "hashes",
        "hashsha256",
        "image",
        "imageloaded",
        "loadedmodule",
        "modulepath",
        "modulename",
        "pid",
        "process",
        "processguid",
        "processid",
        "processname",
        "processpath",
        "sha256",
        "source",
        "sources",
        "state",
        "user",
        "username"
    };

    private static readonly HashSet<string> HandleFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "accessmask",
        "accountname",
        "application",
        "cmdline",
        "commandline",
        "grantedaccess",
        "handle",
        "handleattributes",
        "handlevalue",
        "image",
        "imagename",
        "objectaddress",
        "objectname",
        "objecttype",
        "pid",
        "pipe",
        "pipename",
        "process",
        "processid",
        "processname",
        "processpath",
        "source",
        "sourceimage",
        "state",
        "targetfilename",
        "targetimage",
        "targetobject",
        "user",
        "username"
    };

    public static SigmaCompatibilityAnalysis Analyze(SigmaRule rule)
    {
        var diagnostics = new List<SigmaRuleDiagnostic>();
        var supportedKinds = ResolveEvidenceKinds(rule, diagnostics).ToList();

        if (rule.Selections.Count == 0)
        {
            diagnostics.Add(CreateDiagnostic(rule, "Error", "No detection selections were parsed."));
        }

        var unsupportedFieldCount = 0;
        var conditionCount = 0;
        var seenModifierDiagnostics = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenFieldDiagnostics = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var condition in EnumerateConditions(rule))
        {
            conditionCount++;
            foreach (var modifier in condition.Modifiers.Where(modifier => !IsModifierSupported(modifier)))
            {
                var key = $"{condition.Field}|{modifier}";
                if (!seenModifierDiagnostics.Add(key))
                {
                    continue;
                }

                diagnostics.Add(CreateDiagnostic(
                    rule,
                    "Warning",
                    string.Equals(modifier, "windash", StringComparison.OrdinalIgnoreCase)
                        ? $"Unsupported modifier '{modifier}' on field '{condition.Field}'. {ProductIdentity.DisplayName} reports it and prevents this condition from matching until windash expansion is implemented."
                        : $"Unsupported modifier '{modifier}' on field '{condition.Field}'. This condition will not match until the modifier is implemented."));
            }

            var normalizedField = NormalizeField(condition.Field);
            if (!IsFieldSupported(normalizedField, supportedKinds))
            {
                unsupportedFieldCount++;
                if (seenFieldDiagnostics.Add(normalizedField))
                {
                    diagnostics.Add(CreateDiagnostic(
                        rule,
                        "Warning",
                        $"Unsupported field '{condition.Field}' for logsource {DescribeLogSource(rule)}."));
                }
            }
            else if (string.Equals(normalizedField, "originalfilename", StringComparison.OrdinalIgnoreCase))
            {
                diagnostics.Add(CreateDiagnostic(
                    rule,
                    "Warning",
                    $"OriginalFileName is evaluated only from explicit event details such as Sysmon OriginalFileName. {ProductIdentity.DisplayName} does not substitute FileDescription for PE original filename."));
            }
        }

        var unsupportedCondition = HasUnsupportedConditionForm(rule, diagnostics);
        var hasRunnableSelection = rule.Selections.Count > 0 &&
                                   supportedKinds.Count > 0 &&
                                   conditionCount > 0 &&
                                   unsupportedFieldCount < conditionCount &&
                                   !unsupportedCondition;

        var status = hasRunnableSelection
            ? diagnostics.Any(diagnostic => string.Equals(diagnostic.Severity, "Warning", StringComparison.OrdinalIgnoreCase) ||
                                            string.Equals(diagnostic.Severity, "Error", StringComparison.OrdinalIgnoreCase))
                ? SigmaCompatibilityStatus.PartiallyRunnable
                : SigmaCompatibilityStatus.Runnable
            : SigmaCompatibilityStatus.Unsupported;

        diagnostics.Add(CreateDiagnostic(
            rule,
            status == SigmaCompatibilityStatus.Unsupported ? "Error" : "Info",
            $"Compatibility: {FormatStatus(status)}; evidence: {FormatEvidenceKinds(supportedKinds)}."));

        return new SigmaCompatibilityAnalysis
        {
            Status = status,
            SupportedEvidenceKinds = supportedKinds,
            Diagnostics = diagnostics
        };
    }

    public static bool IsModifierSupported(string modifier)
    {
        return SupportedModifiers.Contains(modifier);
    }

    public static bool IsEventCompatible(SigmaRule rule, TelemetryEventRecord processEvent)
    {
        var category = NormalizeLogSourcePart(rule.LogSource.Category);
        var service = NormalizeCompact(rule.LogSource.Service);

        if (!IsServiceCompatibleWithEvent(service, processEvent))
        {
            return false;
        }

        return category switch
        {
            "" => true,
            "process_creation" => processEvent.Action == ProcessEventAction.ProcessStart,
            "process_termination" => processEvent.Action == ProcessEventAction.ProcessExit,
            "image_load" or "driver_load" => processEvent.Action == ProcessEventAction.ImageLoad,
            "create_remote_thread" => processEvent.Action == ProcessEventAction.CreateRemoteThread,
            "process_access" => processEvent.Action == ProcessEventAction.ProcessAccess,
            "raw_access_thread" or "raw_access_read" => processEvent.Action == ProcessEventAction.RawAccessRead,
            "process_tampering" => processEvent.Action == ProcessEventAction.ProcessTampering,
            "registry_event" or "registry_add" or "registry_set" or "registry_delete" or "registry_rename" =>
                processEvent.Category == ProcessEventCategory.Registry,
            "pipe_created" => processEvent.Action == ProcessEventAction.PipeCreated,
            "pipe_connected" => processEvent.Action == ProcessEventAction.PipeConnected,
            "ps_script" or "ps_module" or "ps_classic_start" or "ps_classic_provider_start" =>
                processEvent.Category == ProcessEventCategory.PowerShell,
            "network_connection" => processEvent.Category == ProcessEventCategory.Network ||
                                    processEvent.Action == ProcessEventAction.Connect,
            "dns_query" => processEvent.Category == ProcessEventCategory.Dns ||
                           processEvent.Action == ProcessEventAction.DnsQuery,
            "file_event" or "file_change" => processEvent.Category == ProcessEventCategory.File,
            "file_delete" => processEvent.Action == ProcessEventAction.FileDelete,
            "file_create" => processEvent.Action is ProcessEventAction.FileCreate or ProcessEventAction.FileWrite,
            "file_rename" => processEvent.Action == ProcessEventAction.FileRename,
            "create_stream_hash" => processEvent.Action == ProcessEventAction.FileCreateStreamHash,
            "wmi_event" => processEvent.Category == ProcessEventCategory.Wmi,
            "service_creation" or "service_installed" =>
                processEvent.EventCode == 7045 ||
                processEvent.Summary.Contains("service", StringComparison.OrdinalIgnoreCase) ||
                processEvent.Details.Contains("service", StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    public static bool IsProcessCompatible(SigmaRule rule, ProcessRecord process)
    {
        var category = NormalizeLogSourcePart(rule.LogSource.Category);
        return category switch
        {
            "" or "process_creation" => true,
            "process_termination" => process.Status == ProcessStatus.Exited,
            _ => false
        };
    }

    public static string FormatStatus(SigmaCompatibilityStatus status)
    {
        return status switch
        {
            SigmaCompatibilityStatus.Runnable => "Runnable",
            SigmaCompatibilityStatus.PartiallyRunnable => "Partially runnable",
            _ => "Unsupported"
        };
    }

    private static IEnumerable<SigmaEvidenceKind> ResolveEvidenceKinds(SigmaRule rule, List<SigmaRuleDiagnostic> diagnostics)
    {
        var product = NormalizeCompact(rule.LogSource.Product);
        var category = NormalizeLogSourcePart(rule.LogSource.Category);
        var service = NormalizeCompact(rule.LogSource.Service);
        var kinds = new HashSet<SigmaEvidenceKind>();

        if (!string.IsNullOrWhiteSpace(product) && product != "windows" && product != "win")
        {
            diagnostics.Add(CreateDiagnostic(rule, "Error", $"Unsupported logsource product '{rule.LogSource.Product}'."));
            return kinds;
        }

        switch (category)
        {
            case "":
                AddKindsForService(service, kinds);
                if (kinds.Count == 0)
                {
                    kinds.Add(SigmaEvidenceKind.Process);
                    kinds.Add(SigmaEvidenceKind.Event);
                    kinds.Add(SigmaEvidenceKind.Module);
                    kinds.Add(SigmaEvidenceKind.Handle);
                    diagnostics.Add(CreateDiagnostic(
                        rule,
                        "Warning",
                        $"Missing or broad logsource. {ProductIdentity.DisplayName} will audit the rule against all supported evidence classes."));
                }
                break;
            case "process_creation":
                kinds.Add(SigmaEvidenceKind.Process);
                kinds.Add(SigmaEvidenceKind.Event);
                break;
            case "process_termination":
                kinds.Add(SigmaEvidenceKind.Process);
                kinds.Add(SigmaEvidenceKind.Event);
                break;
            case "image_load":
            case "driver_load":
                kinds.Add(SigmaEvidenceKind.Module);
                kinds.Add(SigmaEvidenceKind.Event);
                break;
            case "registry_event":
            case "registry_add":
            case "registry_set":
            case "registry_delete":
            case "registry_rename":
            case "pipe_created":
            case "pipe_connected":
            case "ps_script":
            case "ps_module":
            case "ps_classic_start":
            case "ps_classic_provider_start":
            case "network_connection":
            case "dns_query":
            case "file_event":
            case "file_change":
            case "file_delete":
            case "file_create":
            case "file_rename":
            case "create_stream_hash":
            case "create_remote_thread":
            case "process_access":
            case "raw_access_thread":
            case "raw_access_read":
            case "process_tampering":
            case "service_creation":
            case "service_installed":
            case "wmi_event":
                kinds.Add(SigmaEvidenceKind.Event);
                break;
            default:
                diagnostics.Add(CreateDiagnostic(rule, "Error", $"Unsupported logsource category '{rule.LogSource.Category}'."));
                break;
        }

        if (!string.IsNullOrWhiteSpace(service) &&
            service is not ("sysmon" or "eventlog" or "security" or "powershell" or "windowspowershell"))
        {
            diagnostics.Add(CreateDiagnostic(rule, "Warning", $"Unrecognized logsource service '{rule.LogSource.Service}'."));
        }

        return kinds.OrderBy(kind => kind.ToString(), StringComparer.OrdinalIgnoreCase);
    }

    private static void AddKindsForService(string service, HashSet<SigmaEvidenceKind> kinds)
    {
        switch (service)
        {
            case "sysmon":
            case "eventlog":
            case "security":
            case "powershell":
            case "windowspowershell":
                kinds.Add(SigmaEvidenceKind.Event);
                break;
        }
    }

    private static bool IsServiceCompatibleWithEvent(string service, TelemetryEventRecord processEvent)
    {
        return service switch
        {
            "" or "eventlog" => true,
            "sysmon" => ContainsAny(processEvent.Source, processEvent.RawLogName, processEvent.RawProvider, "sysmon"),
            "security" => ContainsAny(processEvent.Source, processEvent.RawLogName, processEvent.RawProvider, "security"),
            "powershell" or "windowspowershell" =>
                processEvent.Category == ProcessEventCategory.PowerShell ||
                ContainsAny(processEvent.Source, processEvent.RawLogName, processEvent.RawProvider, "powershell"),
            _ => true
        };
    }

    private static bool IsFieldSupported(string normalizedField, IReadOnlyCollection<SigmaEvidenceKind> evidenceKinds)
    {
        return evidenceKinds.Any(kind => kind switch
        {
            SigmaEvidenceKind.Process => ProcessFields.Contains(normalizedField),
            SigmaEvidenceKind.Event => EventFields.Contains(normalizedField),
            SigmaEvidenceKind.Module => ModuleFields.Contains(normalizedField),
            SigmaEvidenceKind.Handle => HandleFields.Contains(normalizedField),
            _ => false
        });
    }

    private static bool HasUnsupportedConditionForm(SigmaRule rule, List<SigmaRuleDiagnostic> diagnostics)
    {
        if (string.IsNullOrWhiteSpace(rule.Condition))
        {
            return false;
        }

        if (Regex.IsMatch(rule.Condition, @"(\||\bcount\s*\(|[<>]=?|\bnear\b|\bby\b)", RegexOptions.IgnoreCase))
        {
            diagnostics.Add(CreateDiagnostic(rule, "Warning", $"Unsupported Sigma condition form '{rule.Condition}'."));
            return true;
        }

        var selectors = rule.Selections
            .Select(selection => selection.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var tokens = TokenizeCondition(rule.Condition);
        var unsupportedTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var token in tokens)
        {
            if (token is "(" or ")" ||
                token.Equals("and", StringComparison.OrdinalIgnoreCase) ||
                token.Equals("or", StringComparison.OrdinalIgnoreCase) ||
                token.Equals("not", StringComparison.OrdinalIgnoreCase) ||
                token.Equals("all", StringComparison.OrdinalIgnoreCase) ||
                token.Equals("any", StringComparison.OrdinalIgnoreCase) ||
                token.Equals("of", StringComparison.OrdinalIgnoreCase) ||
                token.Equals("them", StringComparison.OrdinalIgnoreCase) ||
                token.Equals("1", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (selectors.Contains(token) || IsSelectorWildcard(token, selectors))
            {
                continue;
            }

            unsupportedTokens.Add(token);
        }

        foreach (var token in unsupportedTokens)
        {
            diagnostics.Add(CreateDiagnostic(rule, "Warning", $"Unsupported or unresolved condition token '{token}'."));
        }

        return unsupportedTokens.Count > 0;
    }

    private static bool IsSelectorWildcard(string token, HashSet<string> selectors)
    {
        if (!token.EndsWith("*", StringComparison.Ordinal))
        {
            return false;
        }

        var prefix = token[..^1];
        return selectors.Any(selector => selector.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private static IReadOnlyList<string> TokenizeCondition(string condition)
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

    private static IEnumerable<SigmaFieldCondition> EnumerateConditions(SigmaRule rule)
    {
        return rule.Selections
            .SelectMany(selection => selection.Groups)
            .SelectMany(group => group.Conditions);
    }

    private static string FormatEvidenceKinds(IReadOnlyCollection<SigmaEvidenceKind> evidenceKinds)
    {
        return evidenceKinds.Count == 0
            ? "none"
            : string.Join(", ", evidenceKinds.Select(kind => kind.ToString()).OrderBy(value => value, StringComparer.OrdinalIgnoreCase));
    }

    private static string DescribeLogSource(SigmaRule rule)
    {
        var parts = new[] { rule.LogSource.Product, rule.LogSource.Service, rule.LogSource.Category }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToList();
        return parts.Count == 0 ? "<missing>" : string.Join("/", parts);
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

    private static string NormalizeLogSourcePart(string value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim()
                .Replace("-", "_", StringComparison.Ordinal)
                .Replace(" ", "_", StringComparison.Ordinal)
                .ToLowerInvariant();
    }

    private static string NormalizeCompact(string value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim()
                .Replace("_", string.Empty, StringComparison.Ordinal)
                .Replace("-", string.Empty, StringComparison.Ordinal)
                .Replace(".", string.Empty, StringComparison.Ordinal)
                .Replace("/", string.Empty, StringComparison.Ordinal)
                .Replace(" ", string.Empty, StringComparison.Ordinal)
                .ToLowerInvariant();
    }

    private static bool ContainsAny(string source, string logName, string provider, string needle)
    {
        return source.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
               logName.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
               provider.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private static SigmaRuleDiagnostic CreateDiagnostic(SigmaRule rule, string severity, string message)
    {
        return new SigmaRuleDiagnostic
        {
            Severity = severity,
            RuleId = rule.Id,
            RuleTitle = rule.Title,
            SourcePath = rule.SourcePath,
            Message = message
        };
    }
}
