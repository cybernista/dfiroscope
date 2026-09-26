using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using ProcInsider.Models;

namespace ProcInsider.Services;

public static class SystemActivityNormalizer
{
    private static readonly HashSet<int> CandidateEventIds = new()
    {
        104,
        106,
        140,
        141,
        4624,
        4625,
        4634,
        4647,
        4648,
        4672,
        4697,
        4698,
        4702,
        4719,
        4720,
        4722,
        4723,
        4724,
        4725,
        4726,
        4728,
        4729,
        4732,
        4733,
        4740,
        4756,
        4757,
        4902,
        4904,
        4905,
        4906,
        4907,
        7045,
        1102
    };

    public static SystemActivityRecord? TryNormalize(TelemetryEventRecord sourceEvent)
    {
        if (!IsCandidate(sourceEvent))
        {
            return null;
        }

        var metadata = ExtractEventMetadata(sourceEvent.Details);
        var fields = metadata.Fields;
        var eventId = sourceEvent.EventCode ?? metadata.EventId;
        if (!eventId.HasValue)
        {
            return null;
        }

        var provider = FirstNonEmpty(sourceEvent.RawProvider, metadata.Provider, sourceEvent.Source);
        var logName = FirstNonEmpty(sourceEvent.RawLogName, metadata.LogName, sourceEvent.Source);
        var classification = Classify(eventId.Value, provider, logName, fields);
        if (classification == null)
        {
            return null;
        }

        var subjectAccount = FormatAccount(
            GetField(fields, "SubjectDomainName"),
            GetField(fields, "SubjectUserName"));
        var targetAccount = FormatAccount(
            GetField(fields, "TargetDomainName"),
            GetField(fields, "TargetUserName"));
        var memberAccount = FirstNonEmpty(
            GetField(fields, "MemberName"),
            FormatAccount(GetField(fields, "MemberDomainName"), GetField(fields, "MemberUserName")));
        var targetGroup = classification.IsGroupChange
            ? targetAccount
            : FirstNonEmpty(GetField(fields, "TargetGroupName"), GetField(fields, "GroupName"));

        var sourceHost = FirstNonEmpty(
            NormalizeMissing(GetField(fields, "WorkstationName")),
            NormalizeMissing(GetField(fields, "ClientName")),
            NormalizeMissing(GetField(fields, "SourceWorkstation")),
            metadata.Computer);
        var sourceAddress = FirstNonEmpty(
            NormalizeMissing(GetField(fields, "IpAddress")),
            NormalizeMissing(GetField(fields, "ClientAddress")),
            NormalizeMissing(GetField(fields, "SourceAddress")));
        var processPath = FirstNonEmpty(
            GetField(fields, "ProcessName"),
            GetField(fields, "NewProcessName"),
            GetField(fields, "ImagePath"),
            sourceEvent.Target);
        var logonType = GetField(fields, "LogonType");
        var result = classification.Result;
        var status = FirstNonEmpty(GetField(fields, "Status"), GetField(fields, "SubStatus"));
        var failureReason = FirstNonEmpty(GetField(fields, "FailureReason"), GetField(fields, "ErrorCode"));
        var logonId = FirstNonEmpty(GetField(fields, "TargetLogonId"), GetField(fields, "SubjectLogonId"));
        var summary = BuildSummary(
            classification.Activity,
            result,
            targetAccount,
            memberAccount,
            targetGroup,
            subjectAccount,
            sourceHost,
            sourceAddress,
            failureReason,
            sourceEvent.Summary);

        return new SystemActivityRecord
        {
            CaseId = sourceEvent.CaseId,
            EvidenceSessionId = sourceEvent.EvidenceSessionId,
            CaptureId = sourceEvent.CaptureId,
            SourceIdentityId = sourceEvent.SourceIdentityId,
            HostId = sourceEvent.HostId,
            ExecutionRootId = sourceEvent.ExecutionRootId,
            SourceSequenceId = sourceEvent.SequenceId,
            TimestampUtc = sourceEvent.TimestampUtc,
            Source = sourceEvent.Source,
            EventId = eventId,
            Provider = provider,
            LogName = logName,
            RecordId = FirstNonEmpty(sourceEvent.RawRecordId, metadata.RecordId),
            Activity = classification.Activity,
            Result = result,
            Scopes = classification.Scopes,
            SubjectAccount = subjectAccount,
            SubjectSid = GetField(fields, "SubjectUserSid"),
            TargetAccount = targetAccount,
            TargetSid = GetField(fields, "TargetUserSid"),
            MemberAccount = memberAccount,
            MemberSid = GetField(fields, "MemberSid"),
            TargetGroup = targetGroup,
            SourceHost = sourceHost,
            SourceAddress = sourceAddress,
            LogonType = FormatLogonType(logonType),
            LogonId = logonId,
            StatusCode = status,
            FailureReason = failureReason,
            ProcessKey = sourceEvent.ProcessKey,
            ProcessId = sourceEvent.ProcessId,
            ProcessName = sourceEvent.ProcessName,
            ProcessPath = processPath,
            Summary = summary,
            Details = sourceEvent.Details,
            RawXml = metadata.RawXml
        };
    }

    public static EventXmlMetadata ExtractEventMetadata(string details)
    {
        var rawXml = ExtractRawXml(details);
        if (string.IsNullOrWhiteSpace(rawXml))
        {
            return new EventXmlMetadata();
        }

        try
        {
            var document = XDocument.Parse(rawXml);
            var fields = ExtractDataFields(document);
            return new EventXmlMetadata
            {
                RawXml = rawXml,
                Fields = fields,
                Provider = GetSystemAttribute(document, "Provider", "Name"),
                LogName = FirstNonEmpty(GetSystemElement(document, "Channel"), GetSystemElement(document, "LogName")),
                RecordId = GetSystemElement(document, "EventRecordID"),
                Computer = GetSystemElement(document, "Computer"),
                EventId = int.TryParse(GetSystemElement(document, "EventID"), out var id) ? id : null
            };
        }
        catch
        {
            return new EventXmlMetadata { RawXml = rawXml };
        }
    }

    public static bool MatchesQuery(SystemActivityRecord activity, SystemActivityQuery query)
    {
        if (query.Scope.HasValue && !activity.Scopes.Contains(query.Scope.Value))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(query.AccountKey) &&
            !GetAccountKeys(activity).Contains(query.AccountKey, StringComparer.Ordinal))
        {
            return false;
        }

        return MatchesIdentity(activity.CaseId, query.CaseId) &&
               MatchesIdentity(activity.EvidenceSessionId, query.EvidenceSessionId) &&
               MatchesIdentity(activity.CaptureId, query.CaptureId) &&
               MatchesIdentity(activity.SourceIdentityId, query.SourceIdentityId) &&
               MatchesIdentity(activity.HostId, query.HostId) &&
               MatchesIdentity(activity.ExecutionRootId, query.ExecutionRootId);
    }

    public static bool MatchesScope(SystemActivityRecord activity, ExplorerScope scope)
    {
        if (!IsSystemActivityScope(scope))
        {
            return false;
        }

        return MatchesQuery(activity, new SystemActivityQuery
        {
            Scope = scope.SystemActivityScope,
            AccountKey = scope.AccountKey,
            CaseId = scope.CaseId,
            EvidenceSessionId = scope.EvidenceSessionId,
            CaptureId = scope.CaptureId,
            SourceIdentityId = scope.SourceIdentityId,
            HostId = scope.HostId,
            ExecutionRootId = scope.ExecutionRootId,
            MaxCount = 1
        });
    }

    public static IReadOnlyDictionary<SystemActivityScopeKind, int> CountByScope(IEnumerable<SystemActivityRecord> activities)
    {
        var counts = new Dictionary<SystemActivityScopeKind, int>();
        foreach (var activity in activities)
        {
            foreach (var scope in activity.Scopes.Distinct())
            {
                counts[scope] = counts.TryGetValue(scope, out var count) ? count + 1 : 1;
            }
        }

        return counts;
    }

    public static IReadOnlyList<SystemActivityAccountSummary> BuildAccountSummaries(
        IEnumerable<SystemActivityRecord> activities,
        int maxCount)
    {
        var summaries = new Dictionary<string, SystemActivityAccountSummary>(StringComparer.Ordinal);
        foreach (var activity in activities)
        {
            foreach (var account in GetAccounts(activity))
            {
                if (string.IsNullOrWhiteSpace(account.Key))
                {
                    continue;
                }

                var identityKey = string.Join(
                    '\u001f',
                    activity.CaseId,
                    activity.EvidenceSessionId,
                    activity.CaptureId,
                    activity.SourceIdentityId,
                    activity.HostId,
                    activity.ExecutionRootId,
                    account.Key);
                if (!summaries.TryGetValue(identityKey, out var summary))
                {
                    summary = new SystemActivityAccountSummary
                    {
                        AccountKey = account.Key,
                        DisplayName = account.DisplayName,
                        Domain = GetAccountDomain(account.DisplayName),
                        Sid = account.Sid,
                        CaseId = activity.CaseId,
                        EvidenceSessionId = activity.EvidenceSessionId,
                        CaptureId = activity.CaptureId,
                        SourceIdentityId = activity.SourceIdentityId,
                        HostId = activity.HostId,
                        ExecutionRootId = activity.ExecutionRootId
                    };
                    summaries[identityKey] = summary;
                }

                summary.ActivityCount++;
                if (activity.Scopes.Contains(SystemActivityScopeKind.Authentication))
                {
                    summary.LogonCount++;
                }

                if (activity.Scopes.Contains(SystemActivityScopeKind.SecurityGroupMembershipChanges))
                {
                    summary.GroupChangeCount++;
                }

                if (activity.Scopes.Contains(SystemActivityScopeKind.PrivilegedLogons))
                {
                    summary.PrivilegedActivityCount++;
                }
            }
        }

        var ordered = summaries.Values
            .OrderByDescending(summary => summary.ActivityCount)
            .ThenBy(summary => summary.DisplayName, StringComparer.OrdinalIgnoreCase);

        return maxCount <= 0
            ? ordered.ToList()
            : ordered.Take(Math.Clamp(maxCount, 1, 500)).ToList();
    }

    public static int CountAccountSummaries(IEnumerable<SystemActivityRecord> activities)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var activity in activities)
        {
            foreach (var account in GetAccounts(activity))
            {
                if (string.IsNullOrWhiteSpace(account.Key))
                {
                    continue;
                }

                var identityKey = string.Join(
                    '\u001f',
                    activity.CaseId,
                    activity.EvidenceSessionId,
                    activity.CaptureId,
                    activity.SourceIdentityId,
                    activity.HostId,
                    activity.ExecutionRootId,
                    account.Key);
                keys.Add(identityKey);
            }
        }

        return keys.Count;
    }

    public static IReadOnlyList<string> GetAccountKeys(SystemActivityRecord activity)
        => GetAccounts(activity)
            .Select(account => account.Key)
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Distinct(StringComparer.Ordinal)
            .ToList();

    private static bool IsCandidate(TelemetryEventRecord sourceEvent)
    {
        if (sourceEvent.EventCode.HasValue)
        {
            return CandidateEventIds.Contains(sourceEvent.EventCode.Value);
        }

        return string.Equals(sourceEvent.Source, "Security", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(sourceEvent.Source, "WindowsOther", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(sourceEvent.RawLogName, "Security", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(sourceEvent.RawLogName, "System", StringComparison.OrdinalIgnoreCase) ||
               sourceEvent.RawLogName.Contains("TaskScheduler", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSystemActivityScope(ExplorerScope scope)
    {
        return scope.SystemActivityScope.HasValue ||
               !string.IsNullOrWhiteSpace(scope.AccountKey) ||
               scope.Kind is ExplorerScopeKind.SystemActivityRoot or
                   ExplorerScopeKind.ActivityAuthentication or
                   ExplorerScopeKind.ActivitySuccessfulLogons or
                   ExplorerScopeKind.ActivityFailedLogons or
                   ExplorerScopeKind.ActivityRemoteInteractive or
                   ExplorerScopeKind.ActivityExplicitCredentialUse or
                   ExplorerScopeKind.ActivityPrivilegedLogons or
                   ExplorerScopeKind.ActivityAccounts or
                   ExplorerScopeKind.ActivityCreatedUsers or
                   ExplorerScopeKind.ActivityDisabledDeletedUsers or
                   ExplorerScopeKind.ActivityPasswordChanges or
                   ExplorerScopeKind.ActivityGroups or
                   ExplorerScopeKind.ActivityLocalAdministratorsChanges or
                   ExplorerScopeKind.ActivitySecurityGroupMembershipChanges or
                   ExplorerScopeKind.ActivityPolicyAudit or
                   ExplorerScopeKind.ActivityAuditPolicyChanged or
                   ExplorerScopeKind.ActivityLogIntegrity or
                   ExplorerScopeKind.ActivitySecurityLogCleared or
                   ExplorerScopeKind.ActivityServicesTasks or
                   ExplorerScopeKind.ActivityServicesInstalled or
                   ExplorerScopeKind.ActivityScheduledTasksChanged or
                   ExplorerScopeKind.UsersRoot or
                   ExplorerScopeKind.UserAccount;
    }

    private static ActivityClassification? Classify(
        int eventId,
        string provider,
        string logName,
        IReadOnlyDictionary<string, string> fields)
    {
        var scopes = new List<SystemActivityScopeKind> { SystemActivityScopeKind.All };
        var result = SystemActivityResult.Unknown;
        var activity = string.Empty;
        var isGroupChange = false;

        switch (eventId)
        {
            case 4624:
                activity = IsLogonType(fields, "10") ? "Remote interactive logon" : "Successful logon";
                result = SystemActivityResult.Success;
                scopes.AddRange([SystemActivityScopeKind.Authentication, SystemActivityScopeKind.SuccessfulLogons]);
                AddIf(scopes, IsLogonType(fields, "10"), SystemActivityScopeKind.RemoteInteractive);
                break;
            case 4625:
                activity = IsLogonType(fields, "10") ? "Failed remote interactive logon" : "Failed logon";
                result = SystemActivityResult.Failure;
                scopes.AddRange([SystemActivityScopeKind.Authentication, SystemActivityScopeKind.FailedLogons]);
                AddIf(scopes, IsLogonType(fields, "10"), SystemActivityScopeKind.RemoteInteractive);
                break;
            case 4634:
            case 4647:
                activity = "Logoff or session ended";
                result = SystemActivityResult.Success;
                scopes.Add(SystemActivityScopeKind.Authentication);
                break;
            case 4648:
                activity = "Explicit credential use";
                result = SystemActivityResult.Success;
                scopes.AddRange([SystemActivityScopeKind.Authentication, SystemActivityScopeKind.ExplicitCredentialUse]);
                break;
            case 4672:
                activity = "Privileged logon";
                result = SystemActivityResult.Success;
                scopes.AddRange([SystemActivityScopeKind.Authentication, SystemActivityScopeKind.PrivilegedLogons]);
                break;
            case 4720:
                activity = "User account created";
                result = SystemActivityResult.Success;
                scopes.AddRange([SystemActivityScopeKind.Accounts, SystemActivityScopeKind.CreatedUsers]);
                break;
            case 4722:
                activity = "User account enabled";
                result = SystemActivityResult.Success;
                scopes.Add(SystemActivityScopeKind.Accounts);
                break;
            case 4725:
                activity = "User account disabled";
                result = SystemActivityResult.Success;
                scopes.AddRange([SystemActivityScopeKind.Accounts, SystemActivityScopeKind.DisabledDeletedUsers]);
                break;
            case 4726:
                activity = "User account deleted";
                result = SystemActivityResult.Success;
                scopes.AddRange([SystemActivityScopeKind.Accounts, SystemActivityScopeKind.DisabledDeletedUsers]);
                break;
            case 4740:
                activity = "User account locked out";
                result = SystemActivityResult.Failure;
                scopes.Add(SystemActivityScopeKind.Accounts);
                break;
            case 4723:
                activity = "Password change attempted";
                scopes.AddRange([SystemActivityScopeKind.Accounts, SystemActivityScopeKind.PasswordChanges]);
                break;
            case 4724:
                activity = "Password reset attempted";
                scopes.AddRange([SystemActivityScopeKind.Accounts, SystemActivityScopeKind.PasswordChanges]);
                break;
            case 4728:
            case 4729:
            case 4732:
            case 4733:
            case 4756:
            case 4757:
                activity = IsRemovalEvent(eventId) ? "Security group member removed" : "Security group member added";
                result = SystemActivityResult.Success;
                isGroupChange = true;
                scopes.AddRange([SystemActivityScopeKind.Groups, SystemActivityScopeKind.SecurityGroupMembershipChanges]);
                AddIf(scopes, IsPrivilegedGroup(GetField(fields, "TargetUserName")), SystemActivityScopeKind.LocalAdministratorsChanges);
                break;
            case 4719:
            case 4902:
            case 4904:
            case 4905:
            case 4906:
            case 4907:
                activity = "Audit or policy changed";
                result = SystemActivityResult.Success;
                scopes.AddRange([SystemActivityScopeKind.PolicyAudit, SystemActivityScopeKind.AuditPolicyChanged]);
                break;
            case 1102:
            case 104:
                activity = "Security or system log cleared";
                result = SystemActivityResult.Success;
                scopes.AddRange([SystemActivityScopeKind.PolicyAudit, SystemActivityScopeKind.LogIntegrity, SystemActivityScopeKind.SecurityLogCleared]);
                break;
            case 4697:
            case 7045:
                activity = "Service installed";
                result = SystemActivityResult.Success;
                scopes.AddRange([SystemActivityScopeKind.ServicesTasks, SystemActivityScopeKind.ServicesInstalled]);
                break;
            case 4698:
            case 4702:
            case 106:
            case 140:
            case 141:
                activity = "Scheduled task created or changed";
                result = SystemActivityResult.Success;
                scopes.AddRange([SystemActivityScopeKind.ServicesTasks, SystemActivityScopeKind.ScheduledTasksChanged]);
                break;
        }

        if (string.IsNullOrWhiteSpace(activity))
        {
            return null;
        }

        if (eventId == 104 &&
            !string.Equals(logName, "System", StringComparison.OrdinalIgnoreCase) &&
            !provider.Contains("Eventlog", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new ActivityClassification(activity, result, scopes.Distinct().ToList(), isGroupChange);
    }

    private static IEnumerable<AccountCandidate> GetAccounts(SystemActivityRecord activity)
    {
        if (!string.IsNullOrWhiteSpace(activity.TargetAccount))
        {
            yield return new AccountCandidate(NormalizeAccountKey(activity.TargetAccount), activity.TargetAccount, activity.TargetSid);
        }

        if (!string.IsNullOrWhiteSpace(activity.MemberAccount))
        {
            yield return new AccountCandidate(NormalizeAccountKey(activity.MemberAccount), activity.MemberAccount, activity.MemberSid);
        }

        if (!string.IsNullOrWhiteSpace(activity.SubjectAccount) &&
            !activity.SubjectAccount.EndsWith("$", StringComparison.Ordinal))
        {
            yield return new AccountCandidate(NormalizeAccountKey(activity.SubjectAccount), activity.SubjectAccount, activity.SubjectSid);
        }
    }

    private static Dictionary<string, string> ExtractDataFields(XDocument document)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var unnamedIndex = 1;
        foreach (var data in document.Descendants().Where(element => element.Name.LocalName == "Data"))
        {
            var name = data.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == "Name")?.Value;
            if (string.IsNullOrWhiteSpace(name))
            {
                name = $"param{unnamedIndex++}";
            }

            if (!fields.ContainsKey(name))
            {
                fields[name] = data.Value.Trim();
            }
        }

        foreach (var element in document.Descendants().Where(element => element.Name.LocalName is "Param" or "DataItem"))
        {
            var name = element.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == "Name")?.Value;
            if (!string.IsNullOrWhiteSpace(name) && !fields.ContainsKey(name))
            {
                fields[name] = element.Value.Trim();
            }
        }

        return fields;
    }

    private static string ExtractRawXml(string details)
    {
        if (string.IsNullOrWhiteSpace(details))
        {
            return string.Empty;
        }

        const string marker = "Event XML:";
        var markerIndex = details.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        var raw = markerIndex >= 0
            ? details[(markerIndex + marker.Length)..].Trim()
            : details.Trim();
        return raw.StartsWith("<", StringComparison.Ordinal) ? raw : string.Empty;
    }

    private static string GetSystemElement(XDocument document, string localName)
        => document.Descendants()
            .FirstOrDefault(element => element.Name.LocalName == localName)
            ?.Value
            ?.Trim() ?? string.Empty;

    private static string GetSystemAttribute(XDocument document, string localName, string attributeName)
        => document.Descendants()
            .FirstOrDefault(element => element.Name.LocalName == localName)
            ?.Attributes()
            .FirstOrDefault(attribute => attribute.Name.LocalName == attributeName)
            ?.Value
            ?.Trim() ?? string.Empty;

    private static string GetField(IReadOnlyDictionary<string, string> fields, string name)
        => fields.TryGetValue(name, out var value) ? value : string.Empty;

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;

    private static string NormalizeMissing(string value)
        => string.IsNullOrWhiteSpace(value) || value is "-" or "::1" ? string.Empty : value.Trim();

    private static string FormatAccount(string domain, string user)
    {
        domain = NormalizeMissing(domain);
        user = NormalizeMissing(user);
        if (string.IsNullOrWhiteSpace(user))
        {
            return string.Empty;
        }

        return string.IsNullOrWhiteSpace(domain) ? user : $"{domain}\\{user}";
    }

    private static string NormalizeAccountKey(string account)
        => account.Trim().ToLowerInvariant();

    private static string GetAccountDomain(string account)
    {
        var slash = account.IndexOf('\\');
        return slash > 0 ? account[..slash] : string.Empty;
    }

    private static string FormatLogonType(string logonType)
    {
        if (string.IsNullOrWhiteSpace(logonType))
        {
            return string.Empty;
        }

        return logonType.Trim() switch
        {
            "2" => "2 Interactive",
            "3" => "3 Network",
            "4" => "4 Batch",
            "5" => "5 Service",
            "7" => "7 Unlock",
            "8" => "8 NetworkCleartext",
            "9" => "9 NewCredentials",
            "10" => "10 RemoteInteractive / RDP",
            "11" => "11 CachedInteractive",
            var value => value
        };
    }

    private static bool IsLogonType(IReadOnlyDictionary<string, string> fields, string expected)
        => string.Equals(GetField(fields, "LogonType"), expected, StringComparison.Ordinal);

    private static bool IsRemovalEvent(int eventId)
        => eventId is 4729 or 4733 or 4757;

    private static bool IsPrivilegedGroup(string groupName)
        => groupName.Contains("Administrators", StringComparison.OrdinalIgnoreCase) ||
           groupName.Contains("Domain Admins", StringComparison.OrdinalIgnoreCase) ||
           groupName.Contains("Enterprise Admins", StringComparison.OrdinalIgnoreCase) ||
           groupName.Contains("Account Operators", StringComparison.OrdinalIgnoreCase) ||
           groupName.Contains("Backup Operators", StringComparison.OrdinalIgnoreCase);

    private static void AddIf(ICollection<SystemActivityScopeKind> scopes, bool condition, SystemActivityScopeKind scope)
    {
        if (condition)
        {
            scopes.Add(scope);
        }
    }

    private static string BuildSummary(
        string activity,
        SystemActivityResult result,
        string targetAccount,
        string memberAccount,
        string targetGroup,
        string subjectAccount,
        string sourceHost,
        string sourceAddress,
        string failureReason,
        string fallback)
    {
        var actor = FirstNonEmpty(subjectAccount);
        var target = FirstNonEmpty(targetAccount, memberAccount, targetGroup);
        var parts = new List<string> { activity };
        if (!string.IsNullOrWhiteSpace(target))
        {
            parts.Add($"target {target}");
        }

        if (!string.IsNullOrWhiteSpace(actor))
        {
            parts.Add($"by {actor}");
        }

        var origin = FirstNonEmpty(sourceAddress, sourceHost);
        if (!string.IsNullOrWhiteSpace(origin))
        {
            parts.Add($"from {origin}");
        }

        if (result == SystemActivityResult.Failure && !string.IsNullOrWhiteSpace(failureReason))
        {
            parts.Add($"failed: {failureReason}");
        }

        var summary = string.Join("; ", parts);
        return string.IsNullOrWhiteSpace(summary) ? fallback : summary;
    }

    private static bool MatchesIdentity(string actual, string? expected)
        => string.IsNullOrWhiteSpace(expected) ||
           string.Equals(actual, expected, StringComparison.Ordinal);

    private sealed record ActivityClassification(
        string Activity,
        SystemActivityResult Result,
        IReadOnlyList<SystemActivityScopeKind> Scopes,
        bool IsGroupChange);

    private sealed record AccountCandidate(string Key, string DisplayName, string Sid);

    public sealed class EventXmlMetadata
    {
        public string RawXml { get; init; } = string.Empty;
        public IReadOnlyDictionary<string, string> Fields { get; init; } =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public string Provider { get; init; } = string.Empty;
        public string LogName { get; init; } = string.Empty;
        public string RecordId { get; init; } = string.Empty;
        public string Computer { get; init; } = string.Empty;
        public int? EventId { get; init; }
    }
}
