using System.Security.Cryptography;
using System.Text;
using ProcInsider.Models;

namespace ProcInsider.Services.EvidenceSources;

internal enum ProcessEntityResolutionStrategy
{
    ExactOrSourceAlias,
    SysmonGuid,
    SourceRunAlias,
    LegacyCompatibility
}

internal sealed record ProcessObservationAdapterItem(
    ProcessObservation Observation,
    IReadOnlyList<ProcessAlias> Aliases,
    ProcessStatisticsRecord? Statistics = null);

internal static class ProcessObservationAdapterFactory
{
    public static ProcessObservationAdapterItem CreateFromProcessInfo(
        ProcessInfo process,
        EvidenceIdentity identity,
        string captureId,
        string sourceRunId,
        Guid ingestionJobId,
        string adapterId,
        string adapterVersion,
        string source,
        DateTime observedUtc,
        ProcessObservationKind observationKind,
        ProcessEntityResolutionStrategy resolutionStrategy,
        bool includeStatistics,
        string rawRecordId = "",
        string metadataJson = "{}")
    {
        observedUtc = observedUtc.Kind == DateTimeKind.Utc
            ? observedUtc
            : observedUtc.ToUniversalTime();
        var effectiveIdentity = CloneIdentity(identity, captureId, adapterId);
        var processKey = process.GetUniqueKey();
        var record = new ProcessRecord
        {
            ProcessEntityId = process.ProcessEntityId,
            CaseId = effectiveIdentity.CaseId,
            EvidenceSessionId = effectiveIdentity.EvidenceSessionId,
            CaptureId = effectiveIdentity.CaptureId,
            SourceIdentityId = effectiveIdentity.SourceIdentityId,
            HostId = effectiveIdentity.HostId,
            ExecutionRootId = effectiveIdentity.ExecutionRootId,
            ProcessKey = processKey,
            ProcessId = process.ProcessId,
            ProcessGuid = process.ProcessGuid,
            StartTimeUtc = process.StartTime?.ToUniversalTime(),
            EndTimeUtc = process.EndTime?.ToUniversalTime(),
            Status = process.Status,
            ParentProcessId = process.ParentProcessId,
            ParentProcessKey = process.ParentProcessKey,
            ParentProcessEntityId = process.ParentProcessEntityId,
            ParentProcessName = PreferKnownValue(process.ParentProcessName, "<unknown>"),
            ProcessName = PreferKnownValue(process.ProcessName, "<unknown>"),
            ProcessPath = PreferKnownValue(process.ProcessPath, "<not available>"),
            CommandLine = PreferKnownValue(process.CommandLine, "<not available>"),
            UserName = PreferKnownValue(process.UserName, "<not available>"),
            SessionId = process.SessionId,
            Architecture = PreferKnownValue(process.Architecture, "<not available>"),
            CpuUsage = process.CpuUsage,
            MemoryUsageBytes = process.MemoryUsageBytes,
            CompanyName = PreferKnownValue(process.CompanyName, "<not available>"),
            FileDescription = PreferKnownValue(process.FileDescription, "<not available>"),
            Sha256Hash = PreferKnownValue(process.Sha256Hash, "<not available>"),
            TreeDepth = process.TreeDepth,
            FirstObservedUtc = observedUtc,
            LastObservedUtc = observedUtc,
            LastSource = source,
            ModuleCaptureStatus = process.ModuleCaptureStatus,
            ModuleCount = process.ModuleCount,
            ModuleLastCapturedUtc = process.ModuleLastCaptured?.ToUniversalTime(),
            ModuleCaptureError = process.ModuleCaptureError,
            HandleCaptureStatus = process.HandleCaptureStatus,
            HandleCount = process.HandleCount,
            HandleLastCapturedUtc = process.HandleLastCaptured?.ToUniversalTime(),
            HandleCaptureError = process.HandleCaptureError
        };
        return CreateFromProcessRecord(
            record,
            effectiveIdentity,
            sourceRunId,
            ingestionJobId,
            adapterId,
            adapterVersion,
            observedUtc,
            observationKind,
            resolutionStrategy,
            includeStatistics ? CreateStatistics(process, record, observedUtc, source) : null,
            rawRecordId,
            metadataJson);
    }

    public static ProcessObservationAdapterItem CreateFromProcessRecord(
        ProcessRecord record,
        EvidenceIdentity identity,
        string sourceRunId,
        Guid ingestionJobId,
        string adapterId,
        string adapterVersion,
        DateTime observedUtc,
        ProcessObservationKind observationKind,
        ProcessEntityResolutionStrategy resolutionStrategy,
        ProcessStatisticsRecord? statistics = null,
        string rawRecordId = "",
        string metadataJson = "{}")
    {
        ApplyIdentity(record, identity, adapterId);
        observedUtc = observedUtc.Kind == DateTimeKind.Utc
            ? observedUtc
            : observedUtc.ToUniversalTime();
        if (record.FirstObservedUtc == default)
        {
            record.FirstObservedUtc = observedUtc;
        }

        if (record.LastObservedUtc == default)
        {
            record.LastObservedUtc = observedUtc;
        }

        var sourceNativeAlias = ResolveSourceNativeAlias(record, resolutionStrategy, rawRecordId);
        record.ProcessEntityId = ResolveProcessEntityId(
            record,
            sourceRunId,
            sourceNativeAlias,
            resolutionStrategy);
        var correlationMethod = ResolveCorrelationMethod(record, resolutionStrategy);
        var confidence = ResolveCorrelationConfidence(record, resolutionStrategy);
        var observationId = CreateStableId(
            "pobs",
            sourceRunId,
            adapterId,
            observationKind.ToString(),
            sourceNativeAlias,
            observedUtc.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture),
            record.Status.ToString(),
            rawRecordId);
        var observation = new ProcessObservation
        {
            ObservationId = observationId,
            AdapterId = adapterId,
            ObservationKind = observationKind,
            ProcessEntityId = record.ProcessEntityId,
            SourceRunId = sourceRunId,
            IngestionJobId = ingestionJobId,
            RawRecordId = rawRecordId,
            SourceNativeAlias = sourceNativeAlias,
            ObservedUtc = observedUtc,
            ValidFromUtc = record.StartTimeUtc,
            ValidToUtc = record.EndTimeUtc,
            StatusAssertion = record.Status,
            CorrelationMethod = correlationMethod,
            CorrelationConfidence = confidence,
            ParserVersion = adapterVersion,
            MetadataJson = string.IsNullOrWhiteSpace(metadataJson) ? "{}" : metadataJson,
            FieldStates = BuildFieldStates(record),
            Fields = record
        };
        if (statistics != null)
        {
            ApplyIdentity(statistics, identity, adapterId);
        }

        return new ProcessObservationAdapterItem(
            observation,
            CreateAliases(record, sourceNativeAlias, resolutionStrategy),
            statistics);
    }

    public static string CreateStableId(string prefix, params string[] components)
    {
        var value = string.Join("\u001f", components.Select(component => component ?? string.Empty));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return $"{prefix}-{Convert.ToHexString(hash.AsSpan(0, 16)).ToLowerInvariant()}";
    }

    public static Dictionary<string, ProcessObservationValueState> BuildFieldStates(ProcessRecord process)
    {
        var result = new Dictionary<string, ProcessObservationValueState>(StringComparer.Ordinal);
        foreach (var pair in new Dictionary<string, string?>
        {
            ["ProcessKey"] = process.ProcessKey,
            ["ProcessGuid"] = process.ProcessGuid,
            ["ProcessName"] = process.ProcessName,
            ["ProcessPath"] = process.ProcessPath,
            ["CommandLine"] = process.CommandLine,
            ["UserName"] = process.UserName,
            ["ParentProcessKey"] = process.ParentProcessKey,
            ["ParentProcessEntityId"] = process.ParentProcessEntityId,
            ["ParentProcessName"] = process.ParentProcessName,
            ["Architecture"] = process.Architecture,
            ["CompanyName"] = process.CompanyName,
            ["FileDescription"] = process.FileDescription,
            ["Sha256Hash"] = process.Sha256Hash
        })
        {
            result[pair.Key] = pair.Value?.Contains("access denied", StringComparison.OrdinalIgnoreCase) == true
                ? ProcessObservationValueState.AccessDenied
                : ProcessProjectionPolicy.IsKnown(pair.Value)
                    ? ProcessObservationValueState.Available
                    : ProcessObservationValueState.NotCollected;
        }

        return result;
    }

    public static EvidenceIdentity CloneIdentity(EvidenceIdentity identity, string captureId, string sourceIdentityId)
        => new()
        {
            CaseId = identity.CaseId,
            EvidenceSessionId = identity.EvidenceSessionId,
            CaptureId = FirstNonEmpty(captureId, identity.CaptureId),
            SourceIdentityId = FirstNonEmpty(sourceIdentityId, identity.SourceIdentityId),
            HostId = identity.HostId,
            ExecutionRootId = identity.ExecutionRootId
        };

    public static void ApplyIdentity(IHasEvidenceIdentity record, EvidenceIdentity identity, string sourceIdentityId)
    {
        record.CaseId = identity.CaseId;
        record.EvidenceSessionId = identity.EvidenceSessionId;
        record.CaptureId = identity.CaptureId;
        record.SourceIdentityId = FirstNonEmpty(sourceIdentityId, identity.SourceIdentityId);
        record.HostId = identity.HostId;
        record.ExecutionRootId = identity.ExecutionRootId;
    }

    private static string ResolveProcessEntityId(
        ProcessRecord record,
        string sourceRunId,
        string sourceNativeAlias,
        ProcessEntityResolutionStrategy strategy)
    {
        if (!string.IsNullOrWhiteSpace(record.ProcessEntityId))
        {
            return record.ProcessEntityId;
        }

        if (record.StartTimeUtc.HasValue && strategy != ProcessEntityResolutionStrategy.SourceRunAlias)
        {
            return ProcessEntityIdentity.CreateExact(
                record.CaseId,
                record.EvidenceSessionId,
                record.HostId,
                record.ExecutionRootId,
                record.ProcessId,
                record.StartTimeUtc.Value);
        }

        if (strategy == ProcessEntityResolutionStrategy.SysmonGuid &&
            !string.IsNullOrWhiteSpace(record.ProcessGuid))
        {
            return ProcessEntityIdentity.CreateScopedAlias(
                record.CaseId,
                record.EvidenceSessionId,
                record.HostId,
                record.ExecutionRootId,
                ProcessAliasKind.SysmonProcessGuid,
                record.ProcessGuid);
        }

        var aliasKind = strategy == ProcessEntityResolutionStrategy.SourceRunAlias
            ? ProcessAliasKind.ProcmonSyntheticKey
            : ProcessAliasKind.SourceNativeId;
        return ProcessEntityIdentity.CreateSourceScoped(sourceRunId, aliasKind, sourceNativeAlias);
    }

    private static string ResolveSourceNativeAlias(
        ProcessRecord record,
        ProcessEntityResolutionStrategy strategy,
        string rawRecordId)
    {
        if (strategy == ProcessEntityResolutionStrategy.SysmonGuid &&
            !string.IsNullOrWhiteSpace(record.ProcessGuid))
        {
            return record.ProcessGuid;
        }

        if (strategy == ProcessEntityResolutionStrategy.SourceRunAlias)
        {
            return FirstNonEmpty(rawRecordId, record.ProcessKey, $"pid:{record.ProcessId}");
        }

        return FirstNonEmpty(record.ProcessKey, rawRecordId, $"pid:{record.ProcessId}");
    }

    private static ProcessCorrelationMethod ResolveCorrelationMethod(
        ProcessRecord record,
        ProcessEntityResolutionStrategy strategy)
    {
        if (record.StartTimeUtc.HasValue)
        {
            return strategy == ProcessEntityResolutionStrategy.LegacyCompatibility
                ? ProcessCorrelationMethod.LegacyCompatibility
                : ProcessCorrelationMethod.ExactScopedPidStartTime;
        }

        return strategy switch
        {
            ProcessEntityResolutionStrategy.SysmonGuid when !string.IsNullOrWhiteSpace(record.ProcessGuid) =>
                ProcessCorrelationMethod.SysmonProcessGuid,
            ProcessEntityResolutionStrategy.LegacyCompatibility => ProcessCorrelationMethod.LegacyCompatibility,
            _ => ProcessCorrelationMethod.SourceNativeAlias
        };
    }

    private static double ResolveCorrelationConfidence(
        ProcessRecord record,
        ProcessEntityResolutionStrategy strategy)
    {
        if (record.StartTimeUtc.HasValue)
        {
            return 1.0;
        }

        return strategy switch
        {
            ProcessEntityResolutionStrategy.SysmonGuid when !string.IsNullOrWhiteSpace(record.ProcessGuid) => 1.0,
            ProcessEntityResolutionStrategy.SourceRunAlias => 0.8,
            ProcessEntityResolutionStrategy.LegacyCompatibility => 0.65,
            _ => 0.7
        };
    }

    private static IReadOnlyList<ProcessAlias> CreateAliases(
        ProcessRecord record,
        string sourceNativeAlias,
        ProcessEntityResolutionStrategy strategy)
    {
        var aliases = new List<ProcessAlias>();
        AddAlias(record.ProcessKey.StartsWith("procmon:", StringComparison.OrdinalIgnoreCase)
            ? ProcessAliasKind.ProcmonSyntheticKey
            : ProcessAliasKind.LegacyProcessKey, record.ProcessKey);
        AddAlias(ProcessAliasKind.SysmonProcessGuid, record.ProcessGuid);
        if (!string.Equals(sourceNativeAlias, record.ProcessKey, StringComparison.Ordinal) &&
            !string.Equals(sourceNativeAlias, record.ProcessGuid, StringComparison.OrdinalIgnoreCase))
        {
            AddAlias(
                strategy == ProcessEntityResolutionStrategy.SourceRunAlias
                    ? ProcessAliasKind.ProcmonSyntheticKey
                    : ProcessAliasKind.SourceNativeId,
                sourceNativeAlias);
        }

        return aliases;

        void AddAlias(ProcessAliasKind kind, string value)
        {
            if (string.IsNullOrWhiteSpace(value) ||
                aliases.Any(alias => alias.Kind == kind && string.Equals(alias.Value, value, StringComparison.Ordinal)))
            {
                return;
            }

            aliases.Add(new ProcessAlias
            {
                ProcessEntityId = record.ProcessEntityId,
                Kind = kind,
                Value = value,
                CaseId = record.CaseId,
                EvidenceSessionId = record.EvidenceSessionId,
                HostId = record.HostId,
                ExecutionRootId = record.ExecutionRootId,
                SourceIdentityId = record.SourceIdentityId
            });
        }
    }

    private static ProcessStatisticsRecord CreateStatistics(
        ProcessInfo process,
        ProcessRecord record,
        DateTime observedUtc,
        string source)
        => new()
        {
            CaseId = record.CaseId,
            EvidenceSessionId = record.EvidenceSessionId,
            CaptureId = record.CaptureId,
            SourceIdentityId = record.SourceIdentityId,
            HostId = record.HostId,
            ExecutionRootId = record.ExecutionRootId,
            SampleId = $"{(string.IsNullOrWhiteSpace(record.ProcessKey) ? "unknown" : record.ProcessKey)}_{observedUtc.Ticks}",
            ProcessKey = record.ProcessKey,
            ProcessId = record.ProcessId,
            ProcessGuid = record.ProcessGuid,
            ProcessName = record.ProcessName,
            Status = record.Status,
            ObservedUtc = observedUtc,
            TotalProcessorTime = process.TotalProcessorTime,
            UserProcessorTime = process.UserProcessorTime,
            PrivilegedProcessorTime = process.PrivilegedProcessorTime,
            ReadBytes = process.ReadBytes,
            WrittenBytes = process.WrittenBytes,
            CollectionError = process.StatisticsCollectionError,
            Source = source
        };

    private static string PreferKnownValue(string? value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value;

    private static string FirstNonEmpty(params string[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
}
