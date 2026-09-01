using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class SnapshotComparisonService
{
    public const string CurrentComparisonVersion = "snapshot-comparison-v1";

    private static readonly Regex WhitespaceRegex = new(@"\s+", RegexOptions.Compiled);
    private static readonly Regex IsoTimestampRegex = new(
        @"\b\d{4}-\d{2}-\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex VolatilePidRegex = new(
        @"\b(pid|process\s*id|processid|thread\s*id|threadid)\s*[:=]\s*\d+\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly Regex HexAddressRegex = new(
        @"\b0x[0-9a-f]{6,16}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private readonly SnapshotComparisonQueryService _queryService;

    public SnapshotComparisonService(SnapshotComparisonQueryService queryService)
    {
        _queryService = queryService;
    }

    public async Task<SnapshotComparisonResult> CompareAsync(
        string baselineSnapshotPath,
        string currentSnapshotPath,
        BaselinePolicyDocument policy,
        CancellationToken cancellationToken = default)
    {
        var result = await Task.Run(
                () => Compare(baselineSnapshotPath, currentSnapshotPath, policy),
                cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    public SnapshotComparisonResult Compare(
        string baselineSnapshotPath,
        string currentSnapshotPath,
        BaselinePolicyDocument policy)
    {
        var baseline = _queryService.LoadEvidence(baselineSnapshotPath);
        var current = _queryService.LoadEvidence(currentSnapshotPath);
        var findings = new List<SnapshotComparisonFinding>();

        CompareArtifacts(
            SnapshotComparisonArtifactKind.Process,
            BuildProcessArtifacts(baseline),
            BuildProcessArtifacts(current),
            policy,
            findings);
        CompareArtifacts(
            SnapshotComparisonArtifactKind.Module,
            BuildModuleArtifacts(baseline),
            BuildModuleArtifacts(current),
            policy,
            findings);
        CompareArtifacts(
            SnapshotComparisonArtifactKind.PeAnalysis,
            BuildPeArtifacts(baseline),
            BuildPeArtifacts(current),
            policy,
            findings);
        CompareArtifacts(
            SnapshotComparisonArtifactKind.Event,
            BuildEventArtifacts(baseline),
            BuildEventArtifacts(current),
            policy,
            findings);
        CompareArtifacts(
            SnapshotComparisonArtifactKind.NetworkCapture,
            BuildNetworkArtifacts(baseline),
            BuildNetworkArtifacts(current),
            policy,
            findings);
        CompareArtifacts(
            SnapshotComparisonArtifactKind.ZeekNetworkArtifact,
            BuildZeekArtifacts(baseline),
            BuildZeekArtifacts(current),
            policy,
            findings);
        CompareArtifacts(
            SnapshotComparisonArtifactKind.FilesystemArtifact,
            BuildFilesystemArtifacts(baseline),
            BuildFilesystemArtifacts(current),
            policy,
            findings);
        CompareArtifacts(
            SnapshotComparisonArtifactKind.MemoryImage,
            BuildMemoryImageArtifacts(baseline),
            BuildMemoryImageArtifacts(current),
            policy,
            findings);
        CompareArtifacts(
            SnapshotComparisonArtifactKind.VolatilityPluginRun,
            BuildVolatilityPluginRunArtifacts(baseline),
            BuildVolatilityPluginRunArtifacts(current),
            policy,
            findings);
        CompareArtifacts(
            SnapshotComparisonArtifactKind.MemoryProcess,
            BuildMemoryProcessArtifacts(baseline),
            BuildMemoryProcessArtifacts(current),
            policy,
            findings);

        return new SnapshotComparisonResult
        {
            BaselineSnapshotPath = Path.GetFullPath(baselineSnapshotPath),
            CurrentSnapshotPath = Path.GetFullPath(currentSnapshotPath),
            ComparedUtc = DateTime.UtcNow,
            BaselineProcessCount = baseline.Processes.Count,
            CurrentProcessCount = current.Processes.Count,
            Findings = findings
                .OrderBy(finding => GetVerdictSortOrder(finding.Verdict))
                .ThenBy(finding => finding.ArtifactKind)
                .ThenBy(finding => finding.Title, StringComparer.OrdinalIgnoreCase)
                .ToList()
        };
    }

    private static void CompareArtifacts(
        SnapshotComparisonArtifactKind artifactKind,
        IReadOnlyDictionary<string, ComparableArtifact> baseline,
        IReadOnlyDictionary<string, ComparableArtifact> current,
        BaselinePolicyDocument policy,
        ICollection<SnapshotComparisonFinding> findings)
    {
        foreach (var key in baseline.Keys.Concat(current.Keys).Distinct(StringComparer.Ordinal).OrderBy(value => value, StringComparer.Ordinal))
        {
            baseline.TryGetValue(key, out var baselineArtifact);
            current.TryGetValue(key, out var currentArtifact);

            var verdict = GetVerdict(baselineArtifact, currentArtifact);
            var policyFingerprint = currentArtifact?.MeaningfulFingerprint
                                    ?? baselineArtifact?.MeaningfulFingerprint
                                    ?? string.Empty;
            var policyRule = verdict is SnapshotComparisonVerdict.New
                                 or SnapshotComparisonVerdict.Missing
                                 or SnapshotComparisonVerdict.Changed
                ? BaselinePolicyService.FindMatchingRule(policy, artifactKind, key, policyFingerprint)
                : null;
            if (policyRule != null)
            {
                verdict = SnapshotComparisonVerdict.Accepted;
            }

            findings.Add(new SnapshotComparisonFinding
            {
                ArtifactKind = artifactKind,
                Verdict = verdict,
                StableKey = key,
                Fingerprint = policyFingerprint,
                BaselineFingerprint = baselineArtifact?.MeaningfulFingerprint ?? string.Empty,
                CurrentFingerprint = currentArtifact?.MeaningfulFingerprint ?? string.Empty,
                Title = currentArtifact?.Title ?? baselineArtifact?.Title ?? key,
                BaselineSummary = baselineArtifact?.Summary ?? string.Empty,
                CurrentSummary = currentArtifact?.Summary ?? string.Empty,
                Explanation = BuildExplanation(verdict, baselineArtifact, currentArtifact, policyRule),
                ChangedFields = BuildChangedFields(baselineArtifact, currentArtifact),
                PolicyRuleId = policyRule?.RuleId ?? string.Empty
            });
        }
    }

    private static SnapshotComparisonVerdict GetVerdict(ComparableArtifact? baseline, ComparableArtifact? current)
    {
        if (baseline == null)
        {
            return SnapshotComparisonVerdict.New;
        }

        if (current == null)
        {
            return SnapshotComparisonVerdict.Missing;
        }

        if (!string.Equals(baseline.MeaningfulFingerprint, current.MeaningfulFingerprint, StringComparison.Ordinal))
        {
            return SnapshotComparisonVerdict.Changed;
        }

        return string.Equals(baseline.VolatileFingerprint, current.VolatileFingerprint, StringComparison.Ordinal)
            ? SnapshotComparisonVerdict.Known
            : SnapshotComparisonVerdict.Noisy;
    }

    private static string BuildExplanation(
        SnapshotComparisonVerdict verdict,
        ComparableArtifact? baseline,
        ComparableArtifact? current,
        BaselinePolicyRule? policyRule)
    {
        if (policyRule != null)
        {
            return $"Accepted by baseline policy rule {policyRule.RuleId}.";
        }

        return verdict switch
        {
            SnapshotComparisonVerdict.New => "Present only in the current snapshot.",
            SnapshotComparisonVerdict.Missing => "Present only in the baseline snapshot.",
            SnapshotComparisonVerdict.Changed => "Stable identity matched, but meaningful fields changed.",
            SnapshotComparisonVerdict.Noisy => "Only volatile fields such as timestamps, row ids, PIDs, paths, or counters changed.",
            SnapshotComparisonVerdict.Known => "Stable identity and meaningful fingerprint matched.",
            _ => string.Empty
        };
    }

    private static string BuildChangedFields(ComparableArtifact? baseline, ComparableArtifact? current)
    {
        if (baseline == null || current == null)
        {
            return string.Empty;
        }

        var keys = baseline.MeaningfulFields.Keys
            .Concat(current.MeaningfulFields.Keys)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(key => key, StringComparer.Ordinal);
        var changes = new List<string>();
        foreach (var key in keys)
        {
            baseline.MeaningfulFields.TryGetValue(key, out var baselineValue);
            current.MeaningfulFields.TryGetValue(key, out var currentValue);
            if (string.Equals(baselineValue ?? string.Empty, currentValue ?? string.Empty, StringComparison.Ordinal))
            {
                continue;
            }

            changes.Add($"{key}: baseline='{TrimForDisplay(baselineValue)}' current='{TrimForDisplay(currentValue)}'");
        }

        return string.Join("; ", changes);
    }

    private static IReadOnlyDictionary<string, ComparableArtifact> BuildProcessArtifacts(SnapshotComparisonEvidence evidence)
        => Collapse(evidence.Processes.Select(BuildProcessArtifact));

    private static IReadOnlyDictionary<string, ComparableArtifact> BuildModuleArtifacts(SnapshotComparisonEvidence evidence)
    {
        var processKeys = BuildProcessStableKeys(evidence);
        return Collapse(evidence.Modules.Select(module =>
        {
            var processKey = processKeys.TryGetValue(module.ProcessKey, out var stableProcessKey)
                ? stableProcessKey
                : $"process-key={NormalizeKey(module.ProcessKey)}";
            var modulePath = FirstUseful(module.FullPath, module.ModuleName);
            var stableKey = $"module|process={processKey}|image={NormalizePathKey(modulePath)}";
            var meaningful = Fields(
                ("Process", processKey),
                ("ModuleName", module.ModuleName),
                ("FullPath", NormalizePathDisplay(module.FullPath)),
                ("FileVersion", module.FileVersion),
                ("CompanyName", module.CompanyName),
                ("Description", module.Description),
                ("Sha256Hash", NormalizeHash(module.Sha256Hash)),
                ("State", module.State.ToString()),
                ("ModuleMemorySize", module.ModuleMemorySize.ToString()));
            var volatileFields = Fields(
                ("SequenceId", module.SequenceId.ToString()),
                ("ProcessKey", module.ProcessKey),
                ("ProcessId", module.ProcessId.ToString()),
                ("ProcessGuid", module.ProcessGuid),
                ("BaseAddress", module.BaseAddress),
                ("FirstSeenUtc", FormatDate(module.FirstSeenUtc)),
                ("LastSeenUtc", FormatDate(module.LastSeenUtc)),
                ("UnloadedUtc", FormatDate(module.UnloadedUtc)),
                ("Sources", module.Sources),
                ("LastSource", module.LastSource));
            return CreateArtifact(
                SnapshotComparisonArtifactKind.Module,
                stableKey,
                $"Module: {module.ModuleName}",
                $"{module.ModuleName} | {module.FullPath}",
                meaningful,
                volatileFields);
        }));
    }

    private static IReadOnlyDictionary<string, ComparableArtifact> BuildPeArtifacts(SnapshotComparisonEvidence evidence)
    {
        var processKeys = BuildProcessStableKeys(evidence);
        return Collapse(evidence.PeAnalyses.Select(analysis =>
        {
            var processKey = processKeys.TryGetValue(analysis.ProcessKey, out var stableProcessKey)
                ? stableProcessKey
                : $"process-key={NormalizeKey(analysis.ProcessKey)}";
            var sourceIdentity = !string.IsNullOrWhiteSpace(analysis.SourceArtifactId)
                ? analysis.SourceArtifactId
                : analysis.FilePath;
            var stableKey = $"pe|process={processKey}|source={NormalizeKey(analysis.SourceKind.ToString())}|artifact={NormalizePathKey(sourceIdentity)}";
            var meaningful = Fields(
                ("Process", processKey),
                ("SourceKind", analysis.SourceKind.ToString()),
                ("Status", analysis.Status.ToString()),
                ("FilePath", NormalizePathDisplay(analysis.FilePath)),
                ("FileSizeBytes", analysis.FileSizeBytes.ToString()),
                ("Sha256Hash", NormalizeHash(analysis.Sha256Hash)),
                ("Md5Hash", NormalizeHash(analysis.Md5Hash)),
                ("Machine", analysis.Machine),
                ("Subsystem", analysis.Subsystem),
                ("PeKind", analysis.PeKind),
                ("LinkerTimestampUtc", FormatDate(analysis.LinkerTimestampUtc)),
                ("EntryPoint", analysis.EntryPoint),
                ("SectionCount", analysis.SectionCount.ToString()),
                ("ImportCount", analysis.ImportCount.ToString()),
                ("ExportCount", analysis.ExportCount.ToString()),
                ("SectionsHash", HashText(analysis.SectionsJson)),
                ("ImportsHash", HashText(analysis.ImportsJson)),
                ("ExportsHash", HashText(analysis.ExportsJson)),
                ("VersionInfoHash", HashText(analysis.VersionInfoJson)));
            var volatileFields = Fields(
                ("AnalysisId", analysis.AnalysisId),
                ("ProcessKey", analysis.ProcessKey),
                ("ProcessId", analysis.ProcessId.ToString()),
                ("ProcessGuid", analysis.ProcessGuid),
                ("AnalyzedUtc", FormatDate(analysis.AnalyzedUtc)),
                ("Source", analysis.Source));
            return CreateArtifact(
                SnapshotComparisonArtifactKind.PeAnalysis,
                stableKey,
                $"PE: {Path.GetFileName(analysis.FilePath)}",
                $"{analysis.SourceKind} | {analysis.FilePath} | {analysis.Status}",
                meaningful,
                volatileFields);
        }));
    }

    private static IReadOnlyDictionary<string, ComparableArtifact> BuildEventArtifacts(SnapshotComparisonEvidence evidence)
    {
        var processKeys = BuildProcessStableKeys(evidence);
        return Collapse(evidence.Events.Select(record =>
        {
            var processKey = processKeys.TryGetValue(record.ProcessKey, out var stableProcessKey)
                ? stableProcessKey
                : NormalizeEventProcess(record);
            var stableKey = string.Join(
                "|",
                "event",
                NormalizeKey(record.Source),
                NormalizeKey(record.RawProvider),
                NormalizeKey(record.RawLogName),
                record.EventCode?.ToString() ?? string.Empty,
                NormalizeKey(record.Category.ToString()),
                NormalizeKey(record.Action.ToString()),
                NormalizeKey(record.Target),
                NormalizeEventText(record.Summary),
                processKey);
            var meaningful = Fields(
                ("Process", processKey),
                ("Source", record.Source),
                ("RawProvider", record.RawProvider),
                ("RawLogName", record.RawLogName),
                ("EventCode", record.EventCode?.ToString() ?? string.Empty),
                ("Category", record.Category.ToString()),
                ("Action", record.Action.ToString()),
                ("Target", NormalizeEventText(record.Target)),
                ("Summary", NormalizeEventText(record.Summary)),
                ("Details", NormalizeEventText(record.Details)),
                ("RiskFlags", record.RiskFlags),
                ("IsInteresting", record.IsInteresting.ToString()));
            var volatileFields = Fields(
                ("SequenceId", record.SequenceId.ToString()),
                ("TimestampUtc", FormatDate(record.TimestampUtc)),
                ("ProcessKey", record.ProcessKey),
                ("ProcessId", record.ProcessId.ToString()),
                ("ProcessGuid", record.ProcessGuid),
                ("ProcessStartTimeUtc", FormatDate(record.ProcessStartTimeUtc)),
                ("ParentProcessId", record.ParentProcessId.ToString()),
                ("RepeatCount", record.RepeatCount.ToString()),
                ("RawRecordId", record.RawRecordId),
                ("CorrelationMethod", record.CorrelationMethod));
            return CreateArtifact(
                SnapshotComparisonArtifactKind.Event,
                stableKey,
                $"Event: {record.Source} {record.EventCode?.ToString() ?? record.Action.ToString()}",
                $"{record.TimestampUtc:u} | {record.ProcessName} | {record.Summary}",
                meaningful,
                volatileFields);
        }));
    }

    private static IReadOnlyDictionary<string, ComparableArtifact> BuildNetworkArtifacts(SnapshotComparisonEvidence evidence)
        => Collapse(evidence.NetworkCaptures.Select(capture =>
        {
            var identity = !string.IsNullOrWhiteSpace(capture.Sha256Hash)
                ? capture.Sha256Hash
                : $"{capture.CaptureSource}|{capture.FilterDescription}|{capture.SegmentIndex}";
            var stableKey = WithSourceRunIdentity($"network-capture|{NormalizeKey(identity)}", capture.SourceRunId);
            var meaningful = Fields(
                ("Status", capture.Status.ToString()),
                ("FileSizeBytes", capture.FileSizeBytes.ToString()),
                ("Sha256Hash", NormalizeHash(capture.Sha256Hash)),
                ("ToolName", capture.ToolName),
                ("CaptureSource", capture.CaptureSource),
                ("FilterDescription", capture.FilterDescription),
                ("ErrorMessage", capture.ErrorMessage));
            var volatileFields = Fields(
                ("CaptureId", capture.CaptureId),
                ("JobId", capture.JobId?.ToString() ?? string.Empty),
                ("SegmentIndex", capture.SegmentIndex.ToString()),
                ("RequestedUtc", FormatDate(capture.RequestedUtc)),
                ("StartedUtc", FormatDate(capture.StartedUtc)),
                ("CompletedUtc", FormatDate(capture.CompletedUtc)),
                ("OutputDirectory", NormalizePathDisplay(capture.OutputDirectory)),
                ("EtlFilePath", NormalizePathDisplay(capture.EtlFilePath)),
                ("FilePath", NormalizePathDisplay(capture.FilePath)),
                ("Source", capture.Source));
            return CreateArtifact(
                SnapshotComparisonArtifactKind.NetworkCapture,
                stableKey,
                $"Network capture: {capture.CaptureId}",
                $"{capture.Status} | {capture.FilePath}",
                meaningful,
                volatileFields);
        }));

    private static IReadOnlyDictionary<string, ComparableArtifact> BuildZeekArtifacts(SnapshotComparisonEvidence evidence)
        => Collapse(evidence.ZeekNetworkArtifacts.Select(artifact =>
        {
            var identity = FirstUseful(
                artifact.ZeekUid,
                artifact.RawLineHash,
                $"{artifact.LogType}|{artifact.SourceIp}:{artifact.SourcePort}>{artifact.DestinationIp}:{artifact.DestinationPort}|{artifact.DnsQuery}|{artifact.HttpHost}{artifact.HttpUri}");
            var stableKey = WithSourceRunIdentity($"zeek|{NormalizeKey(artifact.LogType)}|{NormalizeKey(identity)}", artifact.SourceRunId);
            var meaningful = Fields(
                ("Status", artifact.Status.ToString()),
                ("LogType", artifact.LogType),
                ("ZeekUid", artifact.ZeekUid),
                ("SourceIp", artifact.SourceIp),
                ("SourcePort", artifact.SourcePort.ToString()),
                ("DestinationIp", artifact.DestinationIp),
                ("DestinationPort", artifact.DestinationPort.ToString()),
                ("Protocol", artifact.Protocol),
                ("Service", artifact.Service),
                ("DnsQuery", artifact.DnsQuery),
                ("HttpMethod", artifact.HttpMethod),
                ("HttpHost", artifact.HttpHost),
                ("HttpUri", artifact.HttpUri),
                ("DurationSeconds", artifact.DurationSeconds.ToString("0.###")),
                ("OrigBytes", artifact.OrigBytes.ToString()),
                ("RespBytes", artifact.RespBytes.ToString()),
                ("OrigPackets", artifact.OrigPackets.ToString()),
                ("RespPackets", artifact.RespPackets.ToString()),
                ("OrigIpBytes", artifact.OrigIpBytes.ToString()),
                ("RespIpBytes", artifact.RespIpBytes.ToString()),
                ("ConnectionState", artifact.ConnectionState),
                ("History", artifact.History),
                ("ServerName", artifact.ServerName),
                ("ClientProtocol", artifact.ClientProtocol),
                ("TlsVersion", artifact.TlsVersion),
                ("TlsCipher", artifact.TlsCipher),
                ("TlsEstablished", artifact.TlsEstablished.ToString()),
                ("WeirdName", artifact.WeirdName),
                ("WeirdAdditional", artifact.WeirdAdditional),
                ("Summary", artifact.Summary),
                ("ProcessName", artifact.ProcessName),
                ("CorrelationMethod", artifact.CorrelationMethod),
                ("CorrelationConfidence", artifact.CorrelationConfidence.ToString("0.###")),
                ("ErrorMessage", artifact.ErrorMessage));
            var volatileFields = Fields(
                ("ArtifactId", artifact.ArtifactId),
                ("CaptureId", artifact.CaptureId),
                ("JobId", artifact.JobId?.ToString() ?? string.Empty),
                ("TimestampUtc", FormatDate(artifact.TimestampUtc)),
                ("ProcessKey", artifact.ProcessKey),
                ("ProcessId", artifact.ProcessId.ToString()),
                ("RawLogPath", NormalizePathDisplay(artifact.RawLogPath)),
                ("RawLineNumber", artifact.RawLineNumber.ToString()),
                ("RawText", NormalizeEventText(artifact.RawText)),
                ("Source", artifact.Source));
            return CreateArtifact(
                SnapshotComparisonArtifactKind.ZeekNetworkArtifact,
                stableKey,
                $"Zeek: {artifact.LogType} {FirstUseful(artifact.ZeekUid, artifact.DnsQuery, artifact.HttpHost)}",
                $"{artifact.TimestampUtc:u} | {artifact.Summary}",
                meaningful,
                volatileFields);
        }));

    private static IReadOnlyDictionary<string, ComparableArtifact> BuildFilesystemArtifacts(SnapshotComparisonEvidence evidence)
        => Collapse(evidence.FilesystemArtifacts.Select(artifact =>
        {
            var identity = FirstUseful(
                artifact.Sha256Hash,
                artifact.RawPayloadHash,
                $"{artifact.Kind}|{artifact.SourcePath}|{artifact.Name}");
            var stableKey = WithSourceRunIdentity($"filesystem|{NormalizeKey(artifact.Kind.ToString())}|{NormalizePathKey(identity)}", artifact.SourceRunId);
            var meaningful = Fields(
                ("Kind", artifact.Kind.ToString()),
                ("Status", artifact.Status.ToString()),
                ("Name", artifact.Name),
                ("SourcePath", NormalizePathDisplay(artifact.SourcePath)),
                ("FileSizeBytes", artifact.FileSizeBytes.ToString()),
                ("CreatedUtc", FormatDate(artifact.CreatedUtc)),
                ("LastModifiedUtc", FormatDate(artifact.LastModifiedUtc)),
                ("Sha256Hash", NormalizeHash(artifact.Sha256Hash)),
                ("Summary", artifact.Summary),
                ("ProcessName", artifact.ProcessName),
                ("RunCount", artifact.RunCount.ToString()),
                ("LastRunUtc", FormatDate(artifact.LastRunUtc)),
                ("RawPayloadHash", NormalizeHash(artifact.RawPayloadHash)),
                ("ErrorMessage", artifact.ErrorMessage));
            var volatileFields = Fields(
                ("ArtifactId", artifact.ArtifactId),
                ("JobId", artifact.JobId?.ToString() ?? string.Empty),
                ("TimestampUtc", FormatDate(artifact.TimestampUtc)),
                ("RawRecordId", artifact.RawRecordId),
                ("RawText", NormalizeEventText(artifact.RawText)),
                ("Source", artifact.Source));
            return CreateArtifact(
                SnapshotComparisonArtifactKind.FilesystemArtifact,
                stableKey,
                $"Filesystem: {artifact.Kind} {FirstUseful(artifact.Name, Path.GetFileName(artifact.SourcePath))}",
                $"{artifact.Status} | {artifact.SourcePath}",
                meaningful,
                volatileFields);
        }));

    private static IReadOnlyDictionary<string, ComparableArtifact> BuildMemoryImageArtifacts(SnapshotComparisonEvidence evidence)
        => Collapse(evidence.MemoryImages.Select(image =>
        {
            var identity = FirstUseful(image.Sha256Hash, image.SourcePath, image.FilePath, image.ImageId);
            var stableKey = WithSourceRunIdentity($"memory-image|{NormalizePathKey(identity)}", image.SourceRunId);
            var meaningful = Fields(
                ("Status", image.Status.ToString()),
                ("ImageFormat", image.ImageFormat),
                ("FileSizeBytes", image.FileSizeBytes.ToString()),
                ("Sha256Hash", NormalizeHash(image.Sha256Hash)),
                ("HostName", image.HostName),
                ("OsBuild", image.OsBuild),
                ("AcquisitionTool", image.AcquisitionTool),
                ("AcquisitionToolVersion", image.AcquisitionToolVersion),
                ("AcquisitionCommandLine", NormalizeEventText(image.AcquisitionCommandLine)),
                ("PrivilegeState", image.PrivilegeState),
                ("ErrorMessage", image.ErrorMessage));
            var volatileFields = Fields(
                ("ImageId", image.ImageId),
                ("JobId", image.JobId?.ToString() ?? string.Empty),
                ("ImportedUtc", FormatDate(image.ImportedUtc)),
                ("SourcePath", NormalizePathDisplay(image.SourcePath)),
                ("FilePath", NormalizePathDisplay(image.FilePath)),
                ("IngestionJobId", image.IngestionJobId),
                ("Source", image.Source));
            return CreateArtifact(
                SnapshotComparisonArtifactKind.MemoryImage,
                stableKey,
                $"Memory image: {FirstUseful(image.DisplayName, image.ImageId)}",
                $"{image.Status} | {image.FilePath}",
                meaningful,
                volatileFields);
        }));

    private static IReadOnlyDictionary<string, ComparableArtifact> BuildVolatilityPluginRunArtifacts(SnapshotComparisonEvidence evidence)
        => Collapse(evidence.VolatilityPluginRuns.Select(run =>
        {
            var identity = FirstUseful(run.RawOutputHash, run.RunId);
            var stableKey = WithSourceRunIdentity($"volatility|{NormalizeKey(run.PluginName)}|{NormalizeKey(identity)}", run.SourceRunId);
            var meaningful = Fields(
                ("PluginName", run.PluginName),
                ("Status", run.Status.ToString()),
                ("VolatilityVersion", run.VolatilityVersion),
                ("CommandLine", NormalizeEventText(run.CommandLine)),
                ("RawOutputHash", NormalizeHash(run.RawOutputHash)),
                ("ProfileOrLayer", run.ProfileOrLayer),
                ("NormalizedRowCount", run.NormalizedRowCount.ToString()),
                ("ErrorMessage", run.ErrorMessage));
            var volatileFields = Fields(
                ("RunId", run.RunId),
                ("ImageId", run.ImageId),
                ("JobId", run.JobId?.ToString() ?? string.Empty),
                ("RequestedUtc", FormatDate(run.RequestedUtc)),
                ("StartedUtc", FormatDate(run.StartedUtc)),
                ("CompletedUtc", FormatDate(run.CompletedUtc)),
                ("OutputDirectory", NormalizePathDisplay(run.OutputDirectory)),
                ("StdoutPath", NormalizePathDisplay(run.StdoutPath)),
                ("StderrPath", NormalizePathDisplay(run.StderrPath)),
                ("IngestionJobId", run.IngestionJobId));
            return CreateArtifact(
                SnapshotComparisonArtifactKind.VolatilityPluginRun,
                stableKey,
                $"Volatility: {run.PluginName}",
                $"{run.Status} | {run.NormalizedRowCount} normalized rows",
                meaningful,
                volatileFields);
        }));

    private static IReadOnlyDictionary<string, ComparableArtifact> BuildMemoryProcessArtifacts(SnapshotComparisonEvidence evidence)
        => Collapse(evidence.MemoryProcesses.Select(process =>
        {
            var identity = FirstUseful(process.RawRowHash, process.ObjectOffset, $"{process.PluginName}|{process.RowNumber}");
            var stableKey = WithSourceRunIdentity($"memory-process|{NormalizeKey(identity)}", process.SourceRunId);
            var meaningful = Fields(
                ("PluginName", process.PluginName),
                ("EvidenceKind", process.EvidenceKind.ToString()),
                ("ProcessId", process.ProcessId.ToString()),
                ("ParentProcessId", process.ParentProcessId.ToString()),
                ("ProcessName", process.ProcessName),
                ("ImagePath", NormalizePathDisplay(process.ImagePath)),
                ("CommandLine", NormalizeEventText(process.CommandLine)),
                ("CreateTimeUtc", FormatDate(process.CreateTimeUtc)),
                ("ExitTimeUtc", FormatDate(process.ExitTimeUtc)),
                ("CorrelationState", process.CorrelationState.ToString()),
                ("CorrelationMethod", process.CorrelationMethod),
                ("RawRowHash", NormalizeHash(process.RawRowHash)));
            var volatileFields = Fields(
                ("ArtifactId", process.ArtifactId),
                ("ImageId", process.ImageId),
                ("PluginRunId", process.PluginRunId),
                ("RowNumber", process.RowNumber.ToString()),
                ("ProcessKey", process.ProcessKey),
                ("IngestionJobId", process.IngestionJobId));
            return CreateArtifact(
                SnapshotComparisonArtifactKind.MemoryProcess,
                stableKey,
                $"Memory process: {process.ProcessName} ({process.ProcessId})",
                $"{process.PluginName} | {process.CorrelationState}",
                meaningful,
                volatileFields);
        }));

    private static string WithSourceRunIdentity(string stableKey, string sourceRunId)
        => string.IsNullOrWhiteSpace(sourceRunId)
            ? stableKey
            : $"{stableKey}|source-run={NormalizeKey(sourceRunId)}";

    private static ComparableArtifact BuildProcessArtifact(ProcessRecord process)
    {
        var stableKey = BuildProcessStableKey(process);
        var meaningful = Fields(
            ("ProcessName", process.ProcessName),
            ("ProcessPath", NormalizePathDisplay(process.ProcessPath)),
            ("CommandLine", NormalizeEventText(process.CommandLine)),
            ("UserName", process.UserName),
            ("ParentProcessName", process.ParentProcessName),
            ("Architecture", process.Architecture),
            ("CompanyName", process.CompanyName),
            ("FileDescription", process.FileDescription),
            ("Sha256Hash", NormalizeHash(process.Sha256Hash)));
        var volatileFields = Fields(
            ("ProcessKey", process.ProcessKey),
            ("ProcessId", process.ProcessId.ToString()),
            ("ProcessGuid", process.ProcessGuid),
            ("ParentProcessId", process.ParentProcessId.ToString()),
            ("ParentProcessKey", process.ParentProcessKey),
            ("StartTimeUtc", FormatDate(process.StartTimeUtc)),
            ("EndTimeUtc", FormatDate(process.EndTimeUtc)),
            ("Status", process.Status.ToString()),
            ("CpuUsage", process.CpuUsage.ToString("0.###")),
            ("MemoryUsageBytes", process.MemoryUsageBytes.ToString()),
            ("TreeDepth", process.TreeDepth.ToString()),
            ("FirstObservedUtc", FormatDate(process.FirstObservedUtc)),
            ("LastObservedUtc", FormatDate(process.LastObservedUtc)),
            ("LastSource", process.LastSource));
        return CreateArtifact(
            SnapshotComparisonArtifactKind.Process,
            stableKey,
            $"Process: {process.ProcessName}",
            $"{process.ProcessName} | {process.ProcessPath} | {process.CommandLine}",
            meaningful,
            volatileFields);
    }

    internal static string BuildProcessStableKeyForRisk(ProcessRecord process)
        => BuildProcessStableKey(process);

    internal static string BuildProcessMeaningfulFingerprintForRisk(ProcessRecord process)
        => BuildProcessArtifact(process).MeaningfulFingerprint;

    private static IReadOnlyDictionary<string, string> BuildProcessStableKeys(SnapshotComparisonEvidence evidence)
        => evidence.Processes
            .Where(process => !string.IsNullOrWhiteSpace(process.ProcessKey))
            .GroupBy(process => process.ProcessKey, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => BuildProcessStableKey(group.First()), StringComparer.Ordinal);

    private static string BuildProcessStableKey(ProcessRecord process)
    {
        var image = FirstUseful(process.ProcessPath, process.ProcessName);
        return string.Join(
            "|",
            "process",
            $"image={NormalizePathKey(image)}",
            $"user={NormalizeKey(process.UserName)}",
            $"parent={NormalizeKey(process.ParentProcessName)}");
    }

    private static ComparableArtifact CreateArtifact(
        SnapshotComparisonArtifactKind kind,
        string stableKey,
        string title,
        string summary,
        IReadOnlyDictionary<string, string> meaningfulFields,
        IReadOnlyDictionary<string, string> volatileFields)
    {
        return new ComparableArtifact
        {
            Kind = kind,
            StableKey = stableKey,
            Title = string.IsNullOrWhiteSpace(title) ? stableKey : title,
            Summary = TrimForDisplay(summary, 500),
            MeaningfulFields = meaningfulFields,
            VolatileFields = volatileFields,
            MeaningfulFingerprint = HashFields(meaningfulFields),
            VolatileFingerprint = HashFields(volatileFields)
        };
    }

    private static IReadOnlyDictionary<string, ComparableArtifact> Collapse(IEnumerable<ComparableArtifact> artifacts)
    {
        var result = new Dictionary<string, ComparableArtifact>(StringComparer.Ordinal);
        foreach (var group in artifacts.GroupBy(artifact => artifact.StableKey, StringComparer.Ordinal))
        {
            var rows = group.ToList();
            var first = rows[0];
            if (rows.Count == 1)
            {
                result[group.Key] = first;
                continue;
            }

            var meaningfulFingerprint = HashLines(rows
                .Select(row => row.MeaningfulFingerprint)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(value => value, StringComparer.Ordinal));
            var volatileFingerprint = HashLines(rows
                .Select(row => row.VolatileFingerprint)
                .Concat(new[] { $"row-count={rows.Count}" })
                .Distinct(StringComparer.Ordinal)
                .OrderBy(value => value, StringComparer.Ordinal));

            var meaningfulFields = new Dictionary<string, string>(first.MeaningfulFields, StringComparer.Ordinal)
            {
                ["DistinctMeaningfulRows"] = rows.Select(row => row.MeaningfulFingerprint).Distinct(StringComparer.Ordinal).Count().ToString()
            };
            var volatileFields = new Dictionary<string, string>(first.VolatileFields, StringComparer.Ordinal)
            {
                ["RowCount"] = rows.Count.ToString()
            };

            result[group.Key] = first with
            {
                Title = $"{first.Title} ({rows.Count} rows)",
                Summary = $"{rows.Count} matching rows. First row: {first.Summary}",
                MeaningfulFields = meaningfulFields,
                VolatileFields = volatileFields,
                MeaningfulFingerprint = meaningfulFingerprint,
                VolatileFingerprint = volatileFingerprint
            };
        }

        return result;
    }

    private static IReadOnlyDictionary<string, string> Fields(params (string Key, string? Value)[] values)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in values)
        {
            fields[key] = NormalizeFieldValue(value);
        }

        return fields;
    }

    private static string NormalizeFieldValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim();
        return trimmed is "<not available>" or "<unknown>"
            ? string.Empty
            : trimmed;
    }

    private static string NormalizeEventProcess(TelemetryEventRecord record)
    {
        return string.Join(
            ":",
            "event-process",
            NormalizeKey(record.ProcessName),
            record.ProcessStartTimeUtc?.ToString("O") ?? string.Empty);
    }

    private static string NormalizeEventText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = IsoTimestampRegex.Replace(value, "<time>");
        normalized = VolatilePidRegex.Replace(normalized, match => $"{match.Groups[1].Value}=<id>");
        normalized = HexAddressRegex.Replace(normalized, "<address>");
        return WhitespaceRegex.Replace(normalized.Trim(), " ");
    }

    private static string NormalizePathDisplay(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return value.Trim().Replace('/', '\\');
    }

    private static string NormalizePathKey(string? value)
        => NormalizeKey(NormalizePathDisplay(value));

    private static string NormalizeKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return WhitespaceRegex.Replace(value.Trim().Trim('"').ToLowerInvariant(), " ");
    }

    private static string NormalizeHash(string? value)
    {
        var normalized = NormalizeKey(value);
        return normalized is "<not available>" or "<unknown>" ? string.Empty : normalized;
    }

    private static string HashFields(IReadOnlyDictionary<string, string> fields)
        => HashLines(fields
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => $"{pair.Key}={pair.Value}"));

    private static string HashLines(IEnumerable<string> lines)
        => HashText(string.Join("\n", lines));

    private static string HashText(string? text)
    {
        var bytes = Encoding.UTF8.GetBytes(text ?? string.Empty);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static string FirstUseful(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(NormalizeFieldValue(value))) ?? string.Empty;

    private static string FormatDate(DateTime? value)
        => value?.ToUniversalTime().ToString("O") ?? string.Empty;

    private static string TrimForDisplay(string? value, int maxLength = 160)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = WhitespaceRegex.Replace(value.Trim(), " ");
        return trimmed.Length <= maxLength ? trimmed : trimmed[..maxLength] + "...";
    }

    private static int GetVerdictSortOrder(SnapshotComparisonVerdict verdict)
        => verdict switch
        {
            SnapshotComparisonVerdict.New => 0,
            SnapshotComparisonVerdict.Changed => 1,
            SnapshotComparisonVerdict.Missing => 2,
            SnapshotComparisonVerdict.Accepted => 3,
            SnapshotComparisonVerdict.Noisy => 4,
            SnapshotComparisonVerdict.Known => 5,
            _ => 6
        };

    private sealed record ComparableArtifact
    {
        public SnapshotComparisonArtifactKind Kind { get; init; }
        public string StableKey { get; init; } = string.Empty;
        public string MeaningfulFingerprint { get; init; } = string.Empty;
        public string VolatileFingerprint { get; init; } = string.Empty;
        public string Title { get; init; } = string.Empty;
        public string Summary { get; init; } = string.Empty;
        public IReadOnlyDictionary<string, string> MeaningfulFields { get; init; } =
            new Dictionary<string, string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> VolatileFields { get; init; } =
            new Dictionary<string, string>(StringComparer.Ordinal);
    }
}
