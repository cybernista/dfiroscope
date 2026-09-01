using System;
using System.Collections.Generic;
using System.Linq;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Bounded, read-only records materialized from one validated SQLite projection
/// for a single Sigma evaluation pass.
/// </summary>
public sealed class SigmaEvaluationInput
{
    public IReadOnlyList<ProcessRecord> Processes { get; init; } = Array.Empty<ProcessRecord>();
    public IReadOnlyList<ProcessObservation> ProcessObservations { get; init; } =
        Array.Empty<ProcessObservation>();
    public IReadOnlyList<TelemetryEventRecord> Events { get; init; } = Array.Empty<TelemetryEventRecord>();
    public IReadOnlyList<ModuleObservationRecord> Modules { get; init; } = Array.Empty<ModuleObservationRecord>();
    public IReadOnlyList<HandleObservationRecord> Handles { get; init; } = Array.Empty<HandleObservationRecord>();
    public IReadOnlyList<NetworkCaptureRecord> NetworkCaptures { get; init; } = Array.Empty<NetworkCaptureRecord>();
    public IReadOnlyList<ZeekNetworkRecord> ZeekNetworkArtifacts { get; init; } = Array.Empty<ZeekNetworkRecord>();
    public IReadOnlyList<FilesystemArtifactRecord> FilesystemArtifacts { get; init; } = Array.Empty<FilesystemArtifactRecord>();
    public IReadOnlyList<MemoryImageRecord> MemoryImages { get; init; } = Array.Empty<MemoryImageRecord>();
    public IReadOnlyList<VolatilityPluginRunRecord> VolatilityPluginRuns { get; init; } = Array.Empty<VolatilityPluginRunRecord>();
    public IReadOnlyList<MemoryProcessRecord> MemoryProcesses { get; init; } = Array.Empty<MemoryProcessRecord>();
}

/// <summary>
/// Pure Sigma batch evaluator over caller-owned read-only records. It never opens
/// a database, mutates evidence, or persists the synthetic independent-artifact
/// event projections used for compatible rule matching.
/// </summary>
public sealed class SigmaAnalysisEvaluator
{
    public SigmaRunResult RunWithDiagnostics(
        SigmaEvaluationInput input,
        IReadOnlyList<SigmaRule> rules,
        int maxFindings)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(rules);

        var analyses = rules
            .Select(rule => new
            {
                Rule = rule,
                Compatibility = SigmaCompatibilityAnalyzer.Analyze(rule)
            })
            .ToList();
        var runnableRules = analyses
            .Where(analysis => analysis.Rule.Selections.Count > 0 &&
                               analysis.Compatibility.Status != SigmaCompatibilityStatus.Unsupported)
            .ToList();
        var diagnostics = analyses
            .SelectMany(analysis => analysis.Compatibility.Diagnostics)
            .ToList();
        var runnableRuleCount = analyses.Count(analysis => analysis.Compatibility.Status == SigmaCompatibilityStatus.Runnable);
        var partiallyRunnableRuleCount = analyses.Count(analysis => analysis.Compatibility.Status == SigmaCompatibilityStatus.PartiallyRunnable);
        var unsupportedRuleCount = analyses.Count(analysis => analysis.Compatibility.Status == SigmaCompatibilityStatus.Unsupported);

        if (maxFindings <= 0 || runnableRules.Count == 0)
        {
            return new SigmaRunResult
            {
                Diagnostics = diagnostics,
                RunnableRuleCount = runnableRuleCount,
                PartiallyRunnableRuleCount = partiallyRunnableRuleCount,
                UnsupportedRuleCount = unsupportedRuleCount
            };
        }

        maxFindings = Math.Clamp(maxFindings, 1, 10000);
        var processes = input.Processes;
        var events = CreateEvaluationEvents(input);
        var processesByKey = processes.ToDictionary(process => process.ProcessKey, StringComparer.Ordinal);
        var processesByEntityId = processes
            .Where(process => !string.IsNullOrWhiteSpace(process.ProcessEntityId))
            .GroupBy(process => process.ProcessEntityId, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
        var latestProcessByPid = BuildLatestProcessByPid(processes);
        var findings = new List<SigmaFinding>(Math.Min(maxFindings, 256));
        var seenFindings = new HashSet<string>(StringComparer.Ordinal);

        foreach (var analysis in runnableRules)
        {
            try
            {
                if (TryEvaluateSigmaRule(
                        analysis.Rule,
                        analysis.Compatibility,
                        processes,
                        events,
                        input.Modules,
                        input.Handles,
                        processesByKey,
                        processesByEntityId,
                        latestProcessByPid,
                        findings,
                        seenFindings,
                        maxFindings))
                {
                    return new SigmaRunResult
                    {
                        Findings = findings,
                        Diagnostics = diagnostics,
                        ReachedMaxFindings = true,
                        RunnableRuleCount = runnableRuleCount,
                        PartiallyRunnableRuleCount = partiallyRunnableRuleCount,
                        UnsupportedRuleCount = unsupportedRuleCount
                    };
                }
            }
            catch (Exception ex)
            {
                diagnostics.Add(CreateSigmaDiagnostic(analysis.Rule, "Error", $"Evaluation failed: {ex.Message}"));
            }
        }

        return new SigmaRunResult
        {
            Findings = findings,
            Diagnostics = diagnostics,
            ReachedMaxFindings = false,
            RunnableRuleCount = runnableRuleCount,
            PartiallyRunnableRuleCount = partiallyRunnableRuleCount,
            UnsupportedRuleCount = unsupportedRuleCount
        };
    }

    internal static IReadOnlyList<TelemetryEventRecord> CreateEvaluationEvents(SigmaEvaluationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return input.Events
            .Concat(CreateIndependentAnalysisEvents(
                input.Events.Select(processEvent => processEvent.SequenceId).DefaultIfEmpty(0).Max() + 1,
                input.NetworkCaptures,
                input.ZeekNetworkArtifacts,
                input.FilesystemArtifacts,
                input.MemoryImages,
                input.VolatilityPluginRuns,
                input.MemoryProcesses))
            .ToArray();
    }

    private static bool TryEvaluateSigmaRule(
        SigmaRule rule,
        SigmaCompatibilityAnalysis compatibility,
        IReadOnlyList<ProcessRecord> processes,
        IReadOnlyList<TelemetryEventRecord> events,
        IReadOnlyList<ModuleObservationRecord> modules,
        IReadOnlyList<HandleObservationRecord> handles,
        IReadOnlyDictionary<string, ProcessRecord> processesByKey,
        IReadOnlyDictionary<string, ProcessRecord> processesByEntityId,
        IReadOnlyDictionary<int, ProcessRecord> latestProcessByPid,
        List<SigmaFinding> findings,
        HashSet<string> seenFindings,
        int maxFindings)
    {
        var evidenceKinds = compatibility.SupportedEvidenceKinds.ToHashSet();
        if (evidenceKinds.Contains(SigmaEvidenceKind.Event))
        {
            for (var index = events.Count - 1; index >= 0; index--)
            {
                var processEvent = events[index];
                if (!SigmaCompatibilityAnalyzer.IsEventCompatible(rule, processEvent))
                {
                    continue;
                }

                var process = !string.IsNullOrWhiteSpace(processEvent.ProcessEntityId) &&
                              processesByEntityId.TryGetValue(processEvent.ProcessEntityId, out var entityProcess)
                    ? entityProcess
                    : !string.IsNullOrWhiteSpace(processEvent.ProcessKey) &&
                      processesByKey.TryGetValue(processEvent.ProcessKey, out var keyedProcess)
                        ? keyedProcess
                        : null;
                if (SigmaRuleEvaluator.TryMatchEvent(rule, processEvent, process, out var match))
                {
                    var finding = CreateSigmaFinding(
                        rule,
                        "Event",
                        processEvent.TimestampUtc,
                        processEvent.ProcessKey,
                        processEvent.ProcessId,
                        process?.ProcessName ?? processEvent.ProcessName,
                        BuildEventEvidence(processEvent),
                        processEvent.Source,
                        match,
                        processEvent.ProcessEntityId,
                        processEvent.CorrelationState,
                        processEvent.CorrelationMethod,
                        processEvent.CorrelationCandidateCount);
                    if (TryAddSigmaFinding(findings, seenFindings, finding, maxFindings))
                    {
                        return true;
                    }
                }
            }
        }

        if (evidenceKinds.Contains(SigmaEvidenceKind.Process))
        {
            foreach (var process in processes)
            {
                if (!SigmaCompatibilityAnalyzer.IsProcessCompatible(rule, process))
                {
                    continue;
                }

                if (SigmaRuleEvaluator.TryMatchProcess(rule, process, out var match))
                {
                    var hasExactIdentity =
                        !string.IsNullOrWhiteSpace(process.ProcessEntityId) &&
                        !string.IsNullOrWhiteSpace(process.ProcessKey);
                    var finding = CreateSigmaFinding(
                        rule,
                        "Process",
                        process.LastObservedUtc,
                        process.ProcessKey,
                        process.ProcessId,
                        process.ProcessName,
                        $"{process.ProcessPath} | PID {process.ProcessId} | {process.Status}",
                        process.LastSource,
                        match,
                        process.ProcessEntityId,
                        hasExactIdentity
                            ? EvidenceCorrelationState.Exact
                            : EvidenceCorrelationState.Unresolved,
                        hasExactIdentity ? "ExactProcessEntityId" : string.Empty,
                        hasExactIdentity ? 1 : 0);
                    if (TryAddSigmaFinding(findings, seenFindings, finding, maxFindings))
                    {
                        return true;
                    }
                }
            }
        }

        if (evidenceKinds.Contains(SigmaEvidenceKind.Module))
        {
            foreach (var module in modules)
            {
                var process = GetProcessForResult(module.ProcessKey, module.ProcessId, processesByKey, latestProcessByPid);
                if (SigmaRuleEvaluator.TryMatchModule(rule, module, process, out var match))
                {
                    var hasExactIdentity =
                        module.SequenceId > 0 &&
                        !string.IsNullOrWhiteSpace(module.CaseId) &&
                        !string.IsNullOrWhiteSpace(module.EvidenceSessionId) &&
                        !string.IsNullOrWhiteSpace(module.CaptureId) &&
                        !string.IsNullOrWhiteSpace(module.SourceIdentityId) &&
                        !string.IsNullOrWhiteSpace(module.HostId) &&
                        !string.IsNullOrWhiteSpace(module.ExecutionRootId) &&
                        !string.IsNullOrWhiteSpace(module.ProcessEntityId) &&
                        !string.IsNullOrWhiteSpace(module.ProcessKey) &&
                        !string.IsNullOrWhiteSpace(module.ModuleKey) &&
                        !string.IsNullOrWhiteSpace(module.SourceRunId);
                    var finding = CreateSigmaFinding(
                        rule,
                        "Module",
                        module.LastSeenUtc,
                        module.ProcessKey,
                        module.ProcessId,
                        process?.ProcessName ?? "<unknown>",
                        $"{module.ModuleName} | {module.FullPath} | {module.State}",
                        module.LastSource,
                        match,
                        module.ProcessEntityId,
                        hasExactIdentity
                            ? EvidenceCorrelationState.Exact
                            : EvidenceCorrelationState.Unresolved,
                        hasExactIdentity ? "ExactModuleProcessEntityId" : string.Empty,
                        hasExactIdentity ? 1 : 0,
                        hasExactIdentity ? module.ModuleKey : string.Empty,
                        hasExactIdentity ? module.SourceRunId : string.Empty);
                    if (TryAddSigmaFinding(findings, seenFindings, finding, maxFindings))
                    {
                        return true;
                    }
                }
            }
        }

        if (evidenceKinds.Contains(SigmaEvidenceKind.Handle))
        {
            foreach (var handle in handles)
            {
                var process = GetProcessForResult(handle.ProcessKey, handle.ProcessId, processesByKey, latestProcessByPid);
                if (SigmaRuleEvaluator.TryMatchHandle(rule, handle, process, out var match))
                {
                    var hasExactIdentity =
                        handle.SequenceId > 0 &&
                        !string.IsNullOrWhiteSpace(handle.CaseId) &&
                        !string.IsNullOrWhiteSpace(handle.EvidenceSessionId) &&
                        !string.IsNullOrWhiteSpace(handle.CaptureId) &&
                        !string.IsNullOrWhiteSpace(handle.SourceIdentityId) &&
                        !string.IsNullOrWhiteSpace(handle.HostId) &&
                        !string.IsNullOrWhiteSpace(handle.ExecutionRootId) &&
                        !string.IsNullOrWhiteSpace(handle.ProcessEntityId) &&
                        !string.IsNullOrWhiteSpace(handle.ProcessKey) &&
                        !string.IsNullOrWhiteSpace(handle.HandleKey) &&
                        !string.IsNullOrWhiteSpace(handle.SourceRunId);
                    var finding = CreateSigmaFinding(
                        rule,
                        "Handle",
                        handle.LastSeenUtc,
                        handle.ProcessKey,
                        handle.ProcessId,
                        process?.ProcessName ?? "<unknown>",
                        $"{handle.ObjectType} | {handle.ObjectName} | {handle.State}",
                        handle.LastSource,
                        match,
                        handle.ProcessEntityId,
                        hasExactIdentity
                            ? EvidenceCorrelationState.Exact
                            : EvidenceCorrelationState.Unresolved,
                        hasExactIdentity ? "ExactHandleProcessEntityId" : string.Empty,
                        hasExactIdentity ? 1 : 0,
                        hasExactIdentity ? handle.HandleKey : string.Empty,
                        hasExactIdentity ? handle.SourceRunId : string.Empty);
                    if (TryAddSigmaFinding(findings, seenFindings, finding, maxFindings))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private static IReadOnlyList<TelemetryEventRecord> CreateIndependentAnalysisEvents(
        long nextSequenceId,
        IReadOnlyList<NetworkCaptureRecord> networkCaptures,
        IReadOnlyList<ZeekNetworkRecord> zeekArtifacts,
        IReadOnlyList<FilesystemArtifactRecord> filesystemArtifacts,
        IReadOnlyList<MemoryImageRecord> memoryImages,
        IReadOnlyList<VolatilityPluginRunRecord> volatilityRuns,
        IReadOnlyList<MemoryProcessRecord> memoryProcesses)
    {
        var events = new List<TelemetryEventRecord>();
        foreach (var capture in networkCaptures)
        {
            events.Add(CreateIndependentAnalysisEvent(
                nextSequenceId++,
                capture,
                capture.CompletedUtc ?? capture.StartedUtc ?? capture.RequestedUtc,
                ProcessEventCategory.Network,
                ProcessEventAction.Connect,
                capture.FilePath,
                $"Network capture {capture.Status}: {capture.FilterDescription}",
                $"Path: {capture.FilePath}\nSHA256: {capture.Sha256Hash}\nTool: {capture.ToolName}\nCaptureId: {capture.CaptureId}"));
        }

        foreach (var artifact in zeekArtifacts)
        {
            var isDns = !string.IsNullOrWhiteSpace(artifact.DnsQuery);
            events.Add(CreateIndependentAnalysisEvent(
                nextSequenceId++,
                artifact,
                artifact.TimestampUtc,
                isDns ? ProcessEventCategory.Dns : ProcessEventCategory.Network,
                isDns ? ProcessEventAction.DnsQuery : ProcessEventAction.Connect,
                isDns ? artifact.DnsQuery : artifact.DestinationIp,
                artifact.Summary,
                $"SourceIp: {artifact.SourceIp}\nSourcePort: {artifact.SourcePort}\nDestinationIp: {artifact.DestinationIp}\nDestinationPort: {artifact.DestinationPort}\nDestinationHostname: {FirstKnown(artifact.ServerName, artifact.HttpHost)}\nProtocol: {artifact.Protocol}\nQueryName: {artifact.DnsQuery}\nRawRecordId: {artifact.RawLineHash}",
                artifact.ProcessKey,
                artifact.ProcessId,
                artifact.ProcessName,
                artifact.CorrelationState,
                artifact.CorrelationMethod));
        }

        foreach (var artifact in filesystemArtifacts)
        {
            events.Add(CreateIndependentAnalysisEvent(
                nextSequenceId++,
                artifact,
                artifact.TimestampUtc,
                ProcessEventCategory.File,
                ProcessEventAction.FileWrite,
                artifact.SourcePath,
                artifact.Summary,
                $"TargetFilename: {artifact.SourcePath}\nHashes: {FirstKnown(artifact.Sha256Hash, artifact.RawPayloadHash)}\nRawRecordId: {artifact.RawRecordId}\nArtifactType: {artifact.Kind}"));
        }

        foreach (var image in memoryImages)
        {
            events.Add(CreateIndependentAnalysisEvent(
                nextSequenceId++,
                image,
                image.ImportedUtc,
                ProcessEventCategory.Windows,
                ProcessEventAction.WindowsEvent,
                image.FilePath,
                $"Memory image {image.Status}: {image.DisplayName}",
                $"Path: {image.FilePath}\nHashes: {image.Sha256Hash}\nTool: {image.AcquisitionTool}\nCommandLine: {image.AcquisitionCommandLine}"));
        }

        foreach (var run in volatilityRuns)
        {
            events.Add(CreateIndependentAnalysisEvent(
                nextSequenceId++,
                run,
                run.CompletedUtc ?? run.StartedUtc ?? run.RequestedUtc,
                ProcessEventCategory.Windows,
                ProcessEventAction.WindowsEvent,
                run.PluginName,
                $"Volatility {run.PluginName}: {run.Status}",
                $"CommandLine: {run.CommandLine}\nPath: {run.VolatilityPath}\nHashes: {run.RawOutputHash}\nImageId: {run.ImageId}"));
        }

        foreach (var process in memoryProcesses)
        {
            events.Add(CreateIndependentAnalysisEvent(
                nextSequenceId++,
                process,
                process.CreateTimeUtc ?? DateTime.UnixEpoch,
                ProcessEventCategory.Process,
                ProcessEventAction.ProcessStart,
                process.ImagePath,
                $"Memory process {process.ProcessName} ({process.ProcessId})",
                $"Image: {process.ImagePath}\nCommandLine: {process.CommandLine}\nParentProcessId: {process.ParentProcessId}\nRawRecordId: {process.RawRowHash}\nPlugin: {process.PluginName}",
                process.ProcessKey,
                process.ProcessId,
                process.ProcessName,
                process.CorrelationState == MemoryProcessCorrelationState.Correlated
                    ? EvidenceCorrelationState.Exact
                    : EvidenceCorrelationState.Unresolved,
                process.CorrelationMethod));
        }

        return events;
    }

    private static TelemetryEventRecord CreateIndependentAnalysisEvent(
        long sequenceId,
        IHasSourceRunEvidenceLink evidence,
        DateTime timestampUtc,
        ProcessEventCategory category,
        ProcessEventAction action,
        string target,
        string summary,
        string details,
        string processKey = "",
        int processId = 0,
        string processName = "",
        EvidenceCorrelationState correlationState = EvidenceCorrelationState.Unresolved,
        string correlationMethod = "")
    {
        return new TelemetryEventRecord
        {
            SequenceId = sequenceId,
            CaseId = evidence.CaseId,
            EvidenceSessionId = evidence.EvidenceSessionId,
            CaptureId = evidence.CaptureId,
            SourceIdentityId = evidence.SourceIdentityId,
            HostId = evidence.HostId,
            ExecutionRootId = evidence.ExecutionRootId,
            SourceRunId = evidence.SourceRunId,
            IngestionJobId = evidence.IngestionJobId,
            TimestampUtc = timestampUtc,
            Source = $"IndependentArtifact:{evidence.GetType().Name}",
            ProcessKey = processKey,
            ProcessId = processId,
            ProcessName = string.IsNullOrWhiteSpace(processName) ? "<unmatched>" : processName,
            Category = category,
            Action = action,
            Target = target,
            Summary = summary,
            Details = $"{details}\nSourceRunId: {evidence.SourceRunId}\nIngestionJobId: {evidence.IngestionJobId}",
            RawProvider = "ProcInsider independent artifact projection",
            RawLogName = evidence.GetType().Name,
            CorrelationState = correlationState,
            CorrelationMethod = correlationMethod
        };
    }

    private static SigmaFinding CreateSigmaFinding(
        SigmaRule rule,
        string sourceKind,
        DateTime? timestampUtc,
        string processKey,
        int processId,
        string processName,
        string evidence,
        string source,
        SigmaMatchDetails match,
        string processEntityId = "",
        EvidenceCorrelationState correlationState = EvidenceCorrelationState.Asserted,
        string correlationMethod = "",
        int correlationCandidateCount = 0,
        string sourceEvidenceId = "",
        string sourceRunId = "")
    {
        return new SigmaFinding
        {
            RuleId = rule.Id,
            RuleTitle = rule.Title,
            Level = string.IsNullOrWhiteSpace(rule.Level) ? "informational" : rule.Level,
            SourceKind = sourceKind,
            TimestampUtc = timestampUtc,
            ProcessKey = processKey,
            ProcessId = processId,
            ProcessName = processName,
            MatchedSelector = match.Selector,
            MatchedField = match.Field,
            MatchedValue = match.Value,
            Evidence = TrimMatchValue(evidence),
            Source = source,
            ProcessEntityId = processEntityId,
            SourceEvidenceId = sourceEvidenceId,
            SourceRunId = sourceRunId,
            CorrelationState = correlationState,
            CorrelationMethod = correlationMethod,
            CorrelationCandidateCount = correlationCandidateCount
        };
    }

    private static bool TryAddSigmaFinding(
        List<SigmaFinding> findings,
        HashSet<string> seenFindings,
        SigmaFinding finding,
        int maxFindings)
    {
        if (seenFindings.Add(BuildSigmaFindingKey(finding)))
        {
            findings.Add(finding);
        }

        return findings.Count >= maxFindings;
    }

    private static string BuildSigmaFindingKey(SigmaFinding finding)
    {
        var ruleKey = !string.IsNullOrWhiteSpace(finding.RuleId) ? finding.RuleId : finding.RuleTitle;
        var processKey = !string.IsNullOrWhiteSpace(finding.ProcessKey)
            ? finding.ProcessKey
            : finding.ProcessId.ToString();
        return string.Join(
            "|",
            ruleKey,
            finding.SourceKind,
            finding.TimestampUtc?.Ticks.ToString() ?? string.Empty,
            processKey,
            finding.SourceEvidenceId,
            finding.SourceRunId,
            finding.MatchedSelector,
            finding.MatchedField,
            finding.MatchedValue,
            finding.Evidence);
    }

    private static SigmaRuleDiagnostic CreateSigmaDiagnostic(SigmaRule rule, string severity, string message)
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

    private static string BuildEventEvidence(TelemetryEventRecord processEvent)
    {
        var summary = !string.IsNullOrWhiteSpace(processEvent.Summary)
            ? processEvent.Summary
            : processEvent.Target;
        return string.IsNullOrWhiteSpace(summary)
            ? $"{processEvent.Category} | {processEvent.Action}"
            : $"{processEvent.Category} | {processEvent.Action} | {summary}";
    }

    private static Dictionary<int, ProcessRecord> BuildLatestProcessByPid(IEnumerable<ProcessRecord> processes)
    {
        var latestProcessByPid = new Dictionary<int, ProcessRecord>();
        foreach (var process in processes)
        {
            if (!latestProcessByPid.TryGetValue(process.ProcessId, out var current) ||
                (process.StartTimeUtc ?? process.LastObservedUtc) > (current.StartTimeUtc ?? current.LastObservedUtc))
            {
                latestProcessByPid[process.ProcessId] = process;
            }
        }

        return latestProcessByPid;
    }

    private static ProcessRecord? GetProcessForResult(
        string processKey,
        int processId,
        IReadOnlyDictionary<string, ProcessRecord> processesByKey,
        IReadOnlyDictionary<int, ProcessRecord> latestProcessByPid)
    {
        if (!string.IsNullOrWhiteSpace(processKey) && processesByKey.TryGetValue(processKey, out var process))
        {
            return process;
        }

        return latestProcessByPid.TryGetValue(processId, out var latestProcess)
            ? latestProcess
            : null;
    }

    private static string FirstKnown(params string[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private static string TrimMatchValue(string value)
    {
        value = value.Replace("\r", " ").Replace("\n", " ").Trim();
        return value.Length <= 500 ? value : $"{value[..500]}...";
    }
}
