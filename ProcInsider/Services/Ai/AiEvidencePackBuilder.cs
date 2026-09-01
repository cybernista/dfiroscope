using System.Text;
using System.IO;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Telemetry;
using ProcInsider.Services;

namespace ProcInsider.Services.Ai;

public sealed class AiEvidencePack
{
    public string EvidenceText { get; init; } = string.Empty;

    public string Summary { get; init; } = string.Empty;
}

public sealed class AiEvidencePackBuilder
{
    private const int MaxRowsPerSource = 25;
    private readonly TelemetryProjectionService _projectionService;
    private readonly ApplicationInfoResolutionService _applicationInfoResolver;
    private AnnotationDatabaseService? _annotationStore;

    public AiEvidencePackBuilder(
        TelemetryProjectionService projectionService,
        AnnotationDatabaseService? annotationStore = null,
        ApplicationCatalogService? applicationCatalog = null)
    {
        _projectionService = projectionService;
        _annotationStore = annotationStore;
        _applicationInfoResolver = new ApplicationInfoResolutionService(applicationCatalog);
    }

    public void SetAnnotationStore(AnnotationDatabaseService? annotationStore)
        => _annotationStore = annotationStore;

    public AiEvidencePack BuildForSelectedProcess(
        ProcessInfo process,
        IEnumerable<AiEvidenceSourceKind> selectedSources)
    {
        var sources = selectedSources.Distinct().ToList();
        var evidence = new StringBuilder();
        var summary = new List<string>();

        evidence.AppendLine("Evidence boundary: selected process Data tab evidence only.");
        evidence.AppendLine($"Generated UTC: {DateTime.UtcNow:O}");
        evidence.AppendLine($"Selected source count: {sources.Count}");
        evidence.AppendLine($"Per-source row cap: {MaxRowsPerSource}");
        evidence.AppendLine();

        AppendProcessIdentity(evidence, process);
        AppendEvidenceRelations(evidence, process);

        foreach (var source in sources)
        {
            switch (source)
            {
                case AiEvidenceSourceKind.ProcessProperties:
                    AppendProcessProperties(evidence, process);
                    summary.Add("Properties: process metadata included");
                    break;
                case AiEvidenceSourceKind.ProcessDescription:
                    summary.Add(AppendProcessDescription(evidence, process));
                    break;
                case AiEvidenceSourceKind.Modules:
                    summary.Add(AppendModules(evidence, process));
                    break;
                case AiEvidenceSourceKind.Handles:
                    summary.Add(AppendHandles(evidence, process));
                    break;
                case AiEvidenceSourceKind.RuntimeEvents:
                    summary.Add(AppendEvents(evidence, process, "Runtime", "Runtime Events"));
                    break;
                case AiEvidenceSourceKind.EtwEvents:
                    summary.Add(AppendEvents(evidence, process, "ETW", "ETW Events"));
                    break;
                case AiEvidenceSourceKind.SecurityEvents:
                    summary.Add(AppendEvents(evidence, process, "Security", "Security Events"));
                    break;
                case AiEvidenceSourceKind.PowerShellEvents:
                    summary.Add(AppendEvents(evidence, process, "PowerShell", "PowerShell Logs"));
                    break;
                case AiEvidenceSourceKind.WindowsOtherEvents:
                    summary.Add(AppendEvents(evidence, process, "WindowsOther", "Windows Logs (Other)"));
                    break;
                case AiEvidenceSourceKind.SysmonEvents:
                    summary.Add(AppendEvents(evidence, process, "Sysmon", "Sysmon"));
                    break;
                case AiEvidenceSourceKind.MemoryDumps:
                    summary.Add(AppendMemoryDumps(evidence, process));
                    break;
                case AiEvidenceSourceKind.PeOnDisk:
                    summary.Add(AppendPeAnalyses(evidence, process, "PE On Disk", analysis => analysis.SourceKind == PeAnalysisSourceKind.ProcessImage));
                    break;
                case AiEvidenceSourceKind.PeFromMemoryDump:
                    summary.Add(AppendPeAnalyses(evidence, process, "PE From Memory/Dump", analysis => analysis.SourceKind != PeAnalysisSourceKind.ProcessImage));
                    break;
                case AiEvidenceSourceKind.ZeekArtifacts:
                    summary.Add(AppendZeekArtifacts(evidence, process));
                    break;
                case AiEvidenceSourceKind.FilesystemArtifacts:
                    summary.Add(AppendFilesystemArtifacts(evidence, process));
                    break;
            }
        }

        if (sources.Count == 0)
        {
            AppendUnavailable(evidence, "Selected Data Tabs", "No source tabs selected.");
            summary.Add("No source tabs selected");
        }

        return new AiEvidencePack
        {
            EvidenceText = evidence.ToString(),
            Summary = string.Join("; ", summary)
        };
    }

    private static void AppendProcessIdentity(StringBuilder builder, ProcessInfo process)
    {
        builder.AppendLine("## Selected Process Identity");
        builder.AppendLine($"Process name: {process.ProcessName}");
        builder.AppendLine($"PID: {process.ProcessId}");
        builder.AppendLine($"Process key: {process.GetUniqueKey()}");
        builder.AppendLine($"Image path: {process.ProcessPath}");
        builder.AppendLine($"Command line: {process.CommandLine}");
        builder.AppendLine($"Case id: {process.CaseId}");
        builder.AppendLine($"Evidence session id: {process.EvidenceSessionId}");
        builder.AppendLine($"Capture id: {process.CaptureId}");
        builder.AppendLine($"Source identity id: {process.SourceIdentityId}");
        builder.AppendLine($"Host id: {process.HostId}");
        builder.AppendLine($"Execution root id: {process.ExecutionRootId}");
        builder.AppendLine();
    }

    private void AppendEvidenceRelations(StringBuilder builder, ProcessInfo process)
    {
        if (string.IsNullOrWhiteSpace(process.ProcessEntityId))
        {
            return;
        }

        var relations = _projectionService
            .GetEvidenceRelationsForProcess(process.ProcessEntityId, MaxRowsPerSource)
            .ToList();
        var relationIds = relations.Select(relation => relation.RelationId).ToHashSet(StringComparer.Ordinal);
        var directEndpoints = relations
            .SelectMany(relation => new[]
            {
                (Kind: relation.FromKind, Id: relation.FromId),
                (Kind: relation.ToKind, Id: relation.ToId)
            })
            .Where(endpoint => !string.IsNullOrWhiteSpace(endpoint.Id) &&
                               endpoint.Kind != EvidenceReferenceKind.ProcessEntity)
            .Distinct()
            .Take(MaxRowsPerSource)
            .ToList();
        foreach (var (evidenceKind, evidenceId) in directEndpoints)
        {
            if (relations.Count >= MaxRowsPerSource)
            {
                break;
            }

            foreach (var relation in _projectionService.GetEvidenceRelationsForArtifact(
                         evidenceKind,
                         evidenceId,
                         MaxRowsPerSource - relations.Count))
            {
                if (relationIds.Add(relation.RelationId))
                {
                    relations.Add(relation);
                }

                if (relations.Count >= MaxRowsPerSource)
                {
                    break;
                }
            }

            if (relations.Count >= MaxRowsPerSource)
            {
                break;
            }
        }
        builder.AppendLine("## Shared Evidence Relationships");
        builder.AppendLine("Correlation state is authoritative; confidence is explanatory metadata and must not promote an inferred or ambiguous link to fact.");
        foreach (var relation in relations)
        {
            builder.AppendLine($"- RelationId={relation.RelationId}; Type={relation.RelationType}; State={relation.State}; Method={relation.CorrelationMethod}; Confidence={relation.Confidence:F2}; From={relation.FromKind}/{relation.FromId}; To={relation.ToKind}/{relation.ToId}; Resolver={relation.ResolverName}/{relation.ResolverVersion}; Status={relation.Status}; SourceRun={relation.SourceRunId}; RawInput={relation.RawInputId}; AnalystAnnotation={relation.AnalystAnnotationId}");
        }

        if (relations.Count == 0)
        {
            builder.AppendLine("- No shared relation rows are available for this process entity.");
        }

        builder.AppendLine();
    }

    private static void AppendProcessProperties(StringBuilder builder, ProcessInfo process)
    {
        builder.AppendLine("## Source: Properties");
        builder.AppendLine("Row count: 1");
        builder.AppendLine($"Status: {process.Status}");
        builder.AppendLine($"Start time: {FormatUtc(process.StartTime)}");
        builder.AppendLine($"End time: {FormatUtc(process.EndTime)}");
        builder.AppendLine($"Parent PID: {process.ParentProcessId}");
        builder.AppendLine($"Parent process key: {process.ParentProcessKey}");
        builder.AppendLine($"Parent process name: {process.ParentProcessName}");
        builder.AppendLine($"User: {process.UserName}");
        builder.AppendLine($"Windows session id: {process.SessionId}");
        builder.AppendLine($"Architecture: {process.Architecture}");
        builder.AppendLine($"CPU: {process.CpuUsageFormatted}");
        builder.AppendLine($"Memory: {process.MemoryUsageFormatted}");
        builder.AppendLine($"Company: {process.CompanyName}");
        builder.AppendLine($"File description: {process.FileDescription}");
        builder.AppendLine($"SHA256: {process.Sha256Hash}");
        builder.AppendLine($"Module capture status: {process.ModuleCaptureStatus}; count: {process.ModuleCount}; last captured: {FormatUtc(process.ModuleLastCaptured)}; error: {process.ModuleCaptureError}");
        builder.AppendLine($"Handle capture status: {process.HandleCaptureStatus}; count: {process.HandleCount}; last captured: {FormatUtc(process.HandleLastCaptured)}; error: {process.HandleCaptureError}");
        builder.AppendLine();
    }

    private string AppendProcessDescription(StringBuilder builder, ProcessInfo process)
    {
        var metadata = LoadApplicationMetadata(process);

        builder.AppendLine("## Source: Process Description/App Info");
        AppendRowHeader(builder, metadata == null ? 0 : 1, metadata == null ? 0 : 1);
        if (metadata == null)
        {
            AppendNoRows(builder, 0);
            builder.AppendLine();
            return "Process Description/App Info: no rows available";
        }

        builder.AppendLine($"- ApplicationId={metadata.ApplicationId}; BaseProfileId={metadata.BaseProfileId}; BaseProfileRevision={metadata.BaseProfileRevision}; CatalogRevision={metadata.BaseCatalogRevision}; Origin={metadata.RecordOrigin}; ReviewState={metadata.ReviewState}; DisplayName={metadata.DisplayName}; ExecutablePattern={metadata.ExecutableNamePattern}; Regex={metadata.IsRegexPattern}; Company={metadata.CompanyVendor}; Product={metadata.ProductName}; Source={metadata.Source}; Confidence={metadata.Confidence:F2}; IsAiGenerated={metadata.IsAiGenerated}; AiProviderKind={metadata.AiProviderKind}; AiEndpointMode={metadata.AiEndpointMode}; AiTemplate={metadata.AiPromptTemplateId}; AiRequested={metadata.AiRequestedUtc:O}; AiSourceClaimsUnverified={metadata.AiSourceClaimsUnverified}; Match={metadata.MatchReason}");
        builder.AppendLine($"  Description={metadata.Description}");
        builder.AppendLine($"  Expected responsibilities={metadata.ExpectedResponsibilities}");
        builder.AppendLine($"  Normal behavior={metadata.NormalBehavior}");
        builder.AppendLine($"  Launch triggers={metadata.LaunchTriggers}");
        builder.AppendLine($"  Analyst validation checks={metadata.AnalystValidationChecks}");
        builder.AppendLine($"  AI uncertainty={metadata.AiUncertainty}");
        builder.AppendLine($"  AI validation warnings={metadata.AiValidationWarnings}");
        builder.AppendLine($"  Known benign notes={metadata.KnownBenignNotes}");
        builder.AppendLine($"  Cybersecurity notes={metadata.CybersecurityNotes}");
        builder.AppendLine();
        return "Process Description/App Info: 1 row included";
    }

    private string AppendModules(StringBuilder builder, ProcessInfo process)
    {
        var rows = _projectionService.GetModulesForProcess(new ModuleProjectionQuery
        {
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.GetUniqueKey(),
            IncludeUnloaded = true
        });
        var includedRows = rows.Take(MaxRowsPerSource).ToList();

        builder.AppendLine("## Source: Modules");
        AppendRowHeader(builder, rows.Count, includedRows.Count);
        foreach (var module in includedRows)
        {
            builder.AppendLine($"- Name={module.ModuleName}; Status={module.StatusDisplay}; Path={module.FullPath}; SHA256={module.Sha256Hash}; Company={module.CompanyName}; Description={module.Description}; Base={module.BaseAddress}; Size={module.ModuleMemorySizeFormatted}; LastSeen={FormatUtc(module.LastSeenUtc)}");
        }

        AppendNoRows(builder, rows.Count);
        builder.AppendLine();
        return FormatSummary("Modules", rows.Count, includedRows.Count);
    }

    private string AppendHandles(StringBuilder builder, ProcessInfo process)
    {
        var rows = _projectionService.GetHandlesForProcess(new HandleProjectionQuery
        {
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.GetUniqueKey(),
            IncludeClosed = true
        });
        var includedRows = rows.Take(MaxRowsPerSource).ToList();

        builder.AppendLine("## Source: Handles");
        AppendRowHeader(builder, rows.Count, includedRows.Count);
        foreach (var handle in includedRows)
        {
            builder.AppendLine($"- Handle={handle.HandleValue}; Status={handle.StatusDisplay}; Type={handle.ObjectType}; Name={handle.ObjectName}; Access={handle.GrantedAccess}; Attributes={handle.HandleAttributes}; ObjectAddress={handle.ObjectAddress}; LastSeen={FormatUtc(handle.LastSeenUtc)}");
        }

        AppendNoRows(builder, rows.Count);
        builder.AppendLine();
        return FormatSummary("Handles", rows.Count, includedRows.Count);
    }

    private string AppendEvents(StringBuilder builder, ProcessInfo process, string source, string label)
    {
        var rows = _projectionService.GetEventsForProcess(new EventProjectionQuery
        {
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.GetUniqueKey(),
            Source = source,
            MaxCount = MaxRowsPerSource
        });

        builder.AppendLine($"## Source: {label}");
        AppendRowHeader(builder, rows.Count, rows.Count);
        foreach (var processEvent in rows)
        {
            builder.AppendLine($"- Time={processEvent.TimestampUtc:O}; Seq={processEvent.SequenceId}; EventCode={processEvent.EventCode}; Category={processEvent.Category}; Action={processEvent.Action}; Target={processEvent.Target}; Summary={processEvent.Summary}; Details={processEvent.Details}; RiskFlags={processEvent.RiskFlags}; RepeatCount={processEvent.RepeatCount}");
        }

        AppendNoRows(builder, rows.Count);
        builder.AppendLine();
        return FormatSummary(label, rows.Count, rows.Count);
    }

    private string AppendMemoryDumps(StringBuilder builder, ProcessInfo process)
    {
        var rows = _projectionService.GetMemoryDumpsForProcess(
            process.GetUniqueKey(),
            MaxRowsPerSource,
            process.ProcessEntityId);
        builder.AppendLine("## Source: Memory Dumps");
        AppendRowHeader(builder, rows.Count, rows.Count);
        foreach (var dump in rows)
        {
            builder.AppendLine($"- DumpId={dump.DumpId}; Status={dump.Status}; Kind={dump.DumpKind}; Requested={dump.RequestedUtc:O}; Completed={FormatUtc(dump.CompletedUtc)}; File={dump.FilePath}; Size={dump.FileSizeBytes}; SHA256={dump.Sha256Hash}; Tool={dump.ToolName}; Error={dump.ErrorMessage}");
        }

        AppendNoRows(builder, rows.Count);
        builder.AppendLine();
        return FormatSummary("Memory Dumps", rows.Count, rows.Count);
    }

    private string AppendPeAnalyses(
        StringBuilder builder,
        ProcessInfo process,
        string label,
        Func<PeAnalysisRecord, bool> predicate)
    {
        var matchingRows = _projectionService
            .GetPeAnalysesForProcess(process.GetUniqueKey(), 1000, process.ProcessEntityId)
            .Where(predicate)
            .ToList();
        var includedRows = matchingRows.Take(MaxRowsPerSource).ToList();

        builder.AppendLine($"## Source: {label}");
        AppendRowHeader(builder, matchingRows.Count, includedRows.Count);
        foreach (var analysis in includedRows)
        {
            builder.AppendLine($"- AnalysisId={analysis.AnalysisId}; Status={analysis.Status}; SourceKind={analysis.SourceKind}; SourceArtifactId={analysis.SourceArtifactId}; File={analysis.FilePath}; SHA256={analysis.Sha256Hash}; Machine={analysis.Machine}; Subsystem={analysis.Subsystem}; PEKind={analysis.PeKind}; EntryPoint={analysis.EntryPoint}; ImageBase={analysis.ImageBase}; Sections={analysis.SectionCount}; Imports={analysis.ImportCount}; Exports={analysis.ExportCount}; StringAnalysisStatus={analysis.StringAnalysisStatus}; PrintableStrings={(analysis.StringAnalysisStatus == PeStringAnalysisStatus.Completed ? analysis.PrintableStringCount.ToString() : "<not scanned>")}; Error={analysis.ErrorMessage}");
        }

        AppendNoRows(builder, matchingRows.Count);
        builder.AppendLine();
        return FormatSummary(label, matchingRows.Count, includedRows.Count);
    }

    private string AppendZeekArtifacts(StringBuilder builder, ProcessInfo process)
    {
        var processKey = process.GetUniqueKey();
        var matchingRows = _projectionService
            .GetZeekNetworkArtifacts(1000)
            .Where(row => string.Equals(row.ProcessKey, processKey, StringComparison.Ordinal))
            .ToList();
        var includedRows = matchingRows.Take(MaxRowsPerSource).ToList();

        builder.AppendLine("## Source: Zeek Artifacts");
        AppendRowHeader(builder, matchingRows.Count, includedRows.Count);
        foreach (var artifact in includedRows)
        {
            builder.AppendLine($"- ArtifactId={artifact.ArtifactId}; Status={artifact.Status}; Time={artifact.TimestampUtc:O}; LogType={artifact.LogType}; UID={artifact.ZeekUid}; Src={FormatEndpoint(artifact.SourceIp, artifact.SourcePort)}; Dst={FormatEndpoint(artifact.DestinationIp, artifact.DestinationPort)}; Protocol={artifact.Protocol}; Service={artifact.Service}; DurationSeconds={artifact.DurationSeconds:F3}; OrigBytes={artifact.OrigBytes}; RespBytes={artifact.RespBytes}; OrigPackets={artifact.OrigPackets}; RespPackets={artifact.RespPackets}; State={artifact.ConnectionState}; DNS={artifact.DnsQuery}; HTTP={artifact.HttpMethod} {artifact.HttpHost}{artifact.HttpUri}; ServerName={artifact.ServerName}; ClientProtocol={artifact.ClientProtocol}; TLS={artifact.TlsVersion}/{artifact.TlsCipher}; Weird={artifact.WeirdName} {artifact.WeirdAdditional}; Summary={artifact.Summary}; CorrelationState={artifact.CorrelationState}; Correlation={artifact.CorrelationMethod}/{artifact.CorrelationConfidence:F2}; Error={artifact.ErrorMessage}");
        }

        AppendNoRows(builder, matchingRows.Count);
        builder.AppendLine();
        return FormatSummary("Zeek Artifacts", matchingRows.Count, includedRows.Count);
    }

    private string AppendFilesystemArtifacts(StringBuilder builder, ProcessInfo process)
    {
        var matchingRows = _projectionService
            .GetFilesystemArtifacts(1000)
            .Where(row => IsRelatedFilesystemArtifact(row, process))
            .ToList();
        var includedRows = matchingRows.Take(MaxRowsPerSource).ToList();

        builder.AppendLine("## Source: Filesystem Artifacts");
        AppendRowHeader(builder, matchingRows.Count, includedRows.Count);
        foreach (var artifact in includedRows)
        {
            builder.AppendLine($"- ArtifactId={artifact.ArtifactId}; Kind={artifact.Kind}; Status={artifact.Status}; Time={artifact.TimestampUtc:O}; Name={artifact.Name}; Path={artifact.SourcePath}; Size={artifact.FileSizeBytes}; SHA256={artifact.Sha256Hash}; ProcessName={artifact.ProcessName}; RunCount={artifact.RunCount}; LastRun={FormatUtc(artifact.LastRunUtc)}; Summary={artifact.Summary}; Error={artifact.ErrorMessage}");
        }

        AppendNoRows(builder, matchingRows.Count);
        builder.AppendLine();
        return FormatSummary("Filesystem Artifacts", matchingRows.Count, includedRows.Count);
    }

    private static bool IsRelatedFilesystemArtifact(FilesystemArtifactRecord artifact, ProcessInfo process)
    {
        if (!string.IsNullOrWhiteSpace(artifact.ProcessName) &&
            string.Equals(artifact.ProcessName, process.ProcessName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var fileName = Path.GetFileNameWithoutExtension(process.ProcessPath);
        return !string.IsNullOrWhiteSpace(fileName) &&
               (string.Equals(artifact.Name, fileName, StringComparison.OrdinalIgnoreCase) ||
                artifact.SourcePath.Contains(fileName, StringComparison.OrdinalIgnoreCase));
    }

    private static void AppendUnavailable(StringBuilder builder, string label, string reason)
    {
        builder.AppendLine($"## Source: {label}");
        builder.AppendLine("Row count: 0");
        builder.AppendLine($"no rows available: {reason}");
        builder.AppendLine();
    }

    private static void AppendRowHeader(StringBuilder builder, int availableCount, int includedCount)
    {
        builder.AppendLine($"Rows available: {availableCount}");
        builder.AppendLine($"Rows included: {includedCount}");
        builder.AppendLine($"Row cap per source: {MaxRowsPerSource}");
        if (availableCount > includedCount)
        {
            builder.AppendLine($"Rows omitted by cap: {availableCount - includedCount}");
        }
    }

    private static void AppendNoRows(StringBuilder builder, int count)
    {
        if (count == 0)
        {
            builder.AppendLine("no rows available");
        }
    }

    private static string FormatSummary(string label, int availableCount, int includedCount)
    {
        if (availableCount == 0)
        {
            return $"{label}: no rows available";
        }

        return availableCount == includedCount
            ? $"{label}: {includedCount} row(s) included"
            : $"{label}: {includedCount} of {availableCount} row(s) included";
    }

    private static string FormatUtc(DateTime? value)
        => value?.ToUniversalTime().ToString("O") ?? string.Empty;

    private static string FormatEndpoint(string address, int port)
        => string.IsNullOrWhiteSpace(address) ? string.Empty : port > 0 ? $"{address}:{port}" : address;

    private ApplicationMetadataRecord? LoadApplicationMetadata(ProcessInfo process)
    {
        ApplicationMetadataRecord? sessionOverride = null;
        try
        {
            sessionOverride = _annotationStore?.LoadApplicationMetadataForProcessAsync(process).GetAwaiter().GetResult();
        }
        catch
        {
            // Catalog resolution remains available when session annotations cannot be read.
        }

        return _applicationInfoResolver.Resolve(process, unsavedDraft: null, sessionOverride);
    }
}
