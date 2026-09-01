using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public sealed class AgentHealthDialogViewModel : ViewModelBase
{
    private readonly Func<CancellationToken, Task<(AgentIpcResponse Response, bool IsActiveSession)>>? _refreshHealthAsync;
    private readonly IFeatureCatalog _catalog;
    private int _refreshInProgress;
    private string _statusLine = string.Empty;
    private string _detail = string.Empty;
    private IReadOnlyList<AgentHealthPropertyRowViewModel> _summaryRows = [];
    private IReadOnlyList<AgentHealthMetricRowViewModel> _metricRows = [];
    private IReadOnlyList<AgentHealthSourceRowViewModel> _sourceRows = [];

    private AgentHealthDialogViewModel(
        AgentRegistryEntryViewModel agent,
        string statusLine,
        string detail,
        IReadOnlyList<AgentHealthPropertyRowViewModel> summaryRows,
        IReadOnlyList<AgentHealthMetricRowViewModel> metricRows,
        IReadOnlyList<AgentHealthSourceRowViewModel> sourceRows,
        Func<CancellationToken, Task<(AgentIpcResponse Response, bool IsActiveSession)>>? refreshHealthAsync,
        IFeatureCatalog catalog)
    {
        Agent = agent;
        _refreshHealthAsync = refreshHealthAsync;
        _catalog = catalog;
        StatusLine = FirstNonEmpty(statusLine, "Agent health");
        Detail = FirstNonEmpty(detail, "No health detail was reported.");
        SummaryRows = summaryRows;
        MetricRows = metricRows;
        SourceRows = sourceRows;
        IsSqliteDiagnosticsPublished = catalog.IsPublished(FeatureIds.EventTelemetry);
    }

    public AgentRegistryEntryViewModel Agent { get; }

    public string StatusLine
    {
        get => _statusLine;
        private set => SetProperty(ref _statusLine, value);
    }

    public string Detail
    {
        get => _detail;
        private set => SetProperty(ref _detail, value);
    }

    public IReadOnlyList<AgentHealthPropertyRowViewModel> SummaryRows
    {
        get => _summaryRows;
        private set => SetProperty(ref _summaryRows, value);
    }

    public IReadOnlyList<AgentHealthMetricRowViewModel> MetricRows
    {
        get => _metricRows;
        private set => SetProperty(ref _metricRows, value);
    }

    public IReadOnlyList<AgentHealthSourceRowViewModel> SourceRows
    {
        get => _sourceRows;
        private set => SetProperty(ref _sourceRows, value);
    }

    public bool CanRefresh => _refreshHealthAsync != null;

    public bool IsSqliteDiagnosticsPublished { get; }

    public static AgentHealthDialogViewModel Create(
        AgentRegistryEntryViewModel agent,
        AgentIpcResponse response,
        bool isActiveSession,
        Func<CancellationToken, Task<(AgentIpcResponse Response, bool IsActiveSession)>>? refreshHealthAsync = null,
        IFeatureCatalog? catalog = null)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(response);
        catalog ??= CurrentEducationalReleaseProfile.RuntimeCatalog;

        var checkedAt = DateTime.Now;
        if (!response.Success)
        {
            var status = string.IsNullOrWhiteSpace(response.ErrorCode)
                ? "Agent unavailable"
                : $"Agent unavailable, {response.ErrorCode}";
            return new AgentHealthDialogViewModel(
                agent,
                status,
                FirstNonEmpty(response.ErrorMessage, "Agent health request failed without detail."),
                CreateUnavailableSummaryRows(agent, checkedAt, response),
                Array.Empty<AgentHealthMetricRowViewModel>(),
                Array.Empty<AgentHealthSourceRowViewModel>(),
                refreshHealthAsync,
                catalog);
        }

        if (response.Health == null)
        {
            return new AgentHealthDialogViewModel(
                agent,
                "Agent reachable, health snapshot missing",
                "The agent responded successfully but did not include a health snapshot.",
                CreateBaseSummaryRows(agent, checkedAt),
                Array.Empty<AgentHealthMetricRowViewModel>(),
                Array.Empty<AgentHealthSourceRowViewModel>(),
                refreshHealthAsync,
                catalog);
        }

        var health = response.Health;
        var capture = health.CaptureHealth;
        var runtime = health.Runtime;
        var connection = agent.IsViewerConnected ? "connected" : "reachable";
        var session = isActiveSession ? "active session" : "different or unverified session";
        var captureState = agent.OperationalCaptureStateDisplay.ToLowerInvariant();
        var releaseState = health.ReleaseProfile.Match switch
        {
            AgentReleaseProfileMatch.Match => "release matched",
            AgentReleaseProfileMatch.Mismatch => "release mismatch",
            _ => "release unverified"
        };
        var statusLine = $"Agent {connection}, PID {health.ProcessId}, {captureState} ({session}; {releaseState})";
        var sources = capture.Sources
            .Where(source => IsSourcePublished(source.Source, catalog))
            .OrderBy(source => source.Source, StringComparer.OrdinalIgnoreCase)
            .Select(source => new AgentHealthSourceRowViewModel(
                source.Source,
                source.Status,
                FormatCount(source.RecordsWritten),
                FormatRate(source.RecordsPerSecond),
                FormatCount(source.RecordsQueued),
                FormatCount(source.RecordsDropped),
                FormatCount(source.WriteFailures),
                FormatDedup(source),
                FirstNonEmpty(source.Error, source.Detail)))
            .ToList();

        return new AgentHealthDialogViewModel(
            agent,
            statusLine,
            string.Join(
                Environment.NewLine,
                new[] { health.ReleaseProfile.Status, BuildDetail(capture, runtime, catalog) }
                    .Where(value => !string.IsNullOrWhiteSpace(value))),
            CreateHealthySummaryRows(agent, checkedAt, health, runtime, isActiveSession, catalog),
            CreateMetricRows(capture, runtime, catalog),
            sources,
            refreshHealthAsync,
            catalog);
    }

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        if (_refreshHealthAsync == null ||
            Interlocked.Exchange(ref _refreshInProgress, 1) != 0)
        {
            return;
        }

        try
        {
            var (response, isActiveSession) = await _refreshHealthAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            Apply(Create(Agent, response, isActiveSession, _refreshHealthAsync, _catalog));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            var response = AgentIpcResponse.Failure(
                Guid.Empty,
                ex.GetType().Name,
                $"Agent health refresh failed: {ex.Message}");
            Apply(Create(Agent, response, isActiveSession: false, _refreshHealthAsync, _catalog));
        }
        finally
        {
            Volatile.Write(ref _refreshInProgress, 0);
        }
    }

    private void Apply(AgentHealthDialogViewModel snapshot)
    {
        StatusLine = snapshot.StatusLine;
        Detail = snapshot.Detail;
        SummaryRows = snapshot.SummaryRows;
        MetricRows = snapshot.MetricRows;
        SourceRows = snapshot.SourceRows;
    }

    private static IReadOnlyList<AgentHealthPropertyRowViewModel> CreateUnavailableSummaryRows(
        AgentRegistryEntryViewModel agent,
        DateTime checkedAt,
        AgentIpcResponse response)
    {
        var rows = CreateBaseSummaryRows(agent, checkedAt).ToList();
        rows.Add(new AgentHealthPropertyRowViewModel("IPC error", FirstNonEmpty(response.ErrorCode, "<none>")));
        rows.Add(new AgentHealthPropertyRowViewModel("Message", FirstNonEmpty(response.ErrorMessage, "<none>")));
        return rows;
    }

    private static IReadOnlyList<AgentHealthPropertyRowViewModel> CreateHealthySummaryRows(
        AgentRegistryEntryViewModel agent,
        DateTime checkedAt,
        AgentHealthSnapshot health,
        AgentRuntimeSnapshot runtime,
        bool isActiveSession,
        IFeatureCatalog catalog)
    {
        var rows = CreateBaseSummaryRows(agent, checkedAt).ToList();
        rows.Add(new AgentHealthPropertyRowViewModel("Process ID", health.ProcessId.ToString(CultureInfo.CurrentCulture)));
        rows.Add(new AgentHealthPropertyRowViewModel("Agent version", FirstNonEmpty(health.AgentVersion, "<not reported>")));
        rows.Add(new AgentHealthPropertyRowViewModel("Agent release", FirstNonEmpty(health.ReleaseProfile.ReleaseId, "<not reported>")));
        rows.Add(new AgentHealthPropertyRowViewModel("Viewer release", FirstNonEmpty(health.ReleaseProfile.ViewerReleaseId, "<not supplied>")));
        rows.Add(new AgentHealthPropertyRowViewModel("Release profile", FirstNonEmpty(health.ReleaseProfile.Status, health.ReleaseProfile.Match.ToString())));
        rows.Add(new AgentHealthPropertyRowViewModel(
            "Operational commands",
            FormatOperationalCommandCapabilities(health.ReleaseProfile.PublishedCommandCapabilities)));
        rows.Add(new AgentHealthPropertyRowViewModel(
            "Unavailable or unverified commands",
            FormatNonOperationalCommandCapabilities(health.ReleaseProfile.PublishedCommandCapabilities)));
        rows.Add(new AgentHealthPropertyRowViewModel(
            "Published evidence source adapters",
            FormatEvidenceSourceAdapters(health.EvidenceSourceAdapters)));
        rows.Add(new AgentHealthPropertyRowViewModel("Machine", FirstNonEmpty(health.MachineName, "<not reported>")));
        rows.Add(new AgentHealthPropertyRowViewModel("Started", FormatDateTime(health.StartedAtUtc)));
        rows.Add(new AgentHealthPropertyRowViewModel("Uptime", FormatDuration(DateTime.UtcNow - health.StartedAtUtc)));
        rows.Add(new AgentHealthPropertyRowViewModel("Session", isActiveSession ? "Matches active live database" : "Different or unverified live database"));
        rows.Add(new AgentHealthPropertyRowViewModel("Database", FirstNonEmpty(health.DatabasePath, "<not reported>")));
        rows.Add(new AgentHealthPropertyRowViewModel("Capture runtime", agent.OperationalCaptureStatus));
        rows.Add(new AgentHealthPropertyRowViewModel("Control snapshot", agent.OperationalCaptureDetail));
        rows.Add(new AgentHealthPropertyRowViewModel("Saved capture configuration", agent.CaptureConfigurationDisplay));
        rows.Add(new AgentHealthPropertyRowViewModel("Capture health", health.CaptureHealth.Health.ToString()));
        rows.Add(new AgentHealthPropertyRowViewModel("Jobs", $"running {runtime.RunningJobCount:N0}/{runtime.WorkerCount:N0}, queued {runtime.QueuedJobCount:N0}/{runtime.QueueCapacity:N0}, completed {runtime.CompletedJobCount:N0}, rejected {runtime.RejectedJobCount:N0}"));
        rows.Add(new AgentHealthPropertyRowViewModel("Writer queue", $"pending {runtime.WriterPendingWorkItemCount:N0}/{runtime.WriterQueueCapacity:N0}, peak {runtime.WriterPeakPendingWorkItemCount:N0}, completed work items {runtime.WriterCompletedWorkItemCount:N0}, failed {runtime.WriterFailedWorkItemCount:N0}"));
        rows.Add(new AgentHealthPropertyRowViewModel("Writer policy", $"batch rows <= {runtime.WriterMaxRowsPerTransaction:N0}, max queue wait {runtime.WriterMaxBatchLatencyMilliseconds:N0} ms, warning at {runtime.WriterBackpressureWarningWorkItemCount:N0} work items"));
        rows.Add(new AgentHealthPropertyRowViewModel("Writer checkpoint policy", $"idle PASSIVE when WAL >= {FormatBytes(runtime.WriterCheckpointWalThresholdBytes)}, interval {runtime.WriterCheckpointMinIntervalSeconds:N0} s"));
        rows.Add(new AgentHealthPropertyRowViewModel("Writer rows", $"completed {runtime.WriterCompletedRowCount:N0}, failed {runtime.WriterFailedRowCount:N0}, last batch {runtime.WriterLastBatchRowCount:N0}, max batch {runtime.WriterMaxBatchRowCount:N0}"));
        rows.Add(new AgentHealthPropertyRowViewModel("Writer timing", $"last tx {FormatMilliseconds(runtime.WriterLastTransactionMilliseconds)}, max tx {FormatMilliseconds(runtime.WriterMaxTransactionMilliseconds)}, last queue {FormatMilliseconds(runtime.WriterLastQueueDelayMilliseconds)}, max queue {FormatMilliseconds(runtime.WriterMaxQueueDelayMilliseconds)}"));
        rows.Add(new AgentHealthPropertyRowViewModel("Writer last operation", FirstNonEmpty(runtime.WriterLastOperation, "<none>")));
        rows.Add(new AgentHealthPropertyRowViewModel("Writer backpressure", runtime.WriterBackpressureActive ? "Active" : "Not active"));
        rows.Add(new AgentHealthPropertyRowViewModel("Writer SQLite contention", $"busy/locked failures {runtime.WriterBusyOrLockedFailureCount:N0}"));
        rows.Add(new AgentHealthPropertyRowViewModel("Live buffer policy", $"RAM {FormatBytes(health.CaptureHealth.LiveBufferMemoryLimitBytes)} before disk spill"));
        rows.Add(new AgentHealthPropertyRowViewModel("Live buffer status", BuildLiveBufferStatus(health.CaptureHealth)));
        if (!string.IsNullOrWhiteSpace(health.CaptureHealth.LiveBufferDirectory))
        {
            rows.Add(new AgentHealthPropertyRowViewModel("Live buffer spill folder", health.CaptureHealth.LiveBufferDirectory));
        }

        if (!string.IsNullOrWhiteSpace(runtime.WriterLastCheckpointSummary))
        {
            var timestamp = runtime.WriterLastCheckpointUtc.HasValue
                ? $" at {FormatDateTime(runtime.WriterLastCheckpointUtc.Value)}"
                : string.Empty;
            rows.Add(new AgentHealthPropertyRowViewModel("Writer last checkpoint", $"{runtime.WriterLastCheckpointSummary}{timestamp}"));
        }
        if (!string.IsNullOrWhiteSpace(runtime.CaptureDiagnosticsSummary))
        {
            var timestamp = runtime.CaptureDiagnosticsLastSampleUtc.HasValue
                ? $" at {FormatDateTime(runtime.CaptureDiagnosticsLastSampleUtc.Value)}"
                : string.Empty;
            rows.Add(new AgentHealthPropertyRowViewModel("Capture diagnostics", $"{runtime.CaptureDiagnosticsSummary}{timestamp}"));
        }

        if (!string.IsNullOrWhiteSpace(runtime.CaptureDiagnosticsLogPath))
        {
            rows.Add(new AgentHealthPropertyRowViewModel("Capture diagnostics log", runtime.CaptureDiagnosticsLogPath));
        }

        if (!string.IsNullOrWhiteSpace(runtime.LiveDatabaseDiagnosticsCacheStatus))
        {
            var timestamp = runtime.LiveDatabaseDiagnosticsCapturedAtUtc.HasValue
                ? $" at {FormatDateTime(runtime.LiveDatabaseDiagnosticsCapturedAtUtc.Value)}"
                : string.Empty;
            rows.Add(new AgentHealthPropertyRowViewModel("SQLite diagnostics cache", $"{runtime.LiveDatabaseDiagnosticsCacheStatus}{timestamp}"));
        }

        AddDatabaseDiagnosticRows(rows, runtime.LiveDatabaseDiagnostics);
        if (!string.IsNullOrWhiteSpace(runtime.WriterLastSqliteError))
        {
            var timestamp = runtime.WriterLastSqliteErrorUtc.HasValue
                ? $" at {FormatDateTime(runtime.WriterLastSqliteErrorUtc.Value)}"
                : string.Empty;
            rows.Add(new AgentHealthPropertyRowViewModel("Writer last SQLite error", $"{runtime.WriterLastSqliteError}{timestamp}"));
        }
        if (!string.IsNullOrWhiteSpace(runtime.LastError))
        {
            rows.Add(new AgentHealthPropertyRowViewModel("Last runtime error", runtime.LastError));
        }

        return catalog.IsPublished(FeatureIds.EventTelemetry)
            ? rows
            : rows.Where(row => !IsAdvancedAgentDiagnostic(row.Field)).ToList();
    }

    private static IReadOnlyList<AgentHealthPropertyRowViewModel> CreateBaseSummaryRows(
        AgentRegistryEntryViewModel agent,
        DateTime checkedAt)
    {
        return
        [
            new("Agent", agent.DisplayName),
            new("Agent ID", agent.AgentId),
            new("Host", agent.HostId),
            new("Viewer", agent.ViewerConnectionDisplay),
            new("Deployment", agent.DeploymentStateDisplay),
            new("Checked", checkedAt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture))
        ];
    }

    private static IReadOnlyList<AgentHealthMetricRowViewModel> CreateMetricRows(
        CaptureHealthReport capture,
        AgentRuntimeSnapshot runtime,
        IFeatureCatalog catalog)
    {
        var totalWritten = capture.TotalEventsReceived + capture.TotalProcessRecordsWritten;
        var totalDropped = capture.TotalEventsDropped + capture.TotalProcessRecordsDropped;
        var totalFailures = capture.EventWriteFailures + capture.ProcessWriteFailures;
        var queuedRecords = capture.Sources.Sum(source => Math.Max(0, source.RecordsQueued));
        var recordsPerSecond = capture.Sources.Sum(source => Math.Max(0, source.RecordsPerSecond));

        var rows = new List<AgentHealthMetricRowViewModel>
        {
            new(
                "All live records",
                FormatCount(totalWritten),
                FormatRate(recordsPerSecond),
                FormatCount(queuedRecords),
                FormatCount(totalDropped),
                FormatCount(totalFailures)),
            new(
                "Event records",
                FormatCount(capture.TotalEventsReceived),
                string.Empty,
                BuildEventBufferQueueText(capture),
                FormatCount(capture.TotalEventsDropped),
                FormatCount(capture.EventWriteFailures)),
            new(
                "Process records",
                FormatCount(capture.TotalProcessRecordsWritten),
                string.Empty,
                $"{capture.PendingProcessWriteBatches:N0}/{capture.MaxPendingProcessWriteBatches:N0} batches",
                FormatCount(capture.TotalProcessRecordsDropped),
                FormatCount(capture.ProcessWriteFailures))
        };

        if (runtime.WriterQueueCapacity > 0)
        {
            var writerFailures = runtime.WriterBackpressureActive
                ? $"{runtime.WriterFailedWorkItemCount:N0} work items; locked {runtime.WriterBusyOrLockedFailureCount:N0}; backpressure"
                : $"{runtime.WriterFailedWorkItemCount:N0} work items; locked {runtime.WriterBusyOrLockedFailureCount:N0}";
            rows.Add(new AgentHealthMetricRowViewModel(
                "SQLite writer",
                FormatCount(runtime.WriterCompletedRowCount),
                string.Empty,
                $"{runtime.WriterPendingWorkItemCount:N0}/{runtime.WriterQueueCapacity:N0} work items",
                FormatCount(runtime.WriterFailedRowCount),
                writerFailures));
        }

        if (capture.LiveBufferMemoryLimitBytes > 0)
        {
            rows.Add(new AgentHealthMetricRowViewModel(
                "Live event buffer",
                FormatCount(capture.LiveBufferCompletedRecords),
                string.Empty,
                BuildEventBufferQueueText(capture),
                "0",
                capture.LiveBufferWriteRetries > 0
                    ? $"{capture.LiveBufferWriteRetries:N0} retries"
                    : FormatCount(capture.EventWriteFailures)));
        }

        var enrichment = runtime.ArtifactEnrichment;
        rows.Add(new AgentHealthMetricRowViewModel(
            "DLL/module enrichment",
            FormatCount(enrichment.ModuleRecordCount),
            string.Empty,
            $"active {enrichment.ModuleActiveCount:N0}; completed {enrichment.ModuleCompletedCount:N0}; attempts {enrichment.ModuleAttemptCount:N0}",
            "0",
            BuildEnrichmentFailureText(enrichment.ModuleFailureCount, enrichment.ModuleLastError)));
        rows.Add(new AgentHealthMetricRowViewModel(
            "Handle enrichment",
            FormatCount(enrichment.HandleRecordCount),
            string.Empty,
            $"active {enrichment.HandleActiveCount:N0}; completed {enrichment.HandleCompletedCount:N0}; attempts {enrichment.HandleAttemptCount:N0}",
            "0",
            BuildEnrichmentFailureText(enrichment.HandleFailureCount, enrichment.HandleLastError)));
        rows.Add(new AgentHealthMetricRowViewModel(
            "PE analysis",
            FormatCount(enrichment.PeRecordCount),
            string.Empty,
            $"active {enrichment.PeActiveCount:N0}; completed {enrichment.PeCompletedCount:N0}; attempts {enrichment.PeAttemptCount:N0}; reused {enrichment.PeReuseCount:N0}; cancelled {enrichment.PeCancellationCount:N0}",
            $"freshness {enrichment.PeFreshnessSkipCount:N0}",
            BuildEnrichmentFailureText(enrichment.PeFailureCount, enrichment.PeLastError)));

        return rows.Where(row => IsMetricPublished(row.Scope, catalog)).ToList();
    }

    private static bool IsMetricPublished(string scope, IFeatureCatalog catalog) => scope switch
    {
        "All live records" or "Process records" or "Live event buffer" =>
            catalog.IsPublished(FeatureIds.AgentsAndCapture),
        "Event records" or "SQLite writer" => catalog.IsPublished(FeatureIds.EventTelemetry),
        "DLL/module enrichment" or "Handle enrichment" => catalog.IsPublished(FeatureIds.ModulesAndHandles),
        "PE analysis" => catalog.IsPublished(FeatureIds.DumpsAndPeAnalysis),
        _ => false
    };

    private static bool IsSourcePublished(string source, IFeatureCatalog catalog) =>
        TryGetSourceFeatureId(source, out var featureId) && catalog.IsPublished(featureId);

    private static bool TryGetSourceFeatureId(string source, out FeatureId featureId)
    {
        featureId = source switch
        {
            "Runtime" => FeatureIds.AgentsAndCapture,
            "ETW" or "Security" or "PowerShell" or "WindowsOther" or "Sysmon" =>
                FeatureIds.EventTelemetry,
            _ => default
        };
        return !featureId.IsEmpty;
    }

    private static bool IsAdvancedAgentDiagnostic(string field) =>
        field is "Operational commands" or
            "Unavailable or unverified commands" or
            "Published evidence source adapters" or
            "Last runtime error" ||
        field.StartsWith("Writer", StringComparison.Ordinal) ||
        field.StartsWith("SQLite", StringComparison.Ordinal) ||
        field.StartsWith("Capture diagnostics", StringComparison.Ordinal);

    private static string FormatOperationalCommandCapabilities(
        IReadOnlyList<AgentCommandCapability> capabilities)
    {
        var operational = capabilities
            .Where(capability =>
                capability.OperationalAvailability == AgentCommandOperationalAvailability.Supported)
            .OrderBy(capability => (int)capability.CommandKind)
            .ToArray();
        if (operational.Length == 0)
        {
            return "<none reported>";
        }

        return $"{operational.Length:N0}: " +
               string.Join(", ", operational.Select(capability => capability.CommandKind));
    }

    private static string FormatNonOperationalCommandCapabilities(
        IReadOnlyList<AgentCommandCapability> capabilities)
    {
        var unavailable = capabilities
            .Where(capability =>
                capability.OperationalAvailability != AgentCommandOperationalAvailability.Supported)
            .OrderBy(capability => (int)capability.CommandKind)
            .ToArray();
        if (unavailable.Length == 0)
        {
            return "<none>";
        }

        return string.Join(
            "; ",
            unavailable.Select(capability =>
            {
                var state = capability.OperationalAvailability switch
                {
                    AgentCommandOperationalAvailability.Unavailable => "unavailable",
                    AgentCommandOperationalAvailability.Reserved => "reserved",
                    _ => "availability not reported"
                };
                var reason = BoundAvailabilityReason(capability.AvailabilityReason);
                return string.IsNullOrWhiteSpace(reason)
                    ? $"{capability.CommandKind} ({state})"
                    : $"{capability.CommandKind} ({state}: {reason})";
            }));
    }

    private static string BoundAvailabilityReason(string? reason)
    {
        var normalized = reason?.Trim() ?? string.Empty;
        return normalized.Length <= AgentCommandCapability.MaxAvailabilityReasonLength
            ? normalized
            : normalized[..(AgentCommandCapability.MaxAvailabilityReasonLength - 1)] + "…";
    }

    private static string FormatEvidenceSourceAdapters(
        IReadOnlyList<ProcInsider.Models.EvidenceSources.EvidenceSourceAdapterDescriptor> adapters)
    {
        if (adapters.Count == 0)
        {
            return "<none reported>";
        }

        return string.Join(
            "; ",
            adapters
                .OrderBy(adapter => adapter.AdapterId, StringComparer.Ordinal)
                .Select(adapter =>
                    $"{adapter.DisplayName} {adapter.AdapterVersion} " +
                    $"({adapter.Category}; {adapter.Capabilities})"));
    }

    private static string BuildEnrichmentFailureText(long failures, string? lastError)
    {
        return failures == 0
            ? "0"
            : string.IsNullOrWhiteSpace(lastError)
                ? failures.ToString("N0", CultureInfo.CurrentCulture)
                : $"{failures:N0}; {lastError}";
    }

    private static void AddDatabaseDiagnosticRows(
        List<AgentHealthPropertyRowViewModel> rows,
        AgentSqliteDatabaseDiagnostics? diagnostics)
    {
        if (diagnostics == null)
        {
            rows.Add(new AgentHealthPropertyRowViewModel("SQLite diagnostics", "<not reported>"));
            return;
        }

        rows.Add(new AgentHealthPropertyRowViewModel("SQLite database role", FirstNonEmpty(diagnostics.Role, "<not reported>")));
        rows.Add(new AgentHealthPropertyRowViewModel("SQLite profile", $"{diagnostics.Profile}; journal {diagnostics.JournalMode}; synchronous {diagnostics.SynchronousMode}; busy timeout {diagnostics.BusyTimeoutMilliseconds:N0} ms; wal_autocheckpoint {diagnostics.WalAutoCheckpointPages:N0}"));
        rows.Add(new AgentHealthPropertyRowViewModel("SQLite cache", $"cache_size {diagnostics.CacheSizePages:N0}; temp_store {diagnostics.TempStore:N0}; mmap {FormatBytes(diagnostics.MmapSizeBytes)}"));
        rows.Add(new AgentHealthPropertyRowViewModel("SQLite files", $"db {FormatBytes(diagnostics.DatabaseSizeBytes)}; wal {FormatBytes(diagnostics.WalSizeBytes)}; page {diagnostics.PageSizeBytes:N0} B x {diagnostics.PageCount:N0}; free pages {diagnostics.FreelistCount:N0}"));
        rows.Add(new AgentHealthPropertyRowViewModel("SQLite indexes", $"live {diagnostics.LiveIndexCount:N0}/{diagnostics.LiveIndexExpectedCount:N0}; analysis {diagnostics.AnalysisIndexCount:N0}/{diagnostics.AnalysisIndexExpectedCount:N0}"));
        rows.Add(new AgentHealthPropertyRowViewModel("SQLite diagnostics log", FirstNonEmpty(diagnostics.DiagnosticsLogPath, "<not reported>")));
        if (diagnostics.LastCheckpoint != null)
        {
            var checkpoint = diagnostics.LastCheckpoint;
            var status = checkpoint.Succeeded
                ? $"busy {checkpoint.BusyFrameCount:N0}; log {checkpoint.LogFrameCount:N0}; checkpointed {checkpoint.CheckpointedFrameCount:N0}; {FormatMilliseconds(checkpoint.DurationMilliseconds)}"
                : $"failed after {FormatMilliseconds(checkpoint.DurationMilliseconds)}: {checkpoint.Error}";
            rows.Add(new AgentHealthPropertyRowViewModel("SQLite checkpoint", status));
        }

        if (!string.IsNullOrWhiteSpace(diagnostics.Error))
        {
            rows.Add(new AgentHealthPropertyRowViewModel("SQLite diagnostics error", diagnostics.Error));
        }
    }

    private static string BuildDetail(
        CaptureHealthReport capture,
        AgentRuntimeSnapshot runtime,
        IFeatureCatalog catalog)
    {
        var parts = new List<string?>
        {
            BuildPublishedCaptureDetail(capture, catalog),
            BuildLiveBufferStatus(capture)
        };
        if (catalog.IsPublished(FeatureIds.EventTelemetry))
        {
            parts.Add(runtime.CaptureDiagnosticsSummary);
            parts.Add(runtime.LiveDatabaseDiagnosticsCacheStatus);
            parts.Add(runtime.LiveDatabaseDiagnostics?.Summary);
            parts.Add(string.IsNullOrWhiteSpace(runtime.WriterLastSqliteError)
                ? string.Empty
                : $"Last writer SQLite error: {runtime.WriterLastSqliteError}");
        }

        return string.Join(Environment.NewLine, parts.Where(part => !string.IsNullOrWhiteSpace(part)));
    }

    private static string BuildPublishedCaptureDetail(
        CaptureHealthReport capture,
        IFeatureCatalog catalog)
    {
        var state = capture.Health switch
        {
            CaptureHealth.Idle => "Live capture is not running.",
            CaptureHealth.Healthy => "Live capture is running.",
            CaptureHealth.Degraded => "Live capture is running with degraded health.",
            CaptureHealth.Error => "Live capture reported an error.",
            _ => "Live capture state is unknown."
        };
        var sources = capture.Sources
            .Where(source => IsSourcePublished(source.Source, catalog))
            .OrderBy(source => source.Source, StringComparer.OrdinalIgnoreCase)
            .Select(FormatSourceHealthSummary)
            .ToArray();
        return sources.Length == 0
            ? state
            : $"{state} Source health: {string.Join("; ", sources)}.";
    }

    private static string FormatSourceHealthSummary(CaptureSourceHealthReport source)
    {
        var diagnostics = new List<string>();
        if (source.DedupKeyCapacity > 0)
        {
            diagnostics.Add(
                $"dedup keys {source.DedupKeyCount:N0}/{source.DedupKeyCapacity:N0}, " +
                $"evicted {source.DedupKeysEvicted:N0}");
        }

        if (source.RecordsSeen > 0 ||
            source.RecordsMatched > 0 ||
            source.UnmatchedRecords > 0 ||
            source.DuplicateRecords > 0 ||
            source.MalformedRecords > 0)
        {
            diagnostics.Add(
                $"input seen {source.RecordsSeen:N0}, matched {source.RecordsMatched:N0}, " +
                $"unmatched {source.UnmatchedRecords:N0}, duplicate {source.DuplicateRecords:N0}, " +
                $"malformed {source.MalformedRecords:N0}");
        }

        return diagnostics.Count == 0
            ? $"{source.Source}={source.Status}"
            : $"{source.Source}={source.Status} ({string.Join("; ", diagnostics)})";
    }

    private static string BuildLiveBufferStatus(CaptureHealthReport capture)
    {
        if (capture.LiveBufferMemoryLimitBytes <= 0)
        {
            return string.Empty;
        }

        var mode = capture.LiveBufferDrainingAfterStop
            ? "Capture stopped; SQLite is still loading accepted live event data"
            : capture.LiveBufferPendingRecords > 0
                ? "SQLite is loading accepted live event data"
                : "No accepted live event backlog";
        var spill = capture.LiveBufferSpilledBatches > 0
            ? $"; spilled {capture.LiveBufferSpilledRecords:N0} event(s) in {capture.LiveBufferSpilledBatches:N0} batch(es)"
            : string.Empty;
        var retries = capture.LiveBufferWriteRetries > 0
            ? $"; retries {capture.LiveBufferWriteRetries:N0}"
            : string.Empty;
        var error = string.IsNullOrWhiteSpace(capture.LiveBufferLastError)
            ? string.Empty
            : $"; last detail {capture.LiveBufferLastError}";
        return $"{mode}: pending {capture.LiveBufferPendingRecords:N0} event(s) in {capture.LiveBufferPendingBatches:N0} batch(es), RAM {FormatBytes(capture.LiveBufferMemoryBytes)}/{FormatBytes(capture.LiveBufferMemoryLimitBytes)}, disk {FormatBytes(capture.LiveBufferDiskBytes)}{spill}{retries}{error}.";
    }

    private static string BuildEventBufferQueueText(CaptureHealthReport capture)
    {
        if (capture.LiveBufferMemoryLimitBytes <= 0)
        {
            return $"{capture.PendingEventWriteBatches:N0} batches";
        }

        return $"{capture.LiveBufferPendingRecords:N0} rec; {capture.LiveBufferPendingBatches:N0} batches; RAM {FormatBytes(capture.LiveBufferMemoryBytes)}; disk {FormatBytes(capture.LiveBufferDiskBytes)}";
    }

    private static string FormatDedup(CaptureSourceHealthReport source)
    {
        return source.DedupKeyCapacity <= 0
            ? string.Empty
            : $"{source.DedupKeyCount:N0}/{source.DedupKeyCapacity:N0}, evicted {source.DedupKeysEvicted:N0}";
    }

    private static string FormatCount(long value)
    {
        return value.ToString("N0", CultureInfo.CurrentCulture);
    }

    private static string FormatRate(double value)
    {
        return value <= 0
            ? "0.0/s"
            : $"{value:N1}/s";
    }

    private static string FormatMilliseconds(double milliseconds)
    {
        return milliseconds < 1
            ? "<1 ms"
            : $"{milliseconds:N1} ms";
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        var value = (double)Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:N1} {units[unit]}";
    }

    private static string FormatDateTime(DateTime utc)
    {
        return utc == default
            ? "<not reported>"
            : utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);
    }

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration < TimeSpan.Zero)
        {
            return "<not reported>";
        }

        return duration.TotalDays >= 1
            ? $"{(int)duration.TotalDays:N0}d {duration.Hours:N0}h {duration.Minutes:N0}m"
            : $"{duration.Hours:N0}h {duration.Minutes:N0}m {duration.Seconds:N0}s";
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
    }
}

public sealed record AgentHealthPropertyRowViewModel(string Field, string Value);

public sealed record AgentHealthMetricRowViewModel(
    string Scope,
    string Written,
    string RecordsPerSecond,
    string Queued,
    string Dropped,
    string Failures);

public sealed record AgentHealthSourceRowViewModel(
    string Source,
    string Status,
    string Written,
    string RecordsPerSecond,
    string Queued,
    string Dropped,
    string Failures,
    string Dedup,
    string Detail);
