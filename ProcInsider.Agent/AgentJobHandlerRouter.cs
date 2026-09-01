using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services.EvidenceSources;
using ProcInsider.Services.Features;

namespace ProcInsider.Agent;

internal sealed class AgentJobHandlerRouter : IAgentJobHandler
{
    private readonly IAgentJobHandler _liveCaptureHandler;
    private readonly IAgentJobHandler _moduleEnrichmentHandler;
    private readonly IAgentJobHandler _handleEnrichmentHandler;
    private readonly IAgentJobHandler _importHandler;
    private readonly IAgentJobHandler _processDumpHandler;
    private readonly IAgentJobHandler _networkCaptureHandler;
    private readonly IAgentJobHandler _zeekAnalysisHandler;
    private readonly IAgentJobHandler _artifactImportHandler;
    private readonly IAgentJobHandler _memoryImageImportHandler;
    private readonly IAgentJobHandler _memoryAcquisitionHandler;
    private readonly IAgentJobHandler _volatilityAnalysisHandler;
    private readonly IAgentJobHandler _processMonitorCaptureHandler;
    private readonly IAgentJobHandler _processMonitorImportHandler;
    private readonly IAgentJobHandler _sqliteBenchmarkHandler;
    private readonly EvidenceSourceAdapterRegistry _evidenceSourceAdapters;
    private readonly IFeatureCatalog _featureCatalog;
    private readonly bool _captureSealed;
    private readonly IAgentJobHandler _fallbackHandler;

    public AgentJobHandlerRouter(
        IAgentJobHandler liveCaptureHandler,
        IAgentJobHandler moduleEnrichmentHandler,
        IAgentJobHandler handleEnrichmentHandler,
        IAgentJobHandler importHandler,
        IAgentJobHandler processDumpHandler,
        IAgentJobHandler networkCaptureHandler,
        IAgentJobHandler zeekAnalysisHandler,
        IAgentJobHandler artifactImportHandler,
        IAgentJobHandler memoryImageImportHandler,
        IAgentJobHandler memoryAcquisitionHandler,
        IAgentJobHandler volatilityAnalysisHandler,
        IAgentJobHandler processMonitorCaptureHandler,
        IAgentJobHandler processMonitorImportHandler,
        IAgentJobHandler sqliteBenchmarkHandler,
        EvidenceSourceAdapterRegistry evidenceSourceAdapters,
        IFeatureCatalog featureCatalog,
        bool captureSealed,
        IAgentJobHandler fallbackHandler)
    {
        _liveCaptureHandler = liveCaptureHandler;
        _moduleEnrichmentHandler = moduleEnrichmentHandler;
        _handleEnrichmentHandler = handleEnrichmentHandler;
        _importHandler = importHandler;
        _processDumpHandler = processDumpHandler;
        _networkCaptureHandler = networkCaptureHandler;
        _zeekAnalysisHandler = zeekAnalysisHandler;
        _artifactImportHandler = artifactImportHandler;
        _memoryImageImportHandler = memoryImageImportHandler;
        _memoryAcquisitionHandler = memoryAcquisitionHandler;
        _volatilityAnalysisHandler = volatilityAnalysisHandler;
        _processMonitorCaptureHandler = processMonitorCaptureHandler;
        _processMonitorImportHandler = processMonitorImportHandler;
        _sqliteBenchmarkHandler = sqliteBenchmarkHandler;
        _evidenceSourceAdapters = evidenceSourceAdapters ?? throw new ArgumentNullException(nameof(evidenceSourceAdapters));
        _featureCatalog = featureCatalog ?? throw new ArgumentNullException(nameof(featureCatalog));
        _captureSealed = captureSealed;
        _fallbackHandler = fallbackHandler;
    }

    public Task ExecuteAsync(AgentJobContext context)
    {
        EnsureMigratedAdapterIsRegistered(context.Request.JobKind);
        JsonElement? parameters = context.Request.Parameters == null
            ? null
            : JsonSerializer.SerializeToElement(
                context.Request.Parameters,
                context.Request.Parameters.GetType(),
                AgentJson.JsonOptions);
        var featureDecision = AgentCommandFeaturePolicy.EvaluateJob(
            _featureCatalog,
            context.Request.JobKind,
            parameters);
        if (!featureDecision.Allowed)
        {
            throw new InvalidOperationException(
                $"{featureDecision.ErrorCode}: {featureDecision.ErrorMessage}");
        }

        if (_captureSealed && GetWriteCategory(context.Request.JobKind) is
            CaptureWriteCategory.PrimaryAcquisition or CaptureWriteCategory.PrimaryImport)
        {
            throw new InvalidOperationException(
                $"{CaptureWritePolicy.ArchivedCaptureSealedMessage} Job '{context.Request.JobKind}' was rejected at the handler boundary.");
        }

        return context.Request.JobKind switch
        {
            ProcInsider.Models.Agent.JobKind.LiveCapture => _liveCaptureHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.ModuleEnrichment => _moduleEnrichmentHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.HandleEnrichment => _handleEnrichmentHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.PeAnalysis => _moduleEnrichmentHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.Import => _importHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.ProcessDump => _processDumpHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.NetworkCapture => _networkCaptureHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.ZeekAnalysis => _zeekAnalysisHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.ArtifactImport => _artifactImportHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.MemoryImageImport => _memoryImageImportHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.MemoryAcquisition => _memoryAcquisitionHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.VolatilityAnalysis => _volatilityAnalysisHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.ProcessMonitorCapture => _processMonitorCaptureHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.ProcessMonitorImport => _processMonitorImportHandler.ExecuteAsync(context),
            ProcInsider.Models.Agent.JobKind.SqliteBenchmark => _sqliteBenchmarkHandler.ExecuteAsync(context),
            _ => _fallbackHandler.ExecuteAsync(context)
        };
    }

    private void EnsureMigratedAdapterIsRegistered(JobKind jobKind)
    {
        switch (jobKind)
        {
            case JobKind.LiveCapture:
                _evidenceSourceAdapters.Resolve(
                    RuntimeProcessSnapshotEvidenceSourceAdapter.Id,
                    RuntimeProcessSnapshotEvidenceSourceAdapter.Version);
                break;
            case JobKind.ArtifactImport:
                _evidenceSourceAdapters.Resolve(
                    FilesystemArtifactEvidenceSourceAdapter.Id,
                    FilesystemArtifactEvidenceSourceAdapter.Version);
                break;
            case JobKind.NetworkCapture:
                _evidenceSourceAdapters.Resolve(
                    NetworkCaptureEvidenceSourceAdapter.Id,
                    NetworkCaptureEvidenceSourceAdapter.Version);
                break;
            case JobKind.ZeekAnalysis:
                _evidenceSourceAdapters.Resolve(
                    ZeekNetworkEvidenceSourceAdapter.Id,
                    ZeekNetworkEvidenceSourceAdapter.Version);
                break;
            case JobKind.MemoryImageImport:
            case JobKind.MemoryAcquisition:
                _evidenceSourceAdapters.Resolve(
                    MemoryImageEvidenceSourceAdapter.Id,
                    MemoryImageEvidenceSourceAdapter.Version);
                break;
            case JobKind.ProcessMonitorCapture:
            case JobKind.ProcessMonitorImport:
                _evidenceSourceAdapters.Resolve(
                    ProcessMonitorEvidenceSourceAdapter.Id,
                    ProcessMonitorEvidenceSourceAdapter.Version);
                break;
            case JobKind.VolatilityAnalysis:
                _evidenceSourceAdapters.Resolve(
                    VolatilityProcessEvidenceSourceAdapter.Id,
                    VolatilityProcessEvidenceSourceAdapter.Version);
                break;
            case JobKind.Import:
                _evidenceSourceAdapters.Resolve(
                    LegacyProcessSnapshotEvidenceSourceAdapter.Id,
                    LegacyProcessSnapshotEvidenceSourceAdapter.Version);
                break;
        }
    }

    private static CaptureWriteCategory GetWriteCategory(JobKind jobKind)
        => jobKind switch
        {
            JobKind.LiveCapture or
            JobKind.NetworkCapture or
            JobKind.ProcessDump or
            JobKind.ProcessMonitorCapture or
            JobKind.MemoryAcquisition => CaptureWriteCategory.PrimaryAcquisition,
            JobKind.Import or
            JobKind.ArtifactImport or
            JobKind.MemoryImageImport or
            JobKind.ProcessMonitorImport => CaptureWriteCategory.PrimaryImport,
            JobKind.ModuleEnrichment or
            JobKind.HandleEnrichment or
            JobKind.PeAnalysis or
            JobKind.ZeekAnalysis or
            JobKind.VolatilityAnalysis => CaptureWriteCategory.DerivedEnrichment,
            JobKind.SqliteBenchmark => CaptureWriteCategory.AnalysisMaintenance,
            _ => throw new ArgumentOutOfRangeException(
                nameof(jobKind),
                jobKind,
                "Every agent job kind must declare a capture write category.")
        };
}
