using ProcInsider.Models.Agent;

namespace ProcInsider.Models;

/// <summary>
/// Core-owned policy that classifies every agent command by its effect on the active capture and
/// centrally decides whether that effect is permitted by the workspace mode.
/// New command kinds must be added explicitly so they cannot accidentally
/// inherit a permissive archived-capture default.
/// </summary>
public static class CaptureWritePolicy
{
    public const string ArchivedCaptureSealedMessage = "Archived capture is sealed.";

    public static CaptureWriteCategory GetCategory(AgentCommandKind commandKind)
        => commandKind switch
        {
            AgentCommandKind.StartLiveCapture or
            AgentCommandKind.StartConfiguredCapture or
            AgentCommandKind.StartLiveCaptureSource or
            AgentCommandKind.StopLiveCapture or
            AgentCommandKind.StopEtwCapture or
            AgentCommandKind.StopLiveCaptureSource or
            AgentCommandKind.StopConfiguredCapture or
            AgentCommandKind.StartNetworkCapture or
            AgentCommandKind.StopNetworkCapture or
            AgentCommandKind.StartProcessMonitorCapture or
            AgentCommandKind.StopProcessMonitorCapture or
            AgentCommandKind.QueueProcessDump or
            AgentCommandKind.QueueMemoryAcquisition => CaptureWriteCategory.PrimaryAcquisition,

            AgentCommandKind.QueueBackfill or
            AgentCommandKind.QueueImport or
            AgentCommandKind.QueueArtifactImport or
            AgentCommandKind.QueueMemoryImageImport or
            AgentCommandKind.QueueProcessMonitorImport => CaptureWriteCategory.PrimaryImport,

            AgentCommandKind.QueueEnrichment or
            AgentCommandKind.QueueZeekAnalysis or
            AgentCommandKind.QueueVolatilityAnalysis => CaptureWriteCategory.DerivedEnrichment,

            AgentCommandKind.QueueSqliteBenchmark => CaptureWriteCategory.AnalysisMaintenance,

            AgentCommandKind.GetHostMonitoringConfiguration or
            AgentCommandKind.SaveHostMonitoringConfiguration or
            AgentCommandKind.CheckHostMonitoringConfiguration or
            AgentCommandKind.DeployHostMonitoringConfiguration or
            AgentCommandKind.ReverseHostMonitoringDeployment or
            AgentCommandKind.GetCaptureConfiguration or
            AgentCommandKind.SaveCaptureConfiguration or
            AgentCommandKind.CheckCaptureConfiguration => CaptureWriteCategory.Configuration,

            AgentCommandKind.ShutdownAgent or
            AgentCommandKind.CancelJob or
            AgentCommandKind.PauseJob or
            AgentCommandKind.ResumeJob => CaptureWriteCategory.Control,

            _ => throw new ArgumentOutOfRangeException(
                nameof(commandKind),
                commandKind,
                "Every agent command kind must declare a capture write category.")
        };

    public static bool IsAllowed(CaptureWorkspaceMode mode, AgentCommandKind commandKind)
        => IsAllowed(mode, GetCategory(commandKind));

    public static bool IsAllowed(CaptureWorkspaceMode mode, CaptureWriteCategory category)
        => mode switch
        {
            CaptureWorkspaceMode.LiveCapture => true,
            CaptureWorkspaceMode.ArchivedCapture => category is not
                CaptureWriteCategory.PrimaryAcquisition and not
                CaptureWriteCategory.PrimaryImport,
            _ => false
        };

    public static void EnsureAllowed(CaptureWorkspaceMode mode, AgentCommandKind commandKind)
    {
        var category = GetCategory(commandKind);
        if (IsAllowed(mode, category))
        {
            return;
        }

        throw new InvalidOperationException(mode == CaptureWorkspaceMode.ArchivedCapture
            ? $"{ArchivedCaptureSealedMessage} '{commandKind}' requests {category}."
            : $"No active capture workspace can accept '{commandKind}'.");
    }
}
