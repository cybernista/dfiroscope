using ProcInsider.Models.Agent;
using ProcInsider.Services.AgentIpc;

namespace ProcInsider.ViewModels;

public sealed class AuditApplyResultViewModel
{
    public AuditApplyResultViewModel(WindowsSettingsApplyResult result)
    {
        Summary = result.Summary;
        BackupPath = result.BackupFolder;
        var deployment = result.Applied?.Response?.MonitoringDeployment;
        Actions = (deployment?.AreaResults ?? []).OrderBy(area => Priority(area.Status))
            .Select(area => new AuditApplyActionRow(AreaName(area.Area), StatusName(area.Status),
                Color(area.Status), FormatMessage(area.Message), FormatTechnical(area.TechnicalDetail))).ToArray();
        var diagnostics = new List<string>();
        if (!result.Saved.Succeeded) diagnostics.Add(result.Saved.Diagnostic);
        if (result.Applied is { Succeeded: false }) diagnostics.Add(result.Applied.Diagnostic);
        if (!string.IsNullOrWhiteSpace(deployment?.LastError)) diagnostics.Add(deployment.LastError);
        diagnostics.AddRange(deployment?.Warnings ?? []);
        if (result.Applied == null) diagnostics.Insert(0, "No Apply command was sent. Resolve the draft save problem before applying settings.");
        else if (!result.HasCompleteResults) diagnostics.Insert(0, "A complete result was not received. Do not assume the operation failed or repeat changes automatically.");
        Attention = string.Join(Environment.NewLine, diagnostics.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct());
    }

    public string Summary { get; }
    public string BackupPath { get; }
    public string Attention { get; }
    public bool HasAttention => Attention.Length > 0;
    public IReadOnlyList<AuditApplyActionRow> Actions { get; }
    private static int Priority(AgentConfigurationOperationStatus status) => status switch
    { AgentConfigurationOperationStatus.Failed => 0, AgentConfigurationOperationStatus.Unknown => 0,
        AgentConfigurationOperationStatus.Warning => 1, AgentConfigurationOperationStatus.Skipped => 2, _ => 3 };
    private static string Color(AgentConfigurationOperationStatus status) => status switch
    { AgentConfigurationOperationStatus.Success => "#226622", AgentConfigurationOperationStatus.Warning or
        AgentConfigurationOperationStatus.Skipped => "#855500", _ => "#A02020" };
    private static string StatusName(AgentConfigurationOperationStatus status) => status switch
    { AgentConfigurationOperationStatus.Success => "Succeeded", AgentConfigurationOperationStatus.Warning => "Warning",
        AgentConfigurationOperationStatus.Skipped => "Skipped", AgentConfigurationOperationStatus.Failed => "Failed", _ => "Unconfirmed" };
    private static string AreaName(AgentConfigurationAreaKind area) => area switch
    { AgentConfigurationAreaKind.WindowsSecurityAuditPolicy => "System audit policy",
        AgentConfigurationAreaKind.ProcessCommandLineAuditing => "Process command-line logging",
        AgentConfigurationAreaKind.WindowsSecurityEventLog => "Security event log", _ => area.ToString() };
    private static string FormatMessage(string? message) => string.Join(Environment.NewLine,
        (message ?? string.Empty).Replace("UserFolderAuditing", "User-folder auditing").Replace("RegistryAuditing", "Registry auditing")
            .Split(". ", StringSplitOptions.RemoveEmptyEntries)
            .OrderBy(part => part.Contains("skipped:", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .Select(part => part.Trim().TrimEnd('.') + "."));
    private static string FormatTechnical(string? value) => (value ?? string.Empty).Replace("; ", Environment.NewLine);
}

public sealed record AuditApplyActionRow(string Action, string Status, string StatusColor, string Message, string TechnicalDetails)
{
    public bool HasTechnicalDetails => !string.IsNullOrWhiteSpace(TechnicalDetails);
}
