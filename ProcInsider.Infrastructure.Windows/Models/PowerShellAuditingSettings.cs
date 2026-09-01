namespace ProcInsider.Models;

/// <summary>
/// Represents the current PowerShell auditing policy state exposed in the application menu.
/// </summary>
public class PowerShellAuditingSettings
{
    public bool IsAvailable { get; set; }
    public string StatusDetail { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
    public bool ScriptBlockLoggingEnabled { get; set; }
    public bool ModuleLoggingEnabled { get; set; }
    public bool TranscriptionEnabled { get; set; }
    public string TranscriptPath { get; set; } = @"C:\PS_transcripts";
}
