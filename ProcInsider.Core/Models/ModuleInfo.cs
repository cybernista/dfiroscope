using System;

namespace ProcInsider.Models;

/// <summary>
/// Represents information about a loaded DLL/module in a process.
/// </summary>
public class ModuleInfo
{
    public string ProcessEntityId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public string ModuleName { get; set; } = "<unknown>";
    public string FullPath { get; set; } = "<not available>";
    public string BaseAddress { get; set; } = "<not available>";
    public long ModuleMemorySize { get; set; }
    public string FileVersion { get; set; } = "<not available>";
    public string CompanyName { get; set; } = "<not available>";
    public string Description { get; set; } = "<not available>";
    public string Sha256Hash { get; set; } = "<not available>";
    public DateTime? FirstSeenUtc { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public DateTime? UnloadedUtc { get; set; }
    public ModuleObservationState State { get; set; } = ModuleObservationState.Loaded;
    public bool IsStale => State == ModuleObservationState.Unloaded || State == ModuleObservationState.NotFound;
    public string StatusDisplay => State switch
    {
        ModuleObservationState.Unloaded when UnloadedUtc.HasValue => $"Unloaded {UnloadedUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}",
        _ => State.ToString()
    };

    /// <summary>
    /// Formats module memory size for display.
    /// </summary>
    public string ModuleMemorySizeFormatted
    {
        get
        {
            if (ModuleMemorySize < 1024)
                return $"{ModuleMemorySize} B";
            if (ModuleMemorySize < 1024 * 1024)
                return $"{ModuleMemorySize / 1024.0:F1} KB";
            return $"{ModuleMemorySize / (1024.0 * 1024.0):F1} MB";
        }
    }
}
