using ProcInsider.Models;
using System;
using System.Collections.Generic;

namespace ProcInsider.ViewModels;

/// <summary>
/// View model for a single module row in the modules DataGrid.
/// </summary>
public class ModuleRowViewModel : ViewModelBase
{
    private readonly ModuleInfo _moduleInfo;

    public ModuleRowViewModel(ModuleInfo moduleInfo)
    {
        _moduleInfo = moduleInfo;
    }

    public string ModuleName => _moduleInfo.ModuleName;
    public string ProcessEntityId => _moduleInfo.ProcessEntityId;
    public string SourceRunId => _moduleInfo.SourceRunId;
    public string IngestionJobId => _moduleInfo.IngestionJobId;
    public string FullPath => _moduleInfo.FullPath;
    public string BaseAddress => _moduleInfo.BaseAddress;
    public string ModuleMemorySize => _moduleInfo.ModuleMemorySizeFormatted;
    public long ModuleMemorySizeBytes => _moduleInfo.ModuleMemorySize;
    public string FileVersion => _moduleInfo.FileVersion;
    public string CompanyName => _moduleInfo.CompanyName;
    public string Description => _moduleInfo.Description;
    public string Sha256Hash => _moduleInfo.Sha256Hash;
    public string Status => _moduleInfo.StatusDisplay;
    public bool IsStale => _moduleInfo.IsStale;
    public DateTime? LastSeenUtc => _moduleInfo.LastSeenUtc;
    public string LastSeen => LastSeenUtc.HasValue
        ? LastSeenUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        : string.Empty;

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.Module,
            TargetKind = "Module",
            TargetTable = "Modules",
            ArtifactId = $"{BaseAddress}|{FullPath}",
            DisplayPath = FullPath,
            Header = ModuleName,
            Subtitle = $"Module {Status} | {ModuleMemorySize}",
            EmptyStateMessage = "Select a module to inspect it here.",
            RawText = FullPath,
            Properties = new List<PropertyItemViewModel>
            {
                new("Identity", "Module Name", ModuleName),
                new("Identity", "Process Entity", ProcessEntityId),
                new("Provenance", "Source Run", SourceRunId),
                new("Provenance", "Ingestion Job", IngestionJobId),
                new("Identity", "Base Address", BaseAddress),
                new("Lifecycle", "Status", Status),
                new("Lifecycle", "Last Seen", LastSeen),
                new("File", "Full Path", FullPath),
                new("File", "File Version", FileVersion),
                new("File", "Company", CompanyName),
                new("File", "Description", Description),
                new("Runtime", "Memory Size", ModuleMemorySize),
                new("File", "SHA256", Sha256Hash)
            }
        };
    }
}
