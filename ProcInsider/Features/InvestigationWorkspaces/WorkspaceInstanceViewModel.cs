using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal abstract class WorkspaceInstanceViewModel : ViewModelBase, IDisposable
{
    protected WorkspaceInstanceViewModel(WorkspaceTypeMetadata type, int ordinal)
    {
        Type = type;
        Id = WorkspaceInstanceId.Create();
        CreationOrder = ordinal;
    }
    public WorkspaceInstanceId Id { get; }
    public WorkspaceTypeMetadata Type { get; }
    public string Name => NavigationDescription == "All Processes" ? $"{Type.Name} {CreationOrder}" :
        $"{Type.Name} {CreationOrder}: {(NavigationDescription.Length > 28 ? NavigationDescription[..28] + "…" : NavigationDescription)}";
    public int CreationOrder { get; }
    private bool _isPinned;
    public bool IsPinned { get => _isPinned; set => SetProperty(ref _isPinned, value); }
    private string _navigationDescription = "All Processes";
    public string NavigationDescription
    {
        get => _navigationDescription;
        internal set
        {
            if (SetProperty(ref _navigationDescription, value)) { OnPropertyChanged(nameof(Name)); OnPropertyChanged(nameof(ToolTip)); }
        }
    }
    private WorkspaceContext? _context;
    public WorkspaceContext? Context
    {
        get => _context;
        internal set { if (SetProperty(ref _context, value)) OnPropertyChanged(nameof(ToolTip)); }
    }
    public string ToolTip => $"{Name} · {NavigationDescription} · {Type.Description} · {Context?.SessionId ?? "No capture"} · Capture generation {Context?.CaptureGeneration ?? 0} · {Id.Value:D}";
    public WorkspacePanelLayout Layout { get; set; } = new();
    public long ActivationOrder { get; internal set; }
    public bool IsDisposed { get; protected set; }
    public abstract void Dispose();
}
