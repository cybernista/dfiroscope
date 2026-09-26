using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class MemoryDumpsViewModel : ViewModelBase
{
    private const int MaxVisibleDumps = 1000;

    private readonly TelemetryProjectionService _projectionService;
    private readonly InspectorPaneViewModel _inspectorPaneViewModel;
    private string _selectedProcessEntityId = string.Empty;

    [ObservableProperty]
    private ObservableCollection<MemoryDumpRowViewModel> memoryDumps = new();

    [ObservableProperty]
    private ICollectionView? memoryDumpsView;

    [ObservableProperty]
    private MemoryDumpRowViewModel? selectedMemoryDump;

    [ObservableProperty]
    private string selectedProcessKey = string.Empty;

    [ObservableProperty]
    private int selectedProcessId;

    [ObservableProperty]
    private string selectedProcessName = string.Empty;

    [ObservableProperty]
    private string statusMessage = "Select a process to view memory dumps.";

    public MemoryDumpsViewModel(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel)
    {
        _projectionService = projectionService;
        _inspectorPaneViewModel = inspectorPaneViewModel;
        MemoryDumpsView = CollectionViewSource.GetDefaultView(MemoryDumps);
    }

    [RelayCommand]
    public void LoadMemoryDumpsForProcess((string ProcessKey, int ProcessId, string ProcessName) processInfo)
    {
        SelectedProcessKey = processInfo.ProcessKey;
        SelectedProcessId = processInfo.ProcessId;
        SelectedProcessName = processInfo.ProcessName;
        RebuildVisibleDumps();
    }

    public void SetSelectedProcessEntityId(string processEntityId)
        => _selectedProcessEntityId = processEntityId ?? string.Empty;

    [RelayCommand]
    public void RefreshMemoryDumps()
    {
        RebuildVisibleDumps();
    }

    public void Clear()
    {
        SelectedProcessKey = string.Empty;
        SelectedProcessId = 0;
        SelectedProcessName = string.Empty;
        _selectedProcessEntityId = string.Empty;
        SelectedMemoryDump = null;
        MemoryDumps.Clear();
        StatusMessage = "Select a process to view memory dumps.";
    }

    private void RebuildVisibleDumps()
    {
        var previouslySelectedDumpId = SelectedMemoryDump?.DumpId;
        SelectedMemoryDump = null;
        MemoryDumps.Clear();

        if (string.IsNullOrWhiteSpace(SelectedProcessKey))
        {
            StatusMessage = "Select a process to view memory dumps.";
            return;
        }

        var dumps = _projectionService.GetMemoryDumpsForProcess(
            SelectedProcessKey,
            MaxVisibleDumps,
            _selectedProcessEntityId);
        foreach (var dump in dumps)
        {
            MemoryDumps.Add(new MemoryDumpRowViewModel(dump));
        }

        if (!string.IsNullOrWhiteSpace(previouslySelectedDumpId))
        {
            SelectedMemoryDump = MemoryDumps.FirstOrDefault(dump => dump.DumpId == previouslySelectedDumpId);
        }

        StatusMessage = MemoryDumps.Count == 0
            ? $"No memory dump metadata for {SelectedProcessName} (PID: {SelectedProcessId})."
            : $"Showing {MemoryDumps.Count} memory dump record(s) for {SelectedProcessName} (PID: {SelectedProcessId}).";
    }

    partial void OnSelectedMemoryDumpChanged(MemoryDumpRowViewModel? value)
    {
        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a memory dump artifact to inspect it here.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }
}
