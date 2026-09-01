using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class PeAnalysisViewModel : ViewModelBase
{
    private const int MaxVisibleAnalyses = 1000;

    private readonly TelemetryProjectionService _projectionService;
    private readonly InspectorPaneViewModel _inspectorPaneViewModel;
    private string _selectedProcessEntityId = string.Empty;

    [ObservableProperty]
    private ObservableCollection<PeAnalysisRowViewModel> peAnalyses = new();

    [ObservableProperty]
    private ObservableCollection<PeAnalysisRowViewModel> diskPeAnalyses = new();

    [ObservableProperty]
    private ObservableCollection<PeAnalysisRowViewModel> memoryDumpPeAnalyses = new();

    [ObservableProperty]
    private ICollectionView? diskPeAnalysesView;

    [ObservableProperty]
    private ICollectionView? memoryDumpPeAnalysesView;

    [ObservableProperty]
    private PeAnalysisRowViewModel? selectedPeAnalysis;

    [ObservableProperty]
    private PeAnalysisRowViewModel? selectedDiskPeAnalysis;

    [ObservableProperty]
    private PeAnalysisRowViewModel? selectedMemoryDumpPeAnalysis;

    [ObservableProperty]
    private int selectedPeSourceTabIndex;

    [ObservableProperty]
    private string stringFilterText = string.Empty;

    [ObservableProperty]
    private string selectedProcessKey = string.Empty;

    [ObservableProperty]
    private int selectedProcessId;

    [ObservableProperty]
    private string selectedProcessName = string.Empty;

    [ObservableProperty]
    private string statusMessage = "Select a process to view PE analysis.";

    public PeAnalysisViewModel(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel)
    {
        _projectionService = projectionService;
        _inspectorPaneViewModel = inspectorPaneViewModel;
        DiskPeAnalysesView = CollectionViewSource.GetDefaultView(DiskPeAnalyses);
        MemoryDumpPeAnalysesView = CollectionViewSource.GetDefaultView(MemoryDumpPeAnalyses);
        DiskPeAnalysesView.Filter = FilterPeAnalysisRow;
        MemoryDumpPeAnalysesView.Filter = FilterPeAnalysisRow;
    }

    [RelayCommand]
    public void LoadPeAnalysesForProcess((string ProcessKey, int ProcessId, string ProcessName) processInfo)
    {
        SelectedProcessKey = processInfo.ProcessKey;
        SelectedProcessId = processInfo.ProcessId;
        SelectedProcessName = processInfo.ProcessName;
        RebuildVisibleAnalyses();
    }

    public void SetSelectedProcessEntityId(string processEntityId)
        => _selectedProcessEntityId = processEntityId ?? string.Empty;

    [RelayCommand]
    public void RefreshPeAnalyses()
    {
        RebuildVisibleAnalyses();
    }

    public void Clear()
    {
        SelectedProcessKey = string.Empty;
        SelectedProcessId = 0;
        SelectedProcessName = string.Empty;
        _selectedProcessEntityId = string.Empty;
        SelectedPeAnalysis = null;
        SelectedDiskPeAnalysis = null;
        SelectedMemoryDumpPeAnalysis = null;
        SelectedPeSourceTabIndex = 0;
        StringFilterText = string.Empty;
        PeAnalyses.Clear();
        DiskPeAnalyses.Clear();
        MemoryDumpPeAnalyses.Clear();
        StatusMessage = "Select a process to view PE analysis.";
    }

    private void RebuildVisibleAnalyses()
    {
        var previouslySelectedAnalysisId = SelectedPeAnalysis?.AnalysisId;
        SelectedPeAnalysis = null;
        SelectedDiskPeAnalysis = null;
        SelectedMemoryDumpPeAnalysis = null;
        PeAnalyses.Clear();
        DiskPeAnalyses.Clear();
        MemoryDumpPeAnalyses.Clear();

        if (string.IsNullOrWhiteSpace(SelectedProcessKey))
        {
            StatusMessage = "Select a process to view PE analysis.";
            return;
        }

        var analyses = _projectionService.GetPeAnalysesForProcess(
            SelectedProcessKey,
            MaxVisibleAnalyses,
            _selectedProcessEntityId);
        foreach (var analysis in analyses)
        {
            var row = new PeAnalysisRowViewModel(analysis);
            PeAnalyses.Add(row);
            if (row.IsDiskSource)
            {
                DiskPeAnalyses.Add(row);
            }
            else
            {
                MemoryDumpPeAnalyses.Add(row);
            }
        }

        if (!string.IsNullOrWhiteSpace(previouslySelectedAnalysisId))
        {
            SelectedPeAnalysis = PeAnalyses.FirstOrDefault(analysis => analysis.AnalysisId == previouslySelectedAnalysisId);
            if (SelectedPeAnalysis?.IsDiskSource == true)
            {
                SelectedDiskPeAnalysis = SelectedPeAnalysis;
                SelectedPeSourceTabIndex = 0;
            }
            else if (SelectedPeAnalysis != null)
            {
                SelectedMemoryDumpPeAnalysis = SelectedPeAnalysis;
                SelectedPeSourceTabIndex = 1;
            }
        }

        StatusMessage = PeAnalyses.Count == 0
            ? $"No PE analysis records for {SelectedProcessName} (PID: {SelectedProcessId}). Analyze the process image or select an existing dump to parse."
            : $"Showing {DiskPeAnalyses.Count} disk PE and {MemoryDumpPeAnalyses.Count} memory/dump PE record(s) for {SelectedProcessName} (PID: {SelectedProcessId}).";

        RefreshFilteredViews();
    }

    partial void OnSelectedPeAnalysisChanged(PeAnalysisRowViewModel? value)
    {
        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a PE analysis record to inspect it here.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }

    partial void OnSelectedDiskPeAnalysisChanged(PeAnalysisRowViewModel? value)
    {
        if (value == null)
        {
            return;
        }

        SelectedMemoryDumpPeAnalysis = null;
        SelectedPeAnalysis = value;
    }

    partial void OnSelectedMemoryDumpPeAnalysisChanged(PeAnalysisRowViewModel? value)
    {
        if (value == null)
        {
            return;
        }

        SelectedDiskPeAnalysis = null;
        SelectedPeAnalysis = value;
    }

    partial void OnStringFilterTextChanged(string value)
    {
        RefreshFilteredViews();
    }

    private bool FilterPeAnalysisRow(object item)
    {
        return item is PeAnalysisRowViewModel row && row.MatchesStringFilter(StringFilterText);
    }

    private void RefreshFilteredViews()
    {
        DiskPeAnalysesView?.Refresh();
        MemoryDumpPeAnalysesView?.Refresh();
    }
}
