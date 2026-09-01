using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

/// <summary>
/// View model for the loaded modules tab.
/// Displays DLLs and modules loaded by a process.
/// </summary>
public partial class ModulesViewModel : ViewModelBase
{
    private const int MaxVisibleModules = 10000;

    private readonly InspectorPaneViewModel _inspectorPaneViewModel;
    private readonly TelemetryProjectionService _projectionService;
    private CancellationTokenSource? _loadCts;
    
    [ObservableProperty]
    private ObservableCollection<ModuleRowViewModel> modules = new();
    
    [ObservableProperty]
    private string statusMessage = "Select a process to view loaded modules";
    
    [ObservableProperty]
    private bool isLoading;
    
    [ObservableProperty]
    private bool hasError;
    
    [ObservableProperty]
    private int selectedProcessId;
    
    [ObservableProperty]
    private string selectedProcessName = string.Empty;

    [ObservableProperty]
    private ProcessInfo? selectedProcess;
    
    [ObservableProperty]
    private ICollectionView? modulesView;

    [ObservableProperty]
    private ModuleRowViewModel? selectedModule;

    public event EventHandler? CaptureStatusChanged;
    
    // Sorting state
    private string _currentSortColumn = string.Empty;
    private ListSortDirection _currentSortDirection = ListSortDirection.Ascending;
    
    public ModulesViewModel(
        InspectorPaneViewModel inspectorPaneViewModel,
        TelemetryProjectionService projectionService)
    {
        _inspectorPaneViewModel = inspectorPaneViewModel;
        _projectionService = projectionService;
        
        // Set up collection view for sorting
        ModulesView = CollectionViewSource.GetDefaultView(Modules);
    }
    
    /// <summary>
    /// Loads modules for the specified process.
    /// </summary>
    [RelayCommand]
    public async Task LoadModulesForProcessAsync(ProcessInfo? process)
    {
        // Cancel any pending load
        _loadCts?.Cancel();
        _loadCts = new CancellationTokenSource();

        SelectedProcess = process;
        if (process == null)
        {
            Clear();
            return;
        }

        var processId = process.ProcessId;
        var processName = process.ProcessName;
        SelectedProcessId = processId;
        SelectedProcessName = processName;
        IsLoading = true;
        HasError = false;
        SelectedModule = null;
        Modules.Clear();

        LoadStagedModules(process);
        await Task.CompletedTask;
    }

    /// <summary>
    /// Clears the module list.
    /// </summary>
    public void Clear()
    {
        _loadCts?.Cancel();
        Modules.Clear();
        SelectedModule = null;
        SelectedProcess = null;
        SelectedProcessId = 0;
        SelectedProcessName = string.Empty;
        StatusMessage = "Select a process to view loaded modules";
        HasError = false;
    }

    private void PopulateModules(IEnumerable<ModuleInfo> modules)
    {
        Modules.Clear();
        foreach (var module in modules)
        {
            Modules.Add(new ModuleRowViewModel(module));
        }

        if (!string.IsNullOrEmpty(_currentSortColumn))
        {
            ApplySorting(_currentSortColumn, _currentSortDirection);
        }
    }

    private void LoadStagedModules(ProcessInfo process)
    {
        var stagedModules = GetStagedModules(process);
        if (stagedModules.Count > 0)
        {
            PopulateModules(stagedModules);
            if (process.ModuleCaptureStatus == ArtifactCaptureStatus.Pending)
            {
                UpdateModuleCaptureStatus(
                    process,
                    ArtifactCaptureStatus.Captured,
                    stagedModules.Count,
                    process.ModuleLastCaptured,
                    string.Empty);
            }
            StatusMessage = process.Status == ProcessStatus.Exited
                ? $"Showing {stagedModules.Count} staged modules for exited process {process.ProcessName}"
                : $"Showing {stagedModules.Count} staged modules for {process.ProcessName}";
            HasError = false;
            IsLoading = false;
            return;
        }

        Modules.Clear();
        StatusMessage = process.Status == ProcessStatus.Exited
            ? $"Process {process.ProcessName} (PID: {process.ProcessId}) has exited and no module snapshot was captured."
            : $"No snapshot modules for {process.ProcessName} (PID: {process.ProcessId}). Queue agent enrichment, then use Refresh from db.";
        HasError = process.Status == ProcessStatus.Exited;
        IsLoading = false;
    }

    private void UpdateModuleCaptureStatus(
        ProcessInfo process,
        ArtifactCaptureStatus status,
        int count,
        DateTime? lastCaptured,
        string error)
    {
        if (status == ArtifactCaptureStatus.NotFound && process.Status != ProcessStatus.Exited)
        {
            process.Status = ProcessStatus.NotFound;
        }

        process.ModuleCaptureStatus = status;
        process.ModuleCount = count;
        process.ModuleLastCaptured = lastCaptured;
        process.ModuleCaptureError = error;

        CaptureStatusChanged?.Invoke(this, EventArgs.Empty);
    }

    private List<ModuleInfo> GetStagedModules(ProcessInfo process)
    {
        return _projectionService
            .GetModulesForProcess(new ModuleProjectionQuery
            {
                ProcessEntityId = process.ProcessEntityId,
                ProcessKey = process.GetUniqueKey(),
                IncludeUnloaded = true,
                MaxCount = MaxVisibleModules
            })
            .ToList();
    }

    partial void OnSelectedModuleChanged(ModuleRowViewModel? value)
    {
        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a row in Data to inspect its additional properties.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }
    
    /// <summary>
    /// Sorts modules by the specified column.
    /// </summary>
    public void SortByColumn(string columnName)
    {
        // Toggle direction if same column, otherwise ascending
        if (_currentSortColumn == columnName)
        {
            _currentSortDirection = _currentSortDirection == ListSortDirection.Ascending
                ? ListSortDirection.Descending
                : ListSortDirection.Ascending;
        }
        else
        {
            _currentSortColumn = columnName;
            _currentSortDirection = ListSortDirection.Ascending;
        }
        
        ApplySorting(columnName, _currentSortDirection);
    }
    
    private void ApplySorting(string columnName, ListSortDirection direction)
    {
        if (ModulesView == null)
            return;
        
        ModulesView.SortDescriptions.Clear();
        
        var propertyName = columnName switch
        {
            "ModuleName" => nameof(ModuleRowViewModel.ModuleName),
            "FullPath" => nameof(ModuleRowViewModel.FullPath),
            "BaseAddress" => nameof(ModuleRowViewModel.BaseAddress),
            "ModuleMemorySize" => nameof(ModuleRowViewModel.ModuleMemorySizeBytes),
            "FileVersion" => nameof(ModuleRowViewModel.FileVersion),
            "CompanyName" => nameof(ModuleRowViewModel.CompanyName),
            "Description" => nameof(ModuleRowViewModel.Description),
            "Sha256Hash" => nameof(ModuleRowViewModel.Sha256Hash),
            "Status" => nameof(ModuleRowViewModel.Status),
            "LastSeen" => nameof(ModuleRowViewModel.LastSeenUtc),
            _ => columnName
        };
        
        ModulesView.SortDescriptions.Add(new SortDescription(propertyName, direction));
    }
}
