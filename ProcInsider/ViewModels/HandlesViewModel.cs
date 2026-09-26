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
/// View model for the handles tab.
/// Displays open handles for a process.
/// </summary>
public partial class HandlesViewModel : ViewModelBase
{
    private const int MaxVisibleHandles = 10000;

    private readonly InspectorPaneViewModel _inspectorPaneViewModel;
    private readonly TelemetryProjectionService _projectionService;
    private CancellationTokenSource? _loadCts;

    [ObservableProperty]
    private ObservableCollection<HandleRowViewModel> handles = new();

    [ObservableProperty]
    private string statusMessage = "Select a process to view handles";

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
    private ICollectionView? handlesView;

    [ObservableProperty]
    private HandleRowViewModel? selectedHandle;

    public event EventHandler? CaptureStatusChanged;

    public HandlesViewModel(
        InspectorPaneViewModel inspectorPaneViewModel,
        TelemetryProjectionService projectionService)
    {
        _inspectorPaneViewModel = inspectorPaneViewModel;
        _projectionService = projectionService;
        HandlesView = CollectionViewSource.GetDefaultView(Handles);
    }

    /// <summary>
    /// Loads handles for the specified process.
    /// </summary>
    [RelayCommand]
    public async Task LoadHandlesForProcessAsync(ProcessInfo? process)
    {
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
        SelectedHandle = null;
        Handles.Clear();

        LoadStagedHandles(process);
        await Task.CompletedTask;
    }

    /// <summary>
    /// Clears the handle list.
    /// </summary>
    public void Clear()
    {
        _loadCts?.Cancel();
        Handles.Clear();
        SelectedHandle = null;
        SelectedProcess = null;
        SelectedProcessId = 0;
        SelectedProcessName = string.Empty;
        StatusMessage = "Select a process to view handles";
        HasError = false;
    }

    private void PopulateHandles(IEnumerable<HandleInfo> handles)
    {
        Handles.Clear();
        foreach (var handle in handles)
        {
            Handles.Add(new HandleRowViewModel(handle));
        }
    }

    private void LoadStagedHandles(ProcessInfo process)
    {
        var stagedHandles = GetStagedHandles(process);
        if (stagedHandles.Count > 0)
        {
            PopulateHandles(stagedHandles);
            if (process.HandleCaptureStatus == ArtifactCaptureStatus.Pending)
            {
                UpdateHandleCaptureStatus(
                    process,
                    ArtifactCaptureStatus.Captured,
                    stagedHandles.Count,
                    process.HandleLastCaptured,
                    string.Empty);
            }
            StatusMessage = process.Status == ProcessStatus.Exited
                ? $"Showing {stagedHandles.Count} staged handles for exited process {process.ProcessName}"
                : $"Showing {stagedHandles.Count} staged handles for {process.ProcessName}";
            HasError = false;
            IsLoading = false;
            return;
        }

        Handles.Clear();
        StatusMessage = process.Status == ProcessStatus.Exited
            ? $"Process {process.ProcessName} (PID: {process.ProcessId}) has exited and no handle snapshot was captured."
            : $"No snapshot handles for {process.ProcessName} (PID: {process.ProcessId}). Queue agent enrichment, then use Refresh from db.";
        HasError = process.Status == ProcessStatus.Exited;
        IsLoading = false;
    }

    private void UpdateHandleCaptureStatus(
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

        process.HandleCaptureStatus = status;
        process.HandleCount = count;
        process.HandleLastCaptured = lastCaptured;
        process.HandleCaptureError = error;

        CaptureStatusChanged?.Invoke(this, EventArgs.Empty);
    }

    private List<HandleInfo> GetStagedHandles(ProcessInfo process)
    {
        return _projectionService
            .GetHandlesForProcess(new HandleProjectionQuery
            {
                ProcessEntityId = process.ProcessEntityId,
                ProcessKey = process.GetUniqueKey(),
                IncludeClosed = true,
                MaxCount = MaxVisibleHandles
            })
            .ToList();
    }

    partial void OnSelectedHandleChanged(HandleRowViewModel? value)
    {
        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a row in Data to inspect its additional properties.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }
}
