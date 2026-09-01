using System;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

/// <summary>
/// View model for the events tab.
/// Shows projected SQLite event evidence for the selected process.
/// </summary>
public partial class EventsViewModel : ViewModelBase
{
    private const int MaxVisibleEvents = 10000;

    private readonly TelemetryProjectionService _projectionService;
    private readonly string? _eventSource;
    private readonly InspectorPaneViewModel _inspectorPaneViewModel;
    private readonly Action<(string ProcessKey, int ProcessId, string ProcessName)>? _beforeRefresh;
    private string _selectedProcessEntityId = string.Empty;

    [ObservableProperty]
    private ObservableCollection<EventRowViewModel> events = new();

    [ObservableProperty]
    private ICollectionView? eventsView;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsEventSelected))]
    private EventRowViewModel? selectedEvent;

    [ObservableProperty]
    private string selectedProcessKey = string.Empty;

    [ObservableProperty]
    private int selectedProcessId;

    [ObservableProperty]
    private string selectedProcessName = string.Empty;

    [ObservableProperty]
    private string statusMessage = "Select a process to view projected events.";

    [ObservableProperty]
    private int visibleEventCount;

    public EventsViewModel(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel,
        string? eventSource,
        Action<(string ProcessKey, int ProcessId, string ProcessName)>? beforeRefresh = null)
    {
        _projectionService = projectionService ?? throw new ArgumentNullException(nameof(projectionService));
        _inspectorPaneViewModel = inspectorPaneViewModel ?? throw new ArgumentNullException(nameof(inspectorPaneViewModel));
        _eventSource = eventSource;
        _beforeRefresh = beforeRefresh;
        EventsView = CollectionViewSource.GetDefaultView(Events);
    }

    public bool IsEventSelected => SelectedEvent != null;

    public string EventSourceDisplayName =>
        string.IsNullOrWhiteSpace(_eventSource) ? "All sources" : _eventSource;

    /// <summary>
    /// Loads recent events for the selected process.
    /// </summary>
    [RelayCommand]
    public void LoadEventsForProcess((string ProcessKey, int ProcessId, string ProcessName) processInfo)
    {
        SelectedProcessKey = processInfo.ProcessKey;
        SelectedProcessId = processInfo.ProcessId;
        SelectedProcessName = processInfo.ProcessName;

        _beforeRefresh?.Invoke(processInfo);
        RebuildVisibleEvents();
    }

    public void SetSelectedProcessEntityId(string processEntityId)
        => _selectedProcessEntityId = processEntityId ?? string.Empty;

    /// <summary>
    /// Reloads the current visible event list from the active SQLite projection.
    /// </summary>
    [RelayCommand]
    public void RefreshEvents()
    {
        if (!string.IsNullOrEmpty(SelectedProcessKey))
        {
            _beforeRefresh?.Invoke((SelectedProcessKey, SelectedProcessId, SelectedProcessName));
        }

        RebuildVisibleEvents();
    }

    /// <summary>
    /// Clears the visible event list.
    /// </summary>
    public void Clear()
    {
        SelectedProcessKey = string.Empty;
        SelectedProcessId = 0;
        SelectedProcessName = string.Empty;
        _selectedProcessEntityId = string.Empty;
        SelectedEvent = null;
        Events.Clear();
        VisibleEventCount = 0;
        StatusMessage = "Select a process to view projected events.";
    }

    private void RebuildVisibleEvents()
    {
        var previouslySelectedSequenceId = SelectedEvent?.SequenceId;
        SelectedEvent = null;
        Events.Clear();

        if (string.IsNullOrEmpty(SelectedProcessKey))
        {
            VisibleEventCount = 0;
            StatusMessage = "Select a process to view projected events.";
            _inspectorPaneViewModel.Clear();
            return;
        }

        var snapshot = GetEventSnapshot();
        foreach (var processEvent in snapshot)
        {
            Events.Add(new EventRowViewModel(processEvent));
        }

        if (Events.Count > 0 && previouslySelectedSequenceId.HasValue)
        {
            SelectedEvent = Events.FirstOrDefault(e => e.SequenceId == previouslySelectedSequenceId.Value);
        }

        VisibleEventCount = Events.Count;
        StatusMessage =
            $"Showing {VisibleEventCount} projected {EventSourceDisplayName} events for " +
            $"{SelectedProcessName} (PID: {SelectedProcessId}).";
    }

    private IReadOnlyList<ProcessEventInfo> GetEventSnapshot()
        => _projectionService.GetEventsForProcess(new EventProjectionQuery
        {
            ProcessEntityId = _selectedProcessEntityId,
            ProcessKey = SelectedProcessKey,
            Source = _eventSource,
            MaxCount = MaxVisibleEvents
        });

    partial void OnSelectedEventChanged(EventRowViewModel? value)
    {
        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a row in Data to inspect its additional properties.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }
}
