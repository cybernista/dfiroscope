using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class MemoryInvestigationViewModel : ViewModelBase
{
    private const int MaxVisibleImages = 1000;
    private const int MaxVisibleRuns = 1000;
    private const int MaxVisibleProcesses = 5000;

    private readonly TelemetryProjectionService _projectionService;
    private readonly InspectorPaneViewModel _inspectorPaneViewModel;

    [ObservableProperty]
    private ObservableCollection<MemoryImageRowViewModel> memoryImages = new();

    [ObservableProperty]
    private ObservableCollection<VolatilityPluginRunRowViewModel> pluginRuns = new();

    [ObservableProperty]
    private ObservableCollection<MemoryProcessRowViewModel> memoryProcesses = new();

    [ObservableProperty]
    private ICollectionView? memoryImagesView;

    [ObservableProperty]
    private ICollectionView? pluginRunsView;

    [ObservableProperty]
    private ICollectionView? memoryProcessesView;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RefreshMemoryInvestigationCommand))]
    private MemoryImageRowViewModel? selectedMemoryImage;

    [ObservableProperty]
    private VolatilityPluginRunRowViewModel? selectedPluginRun;

    [ObservableProperty]
    private MemoryProcessRowViewModel? selectedMemoryProcess;

    [ObservableProperty]
    private string statusMessage = "No system memory images loaded.";

    public MemoryInvestigationViewModel(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel)
    {
        _projectionService = projectionService;
        _inspectorPaneViewModel = inspectorPaneViewModel;
        MemoryImagesView = CollectionViewSource.GetDefaultView(MemoryImages);
        PluginRunsView = CollectionViewSource.GetDefaultView(PluginRuns);
        PluginRunsView.Filter = FilterPluginRun;
        MemoryProcessesView = CollectionViewSource.GetDefaultView(MemoryProcesses);
        MemoryProcessesView.Filter = FilterMemoryProcess;
    }

    [RelayCommand]
    public void RefreshMemoryInvestigation()
        => ApplySnapshot(
            _projectionService.GetMemoryImages(MaxVisibleImages),
            _projectionService.GetVolatilityPluginRuns(maxCount: MaxVisibleRuns),
            _projectionService.GetMemoryProcesses(maxCount: MaxVisibleProcesses));

    public void ApplySnapshot(
        IReadOnlyList<MemoryImageRecord> images,
        IReadOnlyList<VolatilityPluginRunRecord> runs,
        IReadOnlyList<MemoryProcessRecord> processes)
    {
        var selectedImageId = SelectedMemoryImage?.ImageId;
        var selectedRunId = SelectedPluginRun?.RunId;
        var selectedProcessId = SelectedMemoryProcess?.ArtifactId;

        SelectedMemoryProcess = null;
        SelectedPluginRun = null;
        SelectedMemoryImage = null;
        MemoryImages.Clear();
        PluginRuns.Clear();
        MemoryProcesses.Clear();

        foreach (var image in images)
        {
            MemoryImages.Add(new MemoryImageRowViewModel(image));
        }

        foreach (var run in runs)
        {
            PluginRuns.Add(new VolatilityPluginRunRowViewModel(run));
        }

        foreach (var process in processes)
        {
            MemoryProcesses.Add(new MemoryProcessRowViewModel(process));
        }

        if (!string.IsNullOrWhiteSpace(selectedImageId))
        {
            SelectedMemoryImage = MemoryImages.FirstOrDefault(image => image.ImageId == selectedImageId);
        }

        if (!string.IsNullOrWhiteSpace(selectedRunId))
        {
            SelectedPluginRun = PluginRuns.FirstOrDefault(run => run.RunId == selectedRunId);
        }

        if (!string.IsNullOrWhiteSpace(selectedProcessId))
        {
            SelectedMemoryProcess = MemoryProcesses.FirstOrDefault(process => process.ArtifactId == selectedProcessId);
        }

        PluginRunsView?.Refresh();
        MemoryProcessesView?.Refresh();
        UpdateStatusMessage();
    }

    public void Clear()
    {
        SelectedMemoryProcess = null;
        SelectedPluginRun = null;
        SelectedMemoryImage = null;
        MemoryImages.Clear();
        PluginRuns.Clear();
        MemoryProcesses.Clear();
        StatusMessage = "No system memory images loaded.";
    }

    partial void OnSelectedMemoryImageChanged(MemoryImageRowViewModel? value)
    {
        PluginRunsView?.Refresh();
        MemoryProcessesView?.Refresh();
        UpdateStatusMessage();

        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a memory image to inspect it here.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }

    partial void OnSelectedPluginRunChanged(VolatilityPluginRunRowViewModel? value)
    {
        if (value == null)
        {
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }

    partial void OnSelectedMemoryProcessChanged(MemoryProcessRowViewModel? value)
    {
        if (value == null)
        {
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }

    private bool FilterPluginRun(object item)
    {
        return item is VolatilityPluginRunRowViewModel run &&
               (SelectedMemoryImage == null || string.Equals(run.ImageId, SelectedMemoryImage.ImageId, StringComparison.Ordinal));
    }

    private bool FilterMemoryProcess(object item)
    {
        return item is MemoryProcessRowViewModel process &&
               (SelectedMemoryImage == null || string.Equals(process.ImageId, SelectedMemoryImage.ImageId, StringComparison.Ordinal));
    }

    private void UpdateStatusMessage()
    {
        var visibleRuns = PluginRuns.Count(run => FilterPluginRun(run));
        var visibleProcesses = MemoryProcesses.Count(process => FilterMemoryProcess(process));
        StatusMessage = MemoryImages.Count == 0
            ? "No system memory images loaded."
            : $"Showing {MemoryImages.Count} image(s), {visibleRuns} Volatility run(s), and {visibleProcesses} memory process row(s).";
    }
}
