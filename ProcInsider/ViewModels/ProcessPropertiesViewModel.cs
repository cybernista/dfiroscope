using System.Collections.ObjectModel;

namespace ProcInsider.ViewModels;

/// <summary>
/// View model for the bottom-left selected process properties tab.
/// </summary>
public class ProcessPropertiesViewModel : ViewModelBase
{
    public ObservableCollection<PropertyItemViewModel> Properties { get; } = [];
    public ObservableCollection<ProcessDataOriginItemViewModel> DataOrigin { get; } = [];

    private string _headerText = "No process selected";
    public string HeaderText
    {
        get => _headerText;
        private set => SetProperty(ref _headerText, value);
    }

    private string _subtitleText = "Select a process in the main grid to inspect its properties.";
    public string SubtitleText
    {
        get => _subtitleText;
        private set => SetProperty(ref _subtitleText, value);
    }

    private bool _hasProcessSelected;
    public bool HasProcessSelected
    {
        get => _hasProcessSelected;
        private set => SetProperty(ref _hasProcessSelected, value);
    }

    private bool _hasDataOrigin;
    public bool HasDataOrigin
    {
        get => _hasDataOrigin;
        private set => SetProperty(ref _hasDataOrigin, value);
    }

    public void LoadProcess(ProcessRowViewModel? process, IReadOnlyList<ProcInsider.Models.ProcessProjectionFieldWinner>? provenance = null)
    {
        Properties.Clear();
        DataOrigin.Clear();
        HasDataOrigin = false;

        if (process == null)
        {
            HeaderText = "No process selected";
            SubtitleText = "Select a process in the main grid to inspect its properties.";
            HasProcessSelected = false;
            return;
        }

        HeaderText = process.ProcessName;
        SubtitleText = $"PID {process.ProcessId} | {process.StatusDisplay}";
        HasProcessSelected = true;

        Add("Identity", "Process Name", process.ProcessName);
        Add("Identity", "Process ID", process.ProcessId.ToString());
        Add("Identity", "Process Key", process.ProcessKey);
        Add("Lineage", "Parent PID", process.ParentProcessId.ToString());
        Add("Lineage", "Parent Name", process.ParentProcessName);
        Add("Execution", "Path", process.ProcessPath);
        Add("Execution", "Command Line", process.CommandLine);
        Add("Execution", "User", process.UserName);
        Add("Execution", "Session", process.SessionId.ToString());
        Add("Execution", "Architecture", process.Architecture);
        Add("Runtime", "Status", process.StatusDisplay);
        Add("Runtime", "Start Time", process.StartTimeDisplay);
        Add("Runtime", "End Time", string.IsNullOrWhiteSpace(process.EndTimeDisplay) ? "<running>" : process.EndTimeDisplay);
        Add("Runtime", "CPU", process.CpuUsage);
        Add("Runtime", "Memory", process.MemoryUsage);
        Add("File", "Company", process.CompanyName);
        Add("File", "Description", process.FileDescription);
        Add("File", "SHA256", process.Sha256Hash);
        if (provenance is { Count: > 0 })
        {
            foreach (var winner in provenance)
            {
                var run = string.IsNullOrWhiteSpace(winner.SourceRunId) ? "legacy/unlinked" : winner.SourceRunId;
                DataOrigin.Add(new ProcessDataOriginItemViewModel(
                    winner.FieldName,
                    run,
                    winner.ObservationId,
                    winner.ResolutionReason));
            }

            HasDataOrigin = DataOrigin.Count > 0;
        }
    }

    private void Add(string group, string name, string value)
    {
        Properties.Add(new PropertyItemViewModel(group, name, value));
    }
}
