using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;
using ProcInsider.ViewModels;

namespace ProcInsider;

public enum AddAgentTargetKind
{
    Local,
    Remote
}

public partial class AddAgentDialog : Window
{
    public AddAgentDialog()
        : this(CurrentEducationalReleaseProfile.RuntimeCatalog)
    {
    }

    public AddAgentDialog(
        IFeatureCatalog catalog,
        IEnumerable<AgentCaptureOptionViewModel>? initialCaptureOptions = null,
        int selectedAgentMemoryMegabytes = 500,
        bool isExistingAgentSetup = false)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        var allOptions = AgentCaptureOptionViewModel.CreateDefaultOptions(catalog);
        var publishedOptions = allOptions
            .Where(option => option.IsPublished)
            .ToArray();
        if (!isExistingAgentSetup)
            foreach (var option in publishedOptions)
                option.IsIncluded = option.CanConfigure && option.Kind != AgentCaptureOptionKind.EtwEvents;
        if (isExistingAgentSetup) ApplyInitialCaptureSelections(publishedOptions, initialCaptureOptions);
        _allCaptureOptions = publishedOptions;
        PersistenceOption = allOptions.Single(option => option.Kind == AgentCaptureOptionKind.Persistence);
        var hasLiveForensics = publishedOptions.Any(option => option.Kind == AgentCaptureOptionKind.FilesystemArtifactImport);
        CaptureOptions = new ObservableCollection<AgentCaptureOptionViewModel>(publishedOptions.Where(option =>
            option.Kind != AgentCaptureOptionKind.ProcessMonitorCapture &&
            (option.Kind != AgentCaptureOptionKind.Persistence || !hasLiveForensics)));
        InitializeComponent();
        SelectAgentMemory(selectedAgentMemoryMegabytes);
        if (isExistingAgentSetup)
        {
            Title = "Start Agent";
            AddButton.Content = "Start";
        }
        UpdateSelectedAgentType();
    }

    public AddAgentTargetKind SelectedAgentTargetKind { get; private set; } = AddAgentTargetKind.Local;

    public ObservableCollection<AgentCaptureOptionViewModel> CaptureOptions { get; }

    public AgentCaptureOptionViewModel PersistenceOption { get; }

    private readonly IReadOnlyList<AgentCaptureOptionViewModel> _allCaptureOptions;

    public int? SelectedRunDurationMinutes { get; private set; }

    internal static bool TryParseRunDuration(string? text, out int? minutes)
    {
        minutes = null;
        var value = text?.Trim();
        if (string.Equals(value, "Indefinitely", StringComparison.OrdinalIgnoreCase)) return true;
        if (!int.TryParse(value, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out var parsed) || parsed <= 0) return false;
        minutes = parsed;
        return true;
    }

    public int SelectedAgentMemoryMegabytes
    {
        get
        {
            var selectedTag = (AgentMemoryComboBox?.SelectedItem as ComboBoxItem)?.Tag as string;
            return int.TryParse(selectedTag, out var megabytes)
                ? megabytes
                : 500;
        }
    }

    public IReadOnlyList<AgentCaptureOptionViewModel> GetCaptureOptions()
        => _allCaptureOptions.Select(option => option.Clone()).ToList();

    private static void ApplyInitialCaptureSelections(
        IEnumerable<AgentCaptureOptionViewModel> publishedOptions,
        IEnumerable<AgentCaptureOptionViewModel>? initialCaptureOptions)
    {
        if (initialCaptureOptions == null)
        {
            return;
        }

        var selections = initialCaptureOptions
            .Where(option => option.CanConfigure)
            .ToDictionary(option => option.Kind, option => option.IsIncluded);
        foreach (var option in publishedOptions.Where(option => option.CanConfigure))
        {
            if (selections.TryGetValue(option.Kind, out var included))
            {
                option.IsIncluded = included;
            }
        }
    }

    private void SelectAgentMemory(int selectedAgentMemoryMegabytes)
    {
        var normalized = selectedAgentMemoryMegabytes is 500 or 1024 or 2048
            ? selectedAgentMemoryMegabytes
            : 500;
        foreach (var item in AgentMemoryComboBox.Items.OfType<ComboBoxItem>())
        {
            item.IsSelected = string.Equals(
                item.Tag as string,
                normalized.ToString(System.Globalization.CultureInfo.InvariantCulture),
                StringComparison.Ordinal);
        }
    }

    private void AgentTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateSelectedAgentType();
    }

    private void AddButton_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedAgentTargetKind != AddAgentTargetKind.Local)
        {
            return;
        }

        if (!TryParseRunDuration(AgentRunDurationComboBox.Text, out var minutes))
        {
            RunDurationValidation.Text = "Choose Indefinitely or enter a positive whole number of minutes.";
            AgentRunDurationComboBox.Focus();
            return;
        }
        SelectedRunDurationMinutes = minutes;

        DialogResult = true;
    }

    private void UpdateSelectedAgentType()
    {
        if (AgentTypeComboBox == null || RemoteOptionsPanel == null || AddButton == null)
        {
            return;
        }

        var selectedTag = (AgentTypeComboBox.SelectedItem as ComboBoxItem)?.Tag as string;
        SelectedAgentTargetKind = string.Equals(selectedTag, "Remote", StringComparison.Ordinal)
            ? AddAgentTargetKind.Remote
            : AddAgentTargetKind.Local;

        var isRemote = SelectedAgentTargetKind == AddAgentTargetKind.Remote;
        RemoteOptionsPanel.Visibility = isRemote ? Visibility.Visible : Visibility.Collapsed;
        AddButton.IsEnabled = !isRemote;
    }
}
