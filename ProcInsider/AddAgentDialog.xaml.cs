using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using ProcInsider.Models;
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
        : this(CurrentEducationalReleaseProfile.RuntimeCatalog, monitoringConfiguration: null)
    {
    }

    public AddAgentDialog(HostMonitoringConfigurationViewModel monitoringConfiguration)
        : this(CurrentEducationalReleaseProfile.RuntimeCatalog, monitoringConfiguration)
    {
    }

    public AddAgentDialog(
        IFeatureCatalog catalog,
        HostMonitoringConfigurationViewModel? monitoringConfiguration,
        IEnumerable<AgentCaptureOptionViewModel>? initialCaptureOptions = null,
        int selectedAgentMemoryMegabytes = 500,
        bool isExistingAgentSetup = false)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        IsHostMonitoringPublished = catalog.IsPublished(FeatureIds.SecurityMonitoringConfiguration);
        MonitoringConfiguration = monitoringConfiguration ?? CreateEmptyMonitoringConfiguration();
        var publishedOptions = AgentCaptureOptionViewModel.CreateDefaultOptions(catalog)
            .Where(option => option.IsPublished)
            .ToArray();
        ApplyInitialCaptureSelections(publishedOptions, initialCaptureOptions);
        CaptureOptions = new ObservableCollection<AgentCaptureOptionViewModel>(publishedOptions);
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

    public HostMonitoringConfigurationViewModel MonitoringConfiguration { get; }

    public bool IsHostMonitoringPublished { get; }

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
        => CaptureOptions.Select(option => option.Clone()).ToList();

    public HostMonitoringConfigurationViewModel GetMonitoringConfiguration()
        => MonitoringConfiguration;

    private static HostMonitoringConfigurationViewModel CreateEmptyMonitoringConfiguration() =>
        new(
            Enumerable.Empty<ConfigProfileDefinition>(),
            Enumerable.Empty<ConfigProfileDefinition>(),
            Enumerable.Empty<ConfigProfileDefinition>(),
            Enumerable.Empty<ConfigProfileDefinition>(),
            Enumerable.Empty<ConfigProfileDefinition>());

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
