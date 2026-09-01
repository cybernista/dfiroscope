using System.Collections.ObjectModel;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

/// <summary>
/// Shared inspector surface for a row/object selected inside the Data pane.
/// </summary>
public class InspectorPaneViewModel : ViewModelBase
{
    public ObservableCollection<PropertyItemViewModel> Properties { get; } = [];

    public ObservableCollection<InspectorContentSection> ContentSections { get; } = [];

    public event EventHandler<InspectorPayload?>? CurrentPayloadChanged;

    public InspectorPayload? CurrentPayload { get; private set; }

    private string _headerText = "No item selected";
    public string HeaderText
    {
        get => _headerText;
        private set => SetProperty(ref _headerText, value);
    }

    private string _subtitleText = "Select a row in Data to inspect its additional properties.";
    public string SubtitleText
    {
        get => _subtitleText;
        private set => SetProperty(ref _subtitleText, value);
    }

    private string _emptyStateMessage = "Select a row in Data to inspect its additional properties.";
    public string EmptyStateMessage
    {
        get => _emptyStateMessage;
        private set => SetProperty(ref _emptyStateMessage, value);
    }

    private bool _hasSelection;
    public bool HasSelection
    {
        get => _hasSelection;
        private set => SetProperty(ref _hasSelection, value);
    }

    private InspectorArtifactKind _artifactKind;
    public InspectorArtifactKind ArtifactKind
    {
        get => _artifactKind;
        private set => SetProperty(ref _artifactKind, value);
    }

    private string _rawText = string.Empty;
    public string RawText
    {
        get => _rawText;
        private set => SetProperty(ref _rawText, value);
    }

    public bool HasRawText => !string.IsNullOrWhiteSpace(RawText);

    public bool HasContentSections => ContentSections.Count > 0;

    public bool HasContent => HasRawText || HasContentSections;

    public string ContentHeader => HasContentSections ? "PE contents" : "Content";

    public void Clear(string? message = null)
    {
        Properties.Clear();
        ContentSections.Clear();
        CurrentPayload = null;
        HeaderText = "No item selected";
        SubtitleText = "Select a row in Data to inspect its additional properties.";
        EmptyStateMessage = message ?? "Select a row in Data to inspect its additional properties.";
        ArtifactKind = InspectorArtifactKind.None;
        RawText = string.Empty;
        OnPropertyChanged(nameof(HasRawText));
        OnPropertyChanged(nameof(HasContentSections));
        OnPropertyChanged(nameof(HasContent));
        OnPropertyChanged(nameof(ContentHeader));
        HasSelection = false;
        CurrentPayloadChanged?.Invoke(this, null);
    }

    public void Load(InspectorPayload payload)
    {
        Properties.Clear();
        ContentSections.Clear();
        CurrentPayload = payload;

        HeaderText = payload.Header;
        SubtitleText = payload.Subtitle;
        EmptyStateMessage = payload.EmptyStateMessage;
        ArtifactKind = payload.ArtifactKind;
        RawText = payload.RawText;
        OnPropertyChanged(nameof(HasRawText));
        foreach (var section in payload.ContentSections)
        {
            ContentSections.Add(section);
        }

        OnPropertyChanged(nameof(HasContentSections));
        OnPropertyChanged(nameof(HasContent));
        OnPropertyChanged(nameof(ContentHeader));
        HasSelection = true;

        foreach (var property in payload.Properties)
        {
            Properties.Add(property);
        }

        CurrentPayloadChanged?.Invoke(this, payload);
    }
}
