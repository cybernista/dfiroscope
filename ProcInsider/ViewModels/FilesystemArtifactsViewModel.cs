using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class FilesystemArtifactsViewModel : ViewModelBase
{
    private const int MaxVisibleArtifacts = 2000;

    private readonly TelemetryProjectionService _projectionService;
    private readonly InspectorPaneViewModel _inspectorPaneViewModel;
    private IReadOnlyList<ExplorerScope> _includedScopes = [];
    private IReadOnlyList<ExplorerScope> _excludedScopes = [];
    private ExplorerScope? _activeScope;
    private bool _hasGreenSelection;

    [ObservableProperty]
    private ObservableCollection<FilesystemArtifactRowViewModel> artifacts = new();

    [ObservableProperty]
    private ICollectionView? artifactsView;

    [ObservableProperty]
    private FilesystemArtifactRowViewModel? selectedArtifact;

    [ObservableProperty]
    private string statusMessage = "No filesystem artifacts loaded.";

    public FilesystemArtifactsViewModel(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel)
    {
        _projectionService = projectionService;
        _inspectorPaneViewModel = inspectorPaneViewModel;
        ArtifactsView = CollectionViewSource.GetDefaultView(Artifacts);
        ArtifactsView.Filter = FilterArtifact;
    }

    [RelayCommand]
    public void RefreshArtifacts()
        => RefreshArtifacts(_activeScope);

    public void RefreshArtifacts(ExplorerScope? activeScope)
    {
        var artifacts = ShouldScopeArtifactQuery(activeScope)
            ? _projectionService.GetFilesystemArtifacts(activeScope, includeDescendants: false, MaxVisibleArtifacts)
            : _projectionService.GetFilesystemArtifacts(MaxVisibleArtifacts);
        ApplySnapshot(artifacts, activeScope);
    }

    public void ApplySnapshot(
        IReadOnlyList<FilesystemArtifactRecord> artifacts,
        ExplorerScope? activeScope)
    {
        _activeScope = activeScope;
        var previouslySelectedArtifactId = SelectedArtifact?.ArtifactId;
        SelectedArtifact = null;
        Artifacts.Clear();

        foreach (var artifact in artifacts)
        {
            Artifacts.Add(new FilesystemArtifactRowViewModel(artifact));
        }

        if (!string.IsNullOrWhiteSpace(previouslySelectedArtifactId))
        {
            SelectedArtifact = Artifacts.FirstOrDefault(artifact => artifact.ArtifactId == previouslySelectedArtifactId);
        }

        ArtifactsView?.Refresh();
        UpdateStatusMessage();
    }

    public void ApplyScopedSelection(
        IReadOnlyList<ExplorerScope> includedScopes,
        IReadOnlyList<ExplorerScope> excludedScopes,
        bool hasGreenSelection)
    {
        _includedScopes = includedScopes;
        _excludedScopes = excludedScopes;
        _hasGreenSelection = hasGreenSelection;
        ArtifactsView?.Refresh();
        UpdateStatusMessage();
    }

    public void Clear()
    {
        SelectedArtifact = null;
        Artifacts.Clear();
        StatusMessage = "No filesystem artifacts loaded.";
    }

    partial void OnSelectedArtifactChanged(FilesystemArtifactRowViewModel? value)
    {
        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a filesystem artifact to inspect it here.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }

    private bool FilterArtifact(object item)
    {
        if (item is not FilesystemArtifactRowViewModel artifact)
        {
            return false;
        }

        if (_hasGreenSelection &&
            !_includedScopes.Any(scope => MatchesFilesystemScope(artifact, scope)))
        {
            return false;
        }

        return !_excludedScopes.Any(scope => MatchesFilesystemScope(artifact, scope));
    }

    private void UpdateStatusMessage()
    {
        if (Artifacts.Count == 0)
        {
            StatusMessage = "No NTFS or Prefetch artifacts have been staged.";
            return;
        }

        var visibleCount = Artifacts.Count(artifact => FilterArtifact(artifact));
        StatusMessage = visibleCount == Artifacts.Count
            ? $"Showing {visibleCount} filesystem artifact(s)."
            : $"Showing {visibleCount} of {Artifacts.Count} filesystem artifact(s) in green scopes.";
    }

    private static bool ShouldScopeArtifactQuery(ExplorerScope? scope)
    {
        return scope?.Kind is ExplorerScopeKind.FilesystemFolder or ExplorerScopeKind.FilesystemEvidenceRoots;
    }

    private static bool MatchesFilesystemScope(FilesystemArtifactRowViewModel artifact, ExplorerScope scope)
    {
        return scope.Kind switch
        {
            ExplorerScopeKind.FilesystemRoot or ExplorerScopeKind.FilesystemEvidenceRoots or ExplorerScopeKind.FilesystemArtifacts => MatchesFilesystemIdentity(artifact, scope),
            ExplorerScopeKind.FilesystemFolder => MatchesFilesystemIdentity(artifact, scope) && MatchesFilesystemPath(artifact.SourcePath, scope.FilesystemPath),
            _ => false
        };
    }

    private static bool MatchesFilesystemIdentity(FilesystemArtifactRowViewModel artifact, ExplorerScope scope)
    {
        return MatchesScopeValue(artifact.CaseId, scope.CaseId) &&
               MatchesScopeValue(artifact.EvidenceSessionId, scope.EvidenceSessionId) &&
               MatchesScopeValue(artifact.CaptureId, scope.CaptureId) &&
               MatchesScopeValue(artifact.SourceIdentityId, scope.SourceIdentityId) &&
               MatchesScopeValue(artifact.HostId, scope.HostId) &&
               MatchesScopeValue(artifact.ExecutionRootId, scope.ExecutionRootId);
    }

    private static bool MatchesScopeValue(string artifactValue, string? scopeValue)
    {
        return string.IsNullOrWhiteSpace(scopeValue) ||
               string.Equals(artifactValue, scopeValue, StringComparison.Ordinal);
    }

    private static bool MatchesFilesystemPath(string artifactPath, string? scopePath)
    {
        if (string.IsNullOrWhiteSpace(scopePath))
        {
            return true;
        }

        var normalizedArtifactPath = NormalizeFilesystemPath(artifactPath);
        var normalizedScopePath = NormalizeFilesystemPath(scopePath);
        if (string.IsNullOrWhiteSpace(normalizedArtifactPath) ||
            string.IsNullOrWhiteSpace(normalizedScopePath))
        {
            return false;
        }

        return string.Equals(normalizedArtifactPath, normalizedScopePath, StringComparison.OrdinalIgnoreCase) ||
               normalizedArtifactPath.StartsWith(
                   normalizedScopePath + Path.DirectorySeparatorChar,
                   StringComparison.OrdinalIgnoreCase) ||
               normalizedArtifactPath.StartsWith(
                   normalizedScopePath + Path.AltDirectorySeparatorChar,
                   StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeFilesystemPath(string value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim()
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }
}
