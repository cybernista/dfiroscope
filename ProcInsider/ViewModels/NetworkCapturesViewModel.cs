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

public partial class NetworkCapturesViewModel : ViewModelBase
{
    private const int MaxVisibleCaptures = 1000;

    private readonly TelemetryProjectionService _projectionService;
    private readonly InspectorPaneViewModel _inspectorPaneViewModel;
    private Func<NetworkCaptureRecord, bool> _isActiveNetworkCapture = _ => false;
    private Func<NetworkCaptureRecord, bool> _isFinalizingNetworkCapture = _ => false;
    private IReadOnlyList<ExplorerScope> _includedScopes = [];
    private IReadOnlyList<ExplorerScope> _excludedScopes = [];
    private bool _hasGreenSelection;

    [ObservableProperty]
    private ObservableCollection<NetworkCaptureRowViewModel> networkCaptures = new();

    [ObservableProperty]
    private ObservableCollection<ZeekNetworkArtifactRowViewModel> zeekArtifacts = new();

    [ObservableProperty]
    private ICollectionView? networkCapturesView;

    [ObservableProperty]
    private ICollectionView? zeekArtifactsView;

    [ObservableProperty]
    private NetworkCaptureRowViewModel? selectedNetworkCapture;

    [ObservableProperty]
    private ZeekNetworkArtifactRowViewModel? selectedZeekArtifact;

    [ObservableProperty]
    private string statusMessage = "No network capture metadata loaded.";

    public NetworkCapturesViewModel(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel)
    {
        _projectionService = projectionService;
        _inspectorPaneViewModel = inspectorPaneViewModel;
        NetworkCapturesView = CollectionViewSource.GetDefaultView(NetworkCaptures);
        NetworkCapturesView.Filter = FilterNetworkCapture;
        ZeekArtifactsView = CollectionViewSource.GetDefaultView(ZeekArtifacts);
        ZeekArtifactsView.Filter = FilterZeekArtifact;
    }

    public event EventHandler? Refreshed;

    public void SetActiveNetworkCapturePredicate(Func<NetworkCaptureRecord, bool> isActiveNetworkCapture)
    {
        _isActiveNetworkCapture = isActiveNetworkCapture ?? (_ => false);
    }

    public void SetFinalizingNetworkCapturePredicate(Func<NetworkCaptureRecord, bool> isFinalizingNetworkCapture)
    {
        _isFinalizingNetworkCapture = isFinalizingNetworkCapture ?? (_ => false);
    }

    [RelayCommand]
    public void RefreshNetworkCaptures()
        => ApplySnapshot(
            _projectionService.GetNetworkCaptures(MaxVisibleCaptures),
            _projectionService.GetZeekNetworkArtifacts(MaxVisibleCaptures));

    public void ApplySnapshot(
        IReadOnlyList<NetworkCaptureRecord> captures,
        IReadOnlyList<ZeekNetworkRecord> artifacts)
    {
        var previouslySelectedCaptureId = SelectedNetworkCapture?.CaptureId;
        SelectedNetworkCapture = null;
        NetworkCaptures.Clear();

        foreach (var capture in captures.Select(capture => NormalizeCaptureStatus(
                     capture,
                     _isActiveNetworkCapture(capture),
                     _isFinalizingNetworkCapture(capture))))
        {
            NetworkCaptures.Add(new NetworkCaptureRowViewModel(capture));
        }

        if (!string.IsNullOrWhiteSpace(previouslySelectedCaptureId))
        {
            SelectedNetworkCapture = NetworkCaptures.FirstOrDefault(capture => capture.CaptureId == previouslySelectedCaptureId);
        }

        NetworkCapturesView?.Refresh();
        ApplyZeekSnapshot(artifacts);
        Refreshed?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    public void RefreshZeekArtifacts()
        => ApplyZeekSnapshot(_projectionService.GetZeekNetworkArtifacts(MaxVisibleCaptures));

    private void ApplyZeekSnapshot(IReadOnlyList<ZeekNetworkRecord> artifacts)
    {
        var previouslySelectedArtifactId = SelectedZeekArtifact?.ArtifactId;
        SelectedZeekArtifact = null;
        ZeekArtifacts.Clear();

        foreach (var artifact in artifacts)
        {
            ZeekArtifacts.Add(new ZeekNetworkArtifactRowViewModel(artifact));
        }

        if (!string.IsNullOrWhiteSpace(previouslySelectedArtifactId))
        {
            SelectedZeekArtifact = ZeekArtifacts.FirstOrDefault(artifact => artifact.ArtifactId == previouslySelectedArtifactId);
        }

        ZeekArtifactsView?.Refresh();
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
        NetworkCapturesView?.Refresh();
        ZeekArtifactsView?.Refresh();
        UpdateStatusMessage();
    }

    public void Clear()
    {
        SelectedNetworkCapture = null;
        SelectedZeekArtifact = null;
        NetworkCaptures.Clear();
        ZeekArtifacts.Clear();
        StatusMessage = "No network capture metadata loaded.";
    }

    partial void OnSelectedNetworkCaptureChanged(NetworkCaptureRowViewModel? value)
    {
        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a network capture segment to inspect it here.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }

    partial void OnSelectedZeekArtifactChanged(ZeekNetworkArtifactRowViewModel? value)
    {
        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a Zeek artifact to inspect it here.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }

    private bool FilterNetworkCapture(object item)
    {
        if (item is not NetworkCaptureRowViewModel capture)
        {
            return false;
        }

        if (_hasGreenSelection &&
            !_includedScopes.Any(scope => MatchesNetworkCaptureScope(capture.CaptureId, scope)))
        {
            return false;
        }

        return !_excludedScopes.Any(scope => MatchesNetworkCaptureScope(capture.CaptureId, scope));
    }

    private bool FilterZeekArtifact(object item)
    {
        if (item is not ZeekNetworkArtifactRowViewModel artifact)
        {
            return false;
        }

        if (_hasGreenSelection &&
            !_includedScopes.Any(scope => MatchesZeekArtifactScope(artifact, scope)))
        {
            return false;
        }

        return !_excludedScopes.Any(scope => MatchesZeekArtifactScope(artifact, scope));
    }

    private void UpdateStatusMessage()
    {
        if (NetworkCaptures.Count == 0 && ZeekArtifacts.Count == 0)
        {
            StatusMessage = "No network capture metadata loaded.";
            return;
        }

        var visibleCaptureCount = NetworkCaptures.Count(capture => FilterNetworkCapture(capture));
        var visibleZeekCount = ZeekArtifacts.Count(artifact => FilterZeekArtifact(artifact));
        var totalCount = NetworkCaptures.Count + ZeekArtifacts.Count;
        var visibleCount = visibleCaptureCount + visibleZeekCount;
        StatusMessage = visibleCount == totalCount
            ? $"Showing {visibleCaptureCount} capture segment(s) and {visibleZeekCount} Zeek artifact(s)."
            : $"Showing {visibleCaptureCount} capture segment(s) and {visibleZeekCount} Zeek artifact(s) in green scopes.";
    }

    private static bool MatchesNetworkCaptureScope(string captureId, ExplorerScope scope)
    {
        return scope.Kind switch
        {
            ExplorerScopeKind.NetworkRoot or ExplorerScopeKind.NetworkCaptures => true,
            ExplorerScopeKind.NetworkCapture => string.Equals(captureId, GetNetworkCaptureScopeId(scope), StringComparison.Ordinal),
            _ => false
        };
    }

    private static bool MatchesZeekArtifactScope(ZeekNetworkArtifactRowViewModel artifact, ExplorerScope scope)
    {
        return scope.Kind switch
        {
            ExplorerScopeKind.NetworkRoot or ExplorerScopeKind.ZeekArtifacts => true,
            ExplorerScopeKind.NetworkCaptures => true,
            ExplorerScopeKind.NetworkCapture => string.Equals(artifact.CaptureId, GetNetworkCaptureScopeId(scope), StringComparison.Ordinal),
            _ => false
        };
    }

    private static string GetNetworkCaptureScopeId(ExplorerScope scope)
    {
        const string prefix = "network:capture:";
        return scope.ScopeId.StartsWith(prefix, StringComparison.Ordinal)
            ? scope.ScopeId[prefix.Length..]
            : string.Empty;
    }

    public static NetworkCaptureRecord NormalizeCaptureStatus(
        NetworkCaptureRecord capture,
        bool isActiveCapture,
        bool isFinalizingCapture = false)
    {
        if (capture.Status != NetworkCaptureStatus.Capturing)
        {
            return capture;
        }

        if (isFinalizingCapture)
        {
            var finalizing = CopyNetworkCapture(capture);
            finalizing.Status = NetworkCaptureStatus.Stopping;
            finalizing.ErrorMessage = FirstNonEmpty(
                capture.ErrorMessage,
                "Capture stop was requested; Packet Monitor output is being finalized.");
            return finalizing;
        }

        if (isActiveCapture)
        {
            return capture;
        }

        var normalized = CopyNetworkCapture(capture);
        normalized.Status = NetworkCaptureStatus.Stale;
        normalized.ErrorMessage = FirstNonEmpty(
            capture.ErrorMessage,
            "Capture status is stale; no matching active PCAP capture job is running.");
        return normalized;
    }

    private static NetworkCaptureRecord CopyNetworkCapture(NetworkCaptureRecord source)
    {
        return new NetworkCaptureRecord
        {
            CaseId = source.CaseId,
            EvidenceSessionId = source.EvidenceSessionId,
            SourceIdentityId = source.SourceIdentityId,
            HostId = source.HostId,
            ExecutionRootId = source.ExecutionRootId,
            CaptureId = source.CaptureId,
            JobId = source.JobId,
            SegmentIndex = source.SegmentIndex,
            Status = source.Status,
            RequestedUtc = source.RequestedUtc,
            StartedUtc = source.StartedUtc,
            CompletedUtc = source.CompletedUtc,
            OutputDirectory = source.OutputDirectory,
            EtlFilePath = source.EtlFilePath,
            FilePath = source.FilePath,
            FileSizeBytes = source.FileSizeBytes,
            Sha256Hash = source.Sha256Hash,
            ToolName = source.ToolName,
            CaptureSource = source.CaptureSource,
            FilterDescription = source.FilterDescription,
            ErrorMessage = source.ErrorMessage,
            Source = source.Source
        };
    }

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
}
