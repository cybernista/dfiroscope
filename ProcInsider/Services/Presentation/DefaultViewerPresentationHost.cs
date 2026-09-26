using ProcInsider.Models.Features;
using ProcInsider.ViewModels;
using ProcInsider.Views.Presentation;

namespace ProcInsider.Services.Presentation;

internal sealed class DefaultViewerPresentationHost : IViewerPresentationHost
{
    private readonly ProcessPresentationViewModel _presentation;
    private StandaloneInvestigationView? _content;
    public DefaultViewerPresentationHost(ProcessPresentationViewModel presentation) => _presentation = presentation;
    public object Content => _content ??= new StandaloneInvestigationView { DataContext = _presentation };
    public ProcessPresentationViewModel ActiveProcessPresentation => _presentation;
    public InspectorPaneViewModel ActiveDetailsPresentation => _presentation.InspectorPaneViewModel;
    public Task<PreparedProcessListingSnapshot?> PrepareAsync(ViewerReadBinding candidate,
        ProcessListingSnapshotRequest? request, CancellationToken cancellationToken)
        => request == null ? Task.FromResult<PreparedProcessListingSnapshot?>(null) :
            _presentation._listingWorkflow.PrepareSnapshotAsync(candidate, request, cancellationToken);
    public Task QuiesceAsync(CancellationToken cancellationToken) => _presentation.QuiesceAsync(cancellationToken);
    public void Publish(ViewerReadBinding binding)
    {
        _presentation.BeginPublication();
        _presentation.PublishReadBinding(binding);
    }
    public void CommitPublication() => _presentation.CommitPublication();
    public void Detach(long captureGeneration) => _presentation.DetachReadBinding(captureGeneration);
    public void Abort()
    {
        if (!_presentation.AbortPublication()) _presentation.ResumeReads();
    }
    public bool NavigateToDataTab(FeatureTabKey key, string action) => _presentation.TryNavigateToDataTab(key, action);
    public bool NavigateToExplorerTab(FeatureTabKey key, string action) => _presentation.TryNavigateToExplorerTab(key, action);
    public void Dispose() => _presentation.Dispose();
}

/// <summary>Passes only the explicit shared action bridge through the WPF logical tree.</summary>
public static class ViewerPresentationContext
{
    public static readonly System.Windows.DependencyProperty SharedActionsProperty = System.Windows.DependencyProperty.RegisterAttached(
        "SharedActions", typeof(ViewerSharedActions), typeof(ViewerPresentationContext),
        new System.Windows.FrameworkPropertyMetadata(null, System.Windows.FrameworkPropertyMetadataOptions.Inherits));
    public static ViewerSharedActions? GetSharedActions(System.Windows.DependencyObject target) =>
        (ViewerSharedActions?)target.GetValue(SharedActionsProperty);
    public static void SetSharedActions(System.Windows.DependencyObject target, ViewerSharedActions? value) =>
        target.SetValue(SharedActionsProperty, value);
}
