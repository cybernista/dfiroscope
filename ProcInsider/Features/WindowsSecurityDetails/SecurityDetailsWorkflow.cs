using System.Windows;
using ProcInsider.Features.NativeEventProfiles;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.WindowsSecurityDetails;

/// <summary>Security presentation lifetime bridge to the shared native-profile owner.</summary>
public sealed class SecurityDetailsWorkflow : IDisposable
{
    private readonly EventsViewModel _events;
    private readonly NativeEventProfileStore _profiles;
    private readonly SecurityDetailsStore _legacy;
    private bool _disposed;

    internal SecurityDetailsWorkflow(EventsViewModel events, NativeEventProfileStore profiles, SecurityDetailsStore legacy)
    {
        _events = events;
        _profiles = profiles;
        _legacy = legacy;
        _events.ConfigureSecurityProfiles(profiles);
        _events.OpenSecurityProfiles = () => ShowEditor(Application.Current?.MainWindow);
        _profiles.Changed += OnChanged;
    }
    private void OnChanged(object? sender, EventArgs e) { if (!_disposed) _events.RefreshSecurityDetails(); }
    internal NativeEventProfileEditorViewModel CreateEditor() => new(_profiles,
        _events.SelectedEvent is { } row ? EventsViewModel.ExtractSecurityFields(row) : null,
        _legacy.Snapshot().FirstOrDefault(d => d.EventId == _events.SelectedEvent?.EventCode), _legacy.LoadError,
        type => type.Provider == SecurityDetailsTemplate.Provider && type.Channel == "Security");
    public void ShowEditor(Window? owner)
    {
        if (_disposed) return;
        new NativeEventProfileEditorWindow { Owner = owner, DataContext = CreateEditor() }.ShowDialog();
    }
    public void Dispose()
    {
        _disposed = true;
        _profiles.Changed -= OnChanged;
        _events.OpenSecurityProfiles = null;
    }
}
