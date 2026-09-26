using ProcInsider.Features.NativeEventProfiles;
using ProcInsider.Services.Events;
using CommunityToolkit.Mvvm.Input;
using System.Windows.Threading;

namespace ProcInsider.ViewModels;

public partial class EventsViewModel
{
    private NativeEventProfileStore? _detailsProfiles;
    private readonly Dictionary<NativeEventType, string> _detailsProfileChoices = [];
    private CancellationTokenSource? _detailsCancellation;
    private CancellationTokenSource? _detailsSelectionCancellation;
    private readonly Dispatcher _detailsDispatcher = Dispatcher.CurrentDispatcher;
    private NativeEventType? _selectedDetailsType;
    private NativeEventProfile? _securityDetailsProfile;
    internal Action? OpenSecurityProfiles { get; set; }
    public Task DetailsFormattingTask { get; private set; } = Task.CompletedTask;
    public string SecurityProfilesStatus => _detailsProfiles?.LoadError ?? "";
    public IReadOnlyList<NativeEventProfile> MatchingSecurityDetailsProfiles =>
        _detailsProfiles?.Snapshot().Where(p => p.Matches(_selectedDetailsType)).ToArray() ?? [];
    public NativeEventProfile? SecurityDetailsProfile
    {
        get => _securityDetailsProfile;
        set => SetProperty(ref _securityDetailsProfile, value);
    }

    internal void ConfigureSecurityProfiles(NativeEventProfileStore profiles)
    {
        if (_eventSource != "Security") throw new InvalidOperationException("Security profiles require the Security projection.");
        ConfigureNativeProfiles(profiles);
    }

    /// <summary>Attaches the shared profile store only to a source family with verified native identity.</summary>
    internal void ConfigureNativeProfiles(NativeEventProfileStore profiles)
    {
        if (_eventSource is not ("Security" or "PowerShell" or "Sysmon"))
            throw new InvalidOperationException("Native profiles are available only to Security, PowerShell and Sysmon projections.");
        _detailsProfiles = profiles;
        RefreshNativeDetails();
    }
    [RelayCommand]
    private void EditSecurityProfiles() => OpenSecurityProfiles?.Invoke();
    [RelayCommand]
    private void UseSecurityDetailsProfile()
    {
        if (_selectedDetailsType is not { } type || SecurityDetailsProfile is not { } profile ||
            !MatchingSecurityDetailsProfiles.Any(p => p.Id == profile.Id && p.Revision == profile.Revision)) return;
        _detailsProfileChoices[type] = profile.Id;
        BeginDetailsFormatting();
    }
    internal static EventFieldExtraction ExtractSecurityFields(EventRowViewModel row, CancellationToken token = default) =>
        NativeEventFieldExtractor.Extract(row.Details, row.EventCode, "Microsoft-Windows-Security-Auditing", "Security", token);
    private void RefreshSecurityProfileSelection()
    {
        _detailsSelectionCancellation?.Cancel();
        _detailsSelectionCancellation?.Dispose();
        _detailsSelectionCancellation = null;
        _selectedDetailsType = null;
        OnPropertyChanged(nameof(MatchingSecurityDetailsProfiles));
        SecurityDetailsProfile = null;
        if (SelectedEvent is not { } row || _detailsProfiles is null) return;
        var cancellation = _detailsSelectionCancellation = new CancellationTokenSource();
        var profiles = _detailsProfiles.Snapshot();
        _ = ResolveProfileSelectionAsync(row, profiles, cancellation.Token);
    }
    private async Task ResolveProfileSelectionAsync(EventRowViewModel row, IReadOnlyList<NativeEventProfile> profiles, CancellationToken token)
    {
        try
        {
            var type = await Task.Run(() => ExtractNativeFields(row, token).EventType, token);
            if (token.IsCancellationRequested) return;
            await _detailsDispatcher.InvokeAsync(() =>
            {
                if (token.IsCancellationRequested || !ReferenceEquals(SelectedEvent, row)) return;
                _selectedDetailsType = type;
                OnPropertyChanged(nameof(MatchingSecurityDetailsProfiles));
                var matches = profiles.Where(profile => profile.Matches(type)).ToArray();
                SecurityDetailsProfile = type is { } selected && _detailsProfileChoices.TryGetValue(selected, out var id)
                    ? matches.FirstOrDefault(profile => profile.Id == id) : matches.Length == 1 ? matches[0] : null;
            });
        }
        catch (OperationCanceledException) { }
    }
    public void RefreshSecurityDetails() => RefreshNativeDetails();

    internal void RefreshNativeDetails()
    {
        if (!_detailsDispatcher.CheckAccess()) { _detailsDispatcher.BeginInvoke(RefreshSecurityDetails); return; }
        OnPropertyChanged(nameof(SecurityProfilesStatus));
        RefreshSecurityProfileSelection();
        BeginDetailsFormatting();
    }
    private void CancelDetailsFormatting()
    {
        _detailsCancellation?.Cancel();
        _detailsCancellation?.Dispose();
        _detailsCancellation = null;
    }
    private void BeginDetailsFormatting()
    {
        CancelDetailsFormatting();
        if (_detailsProfiles is null || Events.Count == 0) return;
        var cancellation = _detailsCancellation = new CancellationTokenSource();
        var rows = Events.ToArray();
        var projection = new EventsTextProjection(_detailsProfiles.Snapshot(), _detailsProfileChoices);
        foreach (var row in rows) row.DetailsSummary = "Profile Details pending";
        DetailsFormattingTask = FormatDetailsAsync(rows, projection, cancellation.Token);
    }
    private async Task FormatDetailsAsync(EventRowViewModel[] rows, EventsTextProjection projection, CancellationToken token)
    {
        try
        {
            // One native parse per loaded row/revision; repaint and filter/sort only read summary strings.
            var summaries = await Task.Run(() =>
            {
                var values = new string[rows.Length];
                for (var i = 0; i < rows.Length; i++)
                {
                    token.ThrowIfCancellationRequested();
                    values[i] = projection.Project(ExtractNativeFields(rows[i], token), token).Summary;
                }
                return values;
            }, token);
            token.ThrowIfCancellationRequested();
            await _detailsDispatcher.InvokeAsync(() =>
            {
                if (token.IsCancellationRequested) return;
                using (EventsView?.DeferRefresh())
                    for (var i = 0; i < rows.Length; i++) rows[i].DetailsSummary = summaries[i];
                ApplyFilters();
            });
        }
        catch (OperationCanceledException) { }
    }

    private EventFieldExtraction ExtractNativeFields(EventRowViewModel row, CancellationToken token = default)
    {
        // Older Security projections did not carry raw provider/channel on ProcessEventInfo.
        // Only that established compatibility path may supply the exact pair; other families fail closed.
        if (_eventSource == "Security" && row.RawProvider.Length == 0 && row.RawLogName.Length == 0)
            return ExtractSecurityFields(row, token);
        return NativeEventFieldExtractor.Extract(row.Details, row.EventCode, row.RawProvider, row.RawLogName, token);
    }
}
