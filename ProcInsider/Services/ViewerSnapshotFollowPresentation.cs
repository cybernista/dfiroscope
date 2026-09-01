namespace ProcInsider.Services;

public sealed record ViewerSnapshotFollowPresentation(
    string StatusText,
    string DetailText,
    bool CanEnableFollow,
    bool IsFollowIntervalEnabled,
    int IntervalMinutes);

/// <summary>
/// Converts headless coordinator state into bounded analyst-facing wording. Keeping
/// this projection WPF-free makes every mode/failure/accessibility state testable.
/// </summary>
public static class ViewerSnapshotFollowPresentationFormatter
{
    private const int MaximumDetailLength = 420;

    public static ViewerSnapshotFollowPresentation Create(
        ViewerSnapshotFollowState state,
        DateTime utcNow,
        string contextNotice = "")
    {
        ArgumentNullException.ThrowIfNull(state);
        var intervalMinutes = Math.Max(
            1,
            (int)Math.Round(state.FollowInterval.TotalMinutes));
        var followAvailable = state.Workspace.CanRefresh && state.IsCursorSourceAvailable;
        var intervalLabel = $"Follow {intervalMinutes}m";
        var nextEligible = state.NextEligibleUtc.HasValue
            ? state.NextEligibleUtc.Value.ToLocalTime().ToString("HH:mm:ss")
            : "pending";
        var retry = state.Diagnostics.LastRetryUtc ?? state.NextEligibleUtc;
        var retryLabel = retry.HasValue
            ? retry.Value.ToLocalTime().ToString("HH:mm:ss")
            : "pending";

        var status = state.Mode == ViewerSnapshotFollowMode.Manual
            ? state.IsDirty
                ? "Manual / Pinned — newer committed evidence available"
                : $"Manual / Pinned — {FormatSnapshot(state.LastPublishedSnapshotUtc, utcNow)}"
            : !state.Workspace.CanRefresh
                ? "Follow paused/unavailable — no compatible unsealed live workspace"
                : !state.IsCursorSourceAvailable
                    ? "Follow paused/unavailable — verified durable cursor unavailable"
                    : state.Phase switch
                    {
                        ViewerSnapshotFollowPhase.Preparing or
                        ViewerSnapshotFollowPhase.Publishing =>
                            "Follow — updating in background",
                        _ when state.IsAnalysisPreparing && state.IsDirty =>
                            "Follow — analysis finishing; update retained",
                        ViewerSnapshotFollowPhase.Backoff =>
                            $"Follow failed; current snapshot preserved; retry {retryLabel}",
                        ViewerSnapshotFollowPhase.FollowingDirtyWaiting =>
                            $"{intervalLabel} — newer evidence queued, next eligible {nextEligible}",
                        ViewerSnapshotFollowPhase.FollowingClean =>
                            $"{intervalLabel} — up to date",
                        ViewerSnapshotFollowPhase.Disposed =>
                            "Follow paused/unavailable — viewer is shutting down",
                        _ => $"{intervalLabel} — {state.StatusText}"
                    };

        var pending = state.PendingCommittedWorkItemCount > 0 ||
                      state.PendingCommittedRowCount > 0
            ? $" Pending committed metadata: {state.PendingCommittedWorkItemCount:N0} work items, " +
              $"{state.PendingCommittedRowCount:N0} rows."
            : string.Empty;
        var availability = !state.Workspace.CanRefresh
            ? " Follow unavailable: this workspace does not support live snapshot refresh."
            : !state.IsCursorSourceAvailable
                ? " Follow unavailable: no verified durable database-change cursor is available; Manual refresh remains available."
                : string.Empty;
        var detail = $"{state.StatusText}{pending}{availability} {contextNotice}".Trim();
        if (detail.Length > MaximumDetailLength)
        {
            detail = detail[..MaximumDetailLength] + "…";
        }

        return new ViewerSnapshotFollowPresentation(
            status,
            detail,
            followAvailable,
            state.Mode == ViewerSnapshotFollowMode.Follow && followAvailable,
            intervalMinutes);
    }

    private static string FormatSnapshot(DateTime? snapshotUtc, DateTime utcNow)
    {
        if (!snapshotUtc.HasValue)
        {
            return "current snapshot not yet loaded";
        }

        var age = utcNow - snapshotUtc.Value;
        if (age < TimeSpan.Zero)
        {
            age = TimeSpan.Zero;
        }

        var ageText = age.TotalMinutes < 1
            ? "less than 1 minute old"
            : age.TotalHours < 1
                ? $"{Math.Max(1, (int)age.TotalMinutes)} minutes old"
                : $"{Math.Max(1, (int)age.TotalHours)} hours old";
        return $"current snapshot {snapshotUtc.Value.ToLocalTime():HH:mm:ss} ({ageText})";
    }
}
