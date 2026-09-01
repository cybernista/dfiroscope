using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using ProcInsider.Features.BaselineComparison;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class SnapshotComparisonViewModel : ViewModelBase, IDisposable
{
    private readonly SnapshotComparisonCompletionService _completionService;
    private readonly BaselinePolicyService _policyService;
    private readonly BaselineRiskProjectionUpdateService? _riskProjectionUpdateService;
    private CancellationTokenSource? _activeWorkCancellation;
    private BaselineComparisonCompletion? _retainedCompletion;
    private string _activeSnapshotPath = string.Empty;
    private bool _disposed;

    public SnapshotComparisonViewModel(
        SnapshotComparisonCompletionService completionService,
        BaselinePolicyService policyService,
        InvestigationSessionPaths sessionPaths,
        BaselineRiskProjectionUpdateService? riskProjectionUpdateService = null)
    {
        _completionService = completionService ?? throw new ArgumentNullException(nameof(completionService));
        _policyService = policyService ?? throw new ArgumentNullException(nameof(policyService));
        _riskProjectionUpdateService = riskProjectionUpdateService;
        SetSessionPaths(sessionPaths);
    }

    public event EventHandler<BaselineRiskProjectionUpdateResult>? RiskProjectionUpdated;

    public ObservableCollection<SnapshotComparisonFindingRowViewModel> NewFindings { get; } = new();
    public ObservableCollection<SnapshotComparisonFindingRowViewModel> MissingFindings { get; } = new();
    public ObservableCollection<SnapshotComparisonFindingRowViewModel> ChangedFindings { get; } = new();
    public ObservableCollection<SnapshotComparisonFindingRowViewModel> KnownFindings { get; } = new();
    public ObservableCollection<SnapshotComparisonFindingRowViewModel> NoisyFindings { get; } = new();
    public ObservableCollection<SnapshotComparisonFindingRowViewModel> AcceptedFindings { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CompareSnapshotsCommand))]
    [NotifyCanExecuteChangedFor(nameof(SaveBaselineMetadataCommand))]
    private string baselineSnapshotPath = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CompareSnapshotsCommand))]
    private string currentSnapshotPath = string.Empty;

    [ObservableProperty]
    private string baselineName = string.Empty;

    [ObservableProperty]
    private string baselineHostId = string.Empty;

    [ObservableProperty]
    private string baselineTrustNote = string.Empty;

    [ObservableProperty]
    private string statusMessage = "Select baseline and current snapshot SQLite databases.";

    [ObservableProperty]
    private string summaryText = "No comparison has been run.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CompareSnapshotsCommand))]
    [NotifyCanExecuteChangedFor(nameof(AcceptSelectedFindingCommand))]
    private bool isBusy;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AcceptSelectedFindingCommand))]
    private SnapshotComparisonFindingRowViewModel? selectedFinding;

    public void SetSessionPaths(InvestigationSessionPaths sessionPaths)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(sessionPaths);
        CancelActiveWork(clearRetainedCompletion: true);
        _policyService.SetPolicyPath(sessionPaths.BaselinePolicyPath);
        _activeSnapshotPath = string.Empty;
        BaselineSnapshotPath = string.Empty;
        CurrentSnapshotPath = string.Empty;
        BaselineName = sessionPaths.SessionId;
        BaselineHostId = string.Empty;
        BaselineTrustNote = string.Empty;
        ClearFindings();
        SummaryText = "No comparison has been run.";
        StatusMessage = "Select baseline and current snapshot SQLite databases.";
        UseActiveSnapshotAsBaselineCommand.NotifyCanExecuteChanged();
        UseActiveSnapshotAsCurrentCommand.NotifyCanExecuteChanged();
    }

    public void ClearSessionState()
    {
        CancelActiveWork(clearRetainedCompletion: true);
        _activeSnapshotPath = string.Empty;
        BaselineSnapshotPath = string.Empty;
        CurrentSnapshotPath = string.Empty;
        BaselineName = string.Empty;
        BaselineHostId = string.Empty;
        BaselineTrustNote = string.Empty;
        ClearFindings();
        SummaryText = "No comparison has been run.";
        StatusMessage = "No capture workspace is active.";
        UseActiveSnapshotAsBaselineCommand.NotifyCanExecuteChanged();
        UseActiveSnapshotAsCurrentCommand.NotifyCanExecuteChanged();
    }

    public void SetActiveSnapshotPath(string snapshotPath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CancelActiveWork(clearRetainedCompletion: true);
        _activeSnapshotPath = Path.GetFullPath(snapshotPath);
        if (string.IsNullOrWhiteSpace(CurrentSnapshotPath) && File.Exists(snapshotPath))
        {
            CurrentSnapshotPath = _activeSnapshotPath;
        }

        if (HasAnyFindings())
        {
            StatusMessage = "The active viewer snapshot changed; retained Process Risk publication identity was cleared. Run Compare again before publishing or accepting another finding.";
        }

        UseActiveSnapshotAsBaselineCommand.NotifyCanExecuteChanged();
        UseActiveSnapshotAsCurrentCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    private void BrowseBaselineSnapshot()
    {
        var path = BrowseSnapshot("Choose Baseline Snapshot");
        if (path == null)
        {
            StatusMessage = "Baseline snapshot selection canceled.";
            return;
        }

        BaselineSnapshotPath = path;
        if (string.IsNullOrWhiteSpace(BaselineName))
        {
            BaselineName = Path.GetFileNameWithoutExtension(path);
        }
    }

    [RelayCommand]
    private void BrowseCurrentSnapshot()
    {
        var path = BrowseSnapshot("Choose Current Snapshot");
        if (path == null)
        {
            StatusMessage = "Current snapshot selection canceled.";
            return;
        }

        CurrentSnapshotPath = path;
    }

    [RelayCommand(CanExecute = nameof(HasActiveSnapshot))]
    private void UseActiveSnapshotAsBaseline()
    {
        BaselineSnapshotPath = _activeSnapshotPath;
        StatusMessage = "Active viewer snapshot selected as baseline.";
    }

    [RelayCommand(CanExecute = nameof(HasActiveSnapshot))]
    private void UseActiveSnapshotAsCurrent()
    {
        CurrentSnapshotPath = _activeSnapshotPath;
        StatusMessage = "Active viewer snapshot selected as current snapshot.";
    }

    [RelayCommand(CanExecute = nameof(CanSaveBaselineMetadata))]
    private void SaveBaselineMetadata()
    {
        try
        {
            _policyService.SaveBaselineMetadata(new BaselineSnapshotMetadata
            {
                Name = BaselineName.Trim(),
                SnapshotPath = BaselineSnapshotPath,
                HostId = BaselineHostId.Trim(),
                TrustNote = BaselineTrustNote.Trim(),
                CapturedUtc = File.Exists(BaselineSnapshotPath)
                    ? File.GetLastWriteTimeUtc(BaselineSnapshotPath)
                    : null
            });
            StatusMessage = $"Saved baseline metadata to {_policyService.PolicyPath}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Saving baseline metadata failed: {ex.Message}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanCompareSnapshots))]
    private async Task CompareSnapshotsAsync()
    {
        var cancellation = StartOperation(clearRetainedCompletion: true);
        StatusMessage = "Comparing snapshots...";
        try
        {
            var policy = _policyService.Load();
            var execution = await _completionService.CompareAsync(
                BaselineSnapshotPath,
                CurrentSnapshotPath,
                policy,
                cancellation.Token);
            cancellation.Token.ThrowIfCancellationRequested();
            if (execution.ComparisonResult == null)
            {
                ClearFindings();
                SummaryText = "Comparison failed.";
                StatusMessage = $"Snapshot comparison rejected: {execution.Diagnostic}";
                return;
            }

            LoadResult(execution.ComparisonResult);
            _retainedCompletion = execution.Completion;
            var status =
                $"Compared snapshots at {execution.ComparisonResult.ComparedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}. {execution.Diagnostic}";
            if (execution.Completion != null)
            {
                var publication = await PublishCompletionAsync(execution.Completion, cancellation.Token);
                if (publication != null)
                {
                    status = $"{status} {publication.Diagnostic}";
                }
                else if (_riskProjectionUpdateService == null)
                {
                    status = $"{status} Process Risk publication is unavailable in this feature host.";
                }
            }

            StatusMessage = status;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            // Clear, workspace replacement, deactivation, or disposal owns the current status.
        }
        catch (Exception ex)
        {
            ClearFindings();
            _retainedCompletion = null;
            SummaryText = "Comparison failed.";
            StatusMessage = $"Snapshot comparison failed: {ex.Message}";
        }
        finally
        {
            CompleteOperation(cancellation);
        }
    }

    [RelayCommand(CanExecute = nameof(CanAcceptSelectedFinding))]
    private async Task AcceptSelectedFindingAsync()
    {
        if (SelectedFinding == null)
        {
            return;
        }

        var selected = SelectedFinding;
        var cancellation = StartOperation(clearRetainedCompletion: false);
        try
        {
            var rule = _policyService.AcceptFinding(
                selected.Finding,
                "Accepted from Snapshot Comparison tab.");
            RemoveFinding(selected);
            selected.MarkAccepted(rule.RuleId);
            AcceptedFindings.Add(selected);
            SelectedFinding = null;
            UpdateSummaryText();

            var status = $"Accepted finding through policy rule {rule.RuleId}.";
            if (_retainedCompletion != null)
            {
                var evaluatedUtc = DateTime.UtcNow;
                if (evaluatedUtc < _retainedCompletion.ComparedUtc)
                {
                    evaluatedUtc = _retainedCompletion.ComparedUtc;
                }

                _retainedCompletion = _retainedCompletion.WithFindings(
                    CurrentFindings(),
                    evaluatedUtc);
                var publication = await PublishCompletionAsync(
                    _retainedCompletion,
                    cancellation.Token);
                if (publication != null)
                {
                    status = $"{status} {publication.Diagnostic}";
                }
                else if (_riskProjectionUpdateService == null)
                {
                    status = $"{status} Process Risk publication is unavailable in this feature host.";
                }
            }
            else
            {
                status =
                    $"{status} No current hash-stable comparison completion is available for Process Risk publication; run Compare again.";
            }

            StatusMessage = status;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            // The lifecycle action that canceled publication owns the current status.
        }
        catch (Exception ex)
        {
            StatusMessage = $"Accepting finding failed: {ex.Message}";
        }
        finally
        {
            CompleteOperation(cancellation);
        }
    }

    [RelayCommand]
    private void ClearComparison()
    {
        CancelActiveWork(clearRetainedCompletion: true);
        ClearFindings();
        SummaryText = "No comparison has been run.";
        StatusMessage = "Comparison results cleared.";
    }

    private void LoadResult(SnapshotComparisonResult result)
    {
        ClearFindings();
        foreach (var row in result.Findings.Select(finding => new SnapshotComparisonFindingRowViewModel(finding)))
        {
            AddFinding(row);
        }

        UpdateSummaryText();
    }

    private void AddFinding(SnapshotComparisonFindingRowViewModel row)
    {
        switch (row.Verdict)
        {
            case SnapshotComparisonVerdict.New:
                NewFindings.Add(row);
                break;
            case SnapshotComparisonVerdict.Missing:
                MissingFindings.Add(row);
                break;
            case SnapshotComparisonVerdict.Changed:
                ChangedFindings.Add(row);
                break;
            case SnapshotComparisonVerdict.Noisy:
                NoisyFindings.Add(row);
                break;
            case SnapshotComparisonVerdict.Accepted:
                AcceptedFindings.Add(row);
                break;
            default:
                KnownFindings.Add(row);
                break;
        }
    }

    private void RemoveFinding(SnapshotComparisonFindingRowViewModel row)
    {
        NewFindings.Remove(row);
        MissingFindings.Remove(row);
        ChangedFindings.Remove(row);
        KnownFindings.Remove(row);
        NoisyFindings.Remove(row);
        AcceptedFindings.Remove(row);
    }

    private void ClearFindings()
    {
        SelectedFinding = null;
        NewFindings.Clear();
        MissingFindings.Clear();
        ChangedFindings.Clear();
        KnownFindings.Clear();
        NoisyFindings.Clear();
        AcceptedFindings.Clear();
    }

    private void UpdateSummaryText()
    {
        SummaryText =
            $"New {NewFindings.Count} | Changed {ChangedFindings.Count} | Missing {MissingFindings.Count} | " +
            $"Noisy {NoisyFindings.Count} | Known {KnownFindings.Count} | Accepted {AcceptedFindings.Count}";
    }

    private bool CanCompareSnapshots()
        => !IsBusy &&
           File.Exists(BaselineSnapshotPath) &&
           File.Exists(CurrentSnapshotPath);

    private bool CanSaveBaselineMetadata()
        => File.Exists(BaselineSnapshotPath);

    private bool CanAcceptSelectedFinding()
        => !IsBusy &&
           SelectedFinding != null &&
           SelectedFinding.Verdict != SnapshotComparisonVerdict.Known &&
           SelectedFinding.Verdict != SnapshotComparisonVerdict.Noisy &&
           SelectedFinding.Verdict != SnapshotComparisonVerdict.Accepted;

    private bool HasActiveSnapshot()
        => File.Exists(_activeSnapshotPath);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CancelActiveWork(clearRetainedCompletion: true);
        ClearFindings();
    }

    private CancellationTokenSource StartOperation(bool clearRetainedCompletion)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CancelActiveWork(clearRetainedCompletion);
        _activeWorkCancellation = new CancellationTokenSource();
        IsBusy = true;
        return _activeWorkCancellation;
    }

    private void CompleteOperation(CancellationTokenSource cancellation)
    {
        if (!ReferenceEquals(_activeWorkCancellation, cancellation))
        {
            return;
        }

        _activeWorkCancellation = null;
        cancellation.Dispose();
        IsBusy = false;
    }

    private void CancelActiveWork(bool clearRetainedCompletion)
    {
        var cancellation = _activeWorkCancellation;
        _activeWorkCancellation = null;
        cancellation?.Cancel();
        cancellation?.Dispose();
        IsBusy = false;
        if (clearRetainedCompletion)
        {
            _retainedCompletion = null;
        }
    }

    private async Task<BaselineRiskProjectionUpdateResult?> PublishCompletionAsync(
        BaselineComparisonCompletion completion,
        CancellationToken cancellationToken)
    {
        if (_riskProjectionUpdateService == null)
        {
            return null;
        }

        var result = await Task.Run(
                () => _riskProjectionUpdateService.Update(completion, cancellationToken),
                cancellationToken)
            .ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
        RiskProjectionUpdated?.Invoke(this, result);
        return result;
    }

    private IReadOnlyList<SnapshotComparisonFinding> CurrentFindings() =>
        NewFindings
            .Concat(MissingFindings)
            .Concat(ChangedFindings)
            .Concat(KnownFindings)
            .Concat(NoisyFindings)
            .Concat(AcceptedFindings)
            .Select(row => row.Finding)
            .ToArray();

    private bool HasAnyFindings() =>
        NewFindings.Count + MissingFindings.Count + ChangedFindings.Count +
        KnownFindings.Count + NoisyFindings.Count + AcceptedFindings.Count > 0;

    private static string? BrowseSnapshot(string title)
    {
        var dialog = new OpenFileDialog
        {
            Title = title,
            Filter = "SQLite databases (*.sqlite;*.sqlite3;*.db)|*.sqlite;*.sqlite3;*.db|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false
        };

        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }
}
