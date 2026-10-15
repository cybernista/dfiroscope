using System.Collections.ObjectModel;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Services;
using ProcInsider.Services.Ai;

namespace ProcInsider.ViewModels;

public sealed record InvestigationActivityRow(DateTime TimeUtc, string Kind, string Detail);

/// <summary>One instance's pinned formal investigation; all durable state remains in annotations.sqlite.</summary>
public partial class InvestigationDataViewModel : ViewModelBase, IDisposable
{
    private readonly Func<IAgentRuntime?> _runtime;
    private readonly Func<AnnotationDatabaseService?> _store;
    private readonly AiInvestigationService _provider;
    private readonly Func<long> _generation;
    private readonly Func<string> _activeEvidenceSessionId;
    private readonly Func<bool> _active;
    private string? _preparedRecoveryMessageId;
    private string? PreparedRecoveryMessageId
    {
        get => _preparedRecoveryMessageId;
        set { _preparedRecoveryMessageId = value; _live?.PublishRecoveryMessageId(value); }
    }
    private readonly Func<ProcessInfo, AiObjectContext> _captureTarget;
    private readonly Func<AiEvidenceReference, CancellationToken, Task<AiObjectContext?>> _resolveExactTarget;
    private readonly Func<AiEvidenceReference, Task> _navigateCitation;
    private CancellationTokenSource? _pending;
    private readonly object _answerEvidenceGate = new();
    private CancellationTokenSource? _answerEvidenceCancellation;
    private long _answerEvidenceRevision;
    private Task _answerEvidenceLoadTask = Task.CompletedTask;
    private long _revision;
    private long _selectedGeneration;
    private string _selectedEvidenceSessionId = string.Empty;
    private bool _disposed;
    private AiSubmissionConstraint? _disclosedSubmission;
    private AnnotationDatabaseService? _boundStore;
    private AiObjectContext? _pendingStartTarget;
    private string? _pendingStartObjective;
    private int _mutationDepth;
    private AiConversationLiveBinding? _live;
    private string? _liveId;
    private AnnotationDatabaseService? _liveStore;
    private readonly SynchronizationContext? _uiContext = SynchronizationContext.Current;
    private int _annotationRefreshRequested;
    private int _annotationRefreshRunning;
    public bool IsProcessesOrigin { get; set; }

    private void BindLive(AnnotationDatabaseService store, string id)
    {
        if (_live is not null && _liveId == id && ReferenceEquals(_liveStore, store)) return;
        ReleaseLive();
        _liveId = id;
        _liveStore = store;
        _live = AiConversationLiveState.Bind(store, id, this, Messages, SelectedMessageReferences,
            () => Question, value => Question = value,
            () => IsBusy, value => IsBusy = value,
            () => SelectedMessage, value => SelectedMessage = value,
            () => SelectedReference, value => SelectedReference = value,
            () => Status, value => Status = value,
            () => Progress, value => Progress = value,
            nameof(Question), nameof(Status),
            () => new(AnalystInstructions, PreparedRecoveryMessageId, LastSubmissionDestination, EvidenceStatus),
            metadata => { AnalystInstructions = metadata.AnalystInstructions;
                PreparedRecoveryMessageId = metadata.RecoveryMessageId;
                LastSubmissionDestination = metadata.LastSubmissionDestination;
                EvidenceStatus = metadata.EvidenceStatus; },
            nameof(Progress));
        store.AiAnnotationsChanged += OnAiAnnotationsChanged;
    }

    private void ReleaseLive()
    {
        if (_liveStore is { } store) store.AiAnnotationsChanged -= OnAiAnnotationsChanged;
        _live?.Dispose(); _live = null; _liveId = null; _liveStore = null;
        Interlocked.Exchange(ref _annotationRefreshRequested, 0);
    }

    private void OnAiAnnotationsChanged(AnnotationDatabaseService changed)
    {
        if (!ReferenceEquals(changed, _liveStore) || _disposed) return;
        Interlocked.Exchange(ref _annotationRefreshRequested, 1);
        if (Interlocked.CompareExchange(ref _annotationRefreshRunning, 1, 0) != 0) return;
        if (_uiContext is { } context)
            context.Post(_ => _ = RefreshChangedAnnotationsAsync(), null);
        else _ = RefreshChangedAnnotationsAsync();
    }

    private async Task RefreshChangedAnnotationsAsync()
    {
        try
        {
            while (Interlocked.Exchange(ref _annotationRefreshRequested, 0) != 0)
            {
                var store = _liveStore;
                var saved = Investigation;
                var revision = _revision;
                var generation = _selectedGeneration;
                if (_pending is not null)
                {
                    Interlocked.Exchange(ref _annotationRefreshRequested, 1);
                    break;
                }
                if (store is null || saved is null || !CaptureCurrent(revision, generation)) continue;
                try { await RefreshStateAsync(store, saved.Id, revision, generation, CancellationToken.None); }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.TraceWarning($"Investigation live refresh unavailable: {ex.Message}");
                }
            }
        }
        finally
        {
            Interlocked.Exchange(ref _annotationRefreshRunning, 0);
            if (_pending is null && Volatile.Read(ref _annotationRefreshRequested) != 0 && _liveStore is { } store)
                OnAiAnnotationsChanged(store);
        }
    }

    public InvestigationDataViewModel(Func<IAgentRuntime?> runtime,
        Func<AnnotationDatabaseService?> store, AiInvestigationService provider,
        Func<long> generation, Func<bool> active,
        Func<ProcessInfo, AiObjectContext> captureTarget,
        Func<AiEvidenceReference, CancellationToken, Task<AiObjectContext?>> resolveExactTarget,
        Func<AiEvidenceReference, Task> navigateCitation,
        Func<string> activeEvidenceSessionId)
    {
        _runtime = runtime;
        _store = store;
        _provider = provider;
        _generation = generation;
        _activeEvidenceSessionId = activeEvidenceSessionId;
        _active = active;
        _captureTarget = captureTarget;
        _resolveExactTarget = resolveExactTarget;
        _navigateCitation = navigateCitation;
        _selectedGeneration = generation();
        _selectedEvidenceSessionId = activeEvidenceSessionId();
        _provider.SettingsChanged += OnProviderSettingsChanged;
        RefreshProviderDisclosure();
    }

    public AiInvestigationViewModel? SettingsViewModel { get; internal set; }
    public ObservableCollection<InvestigationTask> Tasks { get; } = new();
    public ObservableCollection<InvestigationFinding> Findings { get; } = new();
    public ObservableCollection<InvestigationHypothesis> Hypotheses { get; } = new();
    public ObservableCollection<AgentExecution> Executions { get; } = new();
    public ObservableCollection<AgentToolCall> ToolCalls { get; } = new();
    public ObservableCollection<InvestigationEvidenceLink> EvidenceLinks { get; } = new();
    public ObservableCollection<InvestigationEvidenceLink> SelectedFindingLinks { get; } = new();
    public ObservableCollection<InvestigationEvidenceLink> SelectedHypothesisLinks { get; } = new();
    public ObservableCollection<AiConversationMessage> Messages { get; } = new();
    public ObservableCollection<AiEvidenceReference> SelectedMessageReferences { get; } = new();
    public ObservableCollection<InvestigationActivityRow> Activity { get; } = new();

    [ObservableProperty] private Investigation? investigation;
    [ObservableProperty] private InvestigationTask? selectedTask;
    [ObservableProperty] private InvestigationFinding? selectedFinding;
    [ObservableProperty] private InvestigationHypothesis? selectedHypothesis;
    [ObservableProperty] private AiConversationMessage? selectedMessage;
    [ObservableProperty] private AiEvidenceReference? selectedReference;
    [ObservableProperty] private InvestigationEvidenceLink? selectedEvidenceLink;
    [ObservableProperty] private string evidenceStatus = "Select an answer to inspect its checked citations.";
    [ObservableProperty] private string question = string.Empty;
    [ObservableProperty] private string status = "Open or start an investigation.";
    [ObservableProperty] private string progress = "No execution is active.";
    [ObservableProperty] private string targetSummary = "No target pinned.";
    [ObservableProperty] private string providerDestination = "Provider destination has not been reviewed.";
    [ObservableProperty] private string lastSubmissionDestination = "No AI execution in this view.";
    [ObservableProperty] private string historyStatus = "No conversation history loaded.";
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(FollowUpCommand))] private bool isBusy;
    public bool HasPendingStart => _pendingStartTarget is not null;

    private AiCorrectionDraft.Option? SelectedCorrection =>
        AiCorrectionDraft.ForSelected(Messages, SelectedMessage, Investigation?.ConversationId);
    public bool HasCorrectionOption => !string.IsNullOrEmpty(SelectedCorrection?.Draft);
    public string CorrectionActionText => SelectedCorrection?.ActionText ?? "Ask AI to correct this";
    public string CorrectionGuidance => SelectedCorrection?.Guidance ?? string.Empty;

    private bool CanPrepareCorrection() => !_disposed && !IsBusy && _mutationDepth == 0 &&
        Current(_revision, _selectedGeneration) && Investigation?.Target is not null &&
        Investigation.Status is not (InvestigationState.Closed or InvestigationState.Investigating) &&
        !string.IsNullOrEmpty(SelectedCorrection?.Draft);

    [RelayCommand(CanExecute = nameof(CanPrepareCorrection))]
    private void PrepareCorrection()
    {
        if (!CanPrepareCorrection() || SelectedCorrection is not { } option) return;
        Question = option.Draft;
        PreparedRecoveryMessageId = SelectedMessage!.Id;
        Status = Encoding.UTF8.GetByteCount(option.Draft) > 4_000
            ? "Correction question prepared. It exceeds the 4,000-byte Skill limit; shorten it before Send while retaining the objective."
            : "Correction question prepared in this composer. Review and edit it, then select Send.";
    }

    private void RefreshCorrectionAction()
    {
        PrepareCorrectionCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(HasCorrectionOption));
        OnPropertyChanged(nameof(CorrectionActionText));
        OnPropertyChanged(nameof(CorrectionGuidance));
    }

    private bool Current(long revision, long generation) => _active() && CaptureCurrent(revision, generation);

    private bool CaptureCurrent(long revision, long generation) => !_disposed &&
        revision == _revision && generation == _generation() &&
        !string.IsNullOrWhiteSpace(_selectedEvidenceSessionId) &&
        string.Equals(_selectedEvidenceSessionId, _activeEvidenceSessionId(), StringComparison.Ordinal) &&
        _boundStore is not null && ReferenceEquals(_boundStore, _store());

    private void ClearDisplay()
    {
        PreparedRecoveryMessageId = null;
        AnalystInstructions = string.Empty;
        Investigation = null;
        SelectedTask = null;
        SelectedFinding = null;
        SelectedHypothesis = null;
        SelectedMessage = null;
        SelectedReference = null;
        SelectedEvidenceLink = null;
        Tasks.Clear(); Findings.Clear(); Hypotheses.Clear(); Executions.Clear(); ToolCalls.Clear();
        EvidenceLinks.Clear(); SelectedFindingLinks.Clear(); SelectedHypothesisLinks.Clear(); Messages.Clear(); SelectedMessageReferences.Clear(); Activity.Clear();
        TargetSummary = "No target pinned.";
        Progress = "No execution is active.";
        HistoryStatus = "No conversation history loaded.";
        LastSubmissionDestination = "No AI execution in this view.";
    }

    public async Task<bool> LoadAsync(string savedId, CancellationToken cancellationToken = default)
    {
        if (_mutationDepth != 0 && !(_live?.IsExecuting == true && _live.HasOtherOwners))
        {
            Status = "An investigation write or AI execution is still finishing. Cancel if needed, wait for it to finish, then reload saved state.";
            return false;
        }
        if (_live?.HasOtherOwners != true) _pending?.Cancel();
        ReleaseLive();
        var revision = ++_revision;
        var generation = _selectedGeneration = _generation();
        _selectedEvidenceSessionId = _activeEvidenceSessionId();
        ClearDisplay();
        _pendingStartTarget = null;
        _pendingStartObjective = null;
        _disclosedSubmission = null;
        ProviderDestination = "Provider destination has not been reviewed.";
        OnPropertyChanged(nameof(HasPendingStart));
        if (!_active() || string.IsNullOrWhiteSpace(_selectedEvidenceSessionId) ||
            string.IsNullOrWhiteSpace(savedId) || _store() is not { } store)
        {
            Status = "Open the investigation's annotation store in an active workspace.";
            return false;
        }
        _boundStore = store;
        using var loading = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _pending = loading;
        IsBusy = true;
        try
        {
            var saved = await store.LoadInvestigationAsync(savedId, loading.Token);
            if (!Current(revision, generation)) return false;
            if (saved is null || saved.Target is null)
            {
                Status = "The saved investigation is unavailable in this annotation store.";
                return false;
            }
            if (!string.Equals(saved.Target.Identity.EvidenceSessionId,
                    _selectedEvidenceSessionId, StringComparison.Ordinal))
            {
                Status = "The saved investigation belongs to another evidence session.";
                return false;
            }
            var conversation = await store.LoadConversationAsync(saved.ConversationId, loading.Token);
            if (!Current(revision, generation)) return false;
            if (conversation is null || conversation.IsHistorical ||
                conversation.Scope.ContextType != AiConversationContextType.Investigation ||
                conversation.Scope.ContextId != saved.Id ||
                conversation.Scope.Identity != saved.Target.Identity)
            {
                Status = "Saved investigation conversation or target scope does not match this record.";
                return false;
            }
            await RefreshStateAsync(store, saved.Id, revision, generation, loading.Token);
            if (!Current(revision, generation)) return false;
            Status = "Saved investigation loaded. The target is pinned to its recorded identity.";
            BindLive(store, saved.ConversationId);
            return true;
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception ex)
        {
            if (Current(revision, generation)) Status = $"Investigation could not be loaded: {ex.Message}";
            return false;
        }
        finally
        {
            if (ReferenceEquals(_pending, loading)) { _pending = null; IsBusy = _live?.IsExecuting == true; }
            if (Volatile.Read(ref _annotationRefreshRequested) != 0 && _liveStore is { } liveStore)
                OnAiAnnotationsChanged(liveStore);
        }
    }

    public async Task<bool> StartAsync(ProcessInfo process, string? objective = null, bool submitImmediately = false)
    {
        if (IsBusy || _mutationDepth != 0) return false;
        ReleaseLive();
        if (!_active() || _store() is not { } store || process is null)
        {
            Status = "Select a process in an active capture to investigate.";
            return false;
        }
        var revision = ++_revision;
        var generation = _selectedGeneration = _generation();
        _selectedEvidenceSessionId = _activeEvidenceSessionId();
        _boundStore = store;
        ClearDisplay();
        Question = string.Empty;
        _pendingStartTarget = null;
        _pendingStartObjective = null;
        OnPropertyChanged(nameof(HasPendingStart));
        _disclosedSubmission = null;
        if (string.IsNullOrWhiteSpace(_selectedEvidenceSessionId))
        {
            Status = "The active evidence session is unavailable.";
            return false;
        }
        var taskObjective = string.IsNullOrWhiteSpace(objective)
            ? "Investigate this process using available recorded evidence; identify findings, hypotheses, uncertainty, and next questions."
            : objective.Trim();
        if (taskObjective.Length > 1000) { Status = "Investigation objective exceeds 1,000 characters."; return false; }
        AiObjectContext target;
        try { target = _captureTarget(process); }
        catch (Exception ex) { Status = $"Selected process context is unavailable: {ex.Message}"; return false; }
        if (!string.Equals(target.Reference.Identity.EvidenceSessionId,
                _selectedEvidenceSessionId, StringComparison.Ordinal))
        {
            Status = "The selected process belongs to another evidence session.";
            return false;
        }
        _pendingStartTarget = target;
        _pendingStartObjective = taskObjective;
        OnPropertyChanged(nameof(HasPendingStart));
        TargetSummary = DescribeTarget(target.Reference);
        if (ShowProviderUnavailable(taskObjective)) return false;
        // The process context-menu action explicitly requests immediate submission. Capture
        // its reviewed destination here; ReviewProviderSelection still rejects any change.
        if (submitImmediately) RefreshProviderDisclosure();
        var expected = ReviewProviderSelection();
        if (expected is null) return false;
        return await StartPreparedAsync(target, taskObjective, expected, revision, generation);
    }

    public async Task<bool> StartPendingAsync()
    {
        if (IsBusy || _mutationDepth != 0 || _pendingStartTarget is not { } target ||
            string.IsNullOrWhiteSpace(_pendingStartObjective))
        {
            Status = "Choose a process to investigate first.";
            return false;
        }
        if (ShowProviderUnavailable(_pendingStartObjective)) return false;
        var expected = ReviewProviderSelection();
        if (expected is null) return false;
        return await StartPreparedAsync(target, _pendingStartObjective, expected, _revision, _selectedGeneration);
    }

    private async Task<bool> StartPreparedAsync(AiObjectContext target, string taskObjective,
        AiSubmissionConstraint expected, long revision, long generation)
    {
        var store = _store();
        if (store is null || !Current(revision, generation)) return false;
        using var setup = new CancellationTokenSource();
        _pending = setup;
        _mutationDepth++;
        ReloadSavedCommand.NotifyCanExecuteChanged();
        IsBusy = true;
        try
        {
            var resolved = await _resolveExactTarget(target.Reference, setup.Token);
            if (!Current(revision, generation)) return false;
            if (resolved is null || resolved.Reference.CanonicalObjectKey != target.Reference.CanonicalObjectKey ||
                resolved.Reference.Identity != target.Reference.Identity)
            {
                Status = "The selected process original is missing or ambiguous in the active evidence projection.";
                return false;
            }
            var id = Guid.NewGuid().ToString("N");
            var title = $"Process investigation: {target.Reference.DisplayName}";
            if (title.Length > 240) title = title[..240];
            var conversation = await store.GetOrCreateConversationAsync(
                AiConversationScope.ForInvestigation(id, target.Reference.Identity), title,
                IsProcessesOrigin ? AiConversationCreationOrigin.ForProcess(target.Reference) : null,
                setup.Token);
            if (!Current(revision, generation)) return false;
            var created = conversation.UpdatedUtc ?? DateTime.UtcNow;
            var investigation = new Investigation(id, conversation.Id, title, taskObjective,
                InvestigationState.New, target.Reference, created, created, null, "", []);
            var task = new InvestigationTask(Guid.NewGuid().ToString("N"), id, null, taskObjective,
                InvestigationTaskState.Pending, AgentDefinition.InteractiveInvestigatorId,
                null, created, null, "");
            await store.CreateInvestigationAsync(investigation, task, setup.Token);
            if (!Current(revision, generation)) return false;
            await RefreshStateAsync(store, id, revision, generation, CancellationToken.None);
            if (!Current(revision, generation)) return false;
            BindLive(store, conversation.Id);
            _pendingStartTarget = null;
            _pendingStartObjective = null;
            OnPropertyChanged(nameof(HasPendingStart));
            SelectedTask = Tasks.FirstOrDefault(item => item.Id == task.Id);
            await ExecuteAsync(taskObjective, task.Id, expected, revision, generation);
            return Current(revision, generation) && Investigation?.Id == id;
        }
        catch (OperationCanceledException) { if (Current(revision, generation)) Status = "Investigation setup cancelled."; return false; }
        catch (Exception ex) { if (Current(revision, generation)) Status = $"Investigation could not start: {ex.Message}"; return false; }
        finally
        {
            _mutationDepth--;
            EditSystemPromptCommand.NotifyCanExecuteChanged();
            ReloadSavedCommand.NotifyCanExecuteChanged();
            if (ReferenceEquals(_pending, setup)) { _pending = null; IsBusy = false; }
        }
    }

    private bool CanFollowUp(string? prompt) => !IsBusy && _mutationDepth == 0 &&
        Current(_revision, _selectedGeneration) && Investigation?.Target is not null &&
        Investigation.Status is not (InvestigationState.Closed or InvestigationState.Investigating) &&
        AiFollowUpQuestionClassifier.IsAnalystQuestion(prompt);

    [RelayCommand(CanExecute = nameof(CanFollowUp))]
    private Task FollowUpAsync(string? prompt)
    {
        if (!CanFollowUp(prompt)) return Task.CompletedTask;
        Question = prompt!;
        return Task.CompletedTask;
    }

    public Task ContinueAsync(string? question = null)
    {
        var objective = question ?? Question;
        if (HasPendingStart)
        {
            if (!string.IsNullOrWhiteSpace(objective))
            {
                if (objective.Trim().Length > 1000)
                {
                    Status = "Investigation objective exceeds 1,000 characters.";
                    return Task.CompletedTask;
                }
                _pendingStartObjective = objective.Trim();
            }
            return StartPendingAsync();
        }
        if (string.IsNullOrWhiteSpace(objective)) { Status = "Enter a question to continue this investigation."; return Task.CompletedTask; }
        return BeginExecutionAsync(objective.Trim(), null);
    }

    public Task RunSelectedTaskAsync()
    {
        var task = SelectedTask;
        if (task is null || task.InvestigationId != Investigation?.Id ||
            task.Status is not (InvestigationTaskState.Pending or InvestigationTaskState.NeedsEvidence or
                InvestigationTaskState.Failed or InvestigationTaskState.Cancelled))
        {
            Status = "Select a pending or retryable task in this investigation.";
            return Task.CompletedTask;
        }
        return BeginExecutionAsync(task.Objective, task.Id);
    }

    private async Task BeginExecutionAsync(string objective, string? taskId)
    {
        if (IsBusy || _mutationDepth != 0) return;
        var current = Investigation;
        var revision = _revision;
        var generation = _selectedGeneration;
        if (current?.Target is null || _store() is null || !Current(revision, generation))
        {
            Status = "Open a saved investigation in the active workspace first.";
            return;
        }
        if (current.Status is InvestigationState.Closed or InvestigationState.Investigating)
        {
            Status = "This investigation is closed or already running.";
            return;
        }
        if (Encoding.UTF8.GetByteCount(objective) > 4_000) { Status = "Question exceeds the 4,000-byte Skill limit."; return; }
        if (taskId is null) Question = objective;
        if (ShowProviderUnavailable(objective)) return;
        var expected = ReviewProviderSelection();
        if (expected is null) return;
        await ExecuteAsync(objective, taskId, expected, revision, generation);
    }

    private async Task ExecuteAsync(string objective, string? taskId, AiSubmissionConstraint expected,
        long revision, long generation)
    {
        var saved = Investigation;
        var store = _store();
        if (saved?.Target is null || store is null || !Current(revision, generation)) return;
        var pending = new CancellationTokenSource();
        BindLive(store, saved.ConversationId);
        var executionLease = _live;
        if (!executionLease!.TryBeginExecution(pending))
        {
            pending.Dispose();
            return;
        }
        bool ExecutionValid() => ReferenceEquals(_store(), store) && generation == _generation() &&
            executionLease.IsExecutingWith(pending);
        _pending = pending;
        _mutationDepth++;
        ReloadSavedCommand.NotifyCanExecuteChanged();
        IsBusy = true;
        Status = "Resolving the exact saved process before AI execution.";
        Progress = "Checking the pinned target.";
        Task? monitor = null;
        try
        {
            var target = await _resolveExactTarget(saved.Target, pending.Token);
            if (!ExecutionValid()) return;
            if (target is null || target.Reference.CanonicalObjectKey != saved.Target.CanonicalObjectKey ||
                target.Reference.Identity != saved.Target.Identity)
            {
                Status = "The exact saved process original is unavailable or ambiguous. Saved findings remain readable.";
                return;
            }
            var runtime = _runtime() ?? throw new InvalidOperationException("The active capture has no AI runtime.");
            var request = new AgentRuntimeRequest(saved.ConversationId,
                AgentDefinition.InvestigateProcessSkillId, target, objective,
                ExecutionValid, InvestigationId: saved.Id,
                TaskId: taskId, ExpectedSubmission: expected, AnalystInstructions: AnalystInstructions, SystemInstructionsOverride: _provider.LoadSystemPrompt(AiConversationScope.ForInvestigation(saved.Id, saved.Target.Identity).ScopeKey), PromptSubmitted: (submittedQuestion, promptRequest, promptToken) => AiConversationPromptPresentation.PublishAsync(_promptUiContext, Messages, submittedQuestion, promptRequest, () => Current(revision, generation), promptToken), RecoveryMessageId: taskId is null ? PreparedRecoveryMessageId : null, ConversationOnly: taskId is null);
            var priorExecutions = (await store.LoadAgentExecutionsAsync(saved.ConversationId, pending.Token))
                .Select(execution => execution.Id).ToHashSet(StringComparer.Ordinal);
            if (!ExecutionValid()) return;
            Status = "Running checked InvestigateProcess. Cancel is available.";
            Progress = "Waiting for durable AgentExecution progress.";
            monitor = MonitorProgressAsync(store, saved, priorExecutions, revision, generation,
                executionLease, ExecutionValid, pending.Token);
            var result = await runtime.RunAsync(request, pending.Token);
            if (!ExecutionValid()) return;
            if (!Current(revision, generation))
            {
                executionLease.PublishCompletion(
                    $"Runtime-selected destination: {result.SubmissionDestination}; {result.Execution.ProviderId} / {result.Execution.ModelId}",
                    taskId is null && result.Execution.Status == AgentExecutionState.Completed,
                    result.Execution.Status == AgentExecutionState.Completed);
                var latest = await store.LoadConversationMessagesAsync(saved.ConversationId,
                    cancellationToken: pending.Token);
                if (ExecutionValid()) executionLease.PublishMessages(latest,
                    result.Execution.Status == AgentExecutionState.Completed
                        ? "Investigation execution completed. Review structured findings, evidence and open questions."
                        : $"{result.Execution.ErrorCategory}: See the full diagnostic in chat.");
                return;
            }
            LastSubmissionDestination = $"Runtime-selected destination: {result.SubmissionDestination}; " +
                $"{result.Execution.ProviderId} / {result.Execution.ModelId}";
            await RefreshStateAsync(store, saved.Id, revision, generation, CancellationToken.None);
            if (!Current(revision, generation)) return;
            SelectedMessage = AiAnswerEvidencePresentation.SelectAnswer(Messages.ToArray());
            if (Messages.LastOrDefault(message => message.HasPromptRequests) is { } promptMessage) await LoadPromptAsync(promptMessage);
            if (!Current(revision, generation)) return;
            Status = result.Execution.Status == AgentExecutionState.Completed
                ? "Investigation execution completed. Review structured findings, evidence and open questions."
                : $"{result.Execution.ErrorCategory}: See the full diagnostic in chat.";
            if (result.Execution.Status == AgentExecutionState.Completed) PreparedRecoveryMessageId = null;
            if (taskId is null && result.Execution.Status == AgentExecutionState.Completed)
            {
                Question = string.Empty;
                AnalystInstructions = string.Empty;
            }
        }
        catch (OperationCanceledException)
        {
            if (Current(revision, generation)) Status = "Investigation execution cancelled. Saved state remains available.";
            else executionLease.PublishStatus("Investigation execution cancelled. Saved state remains available.");
        }
        catch (AiSubmissionChangedException ex)
        {
            if (Current(revision, generation)) RefreshChangedProvider(ex.Message);
        }
        catch (Exception ex)
        {
            if (Current(revision, generation)) Status = $"Investigation execution unavailable: {ex.Message}";
            else executionLease.PublishStatus($"Investigation execution unavailable: {ex.Message}");
        }
        finally
        {
            executionLease.EndExecution(pending);
            pending.Cancel();
            if (monitor is not null) try { await monitor; } catch (OperationCanceledException) { }
            _mutationDepth--;
            EditSystemPromptCommand.NotifyCanExecuteChanged();
            ReloadSavedCommand.NotifyCanExecuteChanged();
            if (ReferenceEquals(_pending, pending))
            {
                _pending = null;
                if (Current(revision, generation)) IsBusy = _live?.IsExecuting == true;
            }
            if (Volatile.Read(ref _annotationRefreshRequested) != 0 && _liveStore is { } liveStore)
                OnAiAnnotationsChanged(liveStore);
            pending.Dispose();
            if (Current(revision, generation))
            {
                try { await RefreshStateAsync(store, saved.Id, revision, generation, CancellationToken.None); }
                catch (Exception ex) { Status = $"Saved investigation refresh unavailable: {ex.Message}"; }
            }
        }
    }

    private async Task MonitorProgressAsync(AnnotationDatabaseService store, Investigation saved,
        HashSet<string> priorExecutions,
        long revision, long generation, AiConversationLiveBinding executionLease,
        Func<bool> executionValid, CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(700));
        while (await timer.WaitForNextTickAsync(token) && executionValid())
        {
            try
            {
                var executions = await store.LoadAgentExecutionsAsync(saved.ConversationId, token);
                if (!executionValid()) return;
                var latest = executions.LastOrDefault(execution => !priorExecutions.Contains(execution.Id));
                if (latest is null) continue;
                var tools = await store.LoadAgentToolCallsAsync(latest.Id, token);
                if (!executionValid()) return;
                var progress = $"{latest.Status}: {latest.IterationCount} model iterations, {tools.Count} checked tool attempts; " +
                    $"latest tool {tools.LastOrDefault()?.ToolName ?? "none"} ({tools.LastOrDefault()?.Status.ToString() ?? "none"}).";
                if (Current(revision, generation)) Progress = progress;
                else executionLease.PublishProgress(progress);
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex)
            {
                if (!executionValid()) return;
                var progress = $"Durable progress is temporarily unavailable: {ex.Message}";
                if (Current(revision, generation)) Progress = progress;
                else executionLease.PublishProgress(progress);
            }
        }
    }

    private AiSubmissionConstraint? ReviewProviderSelection()
    {
        try
        {
            var settings = _provider.LoadSettings();
            var selection = AiSubmissionConstraint.Capture(settings);
            if (_disclosedSubmission != selection)
            {
                _disclosedSubmission = selection;
                ProviderDestination = $"Configured for next execution: {settings.DestinationDisplay}; {settings.EndpointDisplay}";
                Status = "Review the configured AI destination and submit again to run this investigation.";
                return null;
            }
            if (!settings.IsEnabled || !settings.TryGetEndpoint(out _) ||
                string.IsNullOrWhiteSpace(settings.ModelName))
            {
                Status = "Configure a valid AI provider and model before running this investigation.";
                return null;
            }
            return selection;
        }
        catch (Exception ex)
        {
            _disclosedSubmission = null;
            ProviderDestination = "AI provider settings unavailable.";
            Status = $"AI provider settings could not be loaded: {ex.Message}";
            return null;
        }
    }

    private void RefreshChangedProvider(string message)
    {
        try
        {
            var settings = _provider.LoadSettings();
            _disclosedSubmission = AiSubmissionConstraint.Capture(settings);
            ProviderDestination = $"Configured for next execution: {settings.DestinationDisplay}; {settings.EndpointDisplay}";
            Status = message;
        }
        catch (Exception ex) { _disclosedSubmission = null; Status = $"AI provider settings could not be loaded: {ex.Message}"; }
    }

    private async Task RefreshStateAsync(AnnotationDatabaseService store, string id,
        long revision, long generation, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!CaptureCurrent(revision, generation) || !ReferenceEquals(store, _boundStore)) return;
        var saved = await store.LoadInvestigationAsync(id, token) ??
            throw new InvalidOperationException("Saved investigation is unavailable.");
        var tasks = await store.LoadInvestigationTasksAsync(id, token);
        var findings = await store.LoadInvestigationFindingsAsync(id, token);
        var hypotheses = await store.LoadInvestigationHypothesesAsync(id, token);
        var executions = await store.LoadAgentExecutionsAsync(saved.ConversationId, token);
        var toolCalls = new List<AgentToolCall>();
        foreach (var execution in executions)
            toolCalls.AddRange(await store.LoadAgentToolCallsAsync(execution.Id, token));
        var links = new List<InvestigationEvidenceLink>();
        foreach (var finding in findings)
            links.AddRange(await store.LoadInvestigationEvidenceAsync(InvestigationEvidenceOwner.Finding, finding.Id, token));
        foreach (var hypothesis in hypotheses)
            links.AddRange(await store.LoadInvestigationEvidenceAsync(InvestigationEvidenceOwner.Hypothesis, hypothesis.Id, token));
        foreach (var tool in toolCalls)
            links.AddRange(await store.LoadInvestigationEvidenceAsync(InvestigationEvidenceOwner.ToolCall, tool.Id, token));
        var messages = await store.LoadConversationMessagesAsync(saved.ConversationId, cancellationToken: token);
        token.ThrowIfCancellationRequested();
        if (!CaptureCurrent(revision, generation)) return;
        var previousAnswer = SelectedMessage;
        var selectedMessageId = previousAnswer?.Id;
        var selectedTaskId = SelectedTask?.Id;
        var selectedFindingId = SelectedFinding?.Id;
        var selectedHypothesisId = SelectedHypothesis?.Id;
        Investigation = saved;
        TargetSummary = saved.Target is { } reference ? DescribeTarget(reference) : "Saved target reference unavailable.";
        Replace(Tasks, tasks); Replace(Findings, findings); Replace(Hypotheses, hypotheses);
        Replace(Executions, executions); Replace(ToolCalls, toolCalls); Replace(EvidenceLinks, links);
        // Metadata refreshes must retain already inspected/live immutable bodies for this exact question.
        // Do not hydrate historical request bodies on each progress poll.
        var inspectedPrompts = Messages.Where(message => message.PromptRequests.Count > 0 || message.IsPromptExpanded)
            .ToDictionary(message => (message.ConversationId, message.Id));
        var taskActions = ProjectTaskActions(saved, messages, executions, tasks);
        ReconcileMessages(messages.Select(message =>
        {
            var retained =
            previousAnswer is not null && message.Id == previousAnswer.Id && message.Content == previousAnswer.Content &&
            message.TimestampUtc == previousAnswer.TimestampUtc && message.ConversationId == previousAnswer.ConversationId ? previousAnswer :
            message.HasPromptRequests && inspectedPrompts.TryGetValue((message.ConversationId, message.Id), out var inspected) &&
            inspected.Content == message.Content && inspected.Role == message.Role && inspected.TimestampUtc == message.TimestampUtc &&
            inspected.PromptRequests.All(prompt => prompt.ConversationId == message.ConversationId && prompt.MessageId == message.Id)
                ? message with { PromptRequests = inspected.PromptRequests, IsPromptExpanded = inspected.IsPromptExpanded } : message;
            var actions = taskActions.GetValueOrDefault(message.Id) ?? [];
            return retained.InvestigationTasks.SequenceEqual(actions) ? retained : retained with { InvestigationTasks = actions };
        }));
        RunFollowUpTaskCommand.NotifyCanExecuteChanged();
        SelectedTask = Tasks.FirstOrDefault(task => task.Id == selectedTaskId);
        SelectedFinding = Findings.FirstOrDefault(finding => finding.Id == selectedFindingId);
        SelectedHypothesis = Hypotheses.FirstOrDefault(hypothesis => hypothesis.Id == selectedHypothesisId);
        OnSelectedFindingChanged(SelectedFinding);
        OnSelectedHypothesisChanged(SelectedHypothesis);
        SelectedMessage = AiAnswerEvidencePresentation.SelectAnswer(Messages.ToArray(), selectedMessageId);
        SelectedEvidenceLink = null;
        HistoryStatus = $"Loaded {messages.Count} most recent conversation messages (maximum 200).";
        var activity = new List<InvestigationActivityRow> { new(saved.CreatedUtc, "Investigation created", "Created by analyst") };
        activity.AddRange(tasks.Select(task => new InvestigationActivityRow(task.CreatedUtc, "Task created",
            $"{task.Objective} | created by {task.CreatedByExecutionId ?? "analyst"}")));
        activity.AddRange(tasks.Where(task => task.CompletedUtc.HasValue).Select(task =>
            new InvestigationActivityRow(task.CompletedUtc!.Value, "Task ended",
                $"{task.Objective} | current status {task.Status} | {task.ResultSummary}")));
        activity.AddRange(findings.Select(finding => new InvestigationActivityRow(finding.CreatedUtc, "Finding created",
            $"{finding.Title} | created by execution {finding.CreatedByExecutionId}")));
        activity.AddRange(findings.Where(finding => finding.AnalystVerifiedUtc.HasValue).Select(finding =>
            new InvestigationActivityRow(finding.AnalystVerifiedUtc!.Value, "Finding verified by analyst",
                $"{finding.Title} | {finding.AnalystVerifiedBy} | current verification {finding.VerificationStatus}")));
        activity.AddRange(hypotheses.Select(hypothesis => new InvestigationActivityRow(hypothesis.CreatedUtc, "Hypothesis created",
            $"{hypothesis.Statement} | created by execution {hypothesis.CreatedByExecutionId}")));
        activity.AddRange(hypotheses.Where(hypothesis => hypothesis.UpdatedUtc > hypothesis.CreatedUtc).Select(hypothesis =>
            new InvestigationActivityRow(hypothesis.UpdatedUtc, "Hypothesis updated",
                $"{hypothesis.Statement} | current status {hypothesis.Status} | updated by {hypothesis.UpdatedByExecutionId ?? "analyst"}")));
        activity.AddRange(executions.Select(execution => new InvestigationActivityRow(execution.StartedUtc, "Execution started",
            $"{execution.SkillId} | {execution.ProviderId} / {execution.ModelId} | {execution.Id}")));
        activity.AddRange(executions.Where(execution => execution.CompletedUtc.HasValue).Select(execution =>
            new InvestigationActivityRow(execution.CompletedUtc!.Value, "Execution ended",
                $"{execution.SkillId} | status {execution.Status} | {execution.Id}")));
        activity.AddRange(toolCalls.Select(tool => new InvestigationActivityRow(tool.StartedUtc, "Tool started",
            $"{tool.ToolName} | {tool.Id}")));
        activity.AddRange(toolCalls.Where(tool => tool.CompletedUtc.HasValue).Select(tool =>
            new InvestigationActivityRow(tool.CompletedUtc!.Value, "Tool ended",
                $"{tool.ToolName} | status {tool.Status} | {tool.ResultSummary}")));
        Replace(Activity, activity.OrderBy(row => row.TimeUtc).ThenBy(row => row.Kind, StringComparer.Ordinal).ToArray());
    }

    private void ReconcileMessages(IEnumerable<AiConversationMessage> source)
    {
        var incoming = source.ToArray();
        for (var index = 0; index < incoming.Length; index++)
        {
            if (index >= Messages.Count) Messages.Add(incoming[index]);
            else if (Messages[index] != incoming[index]) Messages[index] = incoming[index];
        }
        while (Messages.Count > incoming.Length) Messages.RemoveAt(Messages.Count - 1);
    }
    private static void Replace<T>(ObservableCollection<T> destination, IEnumerable<T> source)
    {
        destination.Clear();
        foreach (var item in source) destination.Add(item);
    }

    partial void OnSelectedMessageChanged(AiConversationMessage? value)
    {
        RefreshCorrectionAction();
        _answerEvidenceLoadTask = LoadMessageReferencesAsync(value);
    }

    partial void OnSelectedFindingChanged(InvestigationFinding? value)
    {
        SelectedEvidenceLink = null;
        Replace(SelectedFindingLinks, value is null ? [] :
            EvidenceLinks.Where(link => link.Owner == InvestigationEvidenceOwner.Finding && link.OwnerId == value.Id));
    }

    partial void OnSelectedHypothesisChanged(InvestigationHypothesis? value)
    {
        SelectedEvidenceLink = null;
        Replace(SelectedHypothesisLinks, value is null ? [] :
            EvidenceLinks.Where(link => link.Owner == InvestigationEvidenceOwner.Hypothesis && link.OwnerId == value.Id));
    }

    partial void OnInvestigationChanged(Investigation? value) { RunFollowUpTaskCommand.NotifyCanExecuteChanged(); EditSystemPromptCommand.NotifyCanExecuteChanged(); ReloadSavedCommand.NotifyCanExecuteChanged(); FollowUpCommand.NotifyCanExecuteChanged(); RefreshCorrectionAction(); }
    partial void OnIsBusyChanged(bool value) { RunFollowUpTaskCommand.NotifyCanExecuteChanged(); ReloadSavedCommand.NotifyCanExecuteChanged(); PrepareCorrectionCommand.NotifyCanExecuteChanged(); CancelCommand.NotifyCanExecuteChanged(); EditSystemPromptCommand.NotifyCanExecuteChanged(); }

    private async Task LoadMessageReferencesAsync(AiConversationMessage? message)
    {
        using var answerCancellation = new CancellationTokenSource();
        long answerRevision;
        lock (_answerEvidenceGate)
        {
            answerRevision = Interlocked.Increment(ref _answerEvidenceRevision);
            _answerEvidenceCancellation?.Cancel();
            _answerEvidenceCancellation = answerCancellation;
        }
        try
        {
            SelectedReference = null;
            SelectedMessageReferences.Clear();
            EvidenceStatus = "Select an answer to inspect its checked citations.";
            if (message is null || !message.Role.Equals("assistant", StringComparison.OrdinalIgnoreCase)) return;
            if (message.Status == "Local")
            {
                EvidenceStatus = "Local reply; no provider request or checked capture citations.";
                return;
            }
            if (message.ConversationId != Investigation?.ConversationId)
            {
                EvidenceStatus = "This answer does not belong to the current conversation.";
                return;
            }
            if (_store() is not { } store)
            {
                EvidenceStatus = "The annotation store for this answer is unavailable.";
                return;
            }
            var revision = _revision;
            var generation = _selectedGeneration;
            bool CurrentAnswer() => answerRevision == Interlocked.Read(ref _answerEvidenceRevision) && !answerCancellation.IsCancellationRequested && CaptureCurrent(revision, generation) && SelectedMessage?.Id == message.Id &&
                Investigation?.ConversationId == message.ConversationId && ReferenceEquals(store, _store());
            EvidenceStatus = "Loading checked answer citations and exact originals...";
            try
            {
                var references = await AiAnswerEvidencePresentation.LoadAsync(store, message, _resolveExactTarget, CurrentAnswer, answerCancellation.Token);
                lock (_answerEvidenceGate)
                {
                    if (!CurrentAnswer()) return;
                    SelectedMessageReferences.Clear();
                    foreach (var reference in references)
                    {
                        if (!CurrentAnswer()) return;
                        SelectedMessageReferences.Add(reference);
                    }
                    if (!CurrentAnswer()) return;
                    EvidenceStatus = references.Count == 0 ? "This answer contains no checked capture citations."
                        : $"{references.Count} checked citation(s). Original availability is shown for each reference.";
                }
            }
            catch (Exception) { lock (_answerEvidenceGate) if (CurrentAnswer()) EvidenceStatus = "Answer citations could not be loaded."; }
        }
        finally
        {
            lock (_answerEvidenceGate)
                if (ReferenceEquals(_answerEvidenceCancellation, answerCancellation))
                    _answerEvidenceCancellation = null;
        }
    }

    private void RetireAnswerEvidenceLoad()
    {
        lock (_answerEvidenceGate)
        {
            Interlocked.Increment(ref _answerEvidenceRevision);
            _answerEvidenceCancellation?.Cancel();
            _answerEvidenceCancellation = null;
        }
    }

    [RelayCommand] private Task ContinueFromQuestionAsync() => ContinueAsync();
    private bool CanReloadSaved() => Investigation is not null && !IsBusy && _mutationDepth == 0;

    [RelayCommand(CanExecute = nameof(CanReloadSaved))]
    private async Task ReloadSavedAsync()
    {
        if (Investigation is not { } saved)
        {
            Status = "Open a saved investigation before refreshing its durable state.";
            return;
        }
        await LoadAsync(saved.Id);
    }

    [RelayCommand] private Task StartReviewedAsync() => StartPendingAsync();
    [RelayCommand] private Task RunTaskAsync() => RunSelectedTaskAsync();
    [RelayCommand] private Task OpenEvidenceAsync() =>
        SelectedEvidenceLink is { } link ? _navigateCitation(link.Reference) : Task.CompletedTask;
    [RelayCommand] private Task NavigateSelectedReferenceAsync() =>
        SelectedReference is { } reference ? _navigateCitation(reference) : Task.CompletedTask;
    private bool CanCancel() => IsBusy;
    [RelayCommand(CanExecute = nameof(CanCancel))] public void Cancel()
    {
        _live?.CancelExecution();
        _pending?.Cancel();
    }

    public void Detach()
    {
        if (_live?.IsExecuting != true || _live.HasOtherOwners != true) _pending?.Cancel();
        ReleaseLive();
        RetireAnswerEvidenceLoad();
        _revision++;
        _selectedGeneration = _generation();
        _disclosedSubmission = null;
        _boundStore = null;
        _pendingStartTarget = null;
        _pendingStartObjective = null;
        OnPropertyChanged(nameof(HasPendingStart));
        ClearDisplay();
        ProviderDestination = "Provider destination has not been reviewed.";
        Status = "No capture is attached.";
    }

    public void Dispose() { _provider.SettingsChanged -= OnProviderSettingsChanged; _disposed = true; Detach(); }

    public void Quiesce(bool preserveSharedExecution = false)
    {
        RetireAnswerEvidenceLoad();
        var interrupted = _mutationDepth != 0 && Investigation is not null;
        if (!preserveSharedExecution || _live?.HasOtherOwners != true) Cancel();
        _revision++;
        EditSystemPromptCommand.NotifyCanExecuteChanged();
        if (interrupted)
            Status = "Workspace read interrupted. Reload the saved investigation to refresh its durable state before continuing.";
    }
    public void Resume() { _selectedGeneration = _generation(); EditSystemPromptCommand.NotifyCanExecuteChanged(); }

    private static string DescribeTarget(AiEvidenceReference reference) =>
        $"{reference.DisplayName} | entity {reference.Evidence.Id} | case {reference.Identity.CaseId} | " +
        $"session {reference.Identity.EvidenceSessionId} | capture {reference.Identity.CaptureId} | " +
        $"host {reference.Identity.HostId} | source {reference.Identity.SourceIdentityId} | root {reference.Identity.ExecutionRootId}";
}
