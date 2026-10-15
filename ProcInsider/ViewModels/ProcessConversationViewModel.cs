using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Services;
using ProcInsider.Services.Ai;

namespace ProcInsider.ViewModels;

public enum ProcessConversationAction { Ask, ChatAbout, ReviewRecord, FindRelatedActivity }

/// <summary>One workspace's selected-object conversation and explicit analyst actions.</summary>
public partial class ProcessConversationViewModel : ViewModelBase, IDisposable
{
    private readonly Func<IAgentRuntime?> _runtime;
    private readonly Func<AnnotationDatabaseService?> _store;
    private readonly AiInvestigationService _provider;
    private readonly Func<long> _generation;
    private readonly Func<bool> _active;
    private readonly Func<AiEvidenceReference, Task>? _navigate;
    private readonly Func<AiEvidenceReference, CancellationToken, Task<AiObjectContext?>>? _resolveTarget;
    private CancellationTokenSource? _pending;
    private readonly object _answerEvidenceGate = new();
    private CancellationTokenSource? _answerEvidenceCancellation;
    private long _answerEvidenceRevision;
    private Task _answerEvidenceLoadTask = Task.CompletedTask;
    private long _selectionRevision;
    private long _historyRevision;
    private long _selectedGeneration;
    private AiObjectContext? _target;
    private AiSubmissionConstraint? _disclosedSubmission;
    private string? _preparedRecoveryMessageId;
    private string? PreparedRecoveryMessageId
    {
        get => _preparedRecoveryMessageId;
        set { _preparedRecoveryMessageId = value; _live?.PublishRecoveryMessageId(value); }
    }
    private bool _disposed;
    private AiConversationLiveBinding? _live;
    private string? _liveId;
    private AnnotationDatabaseService? _liveStore;
    private AiConversationScope? _loadedScope;
    private AiConversationCreationOrigin? _loadedOrigin;
    public bool IsProcessesOrigin { get; set; }

    private void BindLive(AnnotationDatabaseService store, string id)
    {
        if (_live is not null && _liveId == id && ReferenceEquals(_liveStore, store)) return;
        _live?.Dispose();
        _liveId = id;
        _liveStore = store;
        _live = AiConversationLiveState.Bind(store, id, this, Messages, SelectedMessageReferences,
            () => Question, value => Question = value,
            () => IsBusy, value => IsBusy = value,
            () => SelectedMessage, value => SelectedMessage = value,
            () => SelectedReference, value => SelectedReference = value,
            () => Status, value => Status = value,
            () => string.Empty, _ => { }, nameof(Question), nameof(Status),
            () => new(AnalystInstructions, PreparedRecoveryMessageId, LastSubmissionDestination, EvidenceStatus),
            metadata => { AnalystInstructions = metadata.AnalystInstructions;
                PreparedRecoveryMessageId = metadata.RecoveryMessageId;
                LastSubmissionDestination = metadata.LastSubmissionDestination;
                EvidenceStatus = metadata.EvidenceStatus; });
    }

    private void ReleaseLive() { _live?.Dispose(); _live = null; _liveId = null; _liveStore = null; }
    private AiConversationScope ScopeFor(AiObjectContext target) =>
        _loadedScope is { } saved && saved.ObjectReference?.CanonicalObjectKey == target.Reference.CanonicalObjectKey &&
            saved.Identity == target.Reference.Identity ? saved :
        IsProcessesOrigin && target.Reference.Evidence.Kind == EvidenceReferenceKind.ProcessEntity
            ? AiConversationScope.ForProcessObject(target.Reference)
            : AiConversationScope.ForObject(target.Reference);

    private AiConversationCreationOrigin? CreationOriginFor(AiObjectContext target) =>
        _loadedScope is { } saved && saved.ObjectReference?.CanonicalObjectKey == target.Reference.CanonicalObjectKey &&
            saved.Identity == target.Reference.Identity ? _loadedOrigin :
        IsProcessesOrigin && target.Reference.Evidence.Kind == EvidenceReferenceKind.ProcessEntity
            ? AiConversationCreationOrigin.ForProcess(target.Reference) : null;

    public ProcessConversationViewModel(IAgentRuntime runtime, Func<AnnotationDatabaseService?> store,
        AiInvestigationService provider, Func<long> generation, Func<bool> active,
        Func<AiEvidenceReference, Task>? navigate = null,
        Func<AiEvidenceReference, CancellationToken, Task<AiObjectContext?>>? resolveTarget = null)
        : this(() => runtime, store, provider, generation, active, navigate, resolveTarget) { }

    public ProcessConversationViewModel(Func<IAgentRuntime?> runtime, Func<AnnotationDatabaseService?> store,
        AiInvestigationService provider, Func<long> generation, Func<bool> active,
        Func<AiEvidenceReference, Task>? navigate = null,
        Func<AiEvidenceReference, CancellationToken, Task<AiObjectContext?>>? resolveTarget = null)
    {
        _runtime = runtime;
        _store = store;
        _provider = provider;
        _generation = generation;
        _active = active;
        _navigate = navigate;
        _resolveTarget = resolveTarget;
        _provider.SettingsChanged += OnProviderSettingsChanged;
    }

    public ObservableCollection<AiConversationMessage> Messages { get; } = new();
    public ObservableCollection<AiConversationBrief> Conversations { get; } = new();
    public System.Windows.Input.ICommand? OpenConversationDetailsCommand { get; internal set; }
    public AiInvestigationViewModel? SettingsViewModel { get; internal set; }
    private IAsyncRelayCommand? _investigateCommand;
    public IAsyncRelayCommand? InvestigateCommand
    {
        get => _investigateCommand;
        internal set
        {
            if (SetProperty(ref _investigateCommand, value)) OnPropertyChanged(nameof(HasInvestigateAction));
        }
    }
    public bool HasInvestigateAction => IsProcessTarget && InvestigateCommand is not null;
    internal bool OwnsSettingsViewModel { get; set; }
    public ObservableCollection<AiEvidenceReference> SelectedMessageReferences { get; } = new();

    [ObservableProperty] private string? conversationId;
    [ObservableProperty] private AiConversationBrief? selectedConversation;
    partial void OnSelectedConversationChanged(AiConversationBrief? value)
    {
        if (value?.Id == ConversationId && OpenConversationDetailsCommand?.CanExecute(null) == true)
            OpenConversationDetailsCommand.Execute(null);
    }
    [ObservableProperty] private string question = string.Empty;
    [ObservableProperty] private string targetSummary = "Select supported evidence to ask AI.";
    [ObservableProperty] private string providerDestination = "Provider not configured.";
    [ObservableProperty] private string lastSubmissionDestination = "No AI submission in this view.";
    [ObservableProperty] private string status = "No question has been sent.";
    [ObservableProperty] private string evidenceStatus = "Select an answer to inspect its checked citations.";
    [ObservableProperty] private string historyStatus = "No conversation history loaded.";
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private AiConversationMessage? selectedMessage;
    [ObservableProperty] private AiEvidenceReference? selectedReference;

    private AiCorrectionDraft.Option? SelectedCorrection =>
        AiCorrectionDraft.ForSelected(Messages, SelectedMessage, ConversationId);
    public bool HasCorrectionOption => !string.IsNullOrEmpty(SelectedCorrection?.Draft);
    public string CorrectionActionText => SelectedCorrection?.ActionText ?? "Ask AI to correct this";
    public string CorrectionGuidance => SelectedCorrection?.Guidance ?? string.Empty;

    private bool CanPrepareCorrection() => !_disposed && !IsBusy && _target is not null &&
        _active() && _selectedGeneration == _generation() &&
        _store() is not null && !string.IsNullOrEmpty(SelectedCorrection?.Draft);

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

    public bool IsProcessTarget => _target?.Reference.Evidence.Kind == EvidenceReferenceKind.ProcessEntity;

    public void SelectProcess(ProcessInfo? process) =>
        SelectObject(process is null ? null : ProcessEvidenceAgentTools.CreateObjectContext(process));
    public void SelectObject(AiObjectContext? context)
    {
        if (_live?.IsExecuting != true || _live.HasOtherOwners != true) _pending?.Cancel();
        ReleaseLive();
        RetireAnswerEvidenceLoad();
        IsBusy = false;
        _selectionRevision++;
        _historyRevision++;
        PreparedRecoveryMessageId = null;
        _selectedGeneration = _generation();
        _target = context;
        _loadedScope = null;
        _loadedOrigin = null;
        AnalystInstructions = string.Empty;
        FollowUpCommand.NotifyCanExecuteChanged();
        EditSystemPromptCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(IsProcessTarget));
        OnPropertyChanged(nameof(HasInvestigateAction));
        ConversationId = null;
        LastSubmissionDestination = "No AI submission in this view.";
        Messages.Clear();
        Conversations.Clear();
        HistoryStatus = "No conversation history loaded.";
        SelectedMessage = null;
        SelectedReference = null;
        SelectedMessageReferences.Clear();
        TargetSummary = context is null ? "Select supported evidence to ask AI." :
            $"{context.Reference.DisplayName} | host {context.Reference.Identity.HostId} | " +
            $"session {context.Reference.Identity.EvidenceSessionId} | source run {context.Reference.SourceRunId} | " +
            $"revision {context.Reference.SourceRevision} | exact object {context.Reference.ObjectId}";
        try
        {
            var configured = _provider.LoadSettings();
            _disclosedSubmission = AiSubmissionConstraint.Capture(configured);
            ProviderDestination = $"Configured for next question: {configured.DestinationDisplay}; {configured.EndpointDisplay}";
        }
        catch (Exception ex)
        {
            _disclosedSubmission = null;
            ProviderDestination = "AI provider settings unavailable.";
            Status = $"AI provider settings could not be loaded: {ex.Message}";
            return;
        }
        Status = context is null ? "No supported evidence selected." : "Ready. Selecting evidence sends no data.";
        if (context is not null) _ = LoadSelectedHistoryAsync(_selectionRevision, _selectedGeneration, _historyRevision);
    }

    public Task<bool> LoadConversationAsync(string id, CancellationToken token = default) =>
        LoadConversationCoreAsync(id, startFresh: false, token);

    private async Task<bool> LoadConversationCoreAsync(string id, bool startFresh, CancellationToken token)
    {
        var historyRevision = ++_historyRevision;
        var target = _target;
        var store = _store();
        var revision = _selectionRevision;
        var generation = _selectedGeneration;
        if (store is null || target is null || !Current(revision, generation) || string.IsNullOrWhiteSpace(id))
        {
            Status = "Select the exact evidence object in the active capture to reopen its conversation.";
            return false;
        }
        try
        {
            var conversation = await store.LoadConversationAsync(id, token);
            if (!Current(revision, generation) || historyRevision != _historyRevision) return false;
            if (conversation is null || conversation.IsHistorical ||
                conversation.Scope.ContextType != AiConversationContextType.Object ||
                conversation.Scope.ObjectReference?.CanonicalObjectKey != target.Reference.CanonicalObjectKey ||
                conversation.Scope.Identity != target.Reference.Identity)
            {
                Status = "The saved conversation does not belong to the selected process in this capture.";
                return false;
            }
            var messages = await store.LoadConversationMessagesAsync(id, cancellationToken: token);
            if (!Current(revision, generation) || historyRevision != _historyRevision) return false;
            ReleaseLive(); // The old saved ID retains its own draft while another presenter owns it.
            if (startFresh)
            {
                RetireAnswerEvidenceLoad();
                Question = string.Empty;
                AnalystInstructions = string.Empty;
                LastSubmissionDestination = "No AI submission in this view.";
                SelectedMessageReferences.Clear();
                EvidenceStatus = "Select an answer to inspect its checked citations.";
            }
            PreparedRecoveryMessageId = null;
            ConversationId = id;
            _loadedScope = conversation.Scope;
            _loadedOrigin = conversation.CreationOrigin;
            Messages.Clear();
            Conversations.Clear();
            SelectedMessage = null;
             SelectedReference = null;
            foreach (var message in messages) Messages.Add(message);
            SelectedMessage = AiAnswerEvidencePresentation.SelectAnswer(messages);
            SetConversationBrief(conversation, messages);
            HistoryStatus = $"Loaded {messages.Count} most recent messages for conversation {id} (maximum 200).";
            Status = "Conversation ready.";
            BindLive(store, id);
            return true;
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception ex)
        {
            if (Current(revision, generation) && historyRevision == _historyRevision)
                Status = $"Conversation could not be loaded: {ex.Message}";
            return false;
        }
    }

    private bool CanFollowUp(string? prompt) => !_disposed && !IsBusy && _target is not null && _active() &&
        _selectedGeneration == _generation() && AiFollowUpQuestionClassifier.IsAnalystQuestion(prompt);
    partial void OnIsBusyChanged(bool value) { FollowUpCommand.NotifyCanExecuteChanged(); PrepareCorrectionCommand.NotifyCanExecuteChanged(); CancelCommand.NotifyCanExecuteChanged(); EditSystemPromptCommand.NotifyCanExecuteChanged(); }

    private void SetConversationBrief(AiConversation conversation, IReadOnlyList<AiConversationMessage> messages)
    {
        Conversations.Clear();
        Conversations.Add(AiConversationBrief.From(conversation, messages));
    }

    // Reopens the existing scoped conversation for surfaces that intentionally keep one thread per object.
    public async Task<bool> OpenConversationAsync(CancellationToken token = default)
    {
        var target = _target;
        var revision = _selectionRevision;
        var generation = _selectedGeneration;
        if (IsBusy || target is null || _store() is not { } store || !Current(revision, generation)) return false;
        var historyRevision = ++_historyRevision;
        try
        {
            var conversation = await store.GetOrCreateConversationAsync(ScopeFor(target),
                target.Reference.DisplayName, CreationOriginFor(target), token);
            if (!Current(revision, generation) || historyRevision != _historyRevision) return false;
            return await LoadConversationAsync(conversation.Id, token);
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception error) { if (Current(revision, generation)) Status = "Conversation unavailable: " + error.Message; return false; }
    }

    [RelayCommand(CanExecute = nameof(CanFollowUp))]
    private Task FollowUpAsync(string? prompt)
    {
        if (!CanFollowUp(prompt)) return Task.CompletedTask;
        Question = prompt!;
        return Task.CompletedTask;
    }
    private async Task LoadSelectedHistoryAsync(long revision, long generation, long historyRevision)
    {
        var store = _store();
        var target = _target;
        if (store is null || target is null) return;
        try
        {
            var found = await store.FindConversationByScopeAsync(ScopeFor(target));
            if (!Current(revision, generation) || historyRevision != _historyRevision) return;
            if (found is not null) await LoadConversationAsync(found.Id);
        }
        catch (Exception ex) { if (Current(revision, generation) && historyRevision == _historyRevision) Status = $"Saved AI history is unavailable: {ex.Message}"; }
    }

    public async Task RunActionAsync(ProcessConversationAction action, string? question = null)
    {
        if (IsBusy) return;
        if (_runtime() is AgentRuntime { IsAiPublished: false })
        {
            Status = "AI assistance is not published.";
            return;
        }
        if (action == ProcessConversationAction.ChatAbout)
        {
            if (await OpenConversationAsync()) Status = "Conversation ready. Enter a question to send.";
            return;
        }
        if (_target is null || _store() is not { } store || !_active())
        {
            Status = "Select supported evidence in an active capture before asking AI.";
            return;
        }
        var objective = action switch
        {
            ProcessConversationAction.Ask => question ?? Question,
            ProcessConversationAction.ReviewRecord => "Review all recorded fields of this exact selected original for cybersecurity and DFIR relevance. Assess only this record; do not retrieve process-generated events or related records. Retain every original field name/value and missing or partial provenance. Separate checked observations, benign explanations and hypotheses; cite the original for record-specific claims and state uncertainty.",
            ProcessConversationAction.FindRelatedActivity => IsProcessTarget ? "Find related activity for this process using bounded process tree, event, network, and persistence evidence." : "Find recorded activity related to this exact object. Distinguish time proximity, verified process ownership, and persistence version history.",
            _ => string.Empty
        };
        if (string.IsNullOrWhiteSpace(objective)) { Status = "Enter a question first."; return; }
        if (Encoding.UTF8.GetByteCount(objective) > 4_000) { Status = "Question exceeds the 4,000-byte Skill limit."; return; }
        var target = _target;
        var revision = _selectionRevision;
        var historyRevision = ++_historyRevision;
        var generation = _selectedGeneration;
        if (ShowProviderUnavailable(objective)) return;
        AiProviderSettings capture;
        try { capture = _provider.LoadSettings(); }
        catch (Exception ex) { Status = $"AI provider settings could not be loaded: {ex.Message}"; return; }
        var expected = AiSubmissionConstraint.Capture(capture);
        if (_disclosedSubmission != expected)
        {
            _disclosedSubmission = expected;
            ProviderDestination = $"Configured for next question: {capture.DestinationDisplay}; {capture.EndpointDisplay}";
            Status = "AI provider destination or model changed. Review the configured destination and submit again.";
            return;
        }
        if (!capture.IsEnabled) { Status = "Configure an AI provider in settings before sending."; return; }
        if (!capture.TryGetEndpoint(out _)) { Status = "Configure a valid AI provider endpoint before sending."; return; }
        var pending = new CancellationTokenSource();
        AiConversationLiveBinding? executionLease = null;
        _pending = pending;
        IsBusy = true;
        Status = "Running the checked AI Skill. Cancel is available.";
        try
        {
            if (target.Reference.Evidence.Kind != EvidenceReferenceKind.ProcessEntity)
            {
                var resolved = _resolveTarget is null ? null : await _resolveTarget(target.Reference, pending.Token);
                if (!Current(revision, generation) || historyRevision != _historyRevision) return;
                if (resolved is null || resolved.Reference.CanonicalObjectKey != target.Reference.CanonicalObjectKey ||
                    resolved.Reference.Identity != target.Reference.Identity)
                {
                    Status = "The exact recorded original is unavailable; no AI submission was made.";
                    return;
                }
                target = resolved;
            }
            var conversation = await store.GetOrCreateConversationAsync(ScopeFor(target),
                $"{target.Reference.DisplayName} | {target.Reference.Process?.ProcessEntityId}",
                CreationOriginFor(target), pending.Token);
            if (!Current(revision, generation) || historyRevision != _historyRevision) return;
            ConversationId = conversation.Id;
            _loadedScope = conversation.Scope;
            _loadedOrigin = conversation.CreationOrigin;
            BindLive(store, conversation.Id);
            executionLease = _live;
            if (!executionLease!.TryBeginExecution(pending))
            {
                return;
            }
            bool ExecutionValid() => ReferenceEquals(_store(), store) && generation == _generation() &&
                executionLease.IsExecutingWith(pending);
            IReadOnlyList<SkillToolQuery>? queries = action == ProcessConversationAction.FindRelatedActivity
                ? !IsProcessTarget ? [new("GetRelatedEvidence", JsonSerializer.SerializeToElement(new { }))] :
                  [new("GetProcessTree", JsonSerializer.SerializeToElement(new { })),
                   new("GetProcessEvents", JsonSerializer.SerializeToElement(new { })),
                   new("GetProcessNetwork", JsonSerializer.SerializeToElement(new { })),
                   new("GetProcessPersistence", JsonSerializer.SerializeToElement(new { }))] : null;
            var request = new AgentRuntimeRequest(conversation.Id,
                action == ProcessConversationAction.ReviewRecord ? AgentDefinition.ReviewRecordSkillId :
                queries is null ? AgentDefinition.ExplainObjectSkillId : AgentDefinition.QueryEvidenceSkillId,
                target, objective, ExecutionValid, Queries: queries,
                ExpectedSubmission: expected, AnalystInstructions: AnalystInstructions, SystemInstructionsOverride: _provider.LoadSystemPrompt(conversation.Scope.ScopeKey), PromptSubmitted: (submittedQuestion, promptRequest, promptToken) => AiConversationPromptPresentation.PublishAsync(_promptUiContext, Messages, submittedQuestion, promptRequest, () => Current(revision, generation) && historyRevision == _historyRevision, promptToken), RecoveryMessageId: action == ProcessConversationAction.Ask ? PreparedRecoveryMessageId : null);
            var runtime = _runtime() ?? throw new InvalidOperationException("The active capture has no AI runtime.");
            var result = await runtime.RunAsync(request, pending.Token);
            if (!ExecutionValid()) return;
            var messages = await store.LoadConversationMessagesAsync(conversation.Id);
            messages = await AiConversationPromptPresentation.LoadLatestAsync(store, messages, pending.Token);
            if (!ExecutionValid()) return;
            if (!Current(revision, generation) || historyRevision != _historyRevision)
            {
                executionLease.PublishCompletion(
                    $"Actual submission destination: {result.SubmissionDestination}; {result.Execution.ProviderId} / {result.Execution.ModelId}",
                    action == ProcessConversationAction.Ask && result.Execution.Status == AgentExecutionState.Completed,
                    result.Execution.Status == AgentExecutionState.Completed);
                executionLease.PublishMessages(messages, result.Execution.Status == AgentExecutionState.Completed
                    ? $"Completed with {result.Execution.ProviderId} / {result.Execution.ModelId}."
                    : $"{result.Execution.ErrorCategory}: See the full diagnostic in chat.");
                return;
            }
            LastSubmissionDestination = $"Actual submission destination: {result.SubmissionDestination}; " +
                $"{result.Execution.ProviderId} / {result.Execution.ModelId}";
            if (!Current(revision, generation) || historyRevision != _historyRevision) return;
            Messages.Clear();
            Conversations.Clear();
            foreach (var message in messages) Messages.Add(message);
            SelectedMessage = AiAnswerEvidencePresentation.SelectAnswer(messages);
            SetConversationBrief(conversation, messages);
            Status = result.Execution.Status == AgentExecutionState.Completed
                ? $"Completed with {result.Execution.ProviderId} / {result.Execution.ModelId}."
                : $"{result.Execution.ErrorCategory}: See the full diagnostic in chat.";
            if (result.Execution.Status == AgentExecutionState.Completed) PreparedRecoveryMessageId = null;
            if (action == ProcessConversationAction.Ask && result.Execution.Status == AgentExecutionState.Completed)
            {
                Question = string.Empty;
                AnalystInstructions = string.Empty;
            }
        }
        catch (OperationCanceledException)
        {
            if (Current(revision, generation) && historyRevision == _historyRevision) Status = "AI request cancelled.";
            else executionLease?.PublishStatus("AI request cancelled.");
        }
        catch (AiSubmissionChangedException ex)
        {
            if (Current(revision, generation) && historyRevision == _historyRevision)
            {
                try
                {
                    var changed = _provider.LoadSettings();
                    _disclosedSubmission = AiSubmissionConstraint.Capture(changed);
                    ProviderDestination = $"Configured for next question: {changed.DestinationDisplay}; {changed.EndpointDisplay}";
                    Status = ex.Message;
                }
                catch (Exception settingsError)
                {
                    _disclosedSubmission = null;
                    ProviderDestination = "AI provider settings unavailable.";
                    Status = $"AI provider settings could not be loaded after the destination changed: {settingsError.Message}";
                }
            }
        }
        catch (Exception ex)
        {
            if (Current(revision, generation) && historyRevision == _historyRevision) Status = $"AI request unavailable: {ex.Message}";
            else executionLease?.PublishStatus($"AI request unavailable: {ex.Message}");
        }
        finally
        {
            executionLease?.EndExecution(pending);
            if (ReferenceEquals(_pending, pending))
            {
                _pending = null;
                if (Current(revision, generation)) IsBusy = _live?.IsExecuting == true;
            }
            pending.Dispose();
        }
    }

    partial void OnSelectedMessageChanged(AiConversationMessage? value)
    {
        RefreshCorrectionAction();
        _answerEvidenceLoadTask = LoadReferencesAsync(value);
    }

    // A process context-menu action owns a fresh, exact-process thread. Creation writes only
    // annotation metadata; the caller decides whether to submit an AI action afterward.
    public async Task<bool> StartNewProcessConversationAsync(CancellationToken token = default)
    {
        var target = _target;
        var revision = _selectionRevision;
        var generation = _selectedGeneration;
        if (IsBusy || target?.Reference.Evidence.Kind != EvidenceReferenceKind.ProcessEntity ||
            !IsProcessesOrigin || _store() is not { } store || !Current(revision, generation)) return false;
        var historyRevision = ++_historyRevision;
        try
        {
            var scope = AiConversationScope.ForNewProcessObject(target.Reference, Guid.NewGuid().ToString("N"));
            var conversation = await store.GetOrCreateConversationAsync(scope, target.Reference.DisplayName,
                AiConversationCreationOrigin.ForProcess(target.Reference), token);
            if (!Current(revision, generation) || historyRevision != _historyRevision) return false;
            return await LoadConversationCoreAsync(conversation.Id, startFresh: true, token);
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception error)
        {
            if (Current(revision, generation) && historyRevision == _historyRevision)
                Status = "New conversation unavailable: " + error.Message;
            return false;
        }
    }

    private async Task LoadReferencesAsync(AiConversationMessage? message)
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
            if (message.ConversationId != ConversationId)
            {
                EvidenceStatus = "This answer does not belong to the current conversation.";
                return;
            }
            if (_store() is not { } store)
            {
                EvidenceStatus = "The annotation store for this answer is unavailable.";
                return;
            }
            var revision = _selectionRevision;
            var generation = _selectedGeneration;
            bool CurrentAnswer() => answerRevision == Interlocked.Read(ref _answerEvidenceRevision) && !answerCancellation.IsCancellationRequested && CaptureCurrent(revision, generation) && SelectedMessage?.Id == message.Id &&
                ConversationId == message.ConversationId && ReferenceEquals(store, _store());
            EvidenceStatus = "Loading checked answer citations and exact originals...";
            try
            {
                var references = await AiAnswerEvidencePresentation.LoadAsync(store, message, _resolveTarget, CurrentAnswer, answerCancellation.Token);
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

    [RelayCommand] private Task AskAsync() => RunActionAsync(ProcessConversationAction.Ask);
    [RelayCommand] private Task ChatAboutAsync() => RunActionAsync(ProcessConversationAction.ChatAbout);
    [RelayCommand] private Task ReviewRecordAsync() => RunActionAsync(ProcessConversationAction.ReviewRecord);
    [RelayCommand] private Task FindRelatedActivityAsync() => RunActionAsync(ProcessConversationAction.FindRelatedActivity);
    [RelayCommand] private Task NavigateReferenceAsync() => SelectedReference is { } reference && _navigate is not null ? _navigate(reference) : Task.CompletedTask;
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
        if (OwnsSettingsViewModel) SettingsViewModel?.CancelConnectionTest();
        IsBusy = false;
        _selectionRevision++;
        _historyRevision++;
        PreparedRecoveryMessageId = null;
        _target = null;
        FollowUpCommand.NotifyCanExecuteChanged();
        EditSystemPromptCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(IsProcessTarget));
        OnPropertyChanged(nameof(HasInvestigateAction));
        TargetSummary = "Select supported evidence to ask AI.";
        _disclosedSubmission = null;
        ConversationId = null;
        ProviderDestination = "Provider not configured.";
        LastSubmissionDestination = "No AI submission in this view.";
        Messages.Clear();
        Conversations.Clear();
        HistoryStatus = "No conversation history loaded.";
        SelectedMessage = null;
        SelectedReference = null;
        SelectedMessageReferences.Clear();
        Status = "No capture is attached.";
    }

    private bool Current(long revision, long generation) => !_disposed && _active() &&
        revision == _selectionRevision && generation == _generation();
    private bool CaptureCurrent(long revision, long generation) => !_disposed &&
        revision == _selectionRevision && generation == _generation();

    public void Dispose() { _provider.SettingsChanged -= OnProviderSettingsChanged; _disposed = true; Detach(); if (OwnsSettingsViewModel) SettingsViewModel?.Dispose(); }

}
