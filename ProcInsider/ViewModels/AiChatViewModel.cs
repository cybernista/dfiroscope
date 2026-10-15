using System.Collections.ObjectModel;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Ai;
using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

/// <summary>One presentation's persistent, host-scoped general Assistant conversation.</summary>
public sealed record AiEvidenceScopeOption(EvidenceIdentity? Identity, string Label);

public partial class AiChatViewModel : ViewModelBase, IDisposable
{
    private string _generalContextId = "assistant-general";
    internal Func<bool>? WorkspaceActive { get; set; }
    private bool Active => _active() && (WorkspaceActive?.Invoke() ?? true);
    public string GeneralContextId => _generalContextId;
    public void SetGeneralContextId(string contextId)
    {
        if (string.IsNullOrWhiteSpace(contextId))
            throw new ArgumentException("A General chat context ID is required.", nameof(contextId));
        _generalContextId = contextId;
    }
    private readonly Func<IAgentRuntime?> _runtime;
    private readonly Func<AnnotationDatabaseService?> _store;
    private readonly AiInvestigationService _provider;
    private readonly FeatureAccessService _access;
    private readonly Func<long> _generation;
    private readonly Func<bool> _active;
    private readonly Func<AiGeneralSubmissionContext?> _captureContext;
    private readonly Func<AiGeneralSubmissionContext, IReadOnlyList<SkillToolQuery>> _selectQueries;
    private readonly Func<AiEvidenceReference, Task> _navigateCitation;
    private readonly Func<AiEvidenceReference, CancellationToken, Task<AiObjectContext?>>? _resolveCitation;
    private readonly Func<string, CancellationToken, Task>? _openInvestigation;
    private readonly Func<IReadOnlyList<EvidenceIdentity>>? _scopeOptions;
    private readonly Func<EvidenceIdentity?, bool>? _selectScope;
    private bool _updatingScopes;
    private CancellationTokenSource? _pending;
    private readonly object _answerEvidenceGate = new();
    private CancellationTokenSource? _answerEvidenceCancellation;
    private long _answerEvidenceRevision;
    private Task _answerEvidenceLoadTask = Task.CompletedTask;
    private long _revision, _historyRevision, _selectedGeneration;
    private AnnotationDatabaseService? _boundStore;
    private AiGeneralSubmissionContext? _disclosedContext;
    private AiSubmissionConstraint? _disclosedSubmission;
    private AiConversationScope? _scope;
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

    private void BindLive(AnnotationDatabaseService store, string id)
    {
        if (_live is not null && _liveId == id && ReferenceEquals(_liveStore, store)) return;
        ReleaseLive();
        _liveId = id;
        _liveStore = store;
        _live = AiConversationLiveState.Bind(store, id, this, Messages, SelectedMessageReferences,
            () => PromptText, value => PromptText = value,
            () => IsBusy, value => IsBusy = value,
            () => SelectedMessage, value => SelectedMessage = value,
            () => SelectedReference, value => SelectedReference = value,
            () => StatusMessage, value => StatusMessage = value,
            () => string.Empty, _ => { }, nameof(PromptText), nameof(StatusMessage),
            () => new(AnalystInstructions, PreparedRecoveryMessageId, LastSubmissionDestination, EvidenceStatus),
            metadata => { AnalystInstructions = metadata.AnalystInstructions;
                PreparedRecoveryMessageId = metadata.RecoveryMessageId;
                LastSubmissionDestination = metadata.LastSubmissionDestination;
                EvidenceStatus = metadata.EvidenceStatus; });
    }

    private void ReleaseLive() { _live?.Dispose(); _live = null; _liveId = null; _liveStore = null; }

    public AiChatViewModel(Func<IAgentRuntime?> runtime, Func<AnnotationDatabaseService?> store,
        AiInvestigationService provider, FeatureAccessService access, Func<long> generation,
        Func<bool> active, Func<AiGeneralSubmissionContext?> captureContext,
        Func<AiGeneralSubmissionContext, IReadOnlyList<SkillToolQuery>> selectQueries,
        Func<AiEvidenceReference, Task> navigateCitation,
        Func<string, CancellationToken, Task>? openInvestigation = null,
        Func<IReadOnlyList<EvidenceIdentity>>? scopeOptions = null,
        Func<EvidenceIdentity?, bool>? selectScope = null,
        Func<AiEvidenceReference, CancellationToken, Task<AiObjectContext?>>? resolveCitation = null)
    {
        _runtime = runtime; _store = store; _provider = provider; _access = access;
        _generation = generation; _active = active; _captureContext = captureContext;
        _selectQueries = selectQueries; _navigateCitation = navigateCitation;
        _openInvestigation = openInvestigation; _scopeOptions = scopeOptions; _selectScope = selectScope;
        _resolveCitation = resolveCitation;
        _provider.SettingsChanged += OnProviderSettingsChanged;
        RefreshContext();
    }

    public ObservableCollection<AiEvidenceScopeOption> EvidenceScopeOptions { get; } = new();
    [ObservableProperty] private AiEvidenceScopeOption? selectedEvidenceScope;
    public bool HasEvidenceScopeOptions => EvidenceScopeOptions.Count > 1;

    partial void OnSelectedEvidenceScopeChanged(AiEvidenceScopeOption? value)
    {
        if (_updatingScopes || value is null || _selectScope is null) return;
        if (!EvidenceScopeOptions.Contains(value) || !_selectScope(value.Identity))
        {
            RefreshContext();
            StatusMessage = "Evidence scope is no longer available in the current assessed capture. Refresh the capture and select again.";
            return;
        }
        RefreshContext();
    }

    private void RefreshScopeOptions(AiGeneralSubmissionContext? context)
    {
        _updatingScopes = true;
        try
        {
            EvidenceScopeOptions.Clear();
            var automatic = new AiEvidenceScopeOption(null, "Automatic — current capture");
            EvidenceScopeOptions.Add(automatic);
            var identities = _scopeOptions?.Invoke() ?? [];
            foreach (var identity in identities)
            {
                var sameHost = identities.Where(item => item.HostId == identity.HostId).ToArray();
                var suffix = sameHost.Length > 1 ? $" — scope {Array.IndexOf(sameHost, identity) + 1}" : "";
                EvidenceScopeOptions.Add(new(identity, $"{identity.HostId} — current capture{suffix}"));
            }
            SelectedEvidenceScope = EvidenceScopeOptions.FirstOrDefault(option => option.Identity == context?.ScopeIdentity) ?? automatic;
            OnPropertyChanged(nameof(HasEvidenceScopeOptions));
        }
        finally { _updatingScopes = false; }
    }

    public AiInvestigationViewModel? SettingsViewModel { get; internal set; }
    public ObservableCollection<AiConversationMessage> Messages { get; } = new();
    public ObservableCollection<AiEvidenceReference> SelectedMessageReferences { get; } = new();
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(SendMessageCommand))]
    private string promptText = string.Empty;
    [ObservableProperty] private string? conversationId;
    [ObservableProperty] private string contextDisplay = "Open a capture to use the general Assistant.";
    [ObservableProperty] private string evidenceDisplay = "Evidence: no capture selected";
    [ObservableProperty] private string evidenceStatus = "Select an answer to inspect its checked evidence.";
    [ObservableProperty] private string providerDestination = "Provider destination has not been reviewed.";
    [ObservableProperty] private string lastSubmissionDestination = "No AI submission in this view.";
    [ObservableProperty] private string lastSubmittedContext = "No submitted context in this view.";
    [ObservableProperty] private string statusMessage = "Open a capture to use the general Assistant.";
    [ObservableProperty] private string historyStatus = "No conversation history loaded.";
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(SendMessageCommand)),
     NotifyCanExecuteChangedFor(nameof(OpenActiveInvestigationCommand))]
    [NotifyCanExecuteChangedFor(nameof(FollowUpCommand))]
    [NotifyCanExecuteChangedFor(nameof(PrepareCorrectionCommand))]
    [NotifyCanExecuteChangedFor(nameof(EditSystemPromptCommand))]
    private bool isHistoricalView;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(SendMessageCommand))]
    [NotifyCanExecuteChangedFor(nameof(FollowUpCommand))]
    [NotifyCanExecuteChangedFor(nameof(PrepareCorrectionCommand))]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    [NotifyCanExecuteChangedFor(nameof(EditSystemPromptCommand))]
    private bool isBusy;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(OpenActiveInvestigationCommand))]
    private bool hasActiveInvestigation;
    [ObservableProperty] private AiConversationMessage? selectedMessage;
    [ObservableProperty] private AiEvidenceReference? selectedReference;

    private AiCorrectionDraft.Option? SelectedCorrection =>
        AiCorrectionDraft.ForSelected(Messages, SelectedMessage, ConversationId);
    public bool HasCorrectionOption => !string.IsNullOrEmpty(SelectedCorrection?.Draft);
    public string CorrectionActionText => SelectedCorrection?.ActionText ?? "Ask AI to correct this";
    public string CorrectionGuidance => SelectedCorrection?.Guidance ?? string.Empty;

    private bool CanPrepareCorrection() => !_disposed && Active && !IsBusy && !IsHistoricalView &&
        _scope is not null && _disclosedContext is { } context &&
        _boundStore is { } store && Current(_revision, _selectedGeneration, store, context) &&
        _access.CanExecute(FeatureIds.AiAssistance, true) &&
        !string.IsNullOrEmpty(SelectedCorrection?.Draft);

    [RelayCommand(CanExecute = nameof(CanPrepareCorrection))]
    private void PrepareCorrection()
    {
        if (!CanPrepareCorrection() || SelectedCorrection is not { } option) return;
        PromptText = option.Draft;
        PreparedRecoveryMessageId = SelectedMessage!.Id;
        StatusMessage = Encoding.UTF8.GetByteCount(option.Draft) > 4_000
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


    private static bool SameHints(AiGeneralSubmissionContext? a, AiGeneralSubmissionContext? b) =>
        a is not null && b is not null && a.ScopeIdentity == b.ScopeIdentity &&
        a.TimeStartUtc == b.TimeStartUtc && a.TimeEndUtc == b.TimeEndUtc &&
        a.Workspace == b.Workspace && a.SelectedEntityHint == b.SelectedEntityHint &&
        a.ActiveInvestigationId == b.ActiveInvestigationId;

    private static bool Valid(AiGeneralSubmissionContext? context) => context is not null &&
        context.ScopeIdentity is not null &&
        !string.IsNullOrWhiteSpace(context.ScopeIdentity.EvidenceSessionId) &&
        (string.IsNullOrWhiteSpace(context.ScopeIdentity.HostId) ||
            !string.IsNullOrWhiteSpace(context.ScopeIdentity.CaptureId)) &&
        context.CapturedUtc.Kind == DateTimeKind.Utc &&
        context.TimeStartUtc is not { Kind: not DateTimeKind.Utc } &&
        context.TimeEndUtc is not { Kind: not DateTimeKind.Utc } &&
        (context.TimeStartUtc is null || context.TimeEndUtc is null || context.TimeStartUtc <= context.TimeEndUtc) &&
        context.Workspace is not null && Encoding.UTF8.GetByteCount(context.Workspace) <= 160 &&
        context.SelectedEntityHint is not null && Encoding.UTF8.GetByteCount(context.SelectedEntityHint) <= 500 &&
        Encoding.UTF8.GetByteCount(context.ActiveInvestigationId ?? "") <= 160;

    private bool Current(long revision, long generation, AnnotationDatabaseService store,
        AiGeneralSubmissionContext context)
    {
        if (_disposed || !Active || revision != _revision || generation != _generation() ||
            !ReferenceEquals(store, _boundStore) || !ReferenceEquals(store, _store())) return false;
        try { return SameHints(context, _captureContext()); }
        catch { return false; }
    }

    public void SetAnnotationStore(AnnotationDatabaseService? _) => RefreshContext();

    /// <summary>Rebase host-scoped history without creating a conversation or sending data.</summary>
    [RelayCommand]
    public void RefreshContext()
    {
        if (_live?.IsExecuting != true || _live.HasOtherOwners != true) _pending?.Cancel();
        ReleaseLive();
        RetireAnswerEvidenceLoad();
        IsBusy = false;
        SettingsViewModel?.CancelConnectionTest();
        var revision = ++_revision;
        var historyRevision = ++_historyRevision;
        PreparedRecoveryMessageId = null;
        _selectedGeneration = _generation();
        _boundStore = _store();
        ConversationId = null;
        AnalystInstructions = string.Empty;
        IsHistoricalView = false;
        HasActiveInvestigation = false;
        SelectedMessage = null; SelectedReference = null;
        Messages.Clear(); SelectedMessageReferences.Clear();
        HistoryStatus = "No conversation history loaded.";
        LastSubmissionDestination = "No AI submission in this view.";
        LastSubmittedContext = "No submitted context in this view.";
        AiGeneralSubmissionContext? context;
        try { context = _captureContext(); }
        catch (Exception ex) { context = null; StatusMessage = $"Assistant context unavailable: {ex.Message}"; }
        RefreshScopeOptions(context);
        if (!Valid(context) || !_access.IsPublished(FeatureIds.AiAssistance) || _boundStore is null)
        {
            _scope = null; _disclosedContext = null;
            ContextDisplay = "Open an active capture to use the general Assistant.";
            EvidenceDisplay = "Evidence: no capture selected";
            SendMessageCommand.NotifyCanExecuteChanged();
            EditSystemPromptCommand.NotifyCanExecuteChanged();
            return;
        }
        _disclosedContext = context;
        HasActiveInvestigation = _openInvestigation is not null &&
            !string.IsNullOrWhiteSpace(context!.ActiveInvestigationId);
        _scope = AiConversationScope.ForGeneral(_generalContextId, context!.ScopeIdentity);
        ContextDisplay = Describe(context);
        EvidenceDisplay = string.IsNullOrWhiteSpace(context.ScopeIdentity.HostId)
            ? "Evidence: current capture — select an evidence scope"
            : $"Evidence: {context.ScopeIdentity.HostId} — current capture";
        ReloadSettings();
        StatusMessage = "General conversation ready. Selection changes send no data.";
        SendMessageCommand.NotifyCanExecuteChanged();
        EditSystemPromptCommand.NotifyCanExecuteChanged();
        _ = LoadExistingAsync(_scope, context, _boundStore, revision, _selectedGeneration, historyRevision);
    }

    [RelayCommand]
    public void ReloadSettings()
    {
        if (!_access.IsPublished(FeatureIds.AiAssistance)) return;
        try
        {
            var settings = _provider.LoadSettings();
            _disclosedSubmission = AiSubmissionConstraint.Capture(settings);
            ProviderDestination = $"Configured for next question: {settings.DestinationDisplay}; {settings.EndpointDisplay}";
        }
        catch (Exception ex)
        {
            _disclosedSubmission = null;
            ProviderDestination = "AI provider settings unavailable.";
            StatusMessage = $"AI provider settings could not be loaded: {ex.Message}";
        }
    }

    private void OnProviderSettingsChanged(object? sender, EventArgs args)
    {
        if (!_disposed && !IsBusy) ReloadSettings();
    }

    private async Task LoadExistingAsync(AiConversationScope scope, AiGeneralSubmissionContext context,
        AnnotationDatabaseService store, long revision, long generation, long historyRevision)
    {
        try
        {
            var saved = await store.FindConversationByScopeAsync(scope);
            if (!Current(revision, generation, store, context) || historyRevision != _historyRevision) return;
            if (saved is not null) await LoadConversationAsync(saved.Id);
        }
        catch (Exception ex)
        {
            if (Current(revision, generation, store, context) && historyRevision == _historyRevision)
                StatusMessage = $"Saved general conversation unavailable: {ex.Message}";
        }
    }

    public async Task<bool> LoadConversationAsync(string id, CancellationToken token = default)
    {
        if (IsBusy && _pending is { IsCancellationRequested: false } &&
            _live?.HasOtherOwners != true) return false;
        var context = _disclosedContext;
        var scope = _scope;
        var store = _boundStore;
        var revision = _revision;
        var generation = _selectedGeneration;
        var historyRevision = ++_historyRevision;
        PreparedRecoveryMessageId = null;
        if (context is null || scope is null || store is null || string.IsNullOrWhiteSpace(id) ||
            !Current(revision, generation, store, context)) return false;
        try
        {
            var saved = await store.LoadConversationAsync(id, token);
            if (!Current(revision, generation, store, context) || historyRevision != _historyRevision) return false;
            if (saved is null || saved.IsHistorical || saved.Scope.ContextType != AiConversationContextType.General ||
                saved.Scope.ScopeKey != scope.ScopeKey)
            {
                StatusMessage = "The saved general conversation belongs to another host or capture.";
                return false;
            }
            var messages = await store.LoadConversationMessagesAsync(id, cancellationToken: token);
            if (!Current(revision, generation, store, context) || historyRevision != _historyRevision) return false;
            ReleaseLive();
            ConversationId = id;
            IsHistoricalView = false;
            SelectedMessage = null; SelectedReference = null;
            Messages.Clear();
            foreach (var message in messages) Messages.Add(message);
            SelectedMessage = AiAnswerEvidencePresentation.SelectAnswer(messages);
            HistoryStatus = $"Loaded {messages.Count} most recent general messages (maximum 200).";
            BindLive(store, id);
            return true;
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception ex)
        {
            if (Current(revision, generation, store, context) && historyRevision == _historyRevision)
                StatusMessage = $"General conversation could not be loaded: {ex.Message}";
            return false;
        }
    }

    /// <summary>Reads migrated legacy chat as history; it can never become a Runtime conversation.</summary>
    public async Task<bool> LoadHistoricalConversationAsync(string id, CancellationToken token = default)
    {
        if ((IsBusy && _live?.HasOtherOwners != true) || string.IsNullOrWhiteSpace(id) ||
            !Active || _boundStore is not { } store)
            return false;
        ReleaseLive();
        var revision = _revision;
        var generation = _selectedGeneration;
        var historyRevision = ++_historyRevision;
        PreparedRecoveryMessageId = null;
        try
        {
            var saved = await store.LoadConversationAsync(id, token);
            if (_disposed || revision != _revision || generation != _generation() ||
                historyRevision != _historyRevision || !ReferenceEquals(store, _store())) return false;
            if (saved is not { IsHistorical: true } ||
                saved.Scope.ContextType != AiConversationContextType.General)
            {
                StatusMessage = "The selected record is not historical general chat.";
                return false;
            }
            var messages = await store.LoadConversationMessagesAsync(id, cancellationToken: token);
            if (_disposed || revision != _revision || generation != _generation() ||
                historyRevision != _historyRevision || !ReferenceEquals(store, _store())) return false;
            ConversationId = id;
            IsHistoricalView = true;
            HasActiveInvestigation = false;
            ContextDisplay = "Historical legacy chat: original host, capture and evidence scope were not recorded. Read only; these messages are not checked Runtime evidence.";
            EvidenceDisplay = "Evidence: original scope unavailable — saved historical chat";
            SelectedMessage = null; SelectedReference = null;
            Messages.Clear(); SelectedMessageReferences.Clear();
            foreach (var message in messages) Messages.Add(message);
            HistoryStatus = $"Loaded {messages.Count} most recent historical chat messages (maximum 200).";
            StatusMessage = "Historical chat is read only. Select New chat to ask about the current capture.";
            return true;
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception ex)
        {
            if (revision == _revision && historyRevision == _historyRevision)
                StatusMessage = $"Historical chat unavailable: {ex.Message}";
            return false;
        }
    }

    private bool CanFollowUp(string? prompt) => !_disposed && !IsBusy && !IsHistoricalView &&
        Active && _scope is not null && AiFollowUpQuestionClassifier.IsAnalystQuestion(prompt) &&
        _access.CanExecute(FeatureIds.AiAssistance, true);

    [RelayCommand(CanExecute = nameof(CanFollowUp))]
    private Task FollowUpAsync(string? prompt)
    {
        if (!CanFollowUp(prompt)) return Task.CompletedTask;
        PromptText = prompt!;
        return Task.CompletedTask;
    }

    private bool CanSendMessage() => _access.CanExecute(FeatureIds.AiAssistance,
        Active && !IsBusy && !IsHistoricalView && _scope is not null && !string.IsNullOrWhiteSpace(PromptText));

    private bool CanOpenActiveInvestigation() => _access.CanExecute(FeatureIds.AiAssistance,
        HasActiveInvestigation && !IsHistoricalView && Active);

    [RelayCommand(CanExecute = nameof(CanOpenActiveInvestigation))]
    private async Task OpenActiveInvestigationAsync()
    {
        if (!CanOpenActiveInvestigation() || _disclosedContext is not { } context ||
            _openInvestigation is null) return;
        AiGeneralSubmissionContext? current;
        try { current = _captureContext(); }
        catch (Exception ex) { StatusMessage = $"Investigation context unavailable: {ex.Message}"; return; }
        if (!SameHints(context, current) || !Valid(current) ||
            !ReferenceEquals(_boundStore, _store()) || _selectedGeneration != _generation())
        {
            RefreshContext();
            StatusMessage = "Investigation context changed. Review the active investigation and open it again.";
            return;
        }
        var id = context.ActiveInvestigationId;
        if (string.IsNullOrWhiteSpace(id)) return;
        var revision = _revision;
        try
        {
            await _openInvestigation(id, CancellationToken.None);
        }
        catch (Exception ex)
        {
            if (revision == _revision && !_disposed)
                StatusMessage = $"Saved investigation could not be opened: {ex.Message}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanSendMessage))]
    public async Task SendMessageAsync()
    {
        if (!CanSendMessage()) return;
        var objective = PromptText.Trim();
        if (Encoding.UTF8.GetByteCount(objective) > 4_000)
        {
            StatusMessage = "Question exceeds the 4,000-byte Skill limit.";
            return;
        }
        AiGeneralSubmissionContext? submitted;
        try { submitted = _captureContext(); }
        catch (Exception ex) { StatusMessage = $"Assistant context unavailable: {ex.Message}"; return; }
        if (!Valid(submitted) || _store() is not { } store || !Active)
        {
            StatusMessage = "Open an active capture before sending a general question.";
            return;
        }
        if (!SameHints(_disclosedContext, submitted) || _scope?.Identity != submitted!.ScopeIdentity ||
            !ReferenceEquals(store, _boundStore))
        {
            if (_scope?.Identity == submitted!.ScopeIdentity && ReferenceEquals(store, _boundStore))
            {
                _disclosedContext = submitted;
                ContextDisplay = Describe(submitted);
                RefreshScopeOptions(submitted);
            }
            else
            {
                RefreshContext();
                StatusMessage = "Assistant context changed. Review the displayed host, time, workspace and selection, then submit again.";
                return;
            }
        }
        if (ShowProviderUnavailable(objective)) return;
        AiProviderSettings settings;
        AiSubmissionConstraint expected;
        try { settings = _provider.LoadSettings(); expected = AiSubmissionConstraint.Capture(settings); }
        catch (Exception ex) { StatusMessage = $"AI provider settings could not be loaded: {ex.Message}"; return; }
        if (expected != _disclosedSubmission)
        {
            _disclosedSubmission = expected;
            ProviderDestination = $"Configured for next question: {settings.DestinationDisplay}; {settings.EndpointDisplay}";
            StatusMessage = "AI destination or model changed. Review it and submit again.";
            return;
        }
        if (!settings.IsEnabled || !settings.TryGetEndpoint(out _) || string.IsNullOrWhiteSpace(settings.ModelName))
        {
            StatusMessage = "Configure a valid AI provider and model before sending.";
            return;
        }
        submitted = submitted! with { CapturedUtc = DateTime.UtcNow };
        IReadOnlyList<SkillToolQuery> queries;
        try { queries = _selectQueries(submitted!) ?? throw new InvalidOperationException("No query selection was returned."); }
        catch (Exception ex) { StatusMessage = $"Checked general query unavailable: {ex.Message}"; return; }
        var revision = _revision;
        var historyRevision = ++_historyRevision;
        var generation = _selectedGeneration;
        var pending = new CancellationTokenSource();
        AiConversationLiveBinding? executionLease = null;
        _pending = pending;
        IsBusy = true;
        LastSubmittedContext = "Context captured for this question: " + Describe(submitted!, queries);
        StatusMessage = "Running checked general Assistant Skill. Cancel is available.";
        try
        {
            var conversation = await store.GetOrCreateConversationAsync(_scope!,
                string.IsNullOrWhiteSpace(submitted!.ScopeIdentity.HostId)
                    ? "General Assistant | host unspecified"
                    : $"General Assistant | {submitted.ScopeIdentity.HostId}", pending.Token);
            if (!Current(revision, generation, store, submitted) || historyRevision != _historyRevision) return;
            ConversationId = conversation.Id;
            BindLive(store, conversation.Id);
            executionLease = _live;
            if (!executionLease!.TryBeginExecution(pending)) return;
            bool ExecutionValid() => ReferenceEquals(_store(), store) && generation == _generation() &&
                executionLease.IsExecutingWith(pending);
            var runtime = _runtime() ?? throw new InvalidOperationException("The active capture has no AI runtime.");
            var result = await runtime.RunAsync(new AgentRuntimeRequest(conversation.Id,
                AgentDefinition.QueryEvidenceSkillId, null, objective,
                ExecutionValid,
                Queries: queries, ExpectedSubmission: expected, GeneralContext: submitted, AnalystInstructions: AnalystInstructions, SystemInstructionsOverride: _provider.LoadSystemPrompt(_scope!.ScopeKey), PromptSubmitted: (submittedQuestion, promptRequest, promptToken) => AiConversationPromptPresentation.PublishAsync(_promptUiContext, Messages, submittedQuestion, promptRequest, () => Current(revision, generation, store, submitted) && historyRevision == _historyRevision, promptToken), RecoveryMessageId: PreparedRecoveryMessageId), pending.Token);
            if (!ExecutionValid()) return;
            var messages = await store.LoadConversationMessagesAsync(conversation.Id, cancellationToken: pending.Token);
            if (!ExecutionValid()) return;
            messages = await AiConversationPromptPresentation.LoadLatestAsync(store, messages, pending.Token);
            if (!ExecutionValid()) return;
            if (!Current(revision, generation, store, submitted) || historyRevision != _historyRevision)
            {
                executionLease.PublishCompletion(
                    $"Actual submission destination: {result.SubmissionDestination}; {result.Execution.ProviderId} / {result.Execution.ModelId}",
                    result.Execution.Status == AgentExecutionState.Completed,
                    result.Execution.Status == AgentExecutionState.Completed);
                executionLease.PublishMessages(messages, result.Execution.Status == AgentExecutionState.Completed
                    ? "General Assistant response saved. Checked evidence, if any, appears in the answer citations."
                    : $"{result.Execution.ErrorCategory}: See the full diagnostic in chat.");
                return;
            }
            LastSubmissionDestination = $"Actual submission destination: {result.SubmissionDestination}; " +
                $"{result.Execution.ProviderId} / {result.Execution.ModelId}";
            Messages.Clear(); SelectedMessage = null;
            foreach (var message in messages) Messages.Add(message);
            SelectedMessage = AiAnswerEvidencePresentation.SelectAnswer(messages);
            HistoryStatus = $"Loaded {messages.Count} most recent general messages (maximum 200).";
            StatusMessage = result.Execution.Status == AgentExecutionState.Completed
                ? "General Assistant response saved. Checked evidence, if any, appears in the answer citations."
                : $"{result.Execution.ErrorCategory}: See the full diagnostic in chat.";
            if (result.Execution.Status == AgentExecutionState.Completed)
            {
                PreparedRecoveryMessageId = null;
                PromptText = string.Empty;
                AnalystInstructions = string.Empty;
            }
        }
        catch (OperationCanceledException)
        {
            if (Current(revision, generation, store, submitted!)) StatusMessage = "General Assistant request cancelled.";
            else executionLease?.PublishStatus("General Assistant request cancelled.");
        }
        catch (AiSubmissionChangedException ex)
        {
            if (Current(revision, generation, store, submitted!))
            {
                ReloadSettings();
                StatusMessage = ex.Message;
            }
        }
        catch (Exception ex)
        {
            if (Current(revision, generation, store, submitted!)) StatusMessage = $"General Assistant unavailable: {ex.Message}";
            else executionLease?.PublishStatus($"General Assistant unavailable: {ex.Message}");
        }
        finally
        {
            executionLease?.EndExecution(pending);
            if (ReferenceEquals(_pending, pending))
            {
                _pending = null;
                if (Current(revision, generation, store, submitted!)) IsBusy = _live?.IsExecuting == true;
            }
            pending.Dispose();
        }
    }

    partial void OnSelectedMessageChanged(AiConversationMessage? value)
    {
        RefreshCorrectionAction();
        _answerEvidenceLoadTask = LoadReferencesAsync(value);
    }

    private bool CaptureCurrent(long revision, long generation, AnnotationDatabaseService store,
        AiGeneralSubmissionContext context) => !_disposed && revision == _revision &&
        generation == _generation() && ReferenceEquals(store, _boundStore) &&
        ReferenceEquals(store, _store()) && Equals(context, _disclosedContext);

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
            SelectedMessageReferences.Clear();
             SelectedReference = null;
            EvidenceStatus = "Select an answer to inspect its checked evidence.";
            if (message is null || !message.Role.Equals("assistant", StringComparison.OrdinalIgnoreCase)) return;
            if (message.Status == "Local")
            {
                EvidenceStatus = "This local message has no checked capture citations.";
                return;
            }
            if (message.ConversationId != ConversationId)
            {
                EvidenceStatus = "This answer does not belong to the current conversation.";
                return;
            }
            if (_boundStore is not { } store || _disclosedContext is not { } context)
            {
                EvidenceStatus = "The annotation store or capture context for this answer is unavailable.";
                return;
            }
            var revision = _revision;
            var generation = _selectedGeneration;
            bool CurrentAnswer() => answerRevision == Interlocked.Read(ref _answerEvidenceRevision) && !answerCancellation.IsCancellationRequested && CaptureCurrent(revision, generation, store, context) &&
                SelectedMessage?.Id == message.Id && SelectedMessage?.ConversationId == message.ConversationId &&
                ConversationId == message.ConversationId;
            EvidenceStatus = "Loading checked answer citations and exact originals...";
            try
            {
                var references = await AiAnswerEvidencePresentation.LoadAsync(store, message, _resolveCitation, CurrentAnswer, answerCancellation.Token);
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
                        : $"{references.Count} checked citation(s) for this answer.";
                }
            }
            catch (Exception ex)
            {
                lock (_answerEvidenceGate) if (CurrentAnswer()) EvidenceStatus = $"Answer citations unavailable: {ex.Message}";
            }
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

    [RelayCommand]
    private Task OpenCitationAsync() => SelectedReference is { } reference
        ? _navigateCitation(reference) : Task.CompletedTask;

    private bool CanCancel() => IsBusy;

    [RelayCommand(CanExecute = nameof(CanCancel))]
    public void Cancel()
    {
        _live?.CancelExecution();
        _pending?.Cancel();
    }

    public void Dispose()
    {
        if (_live?.IsExecuting != true || _live.HasOtherOwners != true) _pending?.Cancel();
        ReleaseLive();
        RetireAnswerEvidenceLoad();
        _disposed = true;
        _provider.SettingsChanged -= OnProviderSettingsChanged;
        SettingsViewModel?.Dispose();
        _revision++;
        _boundStore = null; _pending = null;
        Messages.Clear(); SelectedMessageReferences.Clear();
    }

    private string Describe(AiGeneralSubmissionContext context, IReadOnlyList<SkillToolQuery>? selectedQueries = null) =>
        $"General conversation | session {context.ScopeIdentity.EvidenceSessionId} | " +
        $"capture {context.ScopeIdentity.CaptureId} | CaseId {(context.ScopeIdentity.CaseId.Length == 0 ? "unassigned (empty)" : context.ScopeIdentity.CaseId)} | host " +
        $"{(string.IsNullOrWhiteSpace(context.ScopeIdentity.HostId) ? "unspecified (evidence tools unavailable)" : context.ScopeIdentity.HostId)} | " +
        $"time {(context.TimeStartUtc is null && context.TimeEndUtc is null ? "unspecified" :
            $"{context.TimeStartUtc:O} to {context.TimeEndUtc:O}")} | workspace {context.Workspace} | " +
        $"selected entity {(string.IsNullOrWhiteSpace(context.SelectedEntityHint) ? "none" : context.SelectedEntityHint)} | " +
        $"active investigation {context.ActiveInvestigationId ?? "none"}. " +
        "Selection and investigation labels are hints, not checked evidence; use exact citations for evidence. " +
        DescribeCheckedQuery(context, selectedQueries);

    private string DescribeCheckedQuery(AiGeneralSubmissionContext context,
        IReadOnlyList<SkillToolQuery>? selectedQueries)
    {
        try
        {
            var query = (selectedQueries ?? _selectQueries(context))
                .FirstOrDefault(item => item.ToolId == "GetHostProcesses");
            if (string.IsNullOrWhiteSpace(context.ScopeIdentity.HostId))
                return "Evidence tools are unavailable because an exact assessed evidence scope is unresolved. If case choices are shown, select Evidence scope; otherwise refresh the capture and check its host/capture identity.";
            if (query is null) return "No checked evidence retrieval is preselected for these hints. Registered read tools remain available within the displayed host and capture scope.";
            var arguments = query.Arguments;
            if (!arguments.TryGetProperty("from_utc_ticks", out var lower) ||
                !arguments.TryGetProperty("to_utc_ticks", out var upper))
                return "Initial checked retrieval is a bounded recorded host-process page without a time filter (up to 25 rows). Registered read tools remain available within the displayed host and capture scope.";
            var from = new DateTime(lower.GetInt64(), DateTimeKind.Utc);
            var to = new DateTime(upper.GetInt64(), DateTimeKind.Utc);
            var partial = context.TimeStartUtc != from || context.TimeEndUtc != to;
            return $"Initial checked retrieval searches process starts from {from:O} to {to:O} (up to 25 rows). " +
                (partial ? "This seven-day-or-shorter interval covers only part of the selected time hint." :
                    "This is the selected time interval.") +
                " Registered read tools remain available within the displayed host and capture scope.";
        }
        catch (Exception)
        {
            return "Checked retrieval preview is unavailable; a valid query is required before evidence can be read.";
        }
    }
}
