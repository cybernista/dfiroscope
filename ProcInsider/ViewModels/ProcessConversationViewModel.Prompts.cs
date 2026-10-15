using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Ai;
using ProcInsider.Services.Ai;

namespace ProcInsider.ViewModels;
public partial class ProcessConversationViewModel
{
    private readonly SynchronizationContext? _promptUiContext = SynchronizationContext.Current;
    [ObservableProperty] private string analystInstructions = "";

    [RelayCommand]
    private async Task LoadPromptAsync(AiConversationMessage? message)
    {
        if (message is null || !message.HasPromptRequests || _store() is not { } store || message.ConversationId != ConversationId) return;
        var revision = _selectionRevision; var generation = _selectedGeneration; var history = _historyRevision;
        try
        {
            await AiConversationPromptPresentation.LoadAsync(store, Messages, message,
                () => Current(revision, generation) && history == _historyRevision && ReferenceEquals(store, _store()));
        }
        catch (Exception) { if (Current(revision, generation)) Status = "Submitted prompt could not be loaded."; }
    }

    [RelayCommand]
    private void PreparePromptInstructions(AiPromptInstructionDraft? draft)
    {
        if (_disposed || IsBusy || _target is null || !_active() || _selectedGeneration != _generation()) return;
        if (AiConversationPromptPresentation.InstructionsTooLarge(draft)) { Status = AiConversationPromptPresentation.OversizeInstructionsMessage; return; }
        if (!AiConversationPromptPresentation.ValidDraft(draft, Messages)) return;
        Question = draft!.Objective;
        AnalystInstructions = draft.Instructions;
        Status = "Edited instructions prepared. Review the question and select Send to submit.";
    }

    private AiConversationScope? SystemPromptScope => _target is null ? null : ScopeFor(_target);

    public string GetSystemPromptInstructions() => SystemPromptScope is { } scope
        ? _provider.LoadSystemPrompt(scope.ScopeKey) ?? AiPromptCatalog.GetSystemInstructions(AgentDefinition.ExplainObjectSkillId, true)
        : AiPromptCatalog.GetSystemInstructions(AgentDefinition.ExplainObjectSkillId, true);

    public void SaveSystemPromptInstructions(string text, bool allChatsInSession)
    {
        if (_disposed || IsBusy || _target is null || !Current(_selectionRevision, _selectedGeneration) || SystemPromptScope is not { } scope) return;
        _provider.SaveSystemPrompt(scope.ScopeKey, text, allChatsInSession);
        Status = allChatsInSession ? "System instructions saved for all chats in this session. Select Send to apply them."
            : "System instructions saved for this chat. Select Send to apply them.";
    }

    private bool CanEditSystemPrompt() => !_disposed && !IsBusy && _target is not null && Current(_selectionRevision, _selectedGeneration);

    [RelayCommand(CanExecute = nameof(CanEditSystemPrompt))]
    private void EditSystemPrompt()
    {
        if (_disposed || IsBusy || _target is null || !Current(_selectionRevision, _selectedGeneration) || SystemPromptScope is not { } scope) return;
        try
        {
            var edit = ProcInsider.Views.Features.Ai.SystemPromptWindow.Edit(System.Windows.Application.Current?.MainWindow,
                GetSystemPromptInstructions(), _provider.SystemPromptAppliesToAllChats(scope.ScopeKey));
            if (edit is not null) SaveSystemPromptInstructions(edit.Instructions, edit.AllChatsInSession);
        }
        catch (Exception ex) { Status = "System instructions could not be saved: " + ex.Message; }
    }

    private void OnProviderSettingsChanged(object? sender, EventArgs args)
    {
        if (!_disposed && !IsBusy) RefreshProviderDisclosure();
    }

    public void RefreshProviderDisclosure()
    {
        if (_disposed || IsBusy) return;
        try
        {
            var settings = _provider.LoadSettings();
            _disclosedSubmission = AiSubmissionConstraint.Capture(settings);
            ProviderDestination = $"Configured for next submission: {settings.DestinationDisplay}; {settings.EndpointDisplay}";
        }
        catch (Exception) { _disclosedSubmission = null; ProviderDestination = "AI provider settings unavailable."; }
    }
    private bool ShowProviderUnavailable(string objective)
    {
        var readiness = _provider.GetProviderReadiness();
        if (readiness.IsAvailable) return false;
        Status = readiness.Message;
        return true;
    }
}
