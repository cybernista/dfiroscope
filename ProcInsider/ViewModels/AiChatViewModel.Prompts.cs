using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Ai;
using ProcInsider.Services.Ai;

namespace ProcInsider.ViewModels;
public partial class AiChatViewModel
{
    private readonly SynchronizationContext? _promptUiContext = SynchronizationContext.Current;
    [ObservableProperty] private string analystInstructions = "";

    [RelayCommand]
    private async Task LoadPromptAsync(AiConversationMessage? message)
    {
        if (message is null || !message.HasPromptRequests || _store() is not { } store ||
            _disclosedContext is not { } context || message.ConversationId != ConversationId) return;
        var revision = _revision; var generation = _selectedGeneration; var history = _historyRevision;
        try
        {
            await AiConversationPromptPresentation.LoadAsync(store, Messages, message,
                () => Current(revision, generation, store, context) && history == _historyRevision);
        }
        catch (Exception) { if (Current(revision, generation, store, context)) StatusMessage = "Submitted prompt could not be loaded."; }
    }

    [RelayCommand]
    private void PreparePromptInstructions(AiPromptInstructionDraft? draft)
    {
        if (_disposed || IsBusy || IsHistoricalView || !Active || _scope is null ||
            _selectedGeneration != _generation()) return;
        if (AiConversationPromptPresentation.InstructionsTooLarge(draft)) { StatusMessage = AiConversationPromptPresentation.OversizeInstructionsMessage; return; }
        if (!AiConversationPromptPresentation.ValidDraft(draft, Messages)) return;
        PromptText = draft!.Objective;
        AnalystInstructions = draft.Instructions;
        StatusMessage = "Edited instructions prepared. Review the question and select Send to submit.";
    }

    public string GetSystemPromptInstructions() => _scope is { } scope
        ? _provider.LoadSystemPrompt(scope.ScopeKey) ?? AiPromptCatalog.GetSystemInstructions(AgentDefinition.QueryEvidenceSkillId, false)
        : AiPromptCatalog.GetSystemInstructions(AgentDefinition.QueryEvidenceSkillId, false);

    public void SaveSystemPromptInstructions(string text, bool allChatsInSession)
    {
        if (!CanEditSystemPrompt() || _scope is not { } scope) return;
        _provider.SaveSystemPrompt(scope.ScopeKey, text, allChatsInSession);
        StatusMessage = allChatsInSession
            ? "System instructions saved for all chats in this session. Select Send to apply them."
            : "System instructions saved for this chat. Select Send to apply them.";
    }

    private bool CanEditSystemPrompt() => !_disposed && !IsBusy && !IsHistoricalView && Active && _scope is not null;

    [RelayCommand(CanExecute = nameof(CanEditSystemPrompt))]
    private void EditSystemPrompt()
    {
        if (!CanEditSystemPrompt() || _scope is not { } scope) return;
        try
        {
            var edit = ProcInsider.Views.Features.Ai.SystemPromptWindow.Edit(System.Windows.Application.Current?.MainWindow,
                GetSystemPromptInstructions(), _provider.SystemPromptAppliesToAllChats(scope.ScopeKey));
            if (edit is not null) SaveSystemPromptInstructions(edit.Instructions, edit.AllChatsInSession);
        }
        catch (Exception ex) { StatusMessage = "System instructions could not be saved: " + ex.Message; }
    }

    private bool ShowProviderUnavailable(string objective)
    {
        var readiness = _provider.GetProviderReadiness();
        if (readiness.IsAvailable) return false;
        StatusMessage = readiness.Message;
        return true;
    }
}
