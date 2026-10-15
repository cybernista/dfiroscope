using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Ai;
using ProcInsider.Services.Ai;

namespace ProcInsider.ViewModels;
public partial class InvestigationDataViewModel
{
    private readonly SynchronizationContext? _promptUiContext = SynchronizationContext.Current;
    [ObservableProperty] private string analystInstructions = "";

    [RelayCommand]
    private async Task LoadPromptAsync(AiConversationMessage? message)
    {
        if (message is null || !message.HasPromptRequests || _store() is not { } store ||
            message.ConversationId != Investigation?.ConversationId) return;
        var revision = _revision; var generation = _selectedGeneration;
        try { await AiConversationPromptPresentation.LoadAsync(store, Messages, message, () => Current(revision, generation)); }
        catch (Exception) { if (Current(revision, generation)) Status = "Submitted prompt could not be loaded."; }
    }

    [RelayCommand]
    private void PreparePromptInstructions(AiPromptInstructionDraft? draft)
    {
        if (IsBusy || _mutationDepth != 0 || !Current(_revision, _selectedGeneration) || Investigation?.Target is null ||
            Investigation.Status is InvestigationState.Closed or InvestigationState.Investigating) return;
        if (AiConversationPromptPresentation.InstructionsTooLarge(draft)) { Status = AiConversationPromptPresentation.OversizeInstructionsMessage; return; }
        if (!AiConversationPromptPresentation.ValidDraft(draft, Messages)) return;
        Question = draft!.Objective;
        AnalystInstructions = draft.Instructions;
        Status = "Edited instructions prepared. Review the question and select Send to submit.";
    }

    private AiConversationScope? SystemPromptScope => Investigation?.Target is null ? null : AiConversationScope.ForInvestigation(Investigation.Id, Investigation.Target.Identity);

    public string GetSystemPromptInstructions() => SystemPromptScope is { } scope
        ? _provider.LoadSystemPrompt(scope.ScopeKey) ?? AiPromptCatalog.GetSystemInstructions(AgentDefinition.InvestigateProcessSkillId, true)
        : AiPromptCatalog.GetSystemInstructions(AgentDefinition.InvestigateProcessSkillId, true);

    public void SaveSystemPromptInstructions(string text, bool allChatsInSession)
    {
        if (IsBusy || _mutationDepth != 0 || !Current(_revision, _selectedGeneration) || Investigation?.Target is null || SystemPromptScope is not { } scope) return;
        _provider.SaveSystemPrompt(scope.ScopeKey, text, allChatsInSession);
        Status = allChatsInSession ? "System instructions saved for all chats in this session. Select Send to apply them."
            : "System instructions saved for this chat. Select Send to apply them.";
    }

    private bool CanEditSystemPrompt() => !IsBusy && _mutationDepth == 0 && Current(_revision, _selectedGeneration) && Investigation?.Target is not null;

    [RelayCommand(CanExecute = nameof(CanEditSystemPrompt))]
    private void EditSystemPrompt()
    {
        if (IsBusy || _mutationDepth != 0 || !Current(_revision, _selectedGeneration) || Investigation?.Target is null || SystemPromptScope is not { } scope) return;
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
