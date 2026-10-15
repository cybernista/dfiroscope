using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Features;
using ProcInsider.Services.Presentation;

namespace ProcInsider.ViewModels;

public partial class ProcessPresentationViewModel
{
    private ViewerCaptureBinding? _aiCaptureBinding;
    private ProcessSavedAiNavigationViewModel? _processSavedAiNavigation;
    private object? _aiDataConversation;

    // Construct only when the published Chats view asks for it. A hidden feature does not
    // acquire an annotation subscription or start a scoped query.
    public ProcessSavedAiNavigationViewModel? ProcessSavedAiNavigation
    {
        get
        {
            if (!_services.Access.IsPublished(FeatureIds.AiAssistance) || _disposed) return null;
            if (_processSavedAiNavigation is not null) return _processSavedAiNavigation;
            var navigation = new ProcessSavedAiNavigationViewModel(this);
            _processSavedAiNavigation = navigation;
            navigation.Bind(_aiCaptureBinding);
            navigation.SelectProcess(SelectedProcess?.ProcessInfo);
            return navigation;
        }
    }

    public object? AiDataConversation
    {
        get => _aiDataConversation;
        private set => SetProperty(ref _aiDataConversation, value);
    }

    [ObservableProperty]
    private bool technicalDetailsVisible = true;

    [RelayCommand]
    private void ToggleTechnicalDetails() => TechnicalDetailsVisible = !TechnicalDetailsVisible;

    private void EnsureInitialAiConversation()
    {
        if (_disposed || _readsSuspended || SelectedDataTab?.Key != DataTabKeys.Ai ||
            AiDataConversation is not null || !_services.Access.IsPublished(FeatureIds.AiAssistance)) return;
        var conversation = ProcessConversationViewModel;
        if (conversation.ConversationId is null)
            conversation.SelectProcess(SelectedProcess?.ProcessInfo);
        AiDataConversation = conversation;
    }

    private bool ShowAiConversation(object conversation, string reason)
    {
        if (!TryNavigateToDataTab(DataTabKeys.Ai, reason)) return false;
        AiDataConversation = conversation;
        return true;
    }
}
