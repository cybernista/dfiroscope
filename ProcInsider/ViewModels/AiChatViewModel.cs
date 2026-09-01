using System.Collections.ObjectModel;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public partial class AiChatViewModel : ViewModelBase, IDisposable
{
    private const string ExplorerConversationId = "explorer-ai-chat";
    private const int MaxTranscriptMessages = 30;

    private readonly AiInvestigationService _aiService;
    private readonly string _systemPrompt = $"""
        You are a cybersecurity and DFIR assistant embedded in {ProductIdentity.DisplayName}.
        This Explorer chat does not automatically include process, event, or artifact evidence.
        Use only details the analyst explicitly provides in the chat.
        Separate observed facts from hypotheses, state uncertainty, and suggest concrete {ProductIdentity.DisplayName} or local-host pivots.
        Do not provide malware execution instructions, evasion guidance, persistence code, or offensive step-by-step exploitation.
        """;
    private AnnotationDatabaseService? _annotationStore;
    private readonly FeatureAccessService _featureAccess;
    private CancellationTokenSource? _requestCts;

    public AiChatViewModel(
        AiInvestigationService aiService,
        AnnotationDatabaseService? annotationStore,
        FeatureAccessService? featureAccess = null)
    {
        _aiService = aiService;
        _annotationStore = annotationStore;
        _featureAccess = featureAccess ?? new FeatureAccessService(CurrentEducationalReleaseProfile.RuntimeCatalog);
        ReloadSettings();
        _ = LoadTranscriptAsync();
    }

    public ObservableCollection<AiChatMessage> Messages { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SendMessageCommand))]
    private string promptText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsCloudProvider))]
    [NotifyPropertyChangedFor(nameof(ProviderStatusDisplay))]
    [NotifyPropertyChangedFor(nameof(PrivacyWarning))]
    private AiProviderSettings currentSettings = AiProviderSettings.CreateDefault();

    [ObservableProperty]
    private string statusMessage = "Explorer AI chat is ready. No evidence context is attached automatically.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SendMessageCommand))]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    private bool isBusy;

    public bool IsCloudProvider => CurrentSettings.IsCloudProvider;

    public string ProviderStatusDisplay
    {
        get
        {
            var endpoint = string.IsNullOrWhiteSpace(CurrentSettings.BaseUrl) ? "no endpoint" : CurrentSettings.BaseUrl;
            var model = string.IsNullOrWhiteSpace(CurrentSettings.ModelName) ? "no model" : CurrentSettings.ModelName;
            return $"{CurrentSettings.ProviderDisplayName}; {model}; {endpoint}";
        }
    }

    public string PrivacyWarning
    {
        get
        {
            if (CurrentSettings.IsCloudProvider)
            {
                var endpoint = string.IsNullOrWhiteSpace(CurrentSettings.BaseUrl) ? "the configured endpoint" : CurrentSettings.BaseUrl;
                return $"Cloud/commercial provider selected: chat text is sent to {endpoint} when Send is clicked.";
            }

            if (CurrentSettings.ProviderKind == AiProviderKind.LocalOpenAiCompatible)
            {
                return "Local-first provider selected. Chat text stays on this host if the endpoint is local.";
            }

            return "AI is disabled. Chat text is not sent to any provider.";
        }
    }

    public void SetAnnotationStore(AnnotationDatabaseService? annotationStore)
    {
        _annotationStore = annotationStore;
        _ = LoadTranscriptAsync();
    }

    [RelayCommand(CanExecute = nameof(CanUseFeature))]
    public void ReloadSettings()
    {
        if (!RequirePublished())
        {
            return;
        }

        CurrentSettings = _aiService.LoadSettings();
        StatusMessage = CurrentSettings.ProviderKind == AiProviderKind.Disabled
            ? "AI provider disabled. Configure a provider in the process AI tab before sending chat prompts."
            : $"Loaded {CurrentSettings.ProviderDisplayName} chat settings. No evidence context is attached automatically.";
    }

    [RelayCommand(CanExecute = nameof(CanSendMessage))]
    public async Task SendMessageAsync()
    {
        if (!RequirePublished())
        {
            return;
        }

        var prompt = PromptText.Trim();
        if (string.IsNullOrWhiteSpace(prompt))
        {
            return;
        }

        _requestCts?.Cancel();
        _requestCts?.Dispose();
        _requestCts = new CancellationTokenSource();

        var settings = _aiService.LoadSettings();
        CurrentSettings = settings;
        var userMessage = CreateMessage("user", prompt, settings, AiInvestigationStatus.Succeeded);
        Messages.Add(userMessage);
        PromptText = string.Empty;

        try
        {
            IsBusy = true;
            await SaveMessageAsync(userMessage);
            StatusMessage = settings.IsCloudProvider
                ? "Sending Explorer chat with explicit cloud/commercial provider configuration..."
                : "Sending Explorer chat...";

            var transcriptPrompt = BuildConversationPrompt();
            var result = await _aiService.RunChatAsync(settings, _systemPrompt, transcriptPrompt, _requestCts.Token);
            var assistantMessage = CreateMessage(
                "assistant",
                result.Success ? result.ResponseText : result.ErrorText,
                settings,
                result.Success ? AiInvestigationStatus.Succeeded : AiInvestigationStatus.Failed,
                result.ErrorText);
            assistantMessage.ProviderKind = result.ProviderKind;
            assistantMessage.ProviderName = result.ProviderName;
            assistantMessage.BaseUrl = result.BaseUrl;
            assistantMessage.ModelName = result.ModelName;

            Messages.Add(assistantMessage);
            await SaveMessageAsync(assistantMessage);
            StatusMessage = result.Success
                ? "Explorer chat response saved to the session annotation database."
                : $"Explorer chat did not complete: {result.ErrorText}";
        }
        catch (OperationCanceledException)
        {
            var canceledMessage = CreateMessage(
                "assistant",
                "Chat request canceled.",
                settings,
                AiInvestigationStatus.Failed,
                "Chat request canceled.");
            Messages.Add(canceledMessage);
            await SaveMessageAsync(canceledMessage);
            StatusMessage = "Explorer chat request canceled.";
        }
        catch (Exception ex)
        {
            var failedMessage = CreateMessage(
                "assistant",
                $"Chat request failed: {ex.Message}",
                settings,
                AiInvestigationStatus.Failed,
                ex.Message);
            Messages.Add(failedMessage);
            await SaveMessageAsync(failedMessage);
            StatusMessage = $"Explorer chat failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanCancel))]
    public void Cancel()
    {
        if (!RequirePublished())
        {
            return;
        }

        _requestCts?.Cancel();
    }

    [RelayCommand(CanExecute = nameof(CanUseFeature))]
    public async Task ClearConversationAsync()
    {
        if (!RequirePublished())
        {
            return;
        }

        Messages.Clear();
        if (_annotationStore != null)
        {
            await _annotationStore.ClearAiChatMessagesAsync(ExplorerConversationId);
            StatusMessage = "Explorer chat transcript cleared from the session annotation database.";
        }
        else
        {
            StatusMessage = "Explorer chat transcript cleared. Annotation database is unavailable.";
        }
    }

    public async Task LoadTranscriptAsync()
    {
        if (!RequirePublished())
        {
            return;
        }

        Messages.Clear();
        if (_annotationStore == null)
        {
            StatusMessage = "Annotation database is unavailable; Explorer chat transcript will not persist.";
            return;
        }

        try
        {
            var messages = await _annotationStore.LoadAiChatMessagesAsync(ExplorerConversationId);
            foreach (var message in messages)
            {
                Messages.Add(message);
            }

            if (messages.Count > 0)
            {
                StatusMessage = $"Loaded {messages.Count} Explorer chat message(s) from the session annotation database.";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to load Explorer chat transcript: {ex.Message}";
        }
    }

    private bool CanSendMessage() =>
        _featureAccess.CanExecute(FeatureIds.AiAssistance, !IsBusy && !string.IsNullOrWhiteSpace(PromptText));

    private bool CanCancel() => _featureAccess.CanExecute(FeatureIds.AiAssistance, IsBusy);

    private bool CanUseFeature() => _featureAccess.IsPublished(FeatureIds.AiAssistance);

    public void Dispose()
    {
        _requestCts?.Cancel();
        _requestCts?.Dispose();
        _requestCts = null;
        Messages.Clear();
    }

    private bool RequirePublished()
    {
        if (_featureAccess.TryAccess(FeatureIds.AiAssistance, out var unavailableMessage))
        {
            return true;
        }

        StatusMessage = unavailableMessage;
        return false;
    }

    private async Task SaveMessageAsync(AiChatMessage message)
    {
        if (_annotationStore != null)
        {
            await _annotationStore.SaveAiChatMessageAsync(message);
        }
    }

    private string BuildConversationPrompt()
    {
        var builder = new StringBuilder();
        builder.AppendLine($"Explorer AI chat transcript follows. No {ProductIdentity.DisplayName} evidence is attached unless the analyst typed it in this transcript.");
        builder.AppendLine();

        foreach (var message in Messages.TakeLast(MaxTranscriptMessages))
        {
            builder.Append(message.AuthorDisplay);
            builder.Append(": ");
            builder.AppendLine(message.Content.Trim());
            builder.AppendLine();
        }

        return builder.ToString();
    }

    private static AiChatMessage CreateMessage(
        string role,
        string content,
        AiProviderSettings settings,
        AiInvestigationStatus status,
        string errorText = "")
    {
        return new AiChatMessage
        {
            ConversationId = ExplorerConversationId,
            Role = role,
            Content = content,
            ProviderKind = settings.ProviderKind,
            ProviderName = settings.ProviderDisplayName,
            BaseUrl = settings.BaseUrl,
            ModelName = settings.ModelName,
            CreatedUtc = DateTime.UtcNow,
            Status = status,
            ErrorText = errorText
        };
    }
}
