using System.Text;
using ProcInsider.Models;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public sealed class AiInvestigationService
{
    private readonly AiSettingsService _settingsService;
    private readonly ProtectedAiSecretStore _secretStore;
    private readonly Func<AiProviderSettings, IAiProvider> _providerFactory;

    public AiInvestigationService(string settingsPath, string secretPath)
        : this(settingsPath, secretPath, settings => new AiProviderFactory().Create(settings))
    {
    }

    public AiInvestigationService(
        string settingsPath,
        string secretPath,
        Func<AiProviderSettings, IAiProvider> providerFactory)
    {
        _settingsService = new AiSettingsService(settingsPath);
        _secretStore = new ProtectedAiSecretStore(secretPath);
        _providerFactory = providerFactory ?? throw new ArgumentNullException(nameof(providerFactory));
    }

    public string SettingsPath => _settingsService.SettingsPath;

    public string SecretPath => _secretStore.SecretPath;

    public bool HasApiKey => _secretStore.HasSecret;

    public void SetStoragePaths(string settingsPath, string secretPath)
    {
        _settingsService.SetPath(settingsPath);
        _secretStore.SetPath(secretPath);
    }

    public AiProviderSettings LoadSettings() => _settingsService.Load();

    public void SaveSettings(AiProviderSettings settings, string? apiKey)
    {
        _settingsService.Save(settings);
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            _secretStore.SaveSecret(apiKey);
        }
    }

    public void ClearApiKey() => _secretStore.ClearSecret();

    public async Task<AiProviderTestResult> TestConnectionAsync(AiProviderSettings settings, CancellationToken cancellationToken)
    {
        if (settings.ProviderKind == AiProviderKind.Disabled)
        {
            return new AiProviderTestResult
            {
                Success = false,
                Message = "AI provider is disabled. Select a local or commercial provider first."
            };
        }

        var provider = _providerFactory(settings);
        var response = await provider.CompleteAsync(
            settings,
            LoadApiKeySafely(),
            $"You are testing an AI provider connection for {ProductIdentity.DisplayName}.",
            "Reply with exactly: OK",
            cancellationToken);

        return new AiProviderTestResult
        {
            Success = response.Success,
            Message = response.Success
                ? $"AI provider test succeeded with {settings.ProviderDisplayName}."
                : response.ErrorMessage
        };
    }

    public async Task<AiInvestigationRecord> RunInvestigationAsync(
        AiInvestigationRequest request,
        CancellationToken cancellationToken)
    {
        var requestedUtc = DateTime.UtcNow;
        var userPrompt = BuildUserPrompt(request);
        var record = CreateRecord(request, requestedUtc, userPrompt);

        if (request.Settings.ProviderKind == AiProviderKind.Disabled)
        {
            record.Status = AiInvestigationStatus.Disabled;
            record.CompletedUtc = DateTime.UtcNow;
            record.ErrorText = "AI provider is disabled. Configure a provider before running AI analysis.";
            return record;
        }

        var provider = _providerFactory(request.Settings);
        var response = await provider.CompleteAsync(
            request.Settings,
            LoadApiKeySafely(),
            request.PromptTemplate.SystemPrompt,
            userPrompt,
            cancellationToken);

        record.CompletedUtc = DateTime.UtcNow;
        record.ProviderName = string.IsNullOrWhiteSpace(response.ProviderName)
            ? request.Settings.ProviderDisplayName
            : response.ProviderName;
        record.ModelName = string.IsNullOrWhiteSpace(response.ModelName)
            ? request.Settings.ModelName
            : response.ModelName;
        record.PromptTokens = response.PromptTokens;
        record.CompletionTokens = response.CompletionTokens;
        record.TotalTokens = response.TotalTokens;

        if (response.Success)
        {
            record.Status = AiInvestigationStatus.Succeeded;
            record.ResponseText = response.Content;
            record.ResponseCharacterCount = response.Content.Length;
        }
        else
        {
            record.Status = IsConfigurationError(response.ErrorMessage)
                ? AiInvestigationStatus.ConfigurationRequired
                : AiInvestigationStatus.Failed;
            record.ErrorText = response.ErrorMessage;
        }

        return record;
    }

    public async Task<AiChatCompletionResult> RunChatAsync(
        AiProviderSettings settings,
        string systemPrompt,
        string conversationPrompt,
        CancellationToken cancellationToken)
    {
        if (settings.ProviderKind == AiProviderKind.Disabled)
        {
            return new AiChatCompletionResult
            {
                Success = false,
                ProviderKind = settings.ProviderKind,
                ProviderName = settings.ProviderDisplayName,
                BaseUrl = settings.BaseUrl,
                ModelName = settings.ModelName,
                ErrorText = "AI provider is disabled. Configure a provider before sending chat prompts."
            };
        }

        var provider = _providerFactory(settings);
        var response = await provider.CompleteAsync(
            settings,
            LoadApiKeySafely(),
            systemPrompt,
            TruncateEvidence(conversationPrompt, settings.MaxContextCharacters),
            cancellationToken);

        return new AiChatCompletionResult
        {
            Success = response.Success,
            ProviderKind = settings.ProviderKind,
            ProviderName = string.IsNullOrWhiteSpace(response.ProviderName)
                ? settings.ProviderDisplayName
                : response.ProviderName,
            BaseUrl = settings.BaseUrl,
            ModelName = string.IsNullOrWhiteSpace(response.ModelName)
                ? settings.ModelName
                : response.ModelName,
            ResponseText = response.Content,
            ErrorText = response.ErrorMessage,
            PromptTokens = response.PromptTokens,
            CompletionTokens = response.CompletionTokens,
            TotalTokens = response.TotalTokens
        };
    }

    private string LoadApiKeySafely()
    {
        try
        {
            return _secretStore.LoadSecret();
        }
        catch
        {
            return string.Empty;
        }
    }

    private static AiInvestigationRecord CreateRecord(AiInvestigationRequest request, DateTime requestedUtc, string userPrompt)
    {
        var scope = request.SourceScope;
        return new AiInvestigationRecord
        {
            InvestigationId = request.InvestigationId,
            TargetKind = scope.TargetKind,
            TargetTable = scope.TargetTable,
            TargetId = scope.TargetId,
            ArtifactId = scope.ArtifactId,
            CaseId = scope.CaseId,
            EvidenceSessionId = scope.EvidenceSessionId,
            CaptureId = scope.CaptureId,
            SourceIdentityId = scope.SourceIdentityId,
            HostId = scope.HostId,
            ProcessKey = scope.ProcessKey,
            ProcessId = scope.ProcessId,
            ProcessName = scope.ProcessName,
            Label = scope.Label,
            DisplayPath = scope.DisplayPath,
            SourceScopeKind = scope.ScopeKind,
            SourceScopeSummary = scope.Summary,
            PromptTemplateId = request.PromptTemplate.Id,
            PromptTemplateTitle = request.PromptTemplate.Title,
            SystemPrompt = request.PromptTemplate.SystemPrompt,
            AnalystPrompt = request.AnalystPromptSuffix,
            FinalPrompt = userPrompt,
            ProviderKind = request.Settings.ProviderKind,
            ProviderName = request.Settings.ProviderDisplayName,
            BaseUrl = request.Settings.BaseUrl,
            ModelName = request.Settings.ModelName,
            RequestedUtc = requestedUtc,
            Status = AiInvestigationStatus.Pending,
            RequestCharacterCount = request.PromptTemplate.SystemPrompt.Length + userPrompt.Length
        };
    }

    private static string BuildUserPrompt(AiInvestigationRequest request)
    {
        var evidence = TruncateEvidence(request.EvidenceText, request.Settings.MaxContextCharacters);
        var builder = new StringBuilder();
        builder.AppendLine(request.PromptTemplate.UserPromptPrefix.Trim());
        builder.AppendLine();
        if (!string.IsNullOrWhiteSpace(request.AnalystPromptSuffix))
        {
            builder.AppendLine("Analyst prompt suffix:");
            builder.AppendLine(request.AnalystPromptSuffix.Trim());
            builder.AppendLine();
        }

        builder.AppendLine("Evidence scope:");
        builder.AppendLine(request.SourceScope.Summary);
        builder.AppendLine();
        builder.AppendLine("Evidence:");
        builder.AppendLine(evidence);
        return builder.ToString();
    }

    private static string TruncateEvidence(string evidenceText, int maxContextCharacters)
    {
        if (string.IsNullOrWhiteSpace(evidenceText) || evidenceText.Length <= maxContextCharacters)
        {
            return evidenceText;
        }

        return evidenceText[..maxContextCharacters] + $"\n\n[Evidence truncated by {ProductIdentity.DisplayName} max context size setting.]";
    }

    private static bool IsConfigurationError(string message)
    {
        return message.Contains("required", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("disabled", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("Base URL", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("Model name", StringComparison.OrdinalIgnoreCase);
    }
}
