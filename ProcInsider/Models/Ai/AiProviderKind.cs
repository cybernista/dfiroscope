namespace ProcInsider.Models.Ai;

public enum AiProviderKind
{
    Disabled = 0,
    LocalOpenAiCompatible = 1,
    CommercialOpenAiCompatible = 2
}

public enum AiInvestigationStatus
{
    Pending = 0,
    Succeeded = 1,
    Failed = 2,
    ConfigurationRequired = 3,
    Disabled = 4
}
