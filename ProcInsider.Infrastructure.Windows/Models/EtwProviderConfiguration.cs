using System.Collections.Generic;

namespace ProcInsider.Models;

public class EtwProviderConfiguration
{
    public EtwProfileMetadata Profile { get; set; } = new();

    public EtwSessionConfiguration Session { get; set; } = new();

    public List<EtwProviderDefinition> Providers { get; set; } = new();
}

public class EtwProfileMetadata
{
    public string Id { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string ExpectedVolume { get; set; } = string.Empty;

    public string RiskNote { get; set; } = string.Empty;

    public List<string> CorrelationHints { get; set; } = new();
}

public class EtwSessionConfiguration
{
    public string Name { get; set; } = EtwSessionIdentity.SessionName;

    public int BufferSizeKb { get; set; } = 1024;

    public int MinimumBuffers { get; set; } = 16;

    public int MaximumBuffers { get; set; } = 128;

    public int FlushTimerSeconds { get; set; } = 1;
}

public class EtwProviderDefinition
{
    public string Name { get; set; } = string.Empty;

    public string Guid { get; set; } = string.Empty;

    public bool Enabled { get; set; }

    public string Level { get; set; } = "Verbose";

    public string KeywordsHex { get; set; } = "0xFFFFFFFFFFFFFFFF";

    public List<EtwEventDefinition> Events { get; set; } = new();
}

public class EtwEventDefinition
{
    public int Id { get; set; }

    public string Name { get; set; } = string.Empty;

    public string Category { get; set; } = "Windows";

    public string Action { get; set; } = "EtwEvent";

    public List<string> ProcessIdFields { get; set; } = new();

    public List<string> TargetFields { get; set; } = new();

    public List<string> ProcessNameFields { get; set; } = new();

    public List<string> ImagePathFields { get; set; } = new();
}
