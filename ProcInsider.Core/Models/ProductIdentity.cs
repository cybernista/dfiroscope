namespace ProcInsider.Models;

/// <summary>
/// Core-owned canonical public identity for the desktop product. Compatibility-sensitive
/// executable, path, protocol, persistence, and source identifiers remain owned
/// by their focused contracts and must not be derived from these display values.
/// </summary>
public static class ProductIdentity
{
    public const string DisplayName = "DFIRoscope Live";

    public const string UmbrellaBrand = "DFIRoscope";

    public const string FormerName = "ProcInsider";

    public const string ShortDescription =
        "Open-source Windows investigation and cybersecurity learning platform.";

    public const string Tagline =
        "Observe, correlate and reconstruct Windows activity.";

    public const string? Publisher = null;

    public const string? Domain = null;

    public const string? RepositoryUrl = null;

    public static string AgentDisplayName => $"{DisplayName} agent";
}
