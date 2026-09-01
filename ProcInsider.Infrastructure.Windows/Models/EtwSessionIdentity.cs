namespace ProcInsider.Models;

public static class EtwSessionIdentity
{
    public const string SessionName = "DFIRoscope-ETW";

    public const string LegacySessionName = "ProcInsider-ETW";

    public static string ResolveSessionName(string? configuredName)
    {
        var candidate = string.IsNullOrWhiteSpace(configuredName)
            ? SessionName
            : configuredName.Trim();
        return string.Equals(candidate, LegacySessionName, StringComparison.OrdinalIgnoreCase)
            ? SessionName
            : candidate;
    }

    public static IReadOnlyList<string> GetSessionsToStopBeforeStart(string? configuredName)
    {
        var resolvedName = ResolveSessionName(configuredName);
        return string.Equals(resolvedName, SessionName, StringComparison.OrdinalIgnoreCase)
            ? [SessionName, LegacySessionName]
            : [resolvedName];
    }
}
