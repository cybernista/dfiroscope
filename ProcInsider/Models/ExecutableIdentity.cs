using System.IO;

namespace ProcInsider.Models;

/// <summary>
/// Build-output identity and the bounded former-name compatibility contract.
/// Internal namespaces, project paths, IPC names, and persistence identifiers
/// intentionally remain owned by their existing contracts.
/// </summary>
public static class ExecutableIdentity
{
    private const string PackagedViewerDirectoryName = "Viewer";
    private const string PackagedAgentDirectoryName = "Agent";

    public const string ViewerAssemblyName = "DFIRoscope.Live";
    public const string ViewerExecutableFileName = ViewerAssemblyName + ".exe";
    public const string LegacyViewerAssemblyName = "ProcInsider";
    public const string LegacyViewerExecutableFileName = LegacyViewerAssemblyName + ".exe";

    public const string AgentAssemblyName = "DFIRoscope.Agent";
    public const string AgentExecutableFileName = AgentAssemblyName + ".exe";
    public const string LegacyAgentAssemblyName = "ProcInsider.Agent";
    public const string LegacyAgentExecutableFileName = LegacyAgentAssemblyName + ".exe";

    /// <summary>
    /// Executable identity the viewer is allowed to start. The former name remains
    /// a package/reuse compatibility alias, but is never a viewer launch fallback.
    /// </summary>
    public static IReadOnlyList<string> AgentLaunchExecutableFileNames { get; } =
        Array.AsReadOnly([AgentExecutableFileName]);

    /// <summary>
    /// Exact primary/former executable allowlist accepted when an already-running
    /// same-user elevated agent is independently identity-verified.
    /// </summary>
    public static IReadOnlyList<string> CompatibleAgentExecutableFileNames { get; } =
        Array.AsReadOnly([AgentExecutableFileName, LegacyAgentExecutableFileName]);

    public static IReadOnlyList<string> AgentExecutableFileNames =>
        CompatibleAgentExecutableFileNames;

    public static bool IsSupportedAgentProcessName(string? processName)
    {
        var candidate = Path.GetFileName(processName ?? string.Empty);
        if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            candidate = candidate[..^4];
        }

        return string.Equals(candidate, AgentAssemblyName, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(candidate, LegacyAgentAssemblyName, StringComparison.OrdinalIgnoreCase);
    }

    public static IReadOnlyList<string> BuildAgentLaunchExecutableCandidates(
        string appBaseDirectory,
        string currentDirectory,
        string configurationName) =>
        BuildAgentExecutableCandidates(
            appBaseDirectory,
            currentDirectory,
            configurationName,
            AgentLaunchExecutableFileNames);

    public static IReadOnlyList<string> BuildCompatibleAgentExecutableCandidates(
        string appBaseDirectory,
        string currentDirectory,
        string configurationName) =>
        BuildAgentExecutableCandidates(
            appBaseDirectory,
            currentDirectory,
            configurationName,
            CompatibleAgentExecutableFileNames);

    public static IReadOnlyList<string> BuildAgentExecutableCandidates(
        string appBaseDirectory,
        string currentDirectory,
        string configurationName) =>
        BuildCompatibleAgentExecutableCandidates(
            appBaseDirectory,
            currentDirectory,
            configurationName);

    private static IReadOnlyList<string> BuildAgentExecutableCandidates(
        string appBaseDirectory,
        string currentDirectory,
        string configurationName,
        IReadOnlyList<string> executableFileNames)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appBaseDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationName);

        var normalizedAppBaseDirectory = Path.GetFullPath(appBaseDirectory);
        var alternateConfigurationName = string.Equals(
            configurationName,
            "Debug",
            StringComparison.OrdinalIgnoreCase)
                ? "Release"
                : "Debug";
        var candidateDirectories = new List<string>
        {
            normalizedAppBaseDirectory
        };
        if (string.Equals(
                new DirectoryInfo(normalizedAppBaseDirectory).Name,
                PackagedViewerDirectoryName,
                StringComparison.OrdinalIgnoreCase))
        {
            candidateDirectories.Add(Path.GetFullPath(Path.Combine(
                normalizedAppBaseDirectory,
                "..",
                PackagedAgentDirectoryName)));
        }

        candidateDirectories.AddRange(
        [
            Path.GetFullPath(Path.Combine(
                normalizedAppBaseDirectory,
                "..", "..", "..", "..",
                "ProcInsider.Agent", "bin", configurationName, "net10.0-windows")),
            Path.GetFullPath(Path.Combine(
                normalizedAppBaseDirectory,
                "..", "..", "..", "..",
                "ProcInsider.Agent", "bin", alternateConfigurationName, "net10.0-windows")),
            Path.GetFullPath(Path.Combine(
                currentDirectory,
                "ProcInsider.Agent", "bin", configurationName, "net10.0-windows")),
            Path.GetFullPath(Path.Combine(
                currentDirectory,
                "ProcInsider.Agent", "bin", alternateConfigurationName, "net10.0-windows"))
        ]);

        return candidateDirectories
            .SelectMany(directory => executableFileNames.Select(fileName => Path.Combine(directory, fileName)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
