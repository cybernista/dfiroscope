using System.Diagnostics;
using System.IO;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Opens read-only Windows security monitoring review surfaces.
/// </summary>
public sealed class SecurityMonitoringService
{
    private const string TranscriptDirectory = @"C:\PS_transcripts";
    private static readonly string MonitoringDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "DFIRoscope",
        "SecurityMonitoring");
    private static readonly string LegacyMonitoringDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "ProcInsider",
        "SecurityMonitoring");
    private const string InstallLogFileName = "install.log";

    private readonly ConfigProfileService _configProfileService;

    public SecurityMonitoringService()
        : this(new ConfigProfileService())
    {
    }

    public SecurityMonitoringService(ConfigProfileService configProfileService)
    {
        _configProfileService = configProfileService;
    }

    public string TranscriptPath => TranscriptDirectory;

    public string InstallLogPath
    {
        get
        {
            var preferred = Path.Combine(MonitoringDirectory, InstallLogFileName);
            var legacy = Path.Combine(LegacyMonitoringDirectory, InstallLogFileName);
            return File.Exists(preferred) || !File.Exists(legacy) ? preferred : legacy;
        }
    }

    public IReadOnlyList<ConfigProfileDefinition> GetPolicyProfiles()
    {
        return _configProfileService.GetProfiles(ConfigProfileKind.SecurityMonitoring);
    }

    public string? ResolvePolicyProfilePath(ConfigProfileDefinition profile)
    {
        ValidatePolicyProfile(profile);
        return _configProfileService.ResolveProfileFilePath(profile);
    }

    public void OpenPolicyProfile(ConfigProfileDefinition profile)
    {
        ValidatePolicyProfile(profile);
        var path = ResolvePolicyProfilePath(profile);
        if (string.IsNullOrWhiteSpace(path))
        {
            path = profile.ManifestDirectory;
        }

        if (string.IsNullOrWhiteSpace(path) || (!File.Exists(path) && !Directory.Exists(path)))
        {
            throw new FileNotFoundException("Bundled security monitoring profile file was not found.", path);
        }

        OpenPath(path);
    }

    public void OpenTranscriptFolder()
    {
        if (!Directory.Exists(TranscriptDirectory))
        {
            throw new DirectoryNotFoundException(
                $"The PowerShell transcript folder does not exist: {TranscriptDirectory}");
        }

        OpenPath(TranscriptDirectory);
    }

    public void OpenInstallLog()
    {
        var path = InstallLogPath;
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                "No existing Security Monitoring install log was found.",
                path);
        }

        OpenPath(path);
    }

    public void OpenEventViewer()
    {
        StartProcess("eventvwr.msc", string.Empty);
    }

    public void OpenEventViewerLog(string logName)
    {
        if (string.IsNullOrWhiteSpace(logName))
        {
            throw new ArgumentException("Event log name is required.", nameof(logName));
        }

        StartProcess("eventvwr.msc", $"/c:{QuoteArgument(logName)}");
    }

    private static void ValidatePolicyProfile(ConfigProfileDefinition profile)
    {
        var profileName = string.IsNullOrWhiteSpace(profile.DisplayName) ? profile.Id : profile.DisplayName;
        if (profile.Kind != ConfigProfileKind.SecurityMonitoring)
        {
            throw new InvalidOperationException($"Profile '{profileName}' is not a Security Monitoring profile.");
        }
    }

    private static void OpenPath(string path)
    {
        StartProcess(path, string.Empty);
    }

    private static Process StartProcess(string fileName, string arguments)
    {
        return Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = true
        }) ?? throw new InvalidOperationException($"Failed to start {fileName}.");
    }

    private static string QuoteArgument(string value)
    {
        return "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
    }
}
