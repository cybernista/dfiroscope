using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using Microsoft.Win32;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Detects Sysmon availability and stores the app-level Sysmon integration toggle.
/// </summary>
public class SysmonService
{
    private const string AppSettingsKey = @"Software\DFIRoscope";
    private const string LegacyAppSettingsKey = @"Software\ProcInsider";
    private const string IntegrationValueName = "EnableSysmonIntegration";
    private const string SysmonLogName = "Microsoft-Windows-Sysmon/Operational";
    private const string ConfigRelativePath = @"Config\Sysmon\Procinsider.Sysmon.Medium.xml";
    private const string LegacyConfigRelativePath = @"Sysmon\Procinsider.Sysmon.Medium.xml";

    private readonly ConfigProfileService _configProfileService;

    private static readonly string[] ServiceNames =
    {
        "Sysmon64",
        "Sysmon"
    };

    public SysmonService()
        : this(new ConfigProfileService())
    {
    }

    public SysmonService(ConfigProfileService configProfileService)
    {
        _configProfileService = configProfileService;
    }

    public SysmonSettings LoadSettings()
    {
        var channelStatus = DetectChannelStatus();
        var serviceStateAvailable = true;
        var serviceStatusDetail = "Sysmon service registration and process state were read.";
        var serviceError = string.Empty;
        var isInstalled = false;
        var isRunning = false;
        try
        {
            isInstalled = DetectInstalled();
            isRunning = DetectRunning();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or
                                   System.Security.SecurityException or
                                   IOException)
        {
            serviceStateAvailable = false;
            serviceStatusDetail = "Sysmon service registration or process state is inaccessible to the current process.";
            serviceError = ex.Message;
        }

        return new SysmonSettings
        {
            IntegrationEnabled = LoadIntegrationEnabled(defaultValue: true),
            IsServiceStateAvailable = serviceStateAvailable,
            ServiceStatusDetail = serviceStatusDetail,
            ServiceError = serviceError,
            IsInstalled = isInstalled,
            IsRunning = isRunning,
            IsChannelAvailable = channelStatus.IsAvailable,
            IsChannelEnabled = channelStatus.IsEnabled,
            IsWatcherAccessible = channelStatus.IsWatcherAccessible,
            ChannelStatusDetail = channelStatus.Detail,
            ChannelError = channelStatus.Error
        };
    }

    public string GetBundledConfigPath()
    {
        var defaultProfile = _configProfileService.GetDefaultProfile(ConfigProfileKind.Sysmon);
        var profilePath = defaultProfile == null ? null : _configProfileService.ResolveProfileFilePath(defaultProfile);
        if (!string.IsNullOrWhiteSpace(profilePath))
        {
            return profilePath;
        }

        var configPath = Path.Combine(AppContext.BaseDirectory, ConfigRelativePath);
        return File.Exists(configPath)
            ? configPath
            : Path.Combine(AppContext.BaseDirectory, LegacyConfigRelativePath);
    }

    public IReadOnlyList<ConfigProfileDefinition> GetBundledConfigProfiles()
    {
        return _configProfileService.GetProfiles(ConfigProfileKind.Sysmon);
    }

    public string? ResolveBundledConfigProfilePath(ConfigProfileDefinition profile)
    {
        return _configProfileService.ResolveProfileFilePath(profile);
    }

    public string? FindSysmonExecutablePath()
    {
        var installedPath = ReadInstalledImagePath();
        if (!string.IsNullOrWhiteSpace(installedPath) && File.Exists(installedPath))
        {
            return installedPath;
        }

        foreach (var candidate in EnumerateExecutableCandidates())
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    public void ApplyBundledConfig()
    {
        var configPath = GetBundledConfigPath();
        ApplyConfigPath(configPath);
    }

    public void ApplyBundledConfig(ConfigProfileDefinition profile)
    {
        var profileName = string.IsNullOrWhiteSpace(profile.DisplayName) ? profile.Id : profile.DisplayName;
        if (profile.Kind != ConfigProfileKind.Sysmon)
        {
            throw new InvalidOperationException($"Profile '{profileName}' is not a Sysmon profile.");
        }

        var configPath = ResolveBundledConfigProfilePath(profile);
        if (string.IsNullOrWhiteSpace(configPath))
        {
            throw new FileNotFoundException($"Sysmon profile '{profileName}' does not define a configuration file.", profile.FilePath);
        }

        ApplyConfigPath(configPath);
    }

    private void ApplyConfigPath(string configPath)
    {
        if (!File.Exists(configPath))
        {
            throw new FileNotFoundException("Bundled Sysmon configuration file was not found.", configPath);
        }

        var executablePath = FindSysmonExecutablePath();
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            throw new InvalidOperationException("Unable to locate sysmon64.exe or sysmon.exe. Add Sysmon to PATH or install it first.");
        }

        RunSysmonCommand(executablePath, $"-c \"{configPath}\"");
    }

    public void InstallWithBundledConfig()
    {
        var configPath = GetBundledConfigPath();
        if (!File.Exists(configPath))
        {
            throw new FileNotFoundException("Bundled Sysmon configuration file was not found.", configPath);
        }

        var executablePath = FindSysmonExecutablePath();
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            throw new InvalidOperationException("Unable to locate sysmon64.exe or sysmon.exe. Extract Sysmon and add it to PATH first.");
        }

        RunSysmonCommand(executablePath, $"-accepteula -i \"{configPath}\"");
    }

    public void InstallWithBundledConfig(ConfigProfileDefinition profile)
    {
        var profileName = string.IsNullOrWhiteSpace(profile.DisplayName) ? profile.Id : profile.DisplayName;
        if (profile.Kind != ConfigProfileKind.Sysmon)
        {
            throw new InvalidOperationException($"Profile '{profileName}' is not a Sysmon profile.");
        }

        var configPath = ResolveBundledConfigProfilePath(profile);
        if (string.IsNullOrWhiteSpace(configPath) || !File.Exists(configPath))
        {
            throw new FileNotFoundException($"Sysmon profile '{profileName}' configuration file was not found.", configPath ?? profile.FilePath);
        }

        var executablePath = FindSysmonExecutablePath();
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            throw new InvalidOperationException("Unable to locate sysmon64.exe or sysmon.exe. Extract Sysmon and add it to PATH first.");
        }

        RunSysmonCommand(executablePath, $"-accepteula -i \"{configPath}\"");
    }

    public void SetIntegrationEnabled(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(AppSettingsKey);
        key?.SetValue(IntegrationValueName, enabled ? 1 : 0, RegistryValueKind.DWord);
    }

    private static bool LoadIntegrationEnabled(bool defaultValue)
    {
        try
        {
            using (var key = Registry.CurrentUser.OpenSubKey(AppSettingsKey))
            {
                var preferredValue = key?.GetValue(IntegrationValueName);
                if (preferredValue is int value)
                {
                    return value != 0;
                }

                if (preferredValue != null)
                {
                    Trace.TraceWarning("The preferred Sysmon integration setting has an unsupported value type and was preserved.");
                    return defaultValue;
                }
            }

            using var legacyKey = Registry.CurrentUser.OpenSubKey(LegacyAppSettingsKey);
            if (legacyKey?.GetValue(IntegrationValueName) is not int legacyValue)
            {
                return defaultValue;
            }

            try
            {
                using var preferredKey = Registry.CurrentUser.CreateSubKey(AppSettingsKey);
                if (preferredKey?.GetValue(IntegrationValueName) == null)
                {
                    preferredKey?.SetValue(IntegrationValueName, legacyValue, RegistryValueKind.DWord);
                    Trace.TraceInformation("The legacy Sysmon integration setting was adopted under the DFIRoscope key.");
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {
                Trace.TraceWarning($"Legacy Sysmon integration setting could not be adopted: {ex.GetType().Name}: {ex.Message}");
            }

            return legacyValue != 0;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            Trace.TraceWarning($"Sysmon integration preference could not be read: {ex.GetType().Name}: {ex.Message}");
            return defaultValue;
        }
    }

    private static string? ReadInstalledImagePath()
    {
        foreach (var serviceName in ServiceNames)
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            if (key?.GetValue("ImagePath") is not string rawPath || string.IsNullOrWhiteSpace(rawPath))
            {
                continue;
            }

            var expanded = Environment.ExpandEnvironmentVariables(rawPath).Trim();
            if (expanded.StartsWith("\"", StringComparison.Ordinal))
            {
                var closingQuote = expanded.IndexOf('"', 1);
                if (closingQuote > 1)
                {
                    return expanded[1..closingQuote];
                }
            }

            var executablePath = expanded.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(executablePath))
            {
                return executablePath.Trim('"');
            }
        }

        return null;
    }

    private static bool DetectInstalled()
    {
        return ServiceNames.Any(serviceName =>
            Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}") != null);
    }

    private static bool DetectRunning()
    {
        foreach (var serviceName in ServiceNames)
        {
            try
            {
                if (Process.GetProcessesByName(serviceName).Length > 0)
                {
                    return true;
                }
            }
            catch
            {
                // Ignore missing services or transient controller lookup failures.
            }
        }

        return false;
    }

    private static SysmonChannelStatus DetectChannelStatus()
    {
        try
        {
            using var configuration = new EventLogConfiguration(SysmonLogName);
            if (!configuration.IsEnabled)
            {
                return new SysmonChannelStatus(
                    IsAvailable: false,
                    IsEnabled: false,
                    IsWatcherAccessible: false,
                    Detail: $"Sysmon channel {SysmonLogName} exists but is disabled.",
                    Error: string.Empty);
            }
        }
        catch (Exception ex)
        {
            return new SysmonChannelStatus(
                IsAvailable: false,
                IsEnabled: false,
                IsWatcherAccessible: false,
                Detail: $"Sysmon channel {SysmonLogName} could not be inspected: {ex.Message}",
                Error: ex.Message);
        }

        try
        {
            var query = new EventLogQuery(SysmonLogName, PathType.LogName, "*");
            using var watcher = new EventLogWatcher(query);
            watcher.Enabled = true;
            watcher.Enabled = false;
        }
        catch (Exception ex)
        {
            return new SysmonChannelStatus(
                IsAvailable: false,
                IsEnabled: true,
                IsWatcherAccessible: false,
                Detail: $"Sysmon channel {SysmonLogName} is enabled, but the current process cannot subscribe to it: {ex.Message}",
                Error: ex.Message);
        }

        return new SysmonChannelStatus(
            IsAvailable: true,
            IsEnabled: true,
            IsWatcherAccessible: true,
            Detail: $"Sysmon channel {SysmonLogName} is enabled and watcher subscription is available.",
            Error: string.Empty);
    }

    private static IEnumerable<string> EnumerateExecutableCandidates()
    {
        var candidates = new List<string>();

        foreach (var pathEntry in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            candidates.Add(Path.Combine(pathEntry, "sysmon64.exe"));
            candidates.Add(Path.Combine(pathEntry, "sysmon.exe"));
        }

        candidates.Add(Path.Combine(AppContext.BaseDirectory, "sysmon64.exe"));
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "sysmon.exe"));

        return candidates.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static void RunSysmonCommand(string executablePath, string arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Failed to start Sysmon.");

        var standardOutput = process.StandardOutput.ReadToEnd();
        var standardError = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            var message = string.IsNullOrWhiteSpace(standardError) ? standardOutput : standardError;
            throw new InvalidOperationException($"Sysmon command failed: {message}".Trim());
        }
    }

    private sealed record SysmonChannelStatus(
        bool IsAvailable,
        bool IsEnabled,
        bool IsWatcherAccessible,
        string Detail,
        string Error);
}
