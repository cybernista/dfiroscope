using System.IO;
using Microsoft.Win32;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Reads and updates Windows PowerShell auditing policy settings in the registry.
/// </summary>
public class PowerShellAuditingService
{
    private const string DefaultTranscriptPath = @"C:\PS_transcripts";

    private readonly ConfigProfileService _configProfileService;

    private static readonly string[] PolicyRoots =
    {
        @"SOFTWARE\Policies\Microsoft\Windows\PowerShell",
        @"SOFTWARE\Policies\Microsoft\PowerShellCore"
    };

    public PowerShellAuditingService()
        : this(new ConfigProfileService())
    {
    }

    public PowerShellAuditingService(ConfigProfileService configProfileService)
    {
        _configProfileService = configProfileService;
    }

    public IReadOnlyList<ConfigProfileDefinition> GetAuditingProfiles()
    {
        return _configProfileService.GetProfiles(ConfigProfileKind.PowerShellAuditing);
    }

    public string? ResolveAuditingProfilePath(ConfigProfileDefinition profile)
    {
        ValidateAuditingProfile(profile);
        return _configProfileService.ResolveProfileFilePath(profile);
    }

    /// <summary>
    /// Loads the current effective PowerShell auditing settings.
    /// </summary>
    public PowerShellAuditingSettings LoadSettings()
    {
        try
        {
            return new PowerShellAuditingSettings
            {
                IsAvailable = true,
                StatusDetail = "PowerShell auditing policy registry state was read.",
                ScriptBlockLoggingEnabled = IsEnabled("ScriptBlockLogging", "EnableScriptBlockLogging"),
                ModuleLoggingEnabled = IsEnabled("ModuleLogging", "EnableModuleLogging"),
                TranscriptionEnabled = IsEnabled("Transcription", "EnableTranscripting"),
                TranscriptPath = ReadTranscriptPath() ?? DefaultTranscriptPath
            };
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or
                                   System.Security.SecurityException or
                                   IOException)
        {
            return new PowerShellAuditingSettings
            {
                IsAvailable = false,
                StatusDetail = "PowerShell auditing policy registry state is inaccessible to the current process.",
                Error = ex.Message,
                TranscriptPath = DefaultTranscriptPath
            };
        }
    }

    /// <summary>
    /// Enables or disables script block logging.
    /// </summary>
    public void SetScriptBlockLogging(bool enabled)
    {
        foreach (var root in PolicyRoots)
        {
            using var key = Registry.LocalMachine.CreateSubKey($@"{root}\ScriptBlockLogging");
            key?.SetValue("EnableScriptBlockLogging", enabled ? 1 : 0, RegistryValueKind.DWord);
            key?.SetValue("EnableScriptBlockInvocationLogging", enabled ? 1 : 0, RegistryValueKind.DWord);
        }
    }

    /// <summary>
    /// Enables or disables module logging for all modules.
    /// </summary>
    public void SetModuleLogging(bool enabled)
    {
        foreach (var root in PolicyRoots)
        {
            using var key = Registry.LocalMachine.CreateSubKey($@"{root}\ModuleLogging");
            key?.SetValue("EnableModuleLogging", enabled ? 1 : 0, RegistryValueKind.DWord);

            using var moduleNamesKey = Registry.LocalMachine.CreateSubKey($@"{root}\ModuleLogging\ModuleNames");
            if (enabled)
            {
                moduleNamesKey?.SetValue("*", "*", RegistryValueKind.String);
            }
            else if (moduleNamesKey != null)
            {
                foreach (var valueName in moduleNamesKey.GetValueNames())
                {
                    moduleNamesKey.DeleteValue(valueName, false);
                }
            }
        }
    }

    /// <summary>
    /// Enables or disables transcription logging.
    /// </summary>
    public void SetTranscription(bool enabled, string? transcriptPath = null)
    {
        var outputDirectory = string.IsNullOrWhiteSpace(transcriptPath)
            ? DefaultTranscriptPath
            : transcriptPath;

        if (enabled)
        {
            Directory.CreateDirectory(outputDirectory);
        }

        foreach (var root in PolicyRoots)
        {
            using var key = Registry.LocalMachine.CreateSubKey($@"{root}\Transcription");
            key?.SetValue("EnableTranscripting", enabled ? 1 : 0, RegistryValueKind.DWord);
            key?.SetValue("EnableInvocationHeader", enabled ? 1 : 0, RegistryValueKind.DWord);
            key?.SetValue("OutputDirectory", outputDirectory, RegistryValueKind.String);
        }
    }

    private static bool IsEnabled(string subKeyPath, string valueName)
    {
        foreach (var root in PolicyRoots)
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"{root}\{subKeyPath}");
            if (key?.GetValue(valueName) is int value && value != 0)
            {
                return true;
            }
        }

        return false;
    }

    private static string? ReadTranscriptPath()
    {
        foreach (var root in PolicyRoots)
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"{root}\Transcription");
            if (key?.GetValue("OutputDirectory") is string path && !string.IsNullOrWhiteSpace(path))
            {
                return path;
            }
        }

        return null;
    }

    private static void ValidateAuditingProfile(ConfigProfileDefinition profile)
    {
        var profileName = string.IsNullOrWhiteSpace(profile.DisplayName) ? profile.Id : profile.DisplayName;
        if (profile.Kind != ConfigProfileKind.PowerShellAuditing)
        {
            throw new InvalidOperationException($"Profile '{profileName}' is not a PowerShell Auditing profile.");
        }
    }
}
