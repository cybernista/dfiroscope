using System.IO;
using Microsoft.Win32;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Reads and updates Windows PowerShell auditing policy settings in the registry.
/// </summary>
public class PowerShellAuditingService
{
    public const string DefaultTranscriptPath = @"C:\PS_transcripts";

    private readonly ConfigProfileService _configProfileService;

    private static readonly string[] PolicyRoots =
    {
        @"SOFTWARE\Policies\Microsoft\Windows\PowerShell",
        @"SOFTWARE\Policies\Microsoft\PowerShellCore"
    };

    private static readonly PolicyKeyDefinition[] ManagedPolicyKeys =
    [
        new("ScriptBlockLogging", false, ["EnableScriptBlockLogging", "EnableScriptBlockInvocationLogging"]),
        new("ModuleLogging", false, ["EnableModuleLogging"]),
        new(@"ModuleLogging\ModuleNames", true, []),
        new("Transcription", false, ["EnableTranscripting", "EnableInvocationHeader", "OutputDirectory"])
    ];

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
    public virtual PowerShellAuditingSettings LoadSettings()
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
    /// Captures every registry value that the supported PowerShell policy operations can change,
    /// separately for Windows PowerShell and PowerShell Core policy roots.
    /// </summary>
    public virtual PowerShellAuditingPolicySnapshot CaptureManagedPolicySnapshot()
    {
        try
        {
            var keys = new List<PowerShellAuditingPolicyKeySnapshot>();
            foreach (var root in PolicyRoots)
            foreach (var definition in ManagedPolicyKeys)
                keys.Add(CaptureKey(root, definition));
            return new PowerShellAuditingPolicySnapshot { IsAvailable = true, Keys = keys.ToArray() };
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return new PowerShellAuditingPolicySnapshot { IsAvailable = false, Error = ex.Message };
        }
    }

    /// <summary>
    /// Restores exactly the managed policy values recorded in a readable snapshot. Callers must
    /// compare the current snapshot with their recorded application-owned state before invoking it.
    /// </summary>
    public virtual void RestoreManagedPolicySnapshot(PowerShellAuditingPolicySnapshot snapshot)
    {
        if (!snapshot.IsAvailable || snapshot.Keys.Length != PolicyRoots.Length * ManagedPolicyKeys.Length)
            throw new InvalidOperationException("PowerShell auditing policy snapshot is incomplete.");

        foreach (var key in snapshot.Keys.Where(key => key.Exists))
            RestoreExistingKey(key);
        foreach (var key in snapshot.Keys.Where(key => !key.Exists)
                     .OrderByDescending(key => key.SubKey.Count(character => character == '\\')))
            Registry.LocalMachine.DeleteSubKeyTree($@"{key.Root}\{key.SubKey}", false);
    }

    /// <summary>
    /// Enables or disables script block logging.
    /// </summary>
    public virtual void SetScriptBlockLogging(bool enabled)
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
    public virtual void SetModuleLogging(bool enabled)
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
    public virtual void SetTranscription(bool enabled, string? transcriptPath = null)
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

    private static PowerShellAuditingPolicyKeySnapshot CaptureKey(string root, PolicyKeyDefinition definition)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"{root}\{definition.SubKey}");
        if (key == null)
            return new PowerShellAuditingPolicyKeySnapshot { Root = root, SubKey = definition.SubKey };

        var names = definition.CaptureAllValues
            ? key.GetValueNames().OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray()
            : definition.ValueNames;
        return new PowerShellAuditingPolicyKeySnapshot
        {
            Root = root,
            SubKey = definition.SubKey,
            Exists = true,
            Values = names.Where(name => key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
                .Select(name => CaptureValue(key, name))
                .ToArray()
        };
    }

    private static PowerShellAuditingPolicyValueSnapshot CaptureValue(RegistryKey key, string name)
    {
        var kind = key.GetValueKind(name);
        var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return kind switch
        {
            RegistryValueKind.DWord => new PowerShellAuditingPolicyValueSnapshot { Name = name, Kind = kind, DwordValue = Convert.ToInt32(value) },
            RegistryValueKind.QWord => new PowerShellAuditingPolicyValueSnapshot { Name = name, Kind = kind, QwordValue = Convert.ToInt64(value) },
            RegistryValueKind.String or RegistryValueKind.ExpandString => new PowerShellAuditingPolicyValueSnapshot { Name = name, Kind = kind, StringValue = Convert.ToString(value) ?? string.Empty },
            RegistryValueKind.MultiString => new PowerShellAuditingPolicyValueSnapshot { Name = name, Kind = kind, MultiStringValue = ((string[]?)value) ?? [] },
            RegistryValueKind.Binary or RegistryValueKind.None => new PowerShellAuditingPolicyValueSnapshot { Name = name, Kind = kind, BinaryValue = ((byte[]?)value) ?? [] },
            _ => throw new InvalidOperationException($"PowerShell policy value '{name}' has unsupported registry kind '{kind}'.")
        };
    }

    private static void RestoreExistingKey(PowerShellAuditingPolicyKeySnapshot snapshot)
    {
        var definition = ManagedPolicyKeys.Single(definition =>
            string.Equals(definition.SubKey, snapshot.SubKey, StringComparison.Ordinal));
        using var key = Registry.LocalMachine.CreateSubKey($@"{snapshot.Root}\{snapshot.SubKey}");
        if (key == null) throw new IOException($"Could not open PowerShell policy key '{snapshot.SubKey}' for restoration.");

        var expectedNames = snapshot.Values.Select(value => value.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var namesToRemove = definition.CaptureAllValues
            ? key.GetValueNames().Where(name => !expectedNames.Contains(name)).ToArray()
            : definition.ValueNames.Where(name => !expectedNames.Contains(name)).ToArray();
        foreach (var name in namesToRemove) key.DeleteValue(name, false);
        foreach (var value in snapshot.Values) key.SetValue(value.Name, RestoreValue(value), value.Kind);
    }

    private static object RestoreValue(PowerShellAuditingPolicyValueSnapshot value) => value.Kind switch
    {
        RegistryValueKind.DWord => value.DwordValue,
        RegistryValueKind.QWord => value.QwordValue,
        RegistryValueKind.String or RegistryValueKind.ExpandString => value.StringValue,
        RegistryValueKind.MultiString => value.MultiStringValue,
        RegistryValueKind.Binary or RegistryValueKind.None => value.BinaryValue,
        _ => throw new InvalidOperationException($"PowerShell policy value '{value.Name}' has unsupported registry kind '{value.Kind}'.")
    };

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

    private sealed record PolicyKeyDefinition(string SubKey, bool CaptureAllValues, string[] ValueNames);
}
