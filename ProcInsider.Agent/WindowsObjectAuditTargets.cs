using Microsoft.Win32;
using System.Security.Principal;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal static class WindowsObjectAuditTargets
{
    internal const string WindowsSecurityPolicyRoot = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    internal const string ReservedCommandLinePolicyRoot = WindowsSecurityPolicyRoot + @"\Audit";
    internal static bool IsReservedCommandLinePolicyPath(string path) =>
        path.Equals(ReservedCommandLinePolicyRoot, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(ReservedCommandLinePolicyRoot + "\\", StringComparison.OrdinalIgnoreCase);
    private const string ShellFolders = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    private static readonly string[] UserRegistryPaths =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ];
    private static readonly string[] MachineRegistryPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        @"SOFTWARE\Policies\Microsoft\Windows Defender"
    ];

    internal static ObjectAuditDiscovery Discover(AgentSecurityAuditMonitoringIntent intent)
    {
        var targets = new List<ObjectAuditTarget>();
        var gaps = new List<string>();
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        var profileIds = Array.Empty<string>();
        var profileRoots = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var folderBoundariesAvailable = false;
        try
        {
            using var profiles = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
                ?? throw new InvalidOperationException("Local profile inventory is unavailable.");
            profileIds = profiles.GetSubKeyNames().Where(IsUserSid).Order(StringComparer.Ordinal).ToArray();
            if (profileIds.Length > 128) throw new InvalidOperationException("Object-audit discovery is limited to 128 user profiles.");
            foreach (var sid in profileIds)
            {
                var root = ReadFolderProfileRoot(intent, () =>
                {
                    using var profile = profiles.OpenSubKey(sid);
                    return profile?.GetValue("ProfileImagePath") as string;
                });
                if (root != null) profileRoots.Add(sid, root);
            }
            folderBoundariesAvailable = true;
        }
        catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex))
        { gaps.Add("User-folder boundary inventory unavailable: " + ex.Message); }
        // Registry discovery needs loaded HKU identities, not filesystem profile locations.
        var userIds = profileIds.Take(128).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (intent.AuditRegistryWrites)
        {
            try
            {
                var loaded = users.GetSubKeyNames().Where(IsUserSid).Take(129).ToArray();
                if (loaded.Length > 128) gaps.Add("Loaded-user registry inventory exceeds 128 accounts; remaining accounts are not covered.");
                userIds.UnionWith(loaded.Take(128));
            }
            catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex))
            { gaps.Add("Loaded-user registry inventory unavailable: " + ex.Message); }
        }
        foreach (var sid in userIds.Order(StringComparer.Ordinal))
        {
            try
            {
                using var user = users.OpenSubKey(sid);
                if (user == null)
                {
                    gaps.Add($"{sid}: profile path or loaded user hive unavailable; folders and registry roots unresolved. Recheck after that user signs in.");
                    continue;
                }
                if (intent.AuditRegistryWrites)
                    foreach (var key in UserRegistryPaths) targets.Add(new(ObjectAuditKind.RegistryKey, $"HKU\\{sid}\\{key}"));
                if (intent.AuditUserDataFolders && folderBoundariesAvailable && profileRoots.TryGetValue(sid, out var root))
                {
                    using var shell = user.OpenSubKey(ShellFolders);
                    if (shell == null) gaps.Add($"{sid}: User Shell Folders unavailable.");
                    else
                    {
                        using var environment = user.OpenSubKey("Environment");
                        foreach (var (name, fallback) in new[] { ("Desktop", "Desktop"), ("Personal", "Documents"), ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads") })
                        {
                            var raw = shell.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                            var path = ExpandUserPath(raw ?? Path.Combine(root, fallback), root, environment);
                            if (path.Contains('%')) { gaps.Add($"{sid}/{fallback}: unresolved user-specific environment variable."); continue; }
                            AddFolder(path, targets, gaps, profileRoots.Values);
                        }
                    }
                }
            }
            catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex)) { gaps.Add($"{sid}: {ex.Message}"); }
        }
        if (intent.AuditUserDataFolders && folderBoundariesAvailable)
        {
            var publicRoot = Environment.GetEnvironmentVariable("PUBLIC");
            if (string.IsNullOrWhiteSpace(publicRoot)) gaps.Add("Public profile path unavailable.");
            else foreach (var name in new[] { "Desktop", "Documents", "Downloads" }) AddFolder(Path.Combine(publicRoot, name), targets, gaps, profileRoots.Values);
        }
        if (intent.AuditRegistryWrites)
        {
            targets.AddRange(MachineRegistryPaths.Select(CreateMachineRegistryTarget));
            using var select = machine.OpenSubKey(@"SYSTEM\Select");
            if (select?.GetValue("Current") is int current && current is > 0 and < 1000)
                targets.Add(new(ObjectAuditKind.RegistryKey, $"HKLM\\SYSTEM\\ControlSet{current:D3}\\Services"));
            else gaps.Add("Active SYSTEM control set unavailable; service registry auditing unresolved.");
        }
        return new(targets.Distinct().ToArray(), gaps.ToArray())
        {
            Exclusions = intent.AuditRegistryWrites ?
                [ReservedCommandLinePolicyRoot + ": reserved for Agent command-line policy configuration; this subtree is excluded while its parent security-policy key is audited without inheritance."] : []
        };
    }

    internal static ObjectAuditTarget CreateMachineRegistryTarget(string key)
    {
        var target = new ObjectAuditTarget(ObjectAuditKind.RegistryKey, "HKLM\\" + key);
        return target.Path.Equals(WindowsSecurityPolicyRoot, StringComparison.OrdinalIgnoreCase)
            ? target with { IncludeDescendants = false }
            : target;
    }

    internal static string? ReadFolderProfileRoot(AgentSecurityAuditMonitoringIntent intent, Func<string?> readRoot)
    {
        if (!intent.AuditUserDataFolders) return null;
        var root = readRoot();
        if (string.IsNullOrWhiteSpace(root) || !Path.IsPathFullyQualified(root))
            throw new InvalidOperationException("Cannot bound user-data roots because a profile location is unavailable.");
        return Path.GetFullPath(root).TrimEnd('\\');
    }

    private static void AddFolder(string path, List<ObjectAuditTarget> targets, List<string> gaps, IEnumerable<string> profileRoots)
    {
        try
        {
            if (!Path.IsPathFullyQualified(path))
                throw new InvalidOperationException("Relative user-folder redirection cannot be resolved safely.");
            path = Path.GetFullPath(path).TrimEnd('\\');
            ValidateProfileBoundary(path, profileRoots);
            ValidateDataRoot(path);
            WindowsObjectAuditRuntime.ValidateLocalPath(path);
            // The native open distinguishes exact absence from access denial. Exists()
            // returns false for both and must not decide backup coverage.
            targets.Add(new(ObjectAuditKind.Directory, path));
        }
        catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex)) { gaps.Add($"{path}: {ex.Message}"); }
    }

    internal static string ExpandUserPath(string raw, string root, RegistryKey? environment = null)
    {
        var result = raw.Replace("%USERPROFILE%", root, StringComparison.OrdinalIgnoreCase)
            .Replace("%HOMEDRIVE%", Path.GetPathRoot(root)!.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)
            .Replace("%HOMEPATH%", root[2..], StringComparison.OrdinalIgnoreCase);
        foreach (var name in new[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" })
            if (environment?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string value && !value.Contains('%'))
                result = result.Replace($"%{name}%", value, StringComparison.OrdinalIgnoreCase);
        return result;
    }

    internal static bool IsUserSid(string value)
    {
        try { return new SecurityIdentifier(value).IsAccountSid(); }
        catch (ArgumentException) { return false; }
    }

    internal static void ValidateDataRoot(string path)
    {
        var normalized = Path.GetFullPath(path).TrimEnd('\\');
        if (normalized.Equals(Path.GetPathRoot(normalized)?.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Whole-volume auditing is not supported.");
        foreach (var special in new[] { Environment.SpecialFolder.Windows, Environment.SpecialFolder.ProgramFiles,
                     Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.CommonApplicationData })
        {
            var excluded = Environment.GetFolderPath(special).TrimEnd('\\');
            if (excluded.Length > 0 && (normalized.Equals(excluded, StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith(excluded + "\\", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("System, application and shared application-data trees are not user-data audit roots.");
        }
        if (normalized.Split('\\').Any(p => p.Equals("AppData", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("AppData trees are excluded from this user-data auditing profile.");
    }

    internal static void ValidateProfileBoundary(string path, IEnumerable<string> profileRoots)
    {
        var normalized = Path.GetFullPath(path).TrimEnd('\\');
        foreach (var profile in profileRoots.Select(p => Path.GetFullPath(p).TrimEnd('\\')))
            if (profile.Equals(normalized, StringComparison.OrdinalIgnoreCase) ||
                profile.StartsWith(normalized + "\\", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("A whole profile or its ancestor is too broad for targeted user-folder auditing.");
    }

    internal static void ValidateRegistryRoot(string path)
    {
        if (MachineRegistryPaths.Any(key => path.Equals("HKLM\\" + key, StringComparison.OrdinalIgnoreCase))) return;
        if (System.Text.RegularExpressions.Regex.IsMatch(path, @"^HKLM\\SYSTEM\\ControlSet[0-9]{3}\\Services$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)) return;
        var parts = path.Split('\\', 3);
        if (parts.Length == 3 && parts[0] == "HKU" && IsUserSid(parts[1]) &&
            UserRegistryPaths.Contains(parts[2], StringComparer.OrdinalIgnoreCase)) return;
        throw new InvalidOperationException("Registry path is outside the reviewed object-audit root inventory.");
    }
}
