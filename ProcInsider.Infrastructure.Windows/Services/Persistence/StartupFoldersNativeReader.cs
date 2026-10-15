using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

internal sealed record StartupFolderDeclaration(string Id, string Root, string Sid, string Scope, IReadOnlyDictionary<string, PersistenceNativeValue> Configuration);

internal sealed class StartupFoldersNativeReader : IStartupFoldersNativeReader
{
    internal const int MaxProfiles = 512;
    internal const int MaxEntries = 20000;
    internal const int MaxAggregateBytes = 32 * 1024 * 1024;
    private const string ShellFolders = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    public IReadOnlyList<StartupNativeFolder> Read(CancellationToken token)
    {
        var results = new List<StartupNativeFolder>(); var remainingBytes = MaxAggregateBytes; var remainingEntries = MaxEntries;
        try
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
            using var profiles = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", writable: false)
                ?? throw new IOException("Startup profile directory unavailable.");
            var profileStamp = PersistenceRegistryNativeReader.Metadata(profiles); var userStamp = PersistenceRegistryNativeReader.Metadata(users);
            var loaded = PersistenceRegistryNativeReader.Children(users, MaxProfiles * 2 + 16, token).ToHashSet(StringComparer.OrdinalIgnoreCase);
            ReadFolder(() => Common(machine, profiles, ref remainingBytes));
            foreach (var sid in PersistenceRegistryNativeReader.Children(profiles, MaxProfiles, token))
            {
                token.ThrowIfCancellationRequested();
                if (!Regex.IsMatch(sid, @"^S-\d+(?:-\d+)+$", RegexOptions.CultureInvariant)) continue;
                if (sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20")
                {
                    results.Add(new("ExcludedServiceProfile:" + sid, null, sid, "ExcludedServiceProfile", PersistenceCollectionStatus.Failed, [],
                        new Dictionary<string, PersistenceNativeValue>(), "Windows service-account profile excluded from interactive Startup folders; no empty-folder assertion.", Attempted: false));
                    continue;
                }
                if (!loaded.Contains(sid))
                {
                    results.Add(new("ExcludedUnloadedProfile:" + sid, null, sid, "ExcludedUnloadedProfile", PersistenceCollectionStatus.Failed, [],
                        new Dictionary<string, PersistenceNativeValue>(), "Known profile SID excluded: hive is unloaded, configured Startup root unknown; no hive loading or complete-empty assertion.", Attempted: false));
                    continue;
                }
                ReadFolder(() => User(profiles, users, sid, ref remainingBytes), sid);
                if (remainingBytes <= 0 || remainingEntries <= 0) throw new InvalidDataException("Startup aggregate bound reached.");
            }
            if (PersistenceRegistryNativeReader.Metadata(profiles) != profileStamp || PersistenceRegistryNativeReader.Metadata(users) != userStamp)
                throw new IOException("Startup profile discovery changed during collection.");
        }
        catch (Exception ex) when (ServicesDriversNativeReader.ExpectedFailure(ex))
        {
            results.Add(new("StartupDiscovery", null, "", "LocalConfiguredStartup", PersistenceCollectionStatus.Failed, [], new Dictionary<string, PersistenceNativeValue>(),
                "Startup declaration/discovery set unavailable, changed or bounded; attempted family is incomplete."));
        }
        token.ThrowIfCancellationRequested();
        return results;
        void ReadFolder(Func<StartupFolderDeclaration> declaration, string sid = "")
        {
            StartupFolderDeclaration? value = null; var entries = new List<StartupNativeObject>(); var status = PersistenceCollectionStatus.Complete;
            try
            {
                value = declaration();
                StartupFolderFileReader.Read(value.Root, entries, ref remainingEntries, ref remainingBytes, token);
                var after = declaration();
                if (value.Root != after.Root || JsonSerializer.Serialize(value.Configuration) != JsonSerializer.Serialize(after.Configuration))
                    throw new IOException("Startup declaration changed during object enumeration.");
            }
            catch (Exception ex) when (ServicesDriversNativeReader.ExpectedFailure(ex) || ex is System.Runtime.InteropServices.COMException)
            { status = entries.Count == 0 ? PersistenceCollectionStatus.Failed : PersistenceCollectionStatus.Partial; }
            results.Add(new(value?.Id ?? (sid.Length == 0 ? "CommonStartupDeclaration" : "UserStartupDeclaration:" + sid), value?.Root, sid,
                value?.Scope ?? (sid.Length == 0 ? "MachineCommonStartup" : "DeclaredUserProfile"), status, entries,
                value?.Configuration ?? new Dictionary<string, PersistenceNativeValue>(), status == PersistenceCollectionStatus.Complete
                    ? "Existing declared Startup folder enumerated nonrecursively; target strings are not resolved or accessed."
                    : "Declared Startup root/object unavailable, unsafe, changed or bounded; missing roots are not complete-empty."));
        }
    }
    private static StartupFolderDeclaration Common(RegistryKey machine, RegistryKey profiles, ref int bytes)
    {
        using var key = machine.OpenSubKey(ShellFolders, writable: false) ?? throw new IOException("Common Startup declaration unavailable.");
        var stamp = PersistenceRegistryNativeReader.Metadata(key);
        var value = PersistenceRegistryNativeReader.Field(key, "Common Startup", ref bytes);
        var native = PersistenceRegistryNativeReader.Text(value);
        var programDataValue = ProgramData(profiles, native, ref bytes);
        var programData = programDataValue == null ? null : Expand(PersistenceRegistryNativeReader.Text(programDataValue), null);
        var root = Expand(native, null, programData);
        if (PersistenceRegistryNativeReader.Metadata(key) != stamp) throw new IOException("Common Startup declaration changed.");
        var configuration = new Dictionary<string, PersistenceNativeValue> { ["CommonStartupSetting"] = value! };
        if (programDataValue != null) configuration["ProgramDataSetting"] = programDataValue;
        return new("CommonStartup", root, "", "MachineCommonStartup", configuration);
    }
    private static StartupFolderDeclaration User(RegistryKey profiles, RegistryKey users, string sid, ref int bytes)
    {
        using var profile = profiles.OpenSubKey(sid, writable: false) ?? throw new IOException("Profile declaration disappeared.");
        var profileStamp = PersistenceRegistryNativeReader.Metadata(profile);
        var profileValue = PersistenceRegistryNativeReader.Field(profile, "ProfileImagePath", ref bytes);
        var profilePath = Expand(PersistenceRegistryNativeReader.Text(profileValue), null);
        using var user = users.OpenSubKey(sid, writable: false) ?? throw new IOException("Loaded profile hive disappeared.");
        using var key = user.OpenSubKey(ShellFolders, writable: false) ?? throw new IOException("User Startup declaration unavailable.");
        var stamp = PersistenceRegistryNativeReader.Metadata(key);
        var value = PersistenceRegistryNativeReader.Field(key, "Startup", ref bytes);
        var native = PersistenceRegistryNativeReader.Text(value);
        var programDataValue = ProgramData(profiles, native, ref bytes);
        var programData = programDataValue == null ? null : Expand(PersistenceRegistryNativeReader.Text(programDataValue), null);
        var appDataValue = native.Contains("%APPDATA%", StringComparison.OrdinalIgnoreCase) ? PersistenceRegistryNativeReader.Field(key, "AppData", ref bytes) : null;
        var localAppDataValue = native.Contains("%LOCALAPPDATA%", StringComparison.OrdinalIgnoreCase) ? PersistenceRegistryNativeReader.Field(key, "Local AppData", ref bytes) : null;
        var appData = appDataValue == null ? null : Expand(PersistenceRegistryNativeReader.Text(appDataValue), profilePath, programData);
        var localAppData = localAppDataValue == null ? null : Expand(PersistenceRegistryNativeReader.Text(localAppDataValue), profilePath, programData);
        var root = Expand(native, profilePath, programData, appData, localAppData);
        if (PersistenceRegistryNativeReader.Metadata(key) != stamp || PersistenceRegistryNativeReader.Metadata(profile) != profileStamp) throw new IOException("User Startup declaration changed.");
        var configuration = new Dictionary<string, PersistenceNativeValue> { ["ProfileImagePath"] = profileValue!, ["UserStartupSetting"] = value! };
        if (programDataValue != null) configuration["ProgramDataSetting"] = programDataValue;
        if (appDataValue != null) configuration["UserAppDataSetting"] = appDataValue;
        if (localAppDataValue != null) configuration["UserLocalAppDataSetting"] = localAppDataValue;
        return new("UserStartup:" + sid, root, sid, "DeclaredUserProfile", configuration);
    }
    private static PersistenceNativeValue? ProgramData(RegistryKey profiles, string native, ref int bytes)
    {
        if (!native.Contains("%PROGRAMDATA%", StringComparison.OrdinalIgnoreCase) && !native.Contains("%ALLUSERSPROFILE%", StringComparison.OrdinalIgnoreCase)) return null;
        return PersistenceRegistryNativeReader.Field(profiles, "ProgramData", ref bytes) ?? throw new IOException("Machine ProgramData declaration unavailable.");
    }
    internal static string Expand(string native, string? profile, string? programData = null, string? appData = null, string? localAppData = null)
    {
        if (native.Length > StartupFolderFileReader.MaxPathCharacters) throw new InvalidDataException("Startup declaration path bound reached.");
        var expanded = Regex.Replace(native, "%([^%]+)%", match => match.Groups[1].Value.ToUpperInvariant() switch
        {
            "USERPROFILE" when profile != null => profile,
            "SYSTEMDRIVE" => Path.GetPathRoot(Environment.SystemDirectory)!.TrimEnd('\\'),
            "SYSTEMROOT" or "WINDIR" => Directory.GetParent(Environment.SystemDirectory)!.FullName,
            "PROGRAMDATA" or "ALLUSERSPROFILE" when programData != null => programData,
            "APPDATA" when appData != null => appData,
            "LOCALAPPDATA" when localAppData != null => localAppData,
            _ => throw new InvalidDataException("Unresolved Startup environment variable; current-user substitution is forbidden.")
        }, RegexOptions.CultureInvariant);
        return StartupFolderFileReader.ValidateLocalPath(expanded);
    }
}
