using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services;

/// <summary>Portable settings files shared by Viewer and Agent. Never reads or changes Windows policy or recovery state.</summary>
public sealed class WindowsSettingsFolderStore
{
    public const int MaximumListedFolders = 256;
    public const int MaximumBytes = 256 * 1024;
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 32
    };
    public static string DefaultName(string computer, DateTime time) => $"{SafeHost(computer)}-{time:yyyyMMdd-HHmmssfff}Z-windows-security.dfirconfig";

    public WindowsSettingsFolderEntry[] ListSavedFolders(string parent, string computerName)
    {
        parent = Path.GetFullPath(parent);
        ValidatePath(parent);
        if (!Directory.Exists(parent)) return [];
        var folders = Directory.EnumerateDirectories(parent).Take(MaximumListedFolders + 1).ToArray();
        if (folders.Length > MaximumListedFolders)
            throw new InvalidOperationException("This location has too many folders to list. Use Browse to choose one saved configuration folder.");
        return folders.Where(folder => !folder.EndsWith(".partial", StringComparison.OrdinalIgnoreCase))
            .Select(folder => InspectSavedFolder(folder, computerName))
            .OrderByDescending(entry => entry.Snapshot?.CapturedAtUtc ?? DateTime.MinValue)
            .ThenBy(entry => entry.FolderPath, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public WindowsSettingsFolderEntry InspectSavedFolder(string folder, string computerName)
    {
        folder = Path.GetFullPath(folder);
        try
        {
            var snapshot = Load(folder);
            if (!string.Equals(snapshot.ComputerName, computerName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("This configuration belongs to another computer: " + snapshot.ComputerName + ".");
            if (snapshot.Areas.Length == 0) throw new InvalidOperationException("No saved settings areas are available in this folder.");
            return new(folder, snapshot, string.Empty);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or JsonException or ArgumentException)
        {
            return new(folder, null, ex.Message);
        }
    }

    public static string SnapshotFingerprint(WindowsSecuritySettingsSnapshot snapshot) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(snapshot, Options)));

    public static string PrepareDefaultDirectory()
    {
        var directory = SessionPathService.GetMonitoringConfigurationDirectory();
        ValidatePath(directory);
        Directory.CreateDirectory(directory);
        ValidatePath(directory);
        return directory;
    }

    public string Save(string selectedFile, WindowsSecuritySettingsSnapshot snapshot)
    {
        snapshot.Validate();
        if (snapshot.Areas.Length == 0) throw new InvalidOperationException("No settings areas were available to export. " + string.Join("; ", snapshot.Gaps));
        if (JsonSerializer.SerializeToUtf8Bytes(snapshot, Options).Length > MaximumBytes)
            throw new InvalidOperationException("Selected settings exceed the 256 KiB portable/IPC limit; select fewer areas.");
        var parent = Path.GetDirectoryName(Path.GetFullPath(selectedFile))!;
        foreach (var entry in snapshot.UserFolderAuditing is { RootConfigurationOnly: false } legacy ? legacy.Entries : [])
        {
            var observedPath = Path.GetFullPath(entry.Path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (parent.Equals(observedPath, StringComparison.OrdinalIgnoreCase) ||
                parent.StartsWith(observedPath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Settings cannot be saved inside an audited user folder because the new files would invalidate its restore inventory. " +
                    "Choose a save location outside the audited folders; for automatic pre-apply saves, move the package outside those folders or deselect user-folder auditing. No Windows settings were changed.");
        }
        var fileName = Path.GetFileName(selectedFile);
        if (!fileName.EndsWith(".dfirconfig", StringComparison.OrdinalIgnoreCase) || fileName.Length > 180)
            throw new InvalidOperationException("Choose a bounded .dfirconfig export name.");
        var folder = Path.Combine(parent, $"{SafeHost(snapshot.ComputerName)}-{snapshot.CapturedAtUtc:yyyyMMdd-HHmmssfff}Z");
        ValidatePath(folder);
        if (Directory.Exists(folder) || File.Exists(folder)) throw new IOException("This export folder already exists. Existing exports are never overwritten.");
        Directory.CreateDirectory(parent);
        ValidatePath(parent);
        var temporary = folder + "." + Guid.NewGuid().ToString("N") + ".partial";
        Directory.CreateDirectory(temporary);
        try
        {
            var files = new List<AreaFile>();
            foreach (var area in snapshot.Areas)
            {
                var name = $"{SafeHost(snapshot.ComputerName)}-{snapshot.CapturedAtUtc:yyyyMMdd-HHmmssfff}Z-{area}.json";
                var bytes = JsonSerializer.SerializeToUtf8Bytes(snapshot.Select([area]) with { Gaps = [] }, Options);
                WriteNew(Path.Combine(temporary, name), bytes);
                files.Add(new(area, name, Convert.ToHexString(SHA256.HashData(bytes))));
            }
            WriteNew(Path.Combine(temporary, fileName), JsonSerializer.SerializeToUtf8Bytes(
                new Manifest(snapshot.Version, snapshot.ComputerName, snapshot.CapturedAtUtc, files.ToArray(), snapshot.Gaps), Options));
            ValidatePath(folder);
            Directory.Move(temporary, folder); // Atomic publication; destination must still be absent.
            return Path.Combine(folder, fileName);
        }
        finally { if (Directory.Exists(temporary)) Directory.Delete(temporary, recursive: true); }
    }

    public WindowsSecuritySettingsSnapshot Load(string selectedFolder)
    {
        var folder = Path.GetFullPath(selectedFolder);
        ValidatePath(folder);
        var candidates = Directory.EnumerateFiles(folder, "*.dfirconfig", SearchOption.TopDirectoryOnly).Take(2).ToArray();
        if (candidates.Length != 1) throw new InvalidOperationException("Select a folder containing exactly one DFIRoscope settings export.");
        var manifest = JsonSerializer.Deserialize<Manifest>(Read(candidates[0]), Options)
            ?? throw new InvalidOperationException("Empty settings manifest.");
        if (manifest.Version is not (1 or 2) || manifest.Files == null || manifest.Files.Length is < 1 or > 6 ||
            manifest.Files.Any(f => f == null || !Enum.IsDefined(f.Area) || f.Area == WindowsSecuritySettingsArea.Unknown ||
                string.IsNullOrEmpty(f.Name) || f.Name.Length > 180 || f.Name != Path.GetFileName(f.Name) ||
                f.Name.Contains(':') || f.Name.Contains('/') || f.Name.Contains('\\') || !f.Name.EndsWith(".json", StringComparison.Ordinal) ||
                f.Hash == null || f.Hash.Length != 64) ||
            manifest.Files.Select(f => f.Area).Distinct().Count() != manifest.Files.Length ||
            manifest.Files.Select(f => f.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != manifest.Files.Length)
            throw new InvalidOperationException("Unsupported or malformed settings manifest.");
        var snapshot = new WindowsSecuritySettingsSnapshot { Version = manifest.Version, ComputerName = manifest.ComputerName, CapturedAtUtc = manifest.CapturedAtUtc, Gaps = manifest.Gaps };
        snapshot.Validate();
        foreach (var entry in manifest.Files)
        {
            byte[] bytes;
            try { bytes = Read(Path.Combine(folder, entry.Name)); }
            catch (FileNotFoundException) { continue; } // Missing areas remain unselected and disabled.
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(bytes)), entry.Hash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"{entry.Area} settings failed the export integrity check.");
            var area = JsonSerializer.Deserialize<WindowsSecuritySettingsSnapshot>(bytes, Options)
                ?? throw new InvalidOperationException("Empty settings area.");
            area.Validate();
            if (area.Version != snapshot.Version || area.ComputerName != snapshot.ComputerName || area.CapturedAtUtc != snapshot.CapturedAtUtc ||
                area.Areas.Length != 1 || area.Areas[0] != entry.Area || area.Gaps.Length != 0)
                throw new InvalidOperationException("Mixed settings generations or area identities.");
            snapshot = snapshot with
            {
                AuditPolicy = area.AuditPolicy ?? snapshot.AuditPolicy, CommandLine = area.CommandLine ?? snapshot.CommandLine,
                EventLogEnabled = area.EventLogEnabled ?? snapshot.EventLogEnabled,
                EventLogRetention = area.EventLogRetention ?? snapshot.EventLogRetention,
                UserFolderAuditing = area.UserFolderAuditing ?? snapshot.UserFolderAuditing,
                RegistryAuditing = area.RegistryAuditing ?? snapshot.RegistryAuditing
            };
        }
        snapshot.Validate();
        if (JsonSerializer.SerializeToUtf8Bytes(snapshot, Options).Length > MaximumBytes)
            throw new InvalidOperationException("Settings export exceeds the bounded transport limit.");
        return snapshot;
    }

    private static byte[] Read(string path)
    {
        ValidatePath(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > MaximumBytes) throw new InvalidOperationException("Invalid settings file size.");
        var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes); return bytes;
    }
    private static void WriteNew(string path, byte[] bytes)
    {
        if (bytes.Length > MaximumBytes) throw new InvalidOperationException("Settings area exceeds its size limit.");
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        stream.Write(bytes); stream.Flush(true);
    }
    private static string SafeHost(string host) => new(host.Select(c => char.IsAsciiLetterOrDigit(c) || c == '-' ? c : '_').ToArray());
    private static void ValidatePath(string path)
    {
        for (var current = path; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(current); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Settings paths cannot traverse reparse points.");
        }
    }
    private sealed record Manifest(int Version, string ComputerName, DateTime CapturedAtUtc, AreaFile[] Files, string[] Gaps);
    private sealed record AreaFile(WindowsSecuritySettingsArea Area, string Name, string Hash);
}

public sealed record WindowsSettingsFolderEntry(string FolderPath, WindowsSecuritySettingsSnapshot? Snapshot, string Error)
{
    public bool IsAvailable => Snapshot != null;
    public string Fingerprint => Snapshot == null ? string.Empty : WindowsSettingsFolderStore.SnapshotFingerprint(Snapshot);
}
