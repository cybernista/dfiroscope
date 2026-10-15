using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProcInsider.Services.Persistence;

internal static class StartupFolderFileReader
{
    internal const int MaxPathCharacters = 32768;
    internal const int MaxShortcutBytes = 1024 * 1024;
    internal static string ValidateLocalPath(string path)
    {
        PersistenceRegistryNativeReader.ValidateText(path);
        if (path.Length > MaxPathCharacters || path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\' || path[2..].Contains(':') || path.Contains('%'))
            throw new InvalidDataException("Startup root must be a resolved ordinary local drive path, never UNC/device/stream.");
        // Reject spelling aliases before GetFullPath can normalize trailing dots/spaces away.
        ValidateComponents(path);
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException) { throw new InvalidDataException("Invalid Startup root path.", ex); }
        ValidateComponents(full);
        return full.Length == 3 ? full : full.TrimEnd('\\');
        static void ValidateComponents(string value)
        {
            foreach (var component in value[3..].Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries))
                if (component.EndsWith('.') || component.EndsWith(' ') || System.Text.RegularExpressions.Regex.IsMatch(component, @"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant))
                    throw new InvalidDataException("Startup device name or path alias rejected.");
        }
    }
    internal static void Read(string root, List<StartupNativeObject> entries, ref int remainingEntries, ref int remainingBytes, CancellationToken token,
        Func<byte[], ShortcutNativeValue>? shortcutDecoder = null)
    {
        root = ValidateLocalPath(root);
        var drive = Path.GetPathRoot(root)!;
        if (GetDriveType(drive) is not (2 or 3 or 5 or 6)) throw new IOException("Startup drive is unavailable or remote; no remote root read.");
        var held = new List<SafeFileHandle>();
        try
        {
            // Hold every verified directory against deletion/write while enumerating. OPEN_REPARSE_POINT
            // checks each component itself, so a raced junction cannot redirect a later source read.
            var current = drive;
            Hold(current);
            foreach (var part in Path.GetRelativePath(drive, root).Split('\\', StringSplitOptions.RemoveEmptyEntries).Where(part => part != ".")) { token.ThrowIfCancellationRequested(); current = Path.Combine(current, part); Hold(current); }
            var rootBefore = Metadata(held[^1]);
            foreach (var path in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.TopDirectoryOnly))
            {
                token.ThrowIfCancellationRequested();
                if (remainingEntries-- <= 0) throw new InvalidDataException("Startup attempted-entry bound reached.");
                var source = ValidateLocalPath(path);
                if (!string.Equals(Path.GetDirectoryName(source), root, StringComparison.OrdinalIgnoreCase)) throw new IOException("Startup object escaped declared root.");
                var pathBytes = checked(source.Length * sizeof(char));
                if (pathBytes > remainingBytes) throw new InvalidDataException("Startup aggregate path byte bound reached.");
                remainingBytes -= pathBytes;
                var shortcut = Path.GetExtension(source).Equals(".lnk", StringComparison.OrdinalIgnoreCase);
                using var file = Open(source, shortcut ? 0x80000000u : 0x80u);
                var before = Metadata(file);
                ValidateAttributes(before.Attributes, directory: false);
                var kind = (before.Attributes & 0x10) != 0 ? "Directory" : shortcut ? "Shortcut" : "File";
                ShortcutNativeValue? value = null;
                if (kind == "Shortcut")
                {
                    var length = ((long)before.SizeHigh << 32) | before.SizeLow;
                    if (length <= 0 || length > Math.Min(MaxShortcutBytes, remainingBytes)) throw new InvalidDataException("Startup shortcut input exceeds allocation bound.");
                    remainingBytes -= (int)length;
                    var bytes = new byte[(int)length];
                    using (var stream = new FileStream(file, FileAccess.Read))
                    {
                        stream.ReadExactly(bytes);
                        if (!Same(Metadata(file), before)) throw new IOException("Startup shortcut changed during the bounded handle read.");
                    }
                    // Parser receives the bounded bytes from this no-follow handle, never a source path.
                    value = (shortcutDecoder ?? StartupShortcutReader.Read)(bytes);
                    StartupShortcutReader.ValidateStrings(value);
                    var strings = checked(((value.Target?.Length ?? 0) + (value.Arguments?.Length ?? 0) + (value.WorkingDirectory?.Length ?? 0)) * sizeof(char));
                    if (strings > remainingBytes) throw new InvalidDataException("Startup aggregate decoded-string bound reached.");
                    remainingBytes -= strings;
                    if (!value.Known)
                    {
                        entries.Add(new(Path.GetFileName(source), source, kind, before.Attributes, value.Target, value.Arguments, value.WorkingDirectory, false));
                        throw new InvalidDataException("Startup shortcut target/configuration unresolved; no source reconciliation.");
                    }
                }
                // FileStream above owns its SafeHandle; ordinary objects remain held for this check.
                if (kind != "Shortcut" && !Same(Metadata(file), before)) throw new IOException("Startup object metadata changed during read.");
                entries.Add(new(Path.GetFileName(source), source, kind, before.Attributes, value?.Target, value?.Arguments, value?.WorkingDirectory, value?.Known == true));
            }
            if (!Same(Metadata(held[^1]), rootBefore)) throw new IOException("Startup directory changed during enumeration.");
        }
        finally { foreach (var handle in held) handle.Dispose(); }
        void Hold(string path)
        {
            var handle = Open(path, 0x80);
            try { var info = Metadata(handle); ValidateAttributes(info.Attributes, directory: true); held.Add(handle); }
            catch { handle.Dispose(); throw; }
        }
    }
    internal static void ValidateAttributes(uint attributes, bool directory)
    {
        if ((attributes & 0x400) != 0 || directory && (attributes & 0x10) == 0)
            throw new IOException("Startup source is a reparse point or its directory chain is not a directory; no traversal allowed.");
    }
    private static SafeFileHandle Open(string path, uint access)
    {
        // FILE_SHARE_READ only: no writer/deleter can redirect or alter the held source.
        var handle = CreateFile(path, access, 1, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) { var error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
        return handle;
    }
    private static FileIdentity Metadata(SafeFileHandle handle)
    {
        if (GetFileType(handle) != 1 || !GetFileInformationByHandle(handle, out var value)) throw new IOException("Startup source is not an ordinary disk object or metadata is unavailable.");
        return value;
    }
    private static bool Same(FileIdentity a, FileIdentity b) => a.Attributes == b.Attributes && a.Written == b.Written && a.SizeHigh == b.SizeHigh && a.SizeLow == b.SizeLow && a.Volume == b.Volume && a.IndexHigh == b.IndexHigh && a.IndexLow == b.IndexLow;
    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct FileTime(uint Low, uint High);
    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct FileIdentity(uint Attributes, FileTime Created, FileTime Accessed, FileTime Written, uint Volume, uint SizeHigh, uint SizeLow, uint Links, uint IndexHigh, uint IndexLow);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileIdentity info);
    [DllImport("kernel32.dll")] private static extern uint GetFileType(SafeFileHandle handle);
    [DllImport("kernel32.dll", EntryPoint = "GetDriveTypeW", CharSet = CharSet.Unicode)] private static extern uint GetDriveType(string root);
}
