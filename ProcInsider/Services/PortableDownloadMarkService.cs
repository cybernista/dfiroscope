using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProcInsider.Services;

/// <summary>
/// Offers an explicit, package-local choice to remove the Windows download marker.
/// This is not an authenticity check and never operates on session or configuration data.
/// </summary>
internal sealed class PortableDownloadMarkService
{
    private const string ZoneStreamName = ":Zone.Identifier";
    private const uint FileReadAttributes = 0x80;
    private const uint DeleteAccess = 0x10000;
    private const uint ShareAll = 0x1 | 0x2 | 0x4;
    private const uint ShareReadWrite = 0x1 | 0x2;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeReparsePoint = 0x400;
    private const int FileDispositionInfo = 4;
    private readonly string _applicationDirectory;
    private readonly string _processPath;

    public PortableDownloadMarkService(string applicationDirectory, string processPath)
    {
        _applicationDirectory = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(applicationDirectory));
        _processPath = Path.GetFullPath(processPath);
    }

    public PortableDownloadMarkScan? Inspect()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        var location = ResolveExactViewerPackage();
        if (location == null)
        {
            return null;
        }

        var marked = new List<PortableDownloadMarkFile>();
        var warnings = new List<string>();
        foreach (var directoryName in new[]
                 {
                     PortablePackageLocationService.ViewerDirectoryName,
                     PortablePackageLocationService.AgentDirectoryName
                 })
        {
            var directory = Path.Combine(location.PackageRoot, directoryName);
            try
            {
                // Program binaries are packaged at these two immediate directory levels.
                // Never recurse into Sessions, settings, runtime-created data or links.
                foreach (var filePath in Directory.EnumerateFiles(
                             directory, "*", SearchOption.TopDirectoryOnly))
                {
                    if (!IsProgramBinary(filePath))
                    {
                        continue;
                    }

                    var relativePath = Path.Combine(directoryName, Path.GetFileName(filePath));
                    try
                    {
                        var inspected = InspectZoneStream(filePath, relativePath);
                        if (inspected != null) marked.Add(inspected);
                    }
                    catch (Exception ex) when (IsExpectedFileError(ex))
                    {
                        warnings.Add($"{relativePath}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex) when (IsExpectedFileError(ex))
            {
                warnings.Add($"{directoryName}: {ex.Message}");
            }
        }

        return marked.Count == 0 && warnings.Count == 0
            ? null
            : new PortableDownloadMarkScan(
                location.PackageRoot,
                marked.OrderBy(file => file.RelativePath, StringComparer.OrdinalIgnoreCase).ToArray(),
                warnings.ToArray());
    }

    public PortableDownloadMarkRemovalResult ApplyDecision(
        PortableDownloadMarkScan scan, PortableDownloadMarkDecision decision)
    {
        ArgumentNullException.ThrowIfNull(scan);
        if (decision == PortableDownloadMarkDecision.Skip)
        {
            return new PortableDownloadMarkRemovalResult([], [], []);
        }

        if (decision != PortableDownloadMarkDecision.Remove)
        {
            throw new ArgumentOutOfRangeException(nameof(decision));
        }

        var removed = new List<string>();
        var alreadyAbsent = new List<string>();
        var failed = new List<string>();
        foreach (var file in scan.Files)
        {
            try
            {
                var location = ResolveExactViewerPackage();
                if (location == null || !PathsEqual(location.PackageRoot, scan.PackageRoot) ||
                    !IsExactBinaryChild(file, location))
                {
                    failed.Add($"{file.RelativePath}: portable package validation changed; no marker removed.");
                    continue;
                }

                if (RemoveZoneStream(file))
                {
                    removed.Add(file.RelativePath);
                }
                else
                {
                    alreadyAbsent.Add(file.RelativePath);
                }
            }
            catch (Exception ex) when (IsExpectedFileError(ex))
            {
                failed.Add($"{file.RelativePath}: {ex.Message}");
            }
        }

        return new PortableDownloadMarkRemovalResult(
            removed.ToArray(), alreadyAbsent.ToArray(), failed.ToArray());
    }

    private PortablePackageLocation? ResolveExactViewerPackage()
    {
        try
        {
            var location = PortablePackageLocationService.TryResolve(_applicationDirectory);
            if (location?.ApplicationRole != PortablePackageApplicationRole.Viewer ||
                !PathsEqual(_processPath, Path.Combine(
                    location.ApplicationDirectory,
                    PortablePackageLocationService.ViewerExecutableName)))
            {
                return null;
            }

            return location;
        }
        catch (Exception ex) when (ex is PortablePackageLocationException or IOException or
                                   UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    private static bool IsProgramBinary(string path) =>
        string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Path.GetExtension(path), ".dll", StringComparison.OrdinalIgnoreCase);

    private static bool IsExactBinaryChild(PortableDownloadMarkFile file, PortablePackageLocation location)
    {
        var directoryName = Path.GetDirectoryName(file.RelativePath);
        if (!string.Equals(directoryName, PortablePackageLocationService.ViewerDirectoryName,
                StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(directoryName, PortablePackageLocationService.AgentDirectoryName,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var fileName = Path.GetFileName(file.RelativePath);
        return IsProgramBinary(fileName) &&
               string.Equals(fileName, Path.GetFileName(file.FullPath), StringComparison.Ordinal) &&
               PathsEqual(file.FullPath,
                   Path.Combine(location.PackageRoot, directoryName!, fileName));
    }

    private static PortableDownloadMarkFile? InspectZoneStream(string path, string relativePath)
    {
        using var file = OpenRegularFile(path);
        using var stream = TryOpen(path + ZoneStreamName, FileReadAttributes);
        if (stream == null)
        {
            return null;
        }

        RequireSameFile(file, stream, path);
        if (!GetFileInformationByHandle(file, out var information))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return new PortableDownloadMarkFile(path, relativePath, information.VolumeSerialNumber,
            information.FileIndexHigh, information.FileIndexLow);
    }

    private static bool RemoveZoneStream(PortableDownloadMarkFile expected)
    {
        using var file = OpenRegularFile(expected.FullPath);
        if (!GetFileInformationByHandle(file, out var information))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (information.VolumeSerialNumber != expected.VolumeSerialNumber ||
            information.FileIndexHigh != expected.FileIndexHigh ||
            information.FileIndexLow != expected.FileIndexLow)
            throw new IOException("The inspected program file was replaced before consent was applied.");
        using var stream = TryOpen(expected.FullPath + ZoneStreamName, FileReadAttributes | DeleteAccess,
            ShareReadWrite);
        if (stream == null)
        {
            return false;
        }

        RequireSameFile(file, stream, expected.FullPath);
        var disposition = new FileDispositionInformation { DeleteFile = 1 };
        if (!SetFileInformationByHandle(stream, FileDispositionInfo,
                ref disposition,
                (uint)Marshal.SizeOf<FileDispositionInformation>()))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "Windows could not remove this Zone.Identifier stream");
        }

        return true;
    }

    private static SafeFileHandle OpenRegularFile(string path)
    {
        var handle = TryOpen(path, FileReadAttributes) ??
            throw new IOException("The program file disappeared before its download marker could be checked.");
        try
        {
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if ((information.FileAttributes & (FileAttributeDirectory | FileAttributeReparsePoint)) != 0)
            {
                throw new IOException("The program file is a directory or reparse point.");
            }

            if (information.NumberOfLinks != 1)
            {
                throw new IOException("The program file has another hard-link path.");
            }

            RequireExactFinalPath(handle, path);

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void RequireExactFinalPath(SafeFileHandle handle, string path)
    {
        var finalPath = new StringBuilder(32768);
        var pathLength = GetFinalPathNameByHandle(handle, finalPath,
            (uint)finalPath.Capacity, 0);
        if (pathLength == 0 || pathLength >= finalPath.Capacity)
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "Windows could not verify the opened program-file path");
        var resolvedPath = finalPath.ToString();
        if (resolvedPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            resolvedPath = @"\\" + resolvedPath[8..];
        else if (resolvedPath.StartsWith(@"\\?\", StringComparison.Ordinal))
            resolvedPath = resolvedPath[4..];
        if (!PathsEqual(resolvedPath, path))
            throw new IOException("The opened program file resolves outside its exact portable path.");
    }

    private static SafeFileHandle? TryOpen(string path, uint access, uint shareMode = ShareAll)
    {
        var handle = CreateFile(path, access, shareMode, IntPtr.Zero, OpenExisting,
            OpenReparsePoint, IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }

        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        if (error is 2 or 3)
        {
            return null;
        }

        throw new Win32Exception(error);
    }

    private static void RequireSameFile(SafeFileHandle file, SafeFileHandle stream, string expectedPath)
    {
        if (!GetFileInformationByHandle(file, out var baseInfo) ||
            !GetFileInformationByHandle(stream, out var streamInfo))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        if (baseInfo.VolumeSerialNumber != streamInfo.VolumeSerialNumber ||
            baseInfo.FileIndexHigh != streamInfo.FileIndexHigh ||
            baseInfo.FileIndexLow != streamInfo.FileIndexLow ||
            baseInfo.NumberOfLinks != 1 || streamInfo.NumberOfLinks != 1 ||
            (streamInfo.FileAttributes & FileAttributeReparsePoint) != 0)
        {
            throw new IOException("The program file changed during download-marker inspection.");
        }
        RequireExactFinalPath(file, expectedPath);
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right),
            StringComparison.OrdinalIgnoreCase);

    private static bool IsExpectedFileError(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or Win32Exception or
            ArgumentException or NotSupportedException;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file, out ByHandleFileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true,
        EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file, StringBuilder path, uint pathLength, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file, int fileInformationClass,
        ref FileDispositionInformation information, uint bufferSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        // Win32 BOOLEAN is one byte; BOOL would incorrectly marshal four bytes.
        public byte DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}

internal sealed record PortableDownloadMarkFile(string FullPath, string RelativePath,
    uint VolumeSerialNumber, uint FileIndexHigh, uint FileIndexLow);

internal enum PortableDownloadMarkDecision
{
    Skip,
    Remove
}

internal sealed record PortableDownloadMarkScan(
    string PackageRoot,
    IReadOnlyList<PortableDownloadMarkFile> Files,
    IReadOnlyList<string> Warnings);

internal sealed record PortableDownloadMarkRemovalResult(
    IReadOnlyList<string> Removed,
    IReadOnlyList<string> AlreadyAbsent,
    IReadOnlyList<string> Failed);
