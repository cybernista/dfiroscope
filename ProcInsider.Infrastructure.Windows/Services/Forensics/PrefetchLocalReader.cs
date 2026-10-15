using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models;

namespace ProcInsider.Services.Forensics;

/// <summary>Reads only the immediate local Windows Prefetch directory. Callers receive owned bytes, never a reopenable source path.</summary>
public interface IPrefetchLocalReader
{
    void Read(Action<PrefetchLocalRead> accept, CancellationToken cancellationToken);
}

public sealed record PrefetchLocalRead
{
    public bool IsCoverage { get; init; }
    public string SourcePath { get; init; } = string.Empty;
    public DateTime ReadStartedUtc { get; init; }
    public DateTime ReadCompletedUtc { get; init; }
    public DateTime? SourceCreatedUtc { get; init; }
    public DateTime? SourceLastModifiedUtc { get; init; }
    public ForensicOwnedInput? Input { get; init; }
    public int BytesRead { get; init; }
    public ForensicReadStatus Status { get; init; }
    public ForensicReadConsistency Consistency { get; init; } = ForensicReadConsistency.Unknown;
    public string DiagnosticCode { get; init; } = string.Empty;
    public string Diagnostic { get; init; } = string.Empty;
}

public sealed class PrefetchLocalReader : IPrefetchLocalReader
{
    private readonly Func<string> _rootResolver;
    // This is deliberately internal construction-only test instrumentation. The production reader has
    // no caller/IPC root or fault input and always uses ResolveRoot.
    private readonly Func<string, string?>? _fixtureFailure;
    public const int MaximumFiles = 256;
    public const int MaximumBytes = 64 * 1024 * 1024;
    public static readonly TimeSpan MaximumProcessingTime = TimeSpan.FromMinutes(1);
    public PrefetchLocalReader() : this(ResolveRoot, null) { }
    internal PrefetchLocalReader(Func<string> rootResolver) : this(rootResolver, null) { }
    internal PrefetchLocalReader(Func<string> rootResolver, Func<string, string?>? fixtureFailure)
    {
        _rootResolver = rootResolver ?? throw new ArgumentNullException(nameof(rootResolver));
        _fixtureFailure = fixtureFailure;
    }

    public void Read(Action<PrefetchLocalRead> accept, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accept);
        var root = _rootResolver();
        FileAttributes attributes;
        try { attributes = File.GetAttributes(root); }
        catch (DirectoryNotFoundException) { accept(Coverage(root, "prefetch.root-missing", "The fixed local Prefetch directory is unavailable.")); return; }
        catch (FileNotFoundException) { accept(Coverage(root, "prefetch.root-missing", "The fixed local Prefetch directory is unavailable.")); return; }
        catch (UnauthorizedAccessException ex) { accept(Coverage(root, "prefetch.root-denied", ex.Message)); return; }
        catch (IOException ex) { accept(Coverage(root, "prefetch.root-inaccessible", ex.Message)); return; }
        if ((attributes & FileAttributes.Directory) == 0 || (attributes & FileAttributes.ReparsePoint) != 0)
        { accept(Coverage(root, "prefetch.root-unsafe", "The fixed local Prefetch directory is not an ordinary directory.")); return; }
        var count = 0;
        var remainingBytes = MaximumBytes;
        var deadline = DateTime.UtcNow + MaximumProcessingTime;
        try
        {
            foreach (var source in Directory.EnumerateFiles(root, "*.pf", SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (DateTime.UtcNow >= deadline) { accept(Coverage(root, "prefetch.time-cap", "The fixed Prefetch enumeration reached its processing-time cap.")); break; }
                if (count >= MaximumFiles)
                {
                    accept(Coverage(root, "prefetch.file-cap", "The fixed Prefetch enumeration reached its file cap."));
                    break;
                }
                var read = ReadOne(root, source, remainingBytes, cancellationToken);
                accept(read);
                remainingBytes -= read.BytesRead;
                count++;
            }
            if (count == 0) accept(Coverage(root, "prefetch.empty", "The fixed local Prefetch directory contained no PF files."));
        }
        catch (UnauthorizedAccessException ex) { accept(Coverage(root, "prefetch.root-denied", ex.Message)); }
        catch (IOException ex) { accept(Coverage(root, "prefetch.root-inaccessible", ex.Message)); }
    }

    public static string ResolveRoot()
    {
        var buffer = new char[32768];
        var length = GetSystemWindowsDirectory(buffer, (uint)buffer.Length);
        if (length == 0 || length >= buffer.Length) throw new IOException("GetSystemWindowsDirectoryW did not return a bounded Windows root.");
        var windows = ValidateLocalPath(new string(buffer, 0, (int)length));
        var root = ValidateLocalPath(Path.Combine(windows, "Prefetch"));
        if (!string.Equals(Path.GetDirectoryName(root), windows, StringComparison.OrdinalIgnoreCase)) throw new IOException("The fixed Prefetch path escaped the Windows directory.");
        return root;
    }

    private PrefetchLocalRead ReadOne(string root, string source, int remainingBytes, CancellationToken cancellationToken)
    {
        var started = DateTime.UtcNow;
        var reservedBytes = 0;
        try
        {
            source = ValidateLocalPath(source);
            if (!string.Equals(Path.GetDirectoryName(source), root, StringComparison.OrdinalIgnoreCase) || !Path.GetExtension(source).Equals(".pf", StringComparison.OrdinalIgnoreCase))
                throw new IOException("Prefetch enumeration escaped the fixed immediate directory.");
            var attributes = File.GetAttributes(source);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) throw new IOException("Prefetch input is a directory or reparse point.");
            using var handle = Open(source);
            if (!PathEquals(FinalPath(handle), source)) throw new IOException("The Prefetch handle final path did not remain inside the enumerated fixed root.");
            var before = ApplyFixtureFailure(source, Metadata(handle), beforeRead: true);
            if (before.HasInvalidFileTime) throw new InvalidDataException("Prefetch handle metadata contains an out-of-range native FILETIME.");
            if ((before.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) throw new IOException("Prefetch handle is not an ordinary file.");
            var size = before.Size;
            if (size < 1 || size > Math.Min(PrefetchParser.MaximumInputBytes, remainingBytes)) throw new InvalidDataException("Prefetch input is empty or exceeds the remaining bounded reader allowance.");
            reservedBytes = checked((int)size);
            cancellationToken.ThrowIfCancellationRequested();
            var bytes = new byte[checked((int)size)];
            MetadataValue after;
            using (var stream = new FileStream(handle, FileAccess.Read, bufferSize: 65536, isAsync: false)) { stream.ReadExactly(bytes); after = ApplyFixtureFailure(source, Metadata(handle), beforeRead: false); }
            var completed = DateTime.UtcNow;
            if (after.HasInvalidFileTime) throw new InvalidDataException("Prefetch handle metadata contains an out-of-range native FILETIME.");
            if (!before.Equals(after)) return new() { SourcePath = source, ReadStartedUtc = started, ReadCompletedUtc = completed, SourceCreatedUtc = before.CreatedUtc, SourceLastModifiedUtc = before.LastWriteUtc, BytesRead = bytes.Length, Status = ForensicReadStatus.Failed, Consistency = ForensicReadConsistency.ChangedDuringRead, DiagnosticCode = "prefetch.changed", Diagnostic = "The held Prefetch handle changed during the bounded read." };
            return new() { SourcePath = source, ReadStartedUtc = started, ReadCompletedUtc = completed, SourceCreatedUtc = before.CreatedUtc, SourceLastModifiedUtc = before.LastWriteUtc, BytesRead = bytes.Length, Input = new ForensicOwnedInput(bytes, PrefetchParser.MaximumInputBytes), Status = ForensicReadStatus.Succeeded, Consistency = ForensicReadConsistency.Stable };
        }
        catch (UnauthorizedAccessException ex) { return Failed(source, started, "prefetch.denied", ex.Message, reservedBytes); }
        catch (FileNotFoundException ex) { return Failed(source, started, "prefetch.missing", ex.Message, reservedBytes); }
        catch (Win32Exception ex) { return Failed(source, started, ex.NativeErrorCode == 5 ? "prefetch.denied" : ex.NativeErrorCode is 32 or 33 ? "prefetch.in-use" : "prefetch.open-failed", ex.Message, reservedBytes); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is IOException or InvalidDataException or PathTooLongException) { return Failed(source, started, "prefetch.read-failed", ex.Message, reservedBytes); }
    }

    private MetadataValue ApplyFixtureFailure(string source, MetadataValue metadata, bool beforeRead)
    {
        var fixture = _fixtureFailure?.Invoke(source);
        if (beforeRead && string.Equals(fixture, "invalid-before-filetime", StringComparison.Ordinal))
        {
            const ulong invalidRawFileTime = ulong.MaxValue;
            return metadata with { CreatedRawFileTime = invalidRawFileTime, CreatedUtc = FileTime(invalidRawFileTime) };
        }
        if (!beforeRead && string.Equals(fixture, "post-read-io", StringComparison.Ordinal))
        {
            throw new IOException("ProcInsiderTest injected post-read metadata failure.");
        }
        return metadata;
    }

    private static PrefetchLocalRead Coverage(string root, string code, string detail) => new() { IsCoverage = true, SourcePath = root, ReadStartedUtc = DateTime.UtcNow, ReadCompletedUtc = DateTime.UtcNow, Status = ForensicReadStatus.Failed, DiagnosticCode = code, Diagnostic = detail };
    private static PrefetchLocalRead Failed(string path, DateTime started, string code, string detail, int bytesRead = 0) => new() { SourcePath = path, ReadStartedUtc = started, ReadCompletedUtc = DateTime.UtcNow, BytesRead = bytesRead, Status = ForensicReadStatus.Failed, DiagnosticCode = code, Diagnostic = detail };
    private static SafeFileHandle Open(string path)
    {
        var handle = CreateFile(path, 0x80000000, 1, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) { var error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
        return handle;
    }
    private static string FinalPath(SafeFileHandle handle)
    {
        var buffer = new StringBuilder(32768);
        var length = GetFinalPathNameByHandle(handle, buffer, buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error());
        var path = buffer.ToString();
        return path.StartsWith("\\\\?\\", StringComparison.Ordinal) ? path[4..] : path;
    }
    private static bool PathEquals(string first, string second) => string.Equals(ValidateLocalPath(first), ValidateLocalPath(second), StringComparison.OrdinalIgnoreCase);
    private static string ValidateLocalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 32767 || !Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal) || path[2..].Contains(':') || path.Contains('%')) throw new InvalidDataException("Prefetch paths require a resolved ordinary local drive path.");
        var full = Path.GetFullPath(path); if (full.Length > 3) full = full.TrimEnd('\\');
        foreach (var component in full[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries)) if (component is "." or ".." || component.EndsWith('.') || component.EndsWith(' ')) throw new InvalidDataException("Prefetch path component alias rejected.");
        return full;
    }
    private static MetadataValue Metadata(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var value)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var createdRaw = FileTimeRaw(value.Created);
        var writtenRaw = FileTimeRaw(value.Written);
        return new((FileAttributes)value.Attributes, ((long)value.SizeHigh << 32) | value.SizeLow,
            createdRaw, FileTime(createdRaw), writtenRaw, FileTime(writtenRaw), value.Volume, value.IndexHigh, value.IndexLow);
    }
    private static ulong FileTimeRaw(FileTimeValue value) => ((ulong)value.High << 32) | value.Low;
    private static DateTime? FileTime(ulong raw)
    {
        if (raw == 0 || raw > long.MaxValue) return null;
        try { return DateTime.FromFileTimeUtc((long)raw); }
        catch (ArgumentOutOfRangeException) { return null; }
    }
    private sealed record MetadataValue(FileAttributes Attributes, long Size, ulong CreatedRawFileTime, DateTime? CreatedUtc, ulong LastWriteRawFileTime, DateTime? LastWriteUtc, uint Volume, uint IndexHigh, uint IndexLow)
    {
        public bool HasInvalidFileTime => (CreatedRawFileTime != 0 && CreatedUtc == null) || (LastWriteRawFileTime != 0 && LastWriteUtc == null);
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileTimeValue { public uint Low; public uint High; }
    [StructLayout(LayoutKind.Sequential)] private struct NativeInfo { public uint Attributes; public FileTimeValue Created; public FileTimeValue Accessed; public FileTimeValue Written; public uint Volume; public uint SizeHigh; public uint SizeLow; public uint Links; public uint IndexHigh; public uint IndexLow; }
    [DllImport("kernel32.dll", EntryPoint = "GetSystemWindowsDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)] private static extern uint GetSystemWindowsDirectory([Out] char[] buffer, uint size);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)] private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder buffer, int size, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out NativeInfo info);
}
