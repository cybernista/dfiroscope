using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace ProcInsider.Services.Persistence;

internal sealed record ShortcutNativeValue(string? Target, string? Arguments, string? WorkingDirectory, bool Known);

/// <summary>ShellLink loads only verified bounded bytes. No IPersistFile path, Resolve, icon or target access.</summary>
internal static class StartupShortcutReader
{
    // IShellLinkW.GetPath documents MAX_PATH as its maximum returned path, even with a larger buffer.
    internal const int MaxReturnedTargetCharacters = 260;
    internal static ShortcutNativeValue Read(byte[] bytes)
    {
        if (bytes.Length is < 76 or > StartupFolderFileReader.MaxShortcutBytes) throw new InvalidDataException("Shortcut input size unsupported.");
        if (BitConverter.ToUInt32(bytes, 0) != 76 || new Guid(bytes.AsSpan(4, 16)) != new Guid("00021401-0000-0000-C000-000000000046")) throw new InvalidDataException("Unsupported or malformed ShellLink header.");
        object? instance = null;
        try
        {
            instance = Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("00021401-0000-0000-C000-000000000046"), throwOnError: true)!)!;
            ((IPersistStream)instance).Load(new ReadOnlyBytes(bytes));
            var link = (IShellLink)instance;
            var target = new StringBuilder(StartupFolderFileReader.MaxPathCharacters);
            var arguments = new StringBuilder(StartupFolderFileReader.MaxPathCharacters);
            var directory = new StringBuilder(StartupFolderFileReader.MaxPathCharacters);
            // SLGP_RAWPATH, pfd=NULL: retrieve native strings without resolving or stat-ing a target.
            var pathResult = link.GetPath(target, target.Capacity, IntPtr.Zero, 4);
            var argumentResult = link.GetArguments(arguments, arguments.Capacity);
            var directoryResult = link.GetWorkingDirectory(directory, directory.Capacity);
            foreach (var result in new[] { pathResult, argumentResult, directoryResult }) if (result < 0) Marshal.ThrowExceptionForHR(result);
            var known = pathResult == 0 && argumentResult == 0 && directoryResult == 0 && target.Length < MaxReturnedTargetCharacters - 1 && arguments.Length < arguments.Capacity - 1 && directory.Length < directory.Capacity - 1;
            var value = new ShortcutNativeValue(pathResult == 0 ? target.ToString() : null, argumentResult == 0 ? arguments.ToString() : null, directoryResult == 0 ? directory.ToString() : null, known);
            ValidateStrings(value); return value;
        }
        finally { if (instance != null && Marshal.IsComObject(instance)) Marshal.FinalReleaseComObject(instance); }
    }
    internal static void ValidateStrings(ShortcutNativeValue value)
    {
        PersistenceRegistryNativeReader.ValidateText(value.Target);
        PersistenceRegistryNativeReader.ValidateText(value.Arguments);
        PersistenceRegistryNativeReader.ValidateText(value.WorkingDirectory);
    }
    private sealed class ReadOnlyBytes(byte[] bytes) : IStream
    {
        private long _position;
        public void Read(byte[] buffer, int count, IntPtr read)
        {
            if (count < 0 || count > buffer.Length) throw new IOException("Invalid shortcut stream read.");
            var length = (int)Math.Min(count, bytes.LongLength - _position);
            Array.Copy(bytes, _position, buffer, 0, length); _position += length;
            if (read != IntPtr.Zero) Marshal.WriteInt32(read, length);
        }
        public void Seek(long offset, int origin, IntPtr position)
        {
            var next = checked(origin switch { 0 => offset, 1 => _position + offset, 2 => bytes.LongLength + offset, _ => throw new IOException("Invalid shortcut stream origin.") });
            if (next < 0 || next > bytes.LongLength) throw new IOException("Shortcut stream seek outside bounded input.");
            _position = next; if (position != IntPtr.Zero) Marshal.WriteInt64(position, next);
        }
        public void Stat(out STATSTG value, int flags) { value = new STATSTG { type = 2, cbSize = bytes.LongLength, grfMode = 0 }; }
        public void Clone(out IStream stream) { stream = new ReadOnlyBytes(bytes) { _position = _position }; }
        public void Write(byte[] buffer, int count, IntPtr written) => throw new NotSupportedException("Shortcut input is read-only.");
        public void SetSize(long size) => throw new NotSupportedException("Shortcut input is read-only.");
        public void CopyTo(IStream stream, long count, IntPtr read, IntPtr written) => throw new NotSupportedException("Shortcut input copying unsupported.");
        public void Commit(int flags) => throw new NotSupportedException("Shortcut input is read-only.");
        public void Revert() => throw new NotSupportedException("Shortcut input is read-only.");
        public void LockRegion(long offset, long count, int type) => throw new NotSupportedException("Shortcut input locking unsupported.");
        public void UnlockRegion(long offset, long count, int type) => throw new NotSupportedException("Shortcut input locking unsupported.");
    }
    [ComImport, Guid("00000109-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPersistStream
    {
        void GetClassID(out Guid id);
        [PreserveSig] int IsDirty();
        void Load(IStream stream);
        void Save(IStream stream, [MarshalAs(UnmanagedType.Bool)] bool clearDirty);
        void GetSizeMax(out long size);
    }
    [ComImport, Guid("000214F9-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellLink
    {
        [PreserveSig] int GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int count, IntPtr findData, uint flags);
        void GetIDList(out IntPtr list); void SetIDList(IntPtr list);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder text, int count); void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string text);
        [PreserveSig] int GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder directory, int count);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string directory);
        [PreserveSig] int GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder arguments, int count);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string arguments);
        void GetHotkey(out short key); void SetHotkey(short key); void GetShowCmd(out int command); void SetShowCmd(int command);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder location, int count, out int index);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string location, int index);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string path, uint reserved); void Resolve(IntPtr window, uint flags); void SetPath([MarshalAs(UnmanagedType.LPWStr)] string path);
    }
}
