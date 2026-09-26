using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Enumerates process handles using the native system handle table.
/// </summary>
public class HandleInspector
{
    private const int SystemExtendedHandleInformation = 64;
    private const int ObjectNameInformation = 1;
    private const int ObjectTypeInformation = 2;

    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const int StatusBufferOverflow = unchecked((int)0x80000005);

    private const uint ProcessDupHandle = 0x0040;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint DuplicateSameAccess = 0x00000002;

    private static readonly HashSet<string> ObjectNameBlacklist = new(StringComparer.OrdinalIgnoreCase)
    {
        "ALPC Port",
        "File",
        "IoCompletion",
        "IRTimer",
        "Process",
        "Section",
        "Thread",
        "Token",
        "TpWorkerFactory",
        "WaitCompletionPacket"
    };

    /// <summary>
    /// Gets all handles for a process.
    /// </summary>
    public async Task<HandleInspectionResult> GetHandlesAsync(int processId, CancellationToken cancellationToken = default)
    {
        try
        {
            return await Task.Run(() => GetHandlesInternal(processId, cancellationToken), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return new HandleInspectionResult
            {
                Success = false,
                ErrorMessage = "Handle enumeration was canceled."
            };
        }
    }

    private HandleInspectionResult GetHandlesInternal(int processId, CancellationToken cancellationToken)
    {
        IntPtr processHandle;
        try
        {
            processHandle = OpenProcess(ProcessDupHandle | ProcessQueryLimitedInformation, false, processId);
        }
        catch (Exception ex)
        {
            return new HandleInspectionResult
            {
                Success = false,
                ErrorMessage = $"Unable to access process handles: {ex.Message}"
            };
        }

        if (processHandle == IntPtr.Zero)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            return new HandleInspectionResult
            {
                Success = false,
                ErrorMessage = $"Unable to open process for handle enumeration: {GetFriendlyError(error)}"
            };
        }

        try
        {
            var allHandlesResult = QuerySystemHandles(cancellationToken);
            if (!allHandlesResult.Success)
            {
                return new HandleInspectionResult
                {
                    Success = false,
                    ErrorMessage = allHandlesResult.ErrorMessage
                };
            }

            var handles = new List<HandleInfo>();
            var currentProcess = GetCurrentProcess();

            foreach (var entry in allHandlesResult.Entries.Where(h => h.UniqueProcessId.ToUInt64() == (ulong)processId))
            {
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }
                catch (OperationCanceledException)
                {
                    return new HandleInspectionResult
                    {
                        Success = true,
                        Handles = handles
                    };
                }

                var handleInfo = new HandleInfo
                {
                    HandleValueNumeric = entry.HandleValue.ToUInt64(),
                    HandleValue = FormatPointer(entry.HandleValue.ToUInt64()),
                    GrantedAccessValue = entry.GrantedAccess,
                    GrantedAccess = $"0x{entry.GrantedAccess:X8}",
                    HandleAttributesValue = entry.HandleAttributes,
                    HandleAttributes = FormatHandleAttributes(entry.HandleAttributes),
                    ObjectAddress = FormatPointer(entry.Object.ToUInt64()),
                    ObjectType = $"Type #{entry.ObjectTypeIndex}",
                    ObjectName = "<not available>"
                };

                if (!DuplicateHandle(
                        processHandle,
                        new IntPtr(unchecked((long)entry.HandleValue.ToUInt64())),
                        currentProcess,
                        out var duplicatedHandle,
                        0,
                        false,
                        DuplicateSameAccess))
                {
                    handleInfo.ObjectName = "<unable to duplicate>";
                    handles.Add(handleInfo);
                    continue;
                }

                try
                {
                    var objectType = QueryObjectString(duplicatedHandle, ObjectTypeInformation);
                    if (!string.IsNullOrWhiteSpace(objectType))
                    {
                        handleInfo.ObjectType = objectType;
                    }

                    if (!ObjectNameBlacklist.Contains(handleInfo.ObjectType))
                    {
                        var objectName = QueryObjectString(duplicatedHandle, ObjectNameInformation);
                        if (!string.IsNullOrWhiteSpace(objectName))
                        {
                            handleInfo.ObjectName = objectName;
                        }
                    }
                }
                catch
                {
                    // Keep the default fallback values for handles we cannot fully query.
                }
                finally
                {
                    CloseHandle(duplicatedHandle);
                }

                handles.Add(handleInfo);
            }

            handles.Sort((left, right) => left.HandleValueNumeric.CompareTo(right.HandleValueNumeric));

            return new HandleInspectionResult
            {
                Success = true,
                Handles = handles
            };
        }
        finally
        {
            CloseHandle(processHandle);
        }
    }

    private SystemHandleQueryResult QuerySystemHandles(CancellationToken cancellationToken)
    {
        var bufferLength = 0x10000;
        var buffer = IntPtr.Zero;

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }

                buffer = Marshal.AllocHGlobal(bufferLength);

                var status = NtQuerySystemInformation(
                    SystemExtendedHandleInformation,
                    buffer,
                    bufferLength,
                    out var returnLength);

                if (status == 0)
                {
                    var count = Marshal.ReadIntPtr(buffer).ToInt64();
                    var offset = IntPtr.Size * 2;
                    var entrySize = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
                    var entries = new List<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>((int)Math.Min(count, int.MaxValue));

                    for (var i = 0L; i < count; i++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var entryPtr = IntPtr.Add(buffer, offset + (int)(i * entrySize));
                        entries.Add(Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(entryPtr));
                    }

                    return new SystemHandleQueryResult
                    {
                        Success = true,
                        Entries = entries
                    };
                }

                if (status != StatusInfoLengthMismatch && status != StatusBufferOverflow)
                {
                    return new SystemHandleQueryResult
                    {
                        Success = false,
                        ErrorMessage = $"Unable to query system handle table (NTSTATUS 0x{status:X8})."
                    };
                }

                bufferLength = Math.Max(bufferLength * 2, returnLength);
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static string QueryObjectString(IntPtr handle, int informationClass)
    {
        var bufferLength = 0x400;
        var buffer = IntPtr.Zero;

        try
        {
            while (true)
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }

                buffer = Marshal.AllocHGlobal(bufferLength);

                var status = NtQueryObject(handle, informationClass, buffer, bufferLength, out var returnLength);
                if (status == 0)
                {
                    var unicode = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
                    if (unicode.Length == 0 || unicode.Buffer == IntPtr.Zero)
                    {
                        return string.Empty;
                    }

                    return Marshal.PtrToStringUni(unicode.Buffer, unicode.Length / 2) ?? string.Empty;
                }

                if (status != StatusInfoLengthMismatch && status != StatusBufferOverflow)
                {
                    return string.Empty;
                }

                bufferLength = Math.Max(bufferLength * 2, returnLength);
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static string FormatPointer(ulong value)
    {
        return IntPtr.Size == 8
            ? $"0x{value:X16}"
            : $"0x{value:X8}";
    }

    private static string FormatHandleAttributes(uint attributes)
    {
        if (attributes == 0)
        {
            return "0x00000000";
        }

        var parts = new List<string> { $"0x{attributes:X8}" };

        if ((attributes & 0x1) != 0)
        {
            parts.Add("PROTECT_FROM_CLOSE");
        }

        if ((attributes & 0x2) != 0)
        {
            parts.Add("INHERIT");
        }

        return string.Join(" | ", parts);
    }

    private static string GetFriendlyError(Win32Exception ex)
    {
        return ex.NativeErrorCode switch
        {
            5 => "access denied (insufficient privileges or protected process)",
            87 => "invalid process state",
            _ => ex.Message
        };
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public UIntPtr Object;
        public UIntPtr UniqueProcessId;
        public UIntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    private sealed class SystemHandleQueryResult
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public List<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> Entries { get; set; } = new();
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int systemInformationClass,
        IntPtr systemInformation,
        int systemInformationLength,
        out int returnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryObject(
        IntPtr handle,
        int objectInformationClass,
        IntPtr objectInformation,
        int objectInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(
        IntPtr hSourceProcessHandle,
        IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle,
        out IntPtr lpTargetHandle,
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwOptions);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}

/// <summary>
/// Result of handle enumeration.
/// </summary>
public class HandleInspectionResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public List<HandleInfo> Handles { get; set; } = new();
}
