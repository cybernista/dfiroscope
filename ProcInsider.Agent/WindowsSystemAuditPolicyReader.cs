using System.ComponentModel;
using System.Runtime.InteropServices;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal static class WindowsSystemAuditPolicyReader
{
    // Native GUIDs avoid localized auditpol CSV headers and translated subcategory names.
    public static AuditSubcategorySetting[] Read() => new WindowsObjectAuditRuntime().WithPrivilege(() =>
    {
        if (!AuditEnumerateSubCategories(IntPtr.Zero, true, out var categories, out var count))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            if (count is < 1 or > 256) throw new InvalidOperationException("Unexpected system audit subcategory count.");
            if (!AuditQuerySystemPolicy(categories, count, out var policy)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                return Enumerable.Range(0, (int)count).Select(i =>
                {
                    var item = Marshal.PtrToStructure<AuditPolicyInformation>(policy + i * Marshal.SizeOf<AuditPolicyInformation>());
                    // NONE is an explicit disabled value; zero would mean leave unchanged on apply.
                    return new AuditSubcategorySetting(item.Subcategory, item.Flags == 0 ? 4 : item.Flags);
                }).OrderBy(p => p.Subcategory).ToArray();
            }
            finally { AuditFree(policy); }
        }
        finally { AuditFree(categories); }
    });

    internal static string GetDisplayName(Guid subcategory)
    {
        var fallback = subcategory.ToString("B");
        if (!AuditLookupSubCategoryName(ref subcategory, out var name) || name == IntPtr.Zero) return fallback;
        try { return Marshal.PtrToStringUni(name) is { Length: > 0 } value ? value : fallback; }
        finally { AuditFree(name); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation { public Guid Subcategory; public uint Flags; public Guid Category; }
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditEnumerateSubCategories(IntPtr category, [MarshalAs(UnmanagedType.U1)] bool all,
        out IntPtr categories, out uint count);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy(IntPtr categories, uint count, out IntPtr policy);
    [DllImport("advapi32.dll", EntryPoint = "AuditLookupSubCategoryNameW", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditLookupSubCategoryName(ref Guid subcategory, out IntPtr name);
    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);
}
