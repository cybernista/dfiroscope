using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace ProcInsider.Agent;

internal enum GlobalObjectAccessResourceKind
{
    File,
    Key
}

internal sealed record GlobalObjectAccessAuditPolicyState(
    bool IsAvailable,
    bool HasApplicableSuccessAudit,
    string DescriptorGeneration,
    string Detail);

/// <summary>
/// Reads the effective machine-wide File or Key resource SACL through the Windows Audit API.
/// This type intentionally exposes no set, clear, deployment, or restoration operation.
/// </summary>
internal static class WindowsGlobalObjectAccessAuditPolicyReader
{
    private const int GenericAll = 0x10000000;
    private const int GenericWrite = 0x40000000;
    private const int FileWriteData = 0x00000002;
    private const int KeySetValue = 0x00000002;

    internal static GlobalObjectAccessAuditPolicyState Read(
        GlobalObjectAccessResourceKind kind,
        IReadOnlySet<string> tokenSids)
    {
        ArgumentNullException.ThrowIfNull(tokenSids);
        var objectType = kind == GlobalObjectAccessResourceKind.File ? "File" : "Key";
        if (!AuditQueryGlobalSacl(objectType, out var aclPointer))
        {
            return new GlobalObjectAccessAuditPolicyState(
                IsAvailable: false,
                HasApplicableSuccessAudit: false,
                DescriptorGeneration: string.Empty,
                Detail: $"The effective global {objectType} resource SACL could not be read through AuditQueryGlobalSacl: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
        }

        if (aclPointer == IntPtr.Zero)
        {
            return new GlobalObjectAccessAuditPolicyState(
                IsAvailable: true,
                HasApplicableSuccessAudit: false,
                DescriptorGeneration: "EMPTY",
                Detail: $"The effective global {objectType} resource SACL is not configured; no policy was changed.");
        }

        try
        {
            if (!GetAclInformation(
                    aclPointer,
                    out var information,
                    Marshal.SizeOf<AclSizeInformation>(),
                    AclInformationClass.AclSizeInformation))
            {
                return new GlobalObjectAccessAuditPolicyState(
                    IsAvailable: false,
                    HasApplicableSuccessAudit: false,
                    DescriptorGeneration: string.Empty,
                    Detail: $"The effective global {objectType} resource SACL size could not be read: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
            }

            if (information.AclBytesInUse is < 8 or > 1_048_576)
            {
                return new GlobalObjectAccessAuditPolicyState(
                    IsAvailable: false,
                    HasApplicableSuccessAudit: false,
                    DescriptorGeneration: string.Empty,
                    Detail: $"The effective global {objectType} resource SACL returned an invalid bounded size ({information.AclBytesInUse} bytes).");
            }

            var bytes = new byte[information.AclBytesInUse];
            Marshal.Copy(aclPointer, bytes, 0, bytes.Length);
            var acl = new RawAcl(bytes, 0);
            var requiredMask = kind == GlobalObjectAccessResourceKind.File
                ? FileWriteData
                : KeySetValue;
            var covered = HasApplicableSuccessAudit(acl, tokenSids, requiredMask);
            var generation = Convert.ToHexString(SHA256.HashData(bytes));
            return new GlobalObjectAccessAuditPolicyState(
                IsAvailable: true,
                HasApplicableSuccessAudit: covered,
                DescriptorGeneration: generation,
                Detail: covered
                    ? $"The effective global {objectType} resource SACL generation {generation} has a non-callback success-audit entry applicable to the current token and fixed write operation; it was read without mutation."
                    : $"The effective global {objectType} resource SACL generation {generation} has no non-callback success-audit coverage for the current token and fixed write operation; no policy was changed.");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return new GlobalObjectAccessAuditPolicyState(
                IsAvailable: false,
                HasApplicableSuccessAudit: false,
                DescriptorGeneration: string.Empty,
                Detail: $"The effective global {objectType} resource SACL was malformed or unsupported: {ex.Message}");
        }
        finally
        {
            _ = LocalFree(aclPointer);
        }
    }

    internal static bool HasApplicableSuccessAudit(
        RawAcl acl,
        IReadOnlySet<string> tokenSids,
        int requiredMask)
    {
        ArgumentNullException.ThrowIfNull(acl);
        ArgumentNullException.ThrowIfNull(tokenSids);
        var combinedMask = 0;
        for (var index = 0; index < acl.Count; index++)
        {
            if (acl[index] is not CommonAce ace ||
                ace.IsCallback ||
                ace.AceQualifier != AceQualifier.SystemAudit ||
                (ace.AceFlags & AceFlags.SuccessfulAccess) == 0 ||
                (ace.AceFlags & AceFlags.InheritOnly) != 0 ||
                !IsApplicableTrustee(ace.SecurityIdentifier, tokenSids))
            {
                continue;
            }

            combinedMask |= ace.AccessMask;
        }

        return (combinedMask & requiredMask) == requiredMask ||
               (combinedMask & (GenericAll | GenericWrite)) != 0;
    }

    internal static bool IsApplicableTrustee(
        SecurityIdentifier trustee,
        IReadOnlySet<string> tokenSids)
    {
        ArgumentNullException.ThrowIfNull(trustee);
        ArgumentNullException.ThrowIfNull(tokenSids);
        return tokenSids.Contains(trustee.Value) || trustee.Value is
            "S-1-3-0" or // CREATOR OWNER: mapped to the child object's owner.
            "S-1-3-1" or // CREATOR GROUP: mapped to the child object's primary group.
            "S-1-3-4";   // OWNER RIGHTS: applies to the child object's owner.
    }

    private enum AclInformationClass
    {
        AclRevisionInformation = 1,
        AclSizeInformation = 2
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AclSizeInformation
    {
        public uint AceCount;
        public int AclBytesInUse;
        public int AclBytesFree;
    }

    [DllImport("advapi32.dll", EntryPoint = "AuditQueryGlobalSaclW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQueryGlobalSacl(string objectTypeName, out IntPtr acl);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetAclInformation(
        IntPtr acl,
        out AclSizeInformation information,
        int informationLength,
        AclInformationClass informationClass);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
