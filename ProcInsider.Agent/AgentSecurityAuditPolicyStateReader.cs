using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace ProcInsider.Agent;

internal sealed record AgentSecurityAuditPolicyState(
    bool IsAvailable,
    bool SuccessEnabled,
    bool FailureEnabled,
    string TechnicalDetail,
    string Error = "");

internal interface IAgentSecurityAuditPolicyStateReader
{
    AgentSecurityAuditPolicyState ReadSubcategory(string subcategory, string subcategoryGuid);
}

internal sealed partial class WindowsAgentSecurityAuditPolicyStateReader : IAgentSecurityAuditPolicyStateReader
{
    private const uint AuditSuccess = 0x1;
    private const uint AuditFailure = 0x2;

    public AgentSecurityAuditPolicyState ReadSubcategory(string subcategory, string subcategoryGuid)
    {
        try
        {
            var guid = ResolveSubcategoryGuid(subcategory, subcategoryGuid);
            if (!guid.HasValue)
            {
                return new AgentSecurityAuditPolicyState(
                    IsAvailable: false,
                    SuccessEnabled: false,
                    FailureEnabled: false,
                    TechnicalDetail: string.Empty,
                    Error: $"The effective audit-policy GUID for '{subcategory}' could not be resolved.");
            }

            var values = new[] { guid.Value };
            if (!AuditQuerySystemPolicy(values, 1, out var policyBuffer) || policyBuffer == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                return new AgentSecurityAuditPolicyState(
                    IsAvailable: false,
                    SuccessEnabled: false,
                    FailureEnabled: false,
                    TechnicalDetail: $"Subcategory={subcategory}; GUID={guid.Value:B}.",
                    Error: new Win32Exception(error).Message);
            }

            try
            {
                var policy = Marshal.PtrToStructure<AuditPolicyInformation>(policyBuffer);
                return new AgentSecurityAuditPolicyState(
                    IsAvailable: true,
                    SuccessEnabled: (policy.AuditingInformation & AuditSuccess) != 0,
                    FailureEnabled: (policy.AuditingInformation & AuditFailure) != 0,
                    TechnicalDetail:
                        $"Subcategory={subcategory}; GUID={guid.Value:B}; flags=0x{policy.AuditingInformation:X}.");
            }
            finally
            {
                AuditFree(policyBuffer);
            }
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            return new AgentSecurityAuditPolicyState(
                IsAvailable: false,
                SuccessEnabled: false,
                FailureEnabled: false,
                TechnicalDetail: $"Subcategory={subcategory}.",
                Error: ex.Message);
        }
    }

    private static Guid? ResolveSubcategoryGuid(string subcategory, string subcategoryGuid)
    {
        if (Guid.TryParse(subcategoryGuid, out var configuredGuid))
        {
            return configuredGuid;
        }

        var auditPol = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "auditpol.exe");
        if (!File.Exists(auditPol))
        {
            return null;
        }

        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = auditPol,
            Arguments = $"/get /subcategory:\"{subcategory.Replace("\"", string.Empty, StringComparison.Ordinal)}\" /r",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        }) ?? throw new InvalidOperationException("auditpol.exe could not be started.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"auditpol.exe exited with code {process.ExitCode}: {error}".Trim());
        }

        var match = AuditSubcategoryGuidRegex().Match(output);
        return match.Success && Guid.TryParse(match.Value, out var discoveredGuid)
            ? discoveredGuid
            : null;
    }

    [GeneratedRegex(@"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}")]
    private static partial Regex AuditSubcategoryGuidRegex();

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AuditQuerySystemPolicy(
        [In] Guid[] subCategoryGuids,
        uint policyCount,
        out IntPtr auditPolicy);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);
}

internal sealed class SecurityAuditPolicyProfileEntry
{
    public string Subcategory { get; init; } = string.Empty;

    public string SubcategoryGuid { get; init; } = string.Empty;

    public bool Success { get; init; }

    public bool Failure { get; init; }
}
