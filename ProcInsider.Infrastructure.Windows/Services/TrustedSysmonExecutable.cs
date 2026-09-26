using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Executes only a verified copy of the registered Sysmon image from an Agent-owned
/// location. A service image under a user's Downloads directory can be replaced
/// between verification and Process.Start, so the original path is never executed.
/// </summary>
public sealed class TrustedSysmonExecutable : IDisposable
{
    private readonly string _directory;
    public string Path { get; }

    private TrustedSysmonExecutable(string directory, string path)
    {
        _directory = directory;
        Path = path;
    }

    public static TrustedSysmonExecutable Create(string registeredPath)
    {
        if (!System.IO.Path.IsPathFullyQualified(registeredPath) || !File.Exists(registeredPath) ||
            System.IO.Path.GetFileName(registeredPath) is not { } name ||
            !(name.Equals("Sysmon.exe", StringComparison.OrdinalIgnoreCase) ||
              name.Equals("Sysmon64.exe", StringComparison.OrdinalIgnoreCase) ||
              name.Equals("Sysmon64a.exe", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("The registered Sysmon image is unavailable or has an unexpected name.");

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!System.IO.Path.IsPathFullyQualified(programFiles) || !Directory.Exists(programFiles) ||
            new DirectoryInfo(programFiles).LinkTarget != null)
            throw new InvalidOperationException("A protected Program Files directory is unavailable for Sysmon execution.");

        // Create the child with a protected ACL atomically, even on a machine with
        // nonstandard inherited Program Files permissions. No untrusted neighboring
        // DLLs are copied into the execution directory.
        var directory = System.IO.Path.Combine(programFiles, "DFIRoscope-Sysmon-" + Guid.NewGuid().ToString("N"));
        if (Directory.Exists(directory))
            throw new InvalidOperationException("The protected Sysmon execution directory already exists.");
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null),
                FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).Create(acl);
        var path = System.IO.Path.Combine(directory, name);
        try
        {
            File.Copy(registeredPath, path, overwrite: false);
            var trust = new WindowsAuthenticodeTrustProvider().Verify(path);
            var product = FileVersionInfo.GetVersionInfo(path).ProductName ?? string.Empty;
            if (trust.VerificationStatus != AuthenticodeVerificationStatus.Valid ||
                trust.Publisher is not ("Microsoft Windows Publisher" or "Microsoft Corporation") ||
                !product.Equals("Sysinternals Sysmon", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The installed Sysmon image is not a valid Microsoft-signed Sysinternals Sysmon binary.");
            return new TrustedSysmonExecutable(directory, path);
        }
        catch
        {
            DeleteCopy(path, directory);
            throw;
        }
    }

    public void Dispose() => DeleteCopy(Path, _directory);

    private static void DeleteCopy(string path, string directory)
    {
        // Both paths are constructed above under a newly created, exact Program Files child.
        // A failed cleanup leaves only a signed copy in a protected directory.
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        try { Directory.Delete(directory); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
