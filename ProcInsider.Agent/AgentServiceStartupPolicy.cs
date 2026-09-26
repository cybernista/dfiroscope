using System.Security.AccessControl;
using System.Security.Principal;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal static class AgentServiceStartupPolicy
{
    private static readonly SecurityIdentifier LocalSystemSid =
        new(WellKnownSidType.LocalSystemSid, domainSid: null);
    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, domainSid: null);
    private static readonly HashSet<string> ApprovedWritePrincipals =
    [
        LocalSystemSid.Value,
        AdministratorsSid.Value,
        // NT SERVICE\TrustedInstaller. Installation/update ownership is separate
        // from the LocalSystem runtime identity and remains explicitly bounded.
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    ];
    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData |
        FileSystemRights.AppendData |
        FileSystemRights.WriteExtendedAttributes |
        FileSystemRights.WriteAttributes |
        FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;

    public static void ValidateOrThrow(AgentOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The DFIRoscope Agent Service requires Windows.");
        }

        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) != true)
        {
            throw new UnauthorizedAccessException(
                "The Infrastructure Agent Service must run as LocalSystem; no alternate account is accepted.");
        }

        var machinePaths = SessionPathService.GetInfrastructureAgentMachinePaths();
        if (!Directory.Exists(machinePaths.RootDirectory))
        {
            throw new DirectoryNotFoundException(
                $"The installed Agent Service root does not exist: {machinePaths.RootDirectory}");
        }

        var machineDirectories = new[]
        {
            machinePaths.RootDirectory,
            machinePaths.ConfigurationDirectory,
            machinePaths.SessionsDirectory,
            machinePaths.OperationalLogsDirectory,
            machinePaths.SpoolDirectory,
            machinePaths.ArtifactsDirectory,
            machinePaths.SecretsDirectory
        };
        foreach (var directory in machineDirectories)
        {
            if (!Directory.Exists(directory))
            {
                throw new DirectoryNotFoundException(
                    $"The installed Agent Service directory is missing: {directory}");
            }

            var assessment = AssessSecurity(
                FileSystemAclExtensions.GetAccessControl(
                    new DirectoryInfo(directory),
                    AccessControlSections.Access | AccessControlSections.Owner),
                requireSystemWrite: !string.Equals(
                    directory,
                    machinePaths.ConfigurationDirectory,
                    StringComparison.OrdinalIgnoreCase));
            if (!assessment.IsAllowed)
            {
                throw new UnauthorizedAccessException(
                    $"Agent Service directory ACL rejected '{directory}': {assessment.ErrorCode}: {assessment.Message}");
            }
        }

        foreach (var configurationPath in new[]
                 {
                     machinePaths.ConfigurationFilePath,
                     machinePaths.ConfigurationRecoveryFilePath
                 })
        {
            if (!File.Exists(configurationPath))
            {
                if (string.Equals(
                        configurationPath,
                        machinePaths.ConfigurationRecoveryFilePath,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                throw new FileNotFoundException(
                    "The installed Agent Service machine configuration is missing.",
                    configurationPath);
            }

            var assessment = AssessSecurity(
                FileSystemAclExtensions.GetAccessControl(
                    new FileInfo(configurationPath),
                    AccessControlSections.Access | AccessControlSections.Owner),
                requireSystemWrite: false);
            if (!assessment.IsAllowed)
            {
                throw new UnauthorizedAccessException(
                    $"Agent Service configuration ACL rejected '{configurationPath}': {assessment.ErrorCode}: {assessment.Message}");
            }
        }

        if (!string.IsNullOrWhiteSpace(options.DatabasePath) &&
            !IsPathWithinRoot(machinePaths.RootDirectory, options.DatabasePath))
        {
            throw new InvalidDataException(
                $"The Agent Service database must stay under the installed machine root '{machinePaths.RootDirectory}'.");
        }

        var programFilesRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            SessionPathService.LocalDataRootFolderName,
            SessionPathService.InfrastructureAgentRootFolderName);
        var executablePath = Environment.ProcessPath ?? string.Empty;
        if (string.IsNullOrWhiteSpace(executablePath) || !IsPathWithinRoot(programFilesRoot, executablePath))
        {
            throw new UnauthorizedAccessException(
                $"The Agent Service executable must run from the protected installation root '{programFilesRoot}'.");
        }

        foreach (var directory in EnumerateContainedDirectoryChain(
                     programFilesRoot,
                     Path.GetDirectoryName(executablePath)!))
        {
            if (!Directory.Exists(directory))
            {
                throw new DirectoryNotFoundException(
                    $"The installed Agent Service binary directory is missing: {directory}");
            }

            var directoryAssessment = AssessSecurity(
                FileSystemAclExtensions.GetAccessControl(
                    new DirectoryInfo(directory),
                    AccessControlSections.Access | AccessControlSections.Owner),
                requireSystemWrite: false);
            if (!directoryAssessment.IsAllowed)
            {
                throw new UnauthorizedAccessException(
                    $"Agent Service binary-directory ACL rejected '{directory}': {directoryAssessment.ErrorCode}: {directoryAssessment.Message}");
            }
        }

        var executableAssessment = AssessSecurity(
            FileSystemAclExtensions.GetAccessControl(
                new FileInfo(executablePath),
                AccessControlSections.Access | AccessControlSections.Owner),
            requireSystemWrite: false);
        if (!executableAssessment.IsAllowed)
        {
            throw new UnauthorizedAccessException(
                $"Agent Service executable ACL rejected '{executablePath}': {executableAssessment.ErrorCode}: {executableAssessment.Message}");
        }
    }

    internal static AgentServiceAclAssessment AssessSecurity(
        FileSystemSecurity security,
        bool requireSystemWrite)
    {
        ArgumentNullException.ThrowIfNull(security);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner == null || !ApprovedWritePrincipals.Contains(owner.Value))
        {
            return new AgentServiceAclAssessment(
                false,
                "UnapprovedOwner",
                $"Owner '{owner?.Value ?? "<unavailable>"}' can change permissions outside the approved service/install identities.");
        }

        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .ToArray();
        var unapprovedWrite = rules.FirstOrDefault(rule =>
            rule.IdentityReference is SecurityIdentifier sid &&
            !ApprovedWritePrincipals.Contains(sid.Value) &&
            (rule.FileSystemRights & WriteRights) != 0);
        if (unapprovedWrite != null)
        {
            return new AgentServiceAclAssessment(
                false,
                "UnapprovedWriteAcl",
                $"Principal '{unapprovedWrite.IdentityReference.Value}' has write rights outside the approved service/install identities.");
        }

        var requiredSystemRights = requireSystemWrite
            ? FileSystemRights.Modify
            : FileSystemRights.ReadAndExecute;
        if (!HasRights(rules, LocalSystemSid, requiredSystemRights))
        {
            return new AgentServiceAclAssessment(
                false,
                "LocalSystemAclMissing",
                $"LocalSystem lacks required '{requiredSystemRights}' rights.");
        }

        if (!HasRights(rules, AdministratorsSid, FileSystemRights.Modify))
        {
            return new AgentServiceAclAssessment(
                false,
                "AdministratorsAclMissing",
                "Built-in Administrators lack required Modify rights.");
        }

        return new AgentServiceAclAssessment(true, string.Empty, "ACL is bounded to the approved service principals.");
    }

    private static bool HasRights(
        IEnumerable<FileSystemAccessRule> rules,
        SecurityIdentifier identity,
        FileSystemRights required)
    {
        var combined = rules
            .Where(rule => rule.IdentityReference is SecurityIdentifier sid && sid.Equals(identity))
            .Aggregate((FileSystemRights)0, (rights, rule) => rights | rule.FileSystemRights);
        return (combined & required) == required;
    }

    internal static bool IsPathWithinRoot(string rootPath, string candidatePath)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(rootPath), Path.GetFullPath(candidatePath));
        return !Path.IsPathRooted(relative) &&
               !string.Equals(relative, "..", StringComparison.Ordinal) &&
               !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
               !relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal);
    }

    internal static IReadOnlyList<string> EnumerateContainedDirectoryChain(
        string rootPath,
        string candidateDirectory)
    {
        var root = Path.GetFullPath(rootPath);
        var candidate = Path.GetFullPath(candidateDirectory);
        if (!IsPathWithinRoot(root, candidate))
        {
            throw new InvalidDataException(
                $"The Agent Service binary directory must stay under '{root}'.");
        }

        var directories = new List<string> { root };
        var relative = Path.GetRelativePath(root, candidate);
        if (relative == ".")
        {
            return directories;
        }

        var current = root;
        foreach (var segment in relative.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            directories.Add(current);
        }

        return directories;
    }
}

internal sealed record AgentServiceAclAssessment(
    bool IsAllowed,
    string ErrorCode,
    string Message);
