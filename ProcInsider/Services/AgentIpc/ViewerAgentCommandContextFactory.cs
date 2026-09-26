using System.IO;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.AgentIpc;

/// <summary>
/// Builds the immutable trusted context shared by headless viewer presentation adapters
/// after an exact live package and current-user pairing lease have been validated.
/// </summary>
public static class ViewerAgentCommandContextFactory
{
    public static ViewerAgentCommandExecutionContext CreateVerifiedDeployedAgent(
        ViewerWorkspaceActivation activation,
        AgentPairingLeaseMetadata lease,
        IFeatureCatalog featureCatalog,
        string viewerReleaseId,
        IReadOnlyList<string> supportedExecutablePaths,
        AgentCommandKind commandKind,
        long workspaceGeneration)
    {
        ArgumentNullException.ThrowIfNull(activation);
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(featureCatalog);
        ArgumentException.ThrowIfNullOrWhiteSpace(viewerReleaseId);
        ArgumentNullException.ThrowIfNull(supportedExecutablePaths);
        if (workspaceGeneration <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(workspaceGeneration),
                "The workspace generation must be positive.");
        }

        var package = activation.PackageInfo ??
            throw new ArgumentException("A validated live package is required.", nameof(activation));
        var sessionPaths = activation.SessionPaths;
        var normalizedDatabase = SessionPathService.NormalizeLiveDatabaseIdentity(
            sessionPaths.LiveDatabasePath);
        if (activation.Mode != CaptureWorkspaceMode.LiveCapture ||
            lease.WorkspaceMode != CaptureWorkspaceMode.LiveCapture ||
            lease.CaptureSealed ||
            !string.Equals(sessionPaths.SessionId, lease.SessionId, StringComparison.Ordinal) ||
            !string.Equals(package.SessionId, lease.SessionId, StringComparison.Ordinal) ||
            !PathsMatch(normalizedDatabase, lease.DatabaseIdentity) ||
            !PathsMatch(package.LiveDatabasePath, lease.DatabaseIdentity) ||
            package.CompatibilityAssessment == null ||
            !package.CompatibilityAssessment.Allows(CaptureOpenCapability.ReadEvidence))
        {
            throw new ArgumentException(
                "The live package and pairing lease do not identify the same compatible unsealed workspace.",
                nameof(activation));
        }

        var executablePaths = supportedExecutablePaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (executablePaths.Length == 0)
        {
            throw new ArgumentException(
                "At least one supported local-agent executable path is required.",
                nameof(supportedExecutablePaths));
        }

        return new ViewerAgentCommandExecutionContext(
            sessionPaths,
            new ViewerAgentCommandTarget(
                lease.SessionId,
                normalizedDatabase,
                CaptureWorkspaceMode.LiveCapture,
                IsSealed: false,
                new ViewerAgentCommandPackageIdentity(
                    package.FormatName,
                    package.SessionId,
                    sessionPaths.SessionRoot,
                    normalizedDatabase,
                    package.SchemaVersion,
                    package.EvidenceFormatVersion),
                lease.AgentProcessId,
                lease.AgentStartedAtUtc,
                Array.AsReadOnly(executablePaths)),
            featureCatalog,
            viewerReleaseId,
            new ViewerAgentCommandAccessState(
                ViewerAgentCommandAccessKind.VerifiedDeployedAgent,
                RequiresViewerConnection: false),
            CaptureWritePolicy.GetCategory(commandKind),
            workspaceGeneration);
    }

    private static bool PathsMatch(string left, string right)
    {
        try
        {
            return string.Equals(
                SessionPathService.NormalizeLiveDatabaseIdentity(left),
                SessionPathService.NormalizeLiveDatabaseIdentity(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
