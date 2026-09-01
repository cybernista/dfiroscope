namespace ProcInsider.Models.Infrastructure;

/// <summary>
/// Versioned non-secret binding for one standard-user Infrastructure Viewer. Protected
/// references identify CurrentUser certificate-store material without copying key bytes.
/// </summary>
public static class InfrastructureViewerRuntimeContract
{
    public const int CurrentVersion = 1;
    public const int MaximumIdentityCharacters = 512;

    public static bool IsWellFormed(InfrastructureViewerServerProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return profile.SchemaVersion == CurrentVersion &&
               IsIdentity(profile.PublicationGroupId) &&
               IsIdentity(profile.DeploymentProfileId) &&
               IsIdentity(profile.ReleaseId) &&
               profile.ProtocolGeneration > 0 &&
               Uri.TryCreate(profile.ServerUri, UriKind.Absolute, out var endpoint) &&
               string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
               string.IsNullOrEmpty(endpoint.UserInfo) &&
               string.IsNullOrEmpty(endpoint.Query) &&
               string.IsNullOrEmpty(endpoint.Fragment) &&
               string.Equals(endpoint.AbsolutePath, "/", StringComparison.Ordinal) &&
               IsIdentity(profile.ExpectedServerIdentity) &&
               IsSha256(profile.ServerCertificateSha256) &&
               IsIdentity(profile.ViewerUserId) &&
               profile.CredentialEpoch > 0 &&
               IsCertificateReference(profile.CredentialReference, "CurrentUser") &&
               IsCertificateReference(profile.TrustAnchorReference, "CurrentUser");
    }

    private static bool IsIdentity(string value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= MaximumIdentityCharacters;

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);

    private static bool IsCertificateReference(
        InfrastructureConfigurationContracts.ProtectedStoreReference reference,
        string expectedLocation)
    {
        if (reference.Store != InfrastructureConfigurationContracts.ProtectedStoreKind.WindowsCertificateStore)
        {
            return false;
        }

        var parts = reference.Identifier.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 3 &&
               string.Equals(parts[0], expectedLocation, StringComparison.Ordinal) &&
               string.Equals(parts[1], "My", StringComparison.Ordinal) &&
               IsSha256(parts[2]);
    }
}

public sealed record InfrastructureViewerServerProfile
{
    public int SchemaVersion { get; init; } = InfrastructureViewerRuntimeContract.CurrentVersion;

    public string PublicationGroupId { get; init; } = string.Empty;

    public string DeploymentProfileId { get; init; } = string.Empty;

    public string ReleaseId { get; init; } = string.Empty;

    public int ProtocolGeneration { get; init; }

    public string ServerUri { get; init; } = string.Empty;

    public string ExpectedServerIdentity { get; init; } = string.Empty;

    public string ServerCertificateSha256 { get; init; } = string.Empty;

    public InfrastructureConfigurationContracts.ProtectedStoreReference TrustAnchorReference { get; init; } = new();

    public string ViewerUserId { get; init; } = string.Empty;

    public long CredentialEpoch { get; init; }

    public InfrastructureConfigurationContracts.ProtectedStoreReference CredentialReference { get; init; } = new();
}

public enum InfrastructureViewerRuntimeState
{
    Unavailable = 0,
    NotConnected = 1,
    Authenticating = 2,
    Authenticated = 3,
    Invalidated = 4,
    Disposed = 5
}

public sealed record InfrastructureViewerRuntimeSnapshot(
    InfrastructureViewerRuntimeState State,
    string ServerAuthority,
    string ViewerUserId,
    long CredentialEpoch,
    Guid ConnectionGeneration,
    DateTime FreshUntilUtc,
    string ErrorCode)
{
    public static InfrastructureViewerRuntimeSnapshot Unavailable(string errorCode) =>
        new(
            InfrastructureViewerRuntimeState.Unavailable,
            string.Empty,
            string.Empty,
            0,
            Guid.Empty,
            DateTime.UnixEpoch,
            errorCode);
}
