using ProcInsider.Models.Infrastructure;

namespace ProcInsider.Services.Infrastructure;

/// <summary>
/// Durable non-evidence operational state used before the central case store exists.
/// Implementations may persist salted token hashes and public credential metadata only;
/// private keys, token bytes, request bodies, evidence and audit authority are forbidden.
/// </summary>
public interface IInfrastructureEnrollmentStateStore
{
    void Initialize();

    void CreateToken(InfrastructureEnrollmentTokenRecord record);

    InfrastructureEnrollmentRedemption RedeemToken(
        string tokenId,
        ReadOnlySpan<byte> token,
        DateTime nowUtc);

    InfrastructureCredentialRecord? FindCredential(string identityId, string certificateSha256);

    InfrastructureCredentialRecord? FindActiveCredential(string identityId);

    InfrastructureCredentialRecord? FindLatestCredential(string identityId);

    void AddInitialCredential(InfrastructureCredentialRecord credential);

    bool TryRotateCredential(
        string identityId,
        long expectedCurrentEpoch,
        InfrastructureCredentialRecord replacement,
        DateTime nowUtc);

    bool TryReenrollCredential(
        string identityId,
        long expectedTerminalEpoch,
        InfrastructureCredentialRecord replacement,
        DateTime nowUtc);

    bool TrySetViewerIdentity(
        string identityId,
        long expectedCredentialEpoch,
        bool enabled,
        InfrastructureViewerRole role,
        DateTime nowUtc);

    bool TrySetCredentialState(
        string identityId,
        long expectedCredentialEpoch,
        InfrastructureCredentialLifecycleState state,
        DateTime nowUtc);
}
