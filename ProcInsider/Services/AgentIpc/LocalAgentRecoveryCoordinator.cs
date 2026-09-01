using System.IO;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.AgentIpc;

public enum LocalAgentDiscoveryOutcome
{
    Absent = 0,
    SingleCandidate = 1,
    MultipleCandidates = 2,
    AmbiguousCandidates = 3,
    UnresolvedInspection = 4,
    DiscoveryUnavailable = 5
}

public enum LocalAgentRecoveryOutcome
{
    Absent = 0,
    Recovered = 1,
    DiscoveryUnavailable = 2,
    MultipleCandidates = 3,
    AmbiguousCandidates = 4,
    UnresolvedInspection = 5,
    CandidateRejected = 6,
    PairingRejected = 7,
    WorkspaceRejected = 8,
    AuthenticationRejected = 9,
    FinalValidationRejected = 10,
    Busy = 11,
    Superseded = 12,
    Canceled = 13,
    InternalFailure = 14,
    WorkspacePending = 15
}

public enum LocalAgentRecoveryConflictKind
{
    Unknown = 0,
    DiscoveryUnavailable = 1,
    InvalidLeaseIdentity = 2,
    ProcessExited = 3,
    ProcessIdentityRejected = 4,
    ProcessInspectionUnresolved = 5,
    MultipleVerifiedCandidates = 6,
    AmbiguousCandidates = 7,
    IncompatibleLease = 8,
    ProtectedPairingRejected = 9,
    WorkspaceRejected = 10,
    AuthenticatedBindingRejected = 11,
    WorkspacePending = 12
}

public sealed record LocalAgentRecoveryRequest(
    IFeatureCatalog FeatureCatalog,
    string ViewerReleaseId,
    long WorkspaceGeneration,
    IReadOnlyList<string> SupportedExecutablePaths);

public sealed record LocalAgentRecoveryCandidate(
    AgentPairingDiscoveryRecord Discovery,
    LocalAgentProcessResult ProcessVerification);

public sealed record LocalAgentRecoveryConflict(
    LocalAgentRecoveryConflictKind Kind,
    string Diagnostic,
    AgentPairingDiscoveryRecord? Discovery = null,
    LocalAgentProcessResult? ProcessVerification = null);

public sealed record LocalAgentDiscoveryResult(
    LocalAgentDiscoveryOutcome Outcome,
    IReadOnlyList<AgentPairingDiscoveryRecord> Discoveries,
    IReadOnlyList<LocalAgentRecoveryCandidate> Candidates,
    IReadOnlyList<LocalAgentRecoveryConflict> Conflicts,
    string Diagnostic)
{
    public bool BlocksAdd => Outcome is
        LocalAgentDiscoveryOutcome.SingleCandidate or
        LocalAgentDiscoveryOutcome.MultipleCandidates or
        LocalAgentDiscoveryOutcome.AmbiguousCandidates or
        LocalAgentDiscoveryOutcome.UnresolvedInspection or
        LocalAgentDiscoveryOutcome.DiscoveryUnavailable;

    public bool BlocksStart => Outcome is
        LocalAgentDiscoveryOutcome.MultipleCandidates or
        LocalAgentDiscoveryOutcome.AmbiguousCandidates or
        LocalAgentDiscoveryOutcome.UnresolvedInspection or
        LocalAgentDiscoveryOutcome.DiscoveryUnavailable;
}

public sealed record LocalAgentRecoveredBinding(
    AgentPairingDiscoveryRecord Discovery,
    InvestigationSessionPaths SessionPaths,
    CapturePackageInfo PackageInfo,
    LocalAgentProcessResult ProcessVerification,
    AgentPairingStoreResult ProtectedPairing,
    AgentHealthSnapshot Health,
    AgentIpcResponse AuthenticatedHealthResponse,
    string AuthenticatedEndpoint,
    long PairingGeneration,
    ViewerAgentCommandExecutionContext CommandContext);

public sealed record LocalAgentRecoveryResult(
    LocalAgentRecoveryOutcome Outcome,
    string Diagnostic,
    LocalAgentDiscoveryResult Discovery,
    AgentPairingStoreResult? ProtectedPairing = null,
    ViewerAgentCommandResult? BindingValidation = null,
    LocalAgentRecoveredBinding? Binding = null)
{
    public bool Recovered => Outcome == LocalAgentRecoveryOutcome.Recovered && Binding != null;

    public bool BlocksAdd => Discovery.BlocksAdd || Recovered;
}

public interface ILocalAgentRecoveryRuntime
{
    IReadOnlyList<AgentPairingDiscoveryRecord> DiscoverPairings();

    LocalAgentProcessResult VerifyRunning(LocalAgentProcessIdentity identity);

    AgentPairingStoreResult InspectProtectedPairing(
        AgentPairingDiscoveryRecord discovery,
        string sessionId,
        string databaseIdentity,
        string releaseId,
        DateTime nowUtc);

    Task<ViewerWorkspaceActivation> PrepareExistingLiveWorkspaceAsync(
        string captureManifestPath,
        CancellationToken cancellationToken);

    Task<ViewerAgentCommandResult> ValidateBindingAsync(
        ViewerAgentCommandExecutionRequest request,
        CancellationToken cancellationToken);
}

public sealed class DelegateLocalAgentRecoveryRuntime : ILocalAgentRecoveryRuntime
{
    private readonly Func<IReadOnlyList<AgentPairingDiscoveryRecord>> _discoverPairings;
    private readonly Func<LocalAgentProcessIdentity, LocalAgentProcessResult> _verifyRunning;
    private readonly Func<AgentPairingDiscoveryRecord, string, string, string, DateTime, AgentPairingStoreResult>
        _inspectProtectedPairing;
    private readonly Func<string, CancellationToken, Task<ViewerWorkspaceActivation>>
        _prepareExistingLiveWorkspaceAsync;
    private readonly Func<ViewerAgentCommandExecutionRequest, CancellationToken, Task<ViewerAgentCommandResult>>
        _validateBindingAsync;

    public DelegateLocalAgentRecoveryRuntime(
        Func<IReadOnlyList<AgentPairingDiscoveryRecord>> discoverPairings,
        Func<LocalAgentProcessIdentity, LocalAgentProcessResult> verifyRunning,
        Func<AgentPairingDiscoveryRecord, string, string, string, DateTime, AgentPairingStoreResult>
            inspectProtectedPairing,
        Func<string, CancellationToken, Task<ViewerWorkspaceActivation>> prepareExistingLiveWorkspaceAsync,
        Func<ViewerAgentCommandExecutionRequest, CancellationToken, Task<ViewerAgentCommandResult>>
            validateBindingAsync)
    {
        _discoverPairings = discoverPairings ?? throw new ArgumentNullException(nameof(discoverPairings));
        _verifyRunning = verifyRunning ?? throw new ArgumentNullException(nameof(verifyRunning));
        _inspectProtectedPairing = inspectProtectedPairing ??
            throw new ArgumentNullException(nameof(inspectProtectedPairing));
        _prepareExistingLiveWorkspaceAsync = prepareExistingLiveWorkspaceAsync ??
            throw new ArgumentNullException(nameof(prepareExistingLiveWorkspaceAsync));
        _validateBindingAsync = validateBindingAsync ??
            throw new ArgumentNullException(nameof(validateBindingAsync));
    }

    public IReadOnlyList<AgentPairingDiscoveryRecord> DiscoverPairings() =>
        _discoverPairings();

    public LocalAgentProcessResult VerifyRunning(LocalAgentProcessIdentity identity) =>
        _verifyRunning(identity);

    public AgentPairingStoreResult InspectProtectedPairing(
        AgentPairingDiscoveryRecord discovery,
        string sessionId,
        string databaseIdentity,
        string releaseId,
        DateTime nowUtc) =>
        _inspectProtectedPairing(discovery, sessionId, databaseIdentity, releaseId, nowUtc);

    public Task<ViewerWorkspaceActivation> PrepareExistingLiveWorkspaceAsync(
        string captureManifestPath,
        CancellationToken cancellationToken) =>
        _prepareExistingLiveWorkspaceAsync(captureManifestPath, cancellationToken);

    public Task<ViewerAgentCommandResult> ValidateBindingAsync(
        ViewerAgentCommandExecutionRequest request,
        CancellationToken cancellationToken) =>
        _validateBindingAsync(request, cancellationToken);
}

/// <summary>
/// Headless viewer-side owner for local pairing-lease discovery and authenticated recovery.
/// It treats discovery as a lead only, validates one prospective live workspace before any
/// caller commits a switch, and uses ViewerAgentCommandExecutor for the final binding proof.
/// </summary>
public sealed class LocalAgentRecoveryCoordinator : IDisposable
{
    public const int MaxDiagnosticLength = 1024;

    private readonly ILocalAgentRecoveryRuntime _runtime;
    private readonly Func<DateTime> _utcNow;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly CancellationTokenSource _lifetimeCts = new();
    private bool _disposed;

    public LocalAgentRecoveryCoordinator(
        ILocalAgentRecoveryRuntime runtime,
        Func<DateTime>? utcNow = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
    }

    public LocalAgentDiscoveryResult Discover()
    {
        if (_disposed)
        {
            return DiscoveryUnavailable("The local-agent recovery coordinator is disposed.");
        }

        IReadOnlyList<AgentPairingDiscoveryRecord> discoveries;
        try
        {
            discoveries = _runtime.DiscoverPairings() ?? Array.Empty<AgentPairingDiscoveryRecord>();
        }
        catch (Exception ex)
        {
            return DiscoveryUnavailable(
                $"Local-agent lease discovery could not be completed safely ({ex.GetType().Name}: {ex.Message}).");
        }

        var verified = new List<LocalAgentRecoveryCandidate>();
        var conflicts = new List<LocalAgentRecoveryConflict>();
        foreach (var discovery in discoveries)
        {
            if (discovery?.Lease == null)
            {
                conflicts.Add(new LocalAgentRecoveryConflict(
                    LocalAgentRecoveryConflictKind.InvalidLeaseIdentity,
                    "A discovery record did not contain lease metadata."));
                continue;
            }

            var lease = discovery.Lease;
            if (!HasInspectableLeaseProcessIdentity(lease, out var identityFailure))
            {
                conflicts.Add(new LocalAgentRecoveryConflict(
                    LocalAgentRecoveryConflictKind.InvalidLeaseIdentity,
                    identityFailure,
                    discovery));
                continue;
            }

            var leaseClaimsSupportedExecutable =
                ExecutableIdentity.IsSupportedAgentProcessName(lease.ExecutableName);

            LocalAgentProcessResult processVerification;
            try
            {
                processVerification = _runtime.VerifyRunning(new LocalAgentProcessIdentity(
                    lease.AgentProcessId,
                    lease.AgentStartedAtUtc,
                    Array.AsReadOnly([lease.ExecutablePath]),
                    leaseClaimsSupportedExecutable
                        ? string.Empty
                        : lease.ExecutableName));
            }
            catch (Exception ex)
            {
                processVerification = new LocalAgentProcessResult(
                    LocalAgentProcessOutcome.InspectionFailure,
                    lease.AgentProcessId,
                    IsRunning: false,
                    IsStopped: false,
                    Forced: false,
                    Detail: Bound($"The referenced process could not be inspected ({ex.GetType().Name}: {ex.Message})."));
            }

            switch (processVerification.Outcome)
            {
                case LocalAgentProcessOutcome.VerifiedRunning:
                    verified.Add(new LocalAgentRecoveryCandidate(discovery, processVerification));
                    break;
                case LocalAgentProcessOutcome.InspectionFailure:
                case LocalAgentProcessOutcome.Disposed:
                    conflicts.Add(new LocalAgentRecoveryConflict(
                        LocalAgentRecoveryConflictKind.ProcessInspectionUnresolved,
                        Bound(processVerification.Detail),
                        discovery,
                        processVerification));
                    break;
                case LocalAgentProcessOutcome.AlreadyExited:
                case LocalAgentProcessOutcome.Exited:
                    conflicts.Add(new LocalAgentRecoveryConflict(
                        LocalAgentRecoveryConflictKind.ProcessExited,
                        Bound(processVerification.Detail),
                        discovery,
                        processVerification));
                    break;
                default:
                    if (!leaseClaimsSupportedExecutable &&
                        !processVerification.ExactIdentityMismatchProved)
                    {
                        conflicts.Add(new LocalAgentRecoveryConflict(
                            LocalAgentRecoveryConflictKind.ProcessInspectionUnresolved,
                            Bound(
                                "The discovery lease references an unsupported executable host that is still present or could not be proved stale. " +
                                processVerification.Detail),
                            discovery,
                            processVerification));
                        break;
                    }

                    conflicts.Add(new LocalAgentRecoveryConflict(
                        LocalAgentRecoveryConflictKind.ProcessIdentityRejected,
                        Bound(processVerification.Detail),
                        discovery,
                        processVerification));
                    break;
            }
        }

        var unresolvedCount = conflicts.Count(conflict =>
            conflict.Kind is LocalAgentRecoveryConflictKind.InvalidLeaseIdentity or
                LocalAgentRecoveryConflictKind.ProcessInspectionUnresolved);
        var staleCount = conflicts.Count(conflict =>
            conflict.Kind is LocalAgentRecoveryConflictKind.ProcessExited or
                LocalAgentRecoveryConflictKind.ProcessIdentityRejected);
        if (verified.Count == 0 && unresolvedCount == 0)
        {
            return new LocalAgentDiscoveryResult(
                LocalAgentDiscoveryOutcome.Absent,
                Copy(discoveries),
                Array.Empty<LocalAgentRecoveryCandidate>(),
                Copy(conflicts),
                staleCount == 0
                    ? "No verified or unresolved running local agent was discovered."
                    : $"No verified or unresolved running local agent was discovered; {staleCount} historical exited or identity-mismatched pairing record(s) were ignored after independent process inspection.");
        }

        if (verified.Count == 0)
        {
            var unresolvedDiagnostic = conflicts.First(conflict =>
                conflict.Kind is LocalAgentRecoveryConflictKind.InvalidLeaseIdentity or
                    LocalAgentRecoveryConflictKind.ProcessInspectionUnresolved).Diagnostic;
            return new LocalAgentDiscoveryResult(
                LocalAgentDiscoveryOutcome.UnresolvedInspection,
                Copy(discoveries),
                Array.Empty<LocalAgentRecoveryCandidate>(),
                Copy(conflicts),
                Bound(
                    $"{unresolvedCount} discovery record(s) could not be resolved safely; Add Agent and Start Agent remain blocked. " +
                    $"{staleCount} historical exited or identity-mismatched record(s) were ignored. " +
                    $"First unresolved identity: {unresolvedDiagnostic}"));
        }

        if (verified.Count > 1 && unresolvedCount == 0)
        {
            conflicts.Add(new LocalAgentRecoveryConflict(
                LocalAgentRecoveryConflictKind.MultipleVerifiedCandidates,
                $"{verified.Count} verified running local-agent candidates were discovered."));
            return new LocalAgentDiscoveryResult(
                LocalAgentDiscoveryOutcome.MultipleCandidates,
                Copy(discoveries),
                Copy(verified),
                Copy(conflicts),
                "Multiple verified running local agents were discovered; no candidate was selected.");
        }

        if (verified.Count > 1 || unresolvedCount > 0)
        {
            conflicts.Add(new LocalAgentRecoveryConflict(
                LocalAgentRecoveryConflictKind.AmbiguousCandidates,
                "Verified and unresolved local-agent candidates coexist, so no candidate can be selected safely."));
            return new LocalAgentDiscoveryResult(
                LocalAgentDiscoveryOutcome.AmbiguousCandidates,
                Copy(discoveries),
                Copy(verified),
                Copy(conflicts),
                "Local-agent discovery is ambiguous; no candidate was selected.");
        }

        return new LocalAgentDiscoveryResult(
            LocalAgentDiscoveryOutcome.SingleCandidate,
            Copy(discoveries),
            Copy(verified),
            Copy(conflicts),
            staleCount == 0
                ? "Exactly one verified running local-agent candidate was discovered."
                : $"Exactly one verified running local-agent candidate was discovered; {staleCount} historical exited or identity-mismatched pairing record(s) were ignored.");
    }

    public async Task<LocalAgentRecoveryResult> RecoverAsync(
        LocalAgentRecoveryRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (_disposed)
        {
            return Failure(
                LocalAgentRecoveryOutcome.InternalFailure,
                "The local-agent recovery coordinator is disposed.",
                DiscoveryUnavailable("The local-agent recovery coordinator is disposed."));
        }

        bool gateEntered;
        try
        {
            gateEntered = await _operationGate.WaitAsync(0, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return Failure(LocalAgentRecoveryOutcome.Canceled, "Local-agent recovery was canceled.", EmptyDiscovery());
        }

        if (!gateEntered)
        {
            return Failure(
                LocalAgentRecoveryOutcome.Busy,
                "Another local-agent recovery operation is already in progress.",
                EmptyDiscovery());
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetimeCts.Token);
        try
        {
            var requestFailure = ValidateRequest(request);
            if (!string.IsNullOrEmpty(requestFailure))
            {
                return Failure(LocalAgentRecoveryOutcome.InternalFailure, requestFailure, EmptyDiscovery());
            }

            var discovery = Discover();
            var mappedDiscoveryFailure = MapDiscoveryFailure(discovery);
            if (mappedDiscoveryFailure != null)
            {
                return mappedDiscoveryFailure;
            }

            linkedCts.Token.ThrowIfCancellationRequested();
            var candidate = discovery.Candidates[0];
            var lease = candidate.Discovery.Lease;
            var nowUtc = _utcNow();
            var leaseFailure = ValidateRecoveryLease(lease, request, nowUtc);
            if (!string.IsNullOrEmpty(leaseFailure))
            {
                return Failure(
                    LocalAgentRecoveryOutcome.CandidateRejected,
                    leaseFailure,
                    WithConflict(
                        discovery,
                        new LocalAgentRecoveryConflict(
                            LocalAgentRecoveryConflictKind.IncompatibleLease,
                            leaseFailure,
                            candidate.Discovery,
                            candidate.ProcessVerification)));
            }

            LocalAgentProcessResult exactProcess;
            try
            {
                exactProcess = _runtime.VerifyRunning(new LocalAgentProcessIdentity(
                    lease.AgentProcessId,
                    lease.AgentStartedAtUtc,
                    Copy(request.SupportedExecutablePaths)));
            }
            catch (Exception ex)
            {
                exactProcess = new LocalAgentProcessResult(
                    LocalAgentProcessOutcome.InspectionFailure,
                    lease.AgentProcessId,
                    IsRunning: false,
                    IsStopped: false,
                    Forced: false,
                    Detail: $"Exact candidate inspection failed ({ex.GetType().Name}: {ex.Message}).");
            }

            if (exactProcess.Outcome != LocalAgentProcessOutcome.VerifiedRunning ||
                !exactProcess.IsRunning ||
                exactProcess.IsStopped ||
                exactProcess.Forced ||
                exactProcess.ProcessId != lease.AgentProcessId)
            {
                var diagnostic = FirstNonEmpty(
                    exactProcess.Detail,
                    $"Exact local-agent process verification failed with {exactProcess.Outcome}.");
                return Failure(
                    LocalAgentRecoveryOutcome.CandidateRejected,
                    diagnostic,
                    WithConflict(
                        discovery,
                        new LocalAgentRecoveryConflict(
                            exactProcess.Outcome == LocalAgentProcessOutcome.InspectionFailure
                                ? LocalAgentRecoveryConflictKind.ProcessInspectionUnresolved
                                : LocalAgentRecoveryConflictKind.ProcessIdentityRejected,
                            diagnostic,
                            candidate.Discovery,
                            exactProcess)));
            }

            linkedCts.Token.ThrowIfCancellationRequested();
            AgentPairingStoreResult protectedPairing;
            try
            {
                protectedPairing = _runtime.InspectProtectedPairing(
                    candidate.Discovery,
                    lease.SessionId,
                    lease.DatabaseIdentity,
                    lease.ReleaseId,
                    nowUtc);
            }
            catch (Exception ex)
            {
                var diagnostic =
                    $"The current-user protected pairing could not be inspected ({ex.GetType().Name}: {ex.Message}).";
                return Failure(
                    LocalAgentRecoveryOutcome.PairingRejected,
                    diagnostic,
                    WithConflict(
                        discovery,
                        new LocalAgentRecoveryConflict(
                            LocalAgentRecoveryConflictKind.ProtectedPairingRejected,
                            diagnostic,
                            candidate.Discovery)),
                    new AgentPairingStoreResult(
                        AgentPairingState.Corrupt,
                        lease.PairingGeneration,
                        lease.ExpiresAtUtc,
                        Bound(diagnostic),
                        lease));
            }

            var pairingFailure = ValidateProtectedPairing(protectedPairing, lease, nowUtc);
            if (!string.IsNullOrEmpty(pairingFailure))
            {
                return Failure(
                    LocalAgentRecoveryOutcome.PairingRejected,
                    pairingFailure,
                    WithConflict(
                        discovery,
                        new LocalAgentRecoveryConflict(
                            LocalAgentRecoveryConflictKind.ProtectedPairingRejected,
                            pairingFailure,
                            candidate.Discovery)),
                    protectedPairing);
            }

            linkedCts.Token.ThrowIfCancellationRequested();
            ViewerWorkspaceActivation activation;
            try
            {
                var manifestPath = ResolveManifestPath(lease.DatabaseIdentity);
                activation = await _runtime.PrepareExistingLiveWorkspaceAsync(
                    manifestPath,
                    linkedCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
            {
                throw;
            }
            catch (FileNotFoundException ex) when (PathsMatch(ex.FileName, lease.DatabaseIdentity))
            {
                var diagnostic =
                    "The referenced live workspace is valid, but its Agent-owned evidence database has not been created yet.";
                return Failure(
                    LocalAgentRecoveryOutcome.WorkspacePending,
                    diagnostic,
                    WithConflict(
                        discovery,
                        new LocalAgentRecoveryConflict(
                            LocalAgentRecoveryConflictKind.WorkspacePending,
                            diagnostic,
                            candidate.Discovery)),
                    protectedPairing);
            }
            catch (ViewerWorkspaceStartupPendingException ex) when (
                PathsMatch(ex.DatabasePath, lease.DatabaseIdentity) &&
                ex.CompatibilityAssessment.State == CaptureCompatibilityState.MissingVersionMetadata)
            {
                var diagnostic =
                    "The referenced live workspace is valid, but its exact Agent-owned evidence database is still initializing.";
                return Failure(
                    LocalAgentRecoveryOutcome.WorkspacePending,
                    diagnostic,
                    WithConflict(
                        discovery,
                        new LocalAgentRecoveryConflict(
                            LocalAgentRecoveryConflictKind.WorkspacePending,
                            diagnostic,
                            candidate.Discovery)),
                    protectedPairing);
            }
            catch (Exception ex)
            {
                var diagnostic =
                    $"The referenced live workspace failed manifest-first preparation ({ex.GetType().Name}: {ex.Message}).";
                return Failure(
                    LocalAgentRecoveryOutcome.WorkspaceRejected,
                    diagnostic,
                    WithConflict(
                        discovery,
                        new LocalAgentRecoveryConflict(
                            LocalAgentRecoveryConflictKind.WorkspaceRejected,
                            diagnostic,
                            candidate.Discovery)),
                    protectedPairing);
            }

            var workspaceFailure = ValidatePreparedWorkspace(activation, lease);
            if (!string.IsNullOrEmpty(workspaceFailure))
            {
                return Failure(
                    LocalAgentRecoveryOutcome.WorkspaceRejected,
                    workspaceFailure,
                    WithConflict(
                        discovery,
                        new LocalAgentRecoveryConflict(
                            LocalAgentRecoveryConflictKind.WorkspaceRejected,
                            workspaceFailure,
                            candidate.Discovery)),
                    protectedPairing);
            }

            linkedCts.Token.ThrowIfCancellationRequested();
            var commandContext = CreateCommandContext(request, activation, lease);
            var validationRequest = new ViewerAgentCommandExecutionRequest(
                new GetCaptureConfigurationCommand
                {
                    AgentId = "local",
                    HostId = "local",
                    ConfigurationVersion = "local-agent-recovery-binding-validation"
                },
                commandContext);
            ViewerAgentCommandResult validation;
            try
            {
                validation = await _runtime.ValidateBindingAsync(
                    validationRequest,
                    linkedCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                var diagnostic =
                    $"Authenticated local-agent binding validation failed ({ex.GetType().Name}: {ex.Message}).";
                return Failure(
                    LocalAgentRecoveryOutcome.AuthenticationRejected,
                    diagnostic,
                    WithConflict(
                        discovery,
                        new LocalAgentRecoveryConflict(
                            LocalAgentRecoveryConflictKind.AuthenticatedBindingRejected,
                            diagnostic,
                            candidate.Discovery)),
                    protectedPairing);
            }

            var validationFailure = ValidateBindingResult(validation, lease);
            if (!string.IsNullOrEmpty(validationFailure))
            {
                var outcome = validation?.Outcome switch
                {
                    ViewerAgentCommandOutcome.Superseded => LocalAgentRecoveryOutcome.Superseded,
                    ViewerAgentCommandOutcome.Canceled => LocalAgentRecoveryOutcome.Canceled,
                    ViewerAgentCommandOutcome.PairingRejected or
                    ViewerAgentCommandOutcome.HealthUnavailable or
                    ViewerAgentCommandOutcome.ContractRejected or
                    ViewerAgentCommandOutcome.ReleaseRejected or
                    ViewerAgentCommandOutcome.SessionRejected or
                    ViewerAgentCommandOutcome.ProcessRejected =>
                        LocalAgentRecoveryOutcome.AuthenticationRejected,
                    _ => LocalAgentRecoveryOutcome.FinalValidationRejected
                };
                return Failure(
                    outcome,
                    validationFailure,
                    WithConflict(
                        discovery,
                        new LocalAgentRecoveryConflict(
                            LocalAgentRecoveryConflictKind.AuthenticatedBindingRejected,
                            validationFailure,
                            candidate.Discovery)),
                    protectedPairing,
                    validation);
            }

            var health = validation!.VerifiedHealth!;
            var authenticatedResponse = validation.PreflightResponse!;
            var binding = new LocalAgentRecoveredBinding(
                candidate.Discovery,
                activation.SessionPaths,
                activation.PackageInfo!,
                exactProcess,
                protectedPairing,
                health,
                authenticatedResponse,
                validation.AuthenticatedEndpoint,
                validation.PairingGeneration,
                commandContext);
            return new LocalAgentRecoveryResult(
                LocalAgentRecoveryOutcome.Recovered,
                "Exactly one running local agent, protected pairing, live workspace, authenticated endpoint, and process identity were verified.",
                discovery,
                protectedPairing,
                validation,
                binding);
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
        {
            return Failure(
                _disposed ? LocalAgentRecoveryOutcome.InternalFailure : LocalAgentRecoveryOutcome.Canceled,
                _disposed
                    ? "The local-agent recovery coordinator was disposed."
                    : "Local-agent recovery was canceled.",
                EmptyDiscovery());
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _lifetimeCts.Cancel();
    }

    private static string ValidateRequest(LocalAgentRecoveryRequest request)
    {
        if (request.FeatureCatalog == null ||
            string.IsNullOrWhiteSpace(request.ViewerReleaseId) ||
            !string.Equals(
                request.FeatureCatalog.ReleaseId,
                request.ViewerReleaseId,
                StringComparison.Ordinal) ||
            request.WorkspaceGeneration < 0 ||
            request.SupportedExecutablePaths == null ||
            request.SupportedExecutablePaths.Count == 0 ||
            request.SupportedExecutablePaths.Count > 16)
        {
            return "The local-agent recovery request does not contain one valid release, workspace generation, and executable allowlist.";
        }

        try
        {
            var normalized = request.SupportedExecutablePaths
                .Select(Path.GetFullPath)
                .ToArray();
            if (normalized.Any(path =>
                    !ExecutableIdentity.IsSupportedAgentProcessName(Path.GetFileName(path))) ||
                normalized.Distinct(StringComparer.OrdinalIgnoreCase).Count() != normalized.Length)
            {
                return "The local-agent recovery executable allowlist is invalid or contains duplicate paths.";
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return $"The local-agent recovery executable allowlist is invalid: {ex.Message}";
        }

        return string.Empty;
    }

    private static LocalAgentRecoveryResult? MapDiscoveryFailure(LocalAgentDiscoveryResult discovery) =>
        discovery.Outcome switch
        {
            LocalAgentDiscoveryOutcome.Absent =>
                Failure(LocalAgentRecoveryOutcome.Absent, discovery.Diagnostic, discovery),
            LocalAgentDiscoveryOutcome.DiscoveryUnavailable =>
                Failure(LocalAgentRecoveryOutcome.DiscoveryUnavailable, discovery.Diagnostic, discovery),
            LocalAgentDiscoveryOutcome.MultipleCandidates =>
                Failure(LocalAgentRecoveryOutcome.MultipleCandidates, discovery.Diagnostic, discovery),
            LocalAgentDiscoveryOutcome.AmbiguousCandidates =>
                Failure(LocalAgentRecoveryOutcome.AmbiguousCandidates, discovery.Diagnostic, discovery),
            LocalAgentDiscoveryOutcome.UnresolvedInspection =>
                Failure(LocalAgentRecoveryOutcome.UnresolvedInspection, discovery.Diagnostic, discovery),
            _ => null
        };

    private static string ValidateRecoveryLease(
        AgentPairingLeaseMetadata lease,
        LocalAgentRecoveryRequest request,
        DateTime nowUtc)
    {
        if (lease.State != AgentPairingState.Ready)
        {
            return $"The discovery lease state is {lease.State}, not Ready.";
        }

        if (lease.PairingGeneration <= 0 ||
            lease.ExpiresAtUtc <= nowUtc ||
            lease.PairingContractVersion != AgentContracts.PairingContractVersion ||
            lease.IpcContractVersion != AgentContracts.ContractVersion)
        {
            return "The discovery lease generation, expiry, or pairing/IPC contract is incompatible.";
        }

        if (!string.Equals(lease.ReleaseId, request.ViewerReleaseId, StringComparison.Ordinal))
        {
            return "The discovered local agent belongs to a different DFIRoscope release.";
        }

        if (lease.WorkspaceMode != CaptureWorkspaceMode.LiveCapture || lease.CaptureSealed)
        {
            return "The discovery lease does not identify an unsealed live capture workspace.";
        }

        if (string.IsNullOrWhiteSpace(lease.SessionId) ||
            string.IsNullOrWhiteSpace(lease.DatabaseIdentity) ||
            !HasExactEndpointInventory(lease.Endpoints))
        {
            return "The discovery lease session, database, or endpoint inventory is incomplete or unexpected.";
        }

        return string.Empty;
    }

    private static string ValidateProtectedPairing(
        AgentPairingStoreResult pairing,
        AgentPairingLeaseMetadata lease,
        DateTime nowUtc)
    {
        if (pairing == null ||
            pairing.State != AgentPairingState.Ready ||
            pairing.PairingGeneration != lease.PairingGeneration ||
            pairing.ExpiresAtUtc <= nowUtc ||
            pairing.Lease == null ||
            !MatchesExactLease(pairing.Lease, lease))
        {
            return FirstNonEmpty(
                pairing?.Status,
                "The discovery lease did not match one usable current-user protected pairing generation.");
        }

        return string.Empty;
    }

    private static string ValidatePreparedWorkspace(
        ViewerWorkspaceActivation activation,
        AgentPairingLeaseMetadata lease)
    {
        if (activation == null ||
            activation.Mode != CaptureWorkspaceMode.LiveCapture ||
            activation.SessionPaths == null ||
            activation.PackageInfo == null ||
            !string.Equals(activation.SessionPaths.SessionId, lease.SessionId, StringComparison.Ordinal) ||
            !string.Equals(activation.PackageInfo.SessionId, lease.SessionId, StringComparison.Ordinal) ||
            !PathsMatch(activation.SessionPaths.LiveDatabasePath, lease.DatabaseIdentity) ||
            !PathsMatch(activation.PackageInfo.LiveDatabasePath, lease.DatabaseIdentity) ||
            activation.PackageInfo.CompatibilityAssessment == null ||
            !activation.PackageInfo.CompatibilityAssessment.Allows(CaptureOpenCapability.ReadEvidence))
        {
            return "The prepared live workspace does not exactly match the lease session/database identity and compatibility contract.";
        }

        return string.Empty;
    }

    private static ViewerAgentCommandExecutionContext CreateCommandContext(
        LocalAgentRecoveryRequest request,
        ViewerWorkspaceActivation activation,
        AgentPairingLeaseMetadata lease)
        => ViewerAgentCommandContextFactory.CreateVerifiedDeployedAgent(
            activation,
            lease,
            request.FeatureCatalog,
            request.ViewerReleaseId,
            request.SupportedExecutablePaths,
            AgentCommandKind.GetCaptureConfiguration,
            request.WorkspaceGeneration);

    private static string ValidateBindingResult(
        ViewerAgentCommandResult? validation,
        AgentPairingLeaseMetadata lease)
    {
        if (validation == null)
        {
            return "The shared viewer-agent executor returned no binding validation result.";
        }

        if (!validation.Success ||
            !validation.PreflightVerified ||
            !validation.AuthenticatedHealthVerified ||
            validation.CommandSubmissionAttempted ||
            validation.VerifiedHealth == null ||
            validation.PreflightResponse is not { Success: true } ||
            string.IsNullOrWhiteSpace(validation.AuthenticatedEndpoint) ||
            validation.PairingGeneration != lease.PairingGeneration ||
            validation.VerifiedHealth.ProcessId != lease.AgentProcessId ||
            validation.VerifiedHealth.StartedAtUtc != lease.AgentStartedAtUtc)
        {
            return FirstNonEmpty(
                validation.Diagnostic,
                "The shared viewer-agent executor rejected the authenticated recovery binding.");
        }

        return string.Empty;
    }

    private static bool HasInspectableLeaseProcessIdentity(
        AgentPairingLeaseMetadata lease,
        out string failure)
    {
        if (lease.AgentProcessId <= 0 ||
            lease.AgentStartedAtUtc == default ||
            lease.AgentStartedAtUtc.Kind != DateTimeKind.Utc ||
            string.IsNullOrWhiteSpace(lease.ExecutablePath) ||
            string.IsNullOrWhiteSpace(lease.ExecutableName) ||
            !string.Equals(
                Path.GetFileName(lease.ExecutablePath),
                lease.ExecutableName,
                StringComparison.OrdinalIgnoreCase))
        {
            failure = "The discovery lease does not contain an inspectable exact PID/start/executable identity.";
            return false;
        }

        failure = string.Empty;
        return true;
    }

    private static bool MatchesExactLease(
        AgentPairingLeaseMetadata left,
        AgentPairingLeaseMetadata right) =>
        left.PairingContractVersion == right.PairingContractVersion &&
        left.IpcContractVersion == right.IpcContractVersion &&
        left.PairingGeneration == right.PairingGeneration &&
        left.ExpiresAtUtc == right.ExpiresAtUtc &&
        left.AgentProcessId == right.AgentProcessId &&
        left.AgentStartedAtUtc == right.AgentStartedAtUtc &&
        left.State == right.State &&
        left.WorkspaceMode == right.WorkspaceMode &&
        left.CaptureSealed == right.CaptureSealed &&
        string.Equals(left.SessionId, right.SessionId, StringComparison.Ordinal) &&
        string.Equals(left.ReleaseId, right.ReleaseId, StringComparison.Ordinal) &&
        PathsMatch(left.DatabaseIdentity, right.DatabaseIdentity) &&
        PathsMatch(left.ExecutablePath, right.ExecutablePath) &&
        string.Equals(left.ExecutableName, right.ExecutableName, StringComparison.OrdinalIgnoreCase) &&
        left.Endpoints.SequenceEqual(right.Endpoints, StringComparer.Ordinal);

    private static bool HasExactEndpointInventory(IReadOnlyList<string>? endpoints)
    {
        var expected = AgentContracts.CompatiblePipeNames
            .Concat(AgentContracts.CompatibleShutdownControlPipeNames)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return endpoints != null &&
            endpoints.Count == expected.Length &&
            endpoints.All(endpoint => !string.IsNullOrWhiteSpace(endpoint)) &&
            endpoints.Distinct(StringComparer.Ordinal).Count() == expected.Length &&
            !endpoints.Except(expected, StringComparer.Ordinal).Any() &&
            !expected.Except(endpoints, StringComparer.Ordinal).Any();
    }

    private static string ResolveManifestPath(string databaseIdentity)
    {
        var normalizedDatabase = SessionPathService.NormalizeLiveDatabaseIdentity(databaseIdentity);
        var directory = Path.GetDirectoryName(normalizedDatabase);
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new InvalidDataException("The paired live database directory is unavailable.");
        }

        return Path.Combine(directory, SessionPathService.CapturePackageManifestFileName);
    }

    private static bool PathsMatch(string? left, string? right)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(left) &&
                !string.IsNullOrWhiteSpace(right) &&
                string.Equals(
                    Path.GetFullPath(left),
                    Path.GetFullPath(right),
                    StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static LocalAgentRecoveryResult Failure(
        LocalAgentRecoveryOutcome outcome,
        string diagnostic,
        LocalAgentDiscoveryResult discovery,
        AgentPairingStoreResult? protectedPairing = null,
        ViewerAgentCommandResult? validation = null) =>
        new(
            outcome,
            Bound(diagnostic),
            discovery,
            protectedPairing,
            validation);

    private static LocalAgentDiscoveryResult WithConflict(
        LocalAgentDiscoveryResult discovery,
        LocalAgentRecoveryConflict conflict) =>
        discovery with
        {
            Conflicts = Copy(discovery.Conflicts.Concat([conflict]).ToArray())
        };

    private static LocalAgentDiscoveryResult EmptyDiscovery() =>
        new(
            LocalAgentDiscoveryOutcome.Absent,
            Array.Empty<AgentPairingDiscoveryRecord>(),
            Array.Empty<LocalAgentRecoveryCandidate>(),
            Array.Empty<LocalAgentRecoveryConflict>(),
            "Local-agent discovery did not run.");

    private static LocalAgentDiscoveryResult DiscoveryUnavailable(string diagnostic) =>
        new(
            LocalAgentDiscoveryOutcome.DiscoveryUnavailable,
            Array.Empty<AgentPairingDiscoveryRecord>(),
            Array.Empty<LocalAgentRecoveryCandidate>(),
            [new LocalAgentRecoveryConflict(
                LocalAgentRecoveryConflictKind.DiscoveryUnavailable,
                Bound(diagnostic))],
            Bound(diagnostic));

    private static IReadOnlyList<T> Copy<T>(IEnumerable<T>? values) =>
        values == null
            ? Array.Empty<T>()
            : Array.AsReadOnly(values.ToArray());

    private static string FirstNonEmpty(params string?[] values) =>
        Bound(values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty);

    private static string Bound(string? value)
    {
        var normalized = string.IsNullOrWhiteSpace(value)
            ? "Local-agent recovery was rejected without additional diagnostic detail."
            : value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return normalized.Length <= MaxDiagnosticLength
            ? normalized
            : normalized[..MaxDiagnosticLength];
    }
}
