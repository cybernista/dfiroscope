using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services;
using ProcInsider.Services.Features;
using ProcInsider.Services.Infrastructure;
using Contracts = ProcInsider.Models.Infrastructure.InfrastructureConfigurationContracts;

namespace ProcInsider.Agent;

internal interface IAgentInfrastructureRuntimeCompositionFactory
{
    AgentInfrastructureRuntimeComposition Create(
        Contracts.InfrastructureAgentConfiguration configuration,
        InvestigationSessionPaths sessionPaths);
}

/// <summary>
/// Passive dependency composition for the unpublished LocalSystem runtime. The protected
/// credential/trust adapters are retained but not invoked until the explicit runtime start.
/// </summary>
internal sealed class AgentInfrastructureRuntimeComposition
{
    private readonly InfrastructureModeAccessService _access;
    private readonly Contracts.InfrastructureAgentConfiguration _configuration;
    private readonly InvestigationSessionPaths _sessionPaths;
    private readonly InfrastructureAgentMachinePaths _machinePaths;
    private readonly InfrastructureAgentCredentialBinding _credentialBinding;
    private readonly IInfrastructureAgentCredentialSource _credentialSource;
    private readonly IInfrastructureAgentServerCertificateAuthority _serverAuthority;
    private readonly IAgentCommittedEvidenceBatchMaterializer _materializer;
    private readonly AgentInfrastructureEvidenceSpoolPolicy? _spoolPolicy;
    private readonly Func<AgentInfrastructureSpoolDiskSnapshot>? _diskSnapshot;
    private int _prepared;

    public AgentInfrastructureRuntimeComposition(
        InfrastructureModeAccessService access,
        Contracts.InfrastructureAgentConfiguration configuration,
        InvestigationSessionPaths sessionPaths,
        InfrastructureAgentMachinePaths machinePaths,
        InfrastructureAgentCredentialBinding credentialBinding,
        IInfrastructureAgentCredentialSource credentialSource,
        IInfrastructureAgentServerCertificateAuthority serverAuthority,
        IAgentCommittedEvidenceBatchMaterializer materializer,
        AgentInfrastructureEvidenceSpoolPolicy? spoolPolicy = null,
        Func<AgentInfrastructureSpoolDiskSnapshot>? diskSnapshot = null)
    {
        _access = access ?? throw new ArgumentNullException(nameof(access));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _sessionPaths = sessionPaths ?? throw new ArgumentNullException(nameof(sessionPaths));
        _machinePaths = machinePaths ?? throw new ArgumentNullException(nameof(machinePaths));
        _credentialBinding = credentialBinding ?? throw new ArgumentNullException(nameof(credentialBinding));
        _credentialSource = credentialSource ?? throw new ArgumentNullException(nameof(credentialSource));
        _serverAuthority = serverAuthority ?? throw new ArgumentNullException(nameof(serverAuthority));
        _materializer = materializer ?? throw new ArgumentNullException(nameof(materializer));
        _spoolPolicy = spoolPolicy;
        _diskSnapshot = diskSnapshot;
    }

    public AgentInfrastructurePreparedRuntime Prepare(AgentStagingWriter writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if (Interlocked.Exchange(ref _prepared, 1) != 0)
        {
            throw new InvalidOperationException("The Infrastructure runtime composition was already prepared.");
        }

        var decision = _access.Evaluate(
            InfrastructureEntryPointKind.IpcOrNetworkClientCreation,
            InfrastructureFeatureArea.AgentManagement);
        if (!decision.IsAllowed)
        {
            throw new InvalidOperationException($"{decision.ErrorCode}: {decision.Message}");
        }
        ValidateExactLocalBinding();

        var spool = new AgentInfrastructureEvidenceSpool(
            _machinePaths,
            _credentialBinding.Scope.CaptureId,
            _spoolPolicy,
            _diskSnapshot);
        var connectivity = new AgentInfrastructureEvidenceConnectivity();
        var publisher = new AgentCommittedEvidenceBatchPublisher(
            writer,
            spool,
            _materializer,
            connectivity);
        try
        {
            publisher.Start();
        }
        catch
        {
            publisher.DisposeAsync().AsTask().GetAwaiter().GetResult();
            throw;
        }

        var connector = new AgentInfrastructureHttp2Connector(
            _credentialSource,
            _serverAuthority,
            _credentialBinding);
        return new AgentInfrastructurePreparedRuntime(
            _configuration,
            _sessionPaths.SessionId,
            new AgentInfrastructureSessionClient(connector),
            spool,
            publisher,
            connectivity);
    }

    private void ValidateExactLocalBinding()
    {
        var credential = _credentialBinding.Credential;
        var scope = _credentialBinding.Scope;
        if (!string.Equals(credential.AgentId, _configuration.AgentId, StringComparison.Ordinal) ||
            !string.Equals(credential.HostId, _configuration.HostId, StringComparison.Ordinal) ||
            !string.Equals(credential.ReleaseId, _configuration.ReleaseId, StringComparison.Ordinal) ||
            credential.ProtocolGeneration != _configuration.ProtocolGeneration ||
            _configuration.ServerEndpoints.Count == 0 ||
            !string.Equals(
                credential.ServerUri,
                _configuration.ServerEndpoints[0].Uri,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(scope.SessionId, _sessionPaths.SessionId, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(scope.CaseId) || string.IsNullOrWhiteSpace(scope.CaptureId) ||
            string.IsNullOrWhiteSpace(scope.DatabaseIdentity) ||
            scope.WorkspaceMode != CaptureWorkspaceMode.LiveCapture || scope.CaptureSealed)
        {
            throw new InvalidDataException(
                "The protected Infrastructure credential is not bound to the exact local Agent evidence route.");
        }
    }
}

internal sealed class AgentInfrastructurePreparedRuntime : IAsyncDisposable
{
    private readonly Contracts.InfrastructureAgentConfiguration _configuration;
    private readonly string _localSessionId;
    private readonly AgentInfrastructureSessionClient _sessions;
    private readonly AgentInfrastructureEvidenceSpool _spool;
    private readonly AgentCommittedEvidenceBatchPublisher _publisher;
    private readonly AgentInfrastructureEvidenceConnectivity _connectivity;
    private AgentInfrastructureRuntime? _runtime;
    private bool _disposed;

    public AgentInfrastructurePreparedRuntime(
        Contracts.InfrastructureAgentConfiguration configuration,
        string localSessionId,
        AgentInfrastructureSessionClient sessions,
        AgentInfrastructureEvidenceSpool spool,
        AgentCommittedEvidenceBatchPublisher publisher,
        AgentInfrastructureEvidenceConnectivity connectivity)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _localSessionId = localSessionId;
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _spool = spool ?? throw new ArgumentNullException(nameof(spool));
        _publisher = publisher ?? throw new ArgumentNullException(nameof(publisher));
        _connectivity = connectivity ?? throw new ArgumentNullException(nameof(connectivity));
    }

    public AgentInfrastructureEvidenceOutbox Outbox => _publisher.Outbox;

    public AgentInfrastructureRuntime Activate(
        IFeatureCatalog featureCatalog,
        Func<InfrastructureCommandTarget, CaptureWriteCategory, bool> isCaptureCompatible,
        Func<AgentIpcRequest, CancellationToken, Task<AgentIpcResponse>> executeCommand,
        Func<AgentControlSnapshot> getControlSnapshot,
        Func<CancellationToken, Task> drainAcceptedWork,
        Func<double>? nextJitterFraction = null,
        TimeSpan? idleUploadDelay = null,
        TimeSpan? busyUploadDelay = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_runtime != null)
        {
            throw new InvalidOperationException("The prepared Infrastructure runtime was already activated.");
        }
        ArgumentNullException.ThrowIfNull(featureCatalog);
        ArgumentNullException.ThrowIfNull(isCaptureCompatible);
        ArgumentNullException.ThrowIfNull(executeCommand);
        ArgumentNullException.ThrowIfNull(getControlSnapshot);
        ArgumentNullException.ThrowIfNull(drainAcceptedWork);

        var route = new AgentInfrastructureRouteLease();
        AgentInfrastructureRuntime? runtime = null;
        var dispatcher = new AgentInfrastructureCommandDispatcher(
            featureCatalog,
            (agentId, generation) => runtime?.IsAuthenticationCurrent(agentId, generation) == true,
            route.IsExactTarget,
            isCaptureCompatible,
            executeCommand);
        runtime = new AgentInfrastructureRuntime(
            _configuration,
            _localSessionId,
            _sessions,
            dispatcher,
            _spool,
            _publisher,
            _connectivity,
            route,
            getControlSnapshot,
            drainAcceptedWork,
            nextJitterFraction,
            idleUploadDelay,
            busyUploadDelay);
        _runtime = runtime;
        return runtime;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (_runtime != null)
        {
            await _runtime.DisposeAsync().ConfigureAwait(false);
        }
        else
        {
            await _publisher.DisposeAsync().ConfigureAwait(false);
        }
    }
}
