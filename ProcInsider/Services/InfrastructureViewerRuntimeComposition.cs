using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Features.Infrastructure;
using ProcInsider.Models.Features;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.Features;
using ProcInsider.Services.Infrastructure;

namespace ProcInsider.Services;

/// <summary>
/// Protected inputs for one Viewer runtime. Construction retains references and policies only;
/// CurrentUser certificate access and network activity begin on the first analyst request.
/// </summary>
public sealed record InfrastructureViewerRuntimeBinding(
    InfrastructureViewerServerProfile Profile,
    InfrastructureCredentialRecord Credential,
    IInfrastructureViewerCredentialSource CredentialSource,
    IInfrastructureViewerServerCertificateAuthority ServerAuthority,
    Func<InfrastructureViewerServerProfile, InfrastructureCredentialRecord, bool> IsCurrent,
    Func<DateTime> UtcNow)
{
    public static InfrastructureViewerRuntimeBinding CreateProtected(
        InfrastructureViewerServerProfile profile,
        InfrastructureCredentialRecord credential,
        WindowsInfrastructureCertificateStore certificateStore,
        Func<InfrastructureViewerServerProfile, InfrastructureCredentialRecord, bool> isCurrent)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(certificateStore);
        ArgumentNullException.ThrowIfNull(isCurrent);
        return new InfrastructureViewerRuntimeBinding(
            profile,
            credential,
            new WindowsInfrastructureViewerCredentialSource(certificateStore),
            new WindowsInfrastructureViewerServerCertificateAuthority(profile, certificateStore),
            isCurrent,
            static () => DateTime.UtcNow);
    }
}

/// <summary>
/// Publication fence for the standard-user Viewer composition. All compiled gates are checked
/// before the protected binding factory can read a profile or construct certificate/network owners.
/// </summary>
public static class InfrastructureViewerRuntimeFactory
{
    private static readonly InfrastructureEntryPointKind[] RequiredEntryPoints =
    [
        InfrastructureEntryPointKind.ConfigurationAccess,
        InfrastructureEntryPointKind.CredentialAccess,
        InfrastructureEntryPointKind.HandlerConstruction,
        InfrastructureEntryPointKind.IpcOrNetworkClientCreation
    ];

    public static bool TryCreate(
        InfrastructureModeAccessService access,
        Func<InfrastructureViewerRuntimeBinding> bindingFactory,
        out InfrastructureViewerRuntimeComposition? composition,
        out InfrastructureAccessDecision decision)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(bindingFactory);
        var server = CurrentInfrastructureModeProfile.Definition.CreateIdentity(
            InfrastructureComponentKind.Server);
        foreach (var entryPoint in RequiredEntryPoints)
        {
            decision = access.Evaluate(
                entryPoint,
                InfrastructureFeatureArea.CaseWorkspaces,
                server);
            if (!decision.IsAllowed)
            {
                composition = null;
                return false;
            }
        }

        var binding = bindingFactory() ??
                      throw new InvalidOperationException("InfrastructureViewerRuntimeBindingMissing");
        ValidateBinding(binding);
        composition = new InfrastructureViewerRuntimeComposition(binding);
        decision = new InfrastructureAccessDecision(
            InfrastructureAccessOutcome.Allowed,
            InfrastructureAccessErrorCodes.Allowed,
            "The publication-authorized Infrastructure Viewer runtime is composed but remains connection-lazy.");
        return true;
    }

    private static void ValidateBinding(InfrastructureViewerRuntimeBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding.Profile);
        ArgumentNullException.ThrowIfNull(binding.Credential);
        ArgumentNullException.ThrowIfNull(binding.CredentialSource);
        ArgumentNullException.ThrowIfNull(binding.ServerAuthority);
        ArgumentNullException.ThrowIfNull(binding.IsCurrent);
        ArgumentNullException.ThrowIfNull(binding.UtcNow);
        var profile = binding.Profile;
        var credential = binding.Credential;
        if (!InfrastructureViewerRuntimeContract.IsWellFormed(profile) ||
            !string.Equals(
                profile.PublicationGroupId,
                CurrentInfrastructureModeProfile.PublicationGroupId.Value,
                StringComparison.Ordinal) ||
            !string.Equals(
                profile.DeploymentProfileId,
                CurrentInfrastructureModeProfile.ProfileId.Value,
                StringComparison.Ordinal) ||
            !string.Equals(profile.ReleaseId, CurrentEducationalReleaseProfile.ReleaseId, StringComparison.Ordinal) ||
            profile.ProtocolGeneration != CurrentInfrastructureModeProfile.ProtocolGeneration ||
            credential.IdentityKind != InfrastructureIdentityKind.ViewerUser ||
            !string.Equals(credential.IdentityId, profile.ViewerUserId, StringComparison.Ordinal) ||
            !string.Equals(credential.ViewerUserId, profile.ViewerUserId, StringComparison.Ordinal) ||
            !credential.ViewerEnabled ||
            credential.ViewerRole == InfrastructureViewerRole.Unknown ||
            credential.State != InfrastructureCredentialLifecycleState.Active ||
            credential.CredentialEpoch != profile.CredentialEpoch ||
            !string.Equals(
                credential.CertificateProfileOid,
                InfrastructureCertificateProfiles.ViewerClientOid,
                StringComparison.Ordinal) ||
            !string.Equals(credential.ServerUri, profile.ServerUri, StringComparison.OrdinalIgnoreCase) ||
            credential.ProtocolGeneration != profile.ProtocolGeneration ||
            !string.Equals(credential.ReleaseId, profile.ReleaseId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("InfrastructureViewerRuntimeBindingInvalid");
        }
    }
}

/// <summary>
/// Connection-lazy Viewer composition. One exact HttpClient connection performs fresh proof and
/// carries every revision/query/annotation request until expiry, invalidation, or disposal.
/// </summary>
public sealed class InfrastructureViewerRuntimeComposition :
    IInfrastructureCaseWorkspaceClient
{
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions AuthenticationJson = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
        MaxDepth = 32
    };

    private readonly InfrastructureViewerRuntimeBinding _binding;
    private readonly SemaphoreSlim _sessionGate = new(1, 1);
    private AuthenticatedSession? _session;
    private InfrastructureViewerRuntimeSnapshot _snapshot;
    private int _disposed;

    internal InfrastructureViewerRuntimeComposition(InfrastructureViewerRuntimeBinding binding)
    {
        _binding = binding ?? throw new ArgumentNullException(nameof(binding));
        _snapshot = new InfrastructureViewerRuntimeSnapshot(
            InfrastructureViewerRuntimeState.NotConnected,
            new Uri(binding.Profile.ServerUri).Authority,
            binding.Profile.ViewerUserId,
            binding.Profile.CredentialEpoch,
            Guid.Empty,
            DateTime.UnixEpoch,
            string.Empty);
        Dependencies = new InfrastructureCaseWorkspaceFeatureDependencies(
            () => this,
            GetAuthenticatedViewerAsync);
    }

    public InfrastructureCaseWorkspaceFeatureDependencies Dependencies { get; }

    public InfrastructureViewerRuntimeSnapshot Snapshot => Volatile.Read(ref _snapshot) with { };

    public async Task<AuthenticatedInfrastructureViewerContext> GetAuthenticatedViewerAsync(
        CancellationToken cancellationToken)
    {
        var session = await EnsureSessionAsync(cancellationToken).ConfigureAwait(false);
        return session.Viewer with { };
    }

    public Task<InfrastructureCaseRevisionResponse> OpenCaseRevisionAsync(
        InfrastructureCaseRevisionRequest request,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken) =>
        ExecuteAsync(
            (client, token) => client.OpenCaseRevisionAsync(request, grants, token),
            cancellationToken);

    public Task<InfrastructureViewerQueryResponse> QueryAsync(
        InfrastructureViewerQueryRequest request,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken) =>
        ExecuteAsync(
            (client, token) => client.QueryAsync(request, grants, token),
            cancellationToken);

    public Task<InfrastructureAnnotationMutationResponse> MutateAnnotationAsync(
        InfrastructureAnnotationMutationRequest request,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken) =>
        ExecuteAsync(
            (client, token) => client.MutateAnnotationAsync(request, grants, token),
            cancellationToken);

    private async Task<T> ExecuteAsync<T>(
        Func<InfrastructureHttpCaseWorkspaceClient, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        var session = await EnsureSessionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await action(session.WorkspaceClient, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException or HttpRequestException or AuthenticationException)
        {
            await InvalidateAsync(
                    session,
                    "InfrastructureViewerAuthenticatedConnectionRejected")
                .ConfigureAwait(false);
            throw;
        }
    }

    private async Task<AuthenticatedSession> EnsureSessionAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _sessionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            var nowUtc = GetUtcNow();
            if (!_binding.IsCurrent(_binding.Profile, _binding.Credential))
            {
                DisposeSessionUnsafe();
                Publish(InfrastructureViewerRuntimeState.Invalidated, Guid.Empty, DateTime.UnixEpoch,
                    "InfrastructureViewerBindingSuperseded");
                throw new InvalidOperationException("InfrastructureViewerBindingSuperseded");
            }

            if (_session is { } current && current.Viewer.FreshUntilUtc > nowUtc)
            {
                return current;
            }

            DisposeSessionUnsafe();
            Publish(InfrastructureViewerRuntimeState.Authenticating, Guid.Empty, DateTime.UnixEpoch, string.Empty);
            try
            {
                _session = await ConnectAsync(nowUtc, cancellationToken).ConfigureAwait(false);
                Publish(
                    InfrastructureViewerRuntimeState.Authenticated,
                    _session.Viewer.ConnectionGeneration,
                    _session.Viewer.FreshUntilUtc,
                    string.Empty);
                return _session;
            }
            catch (OperationCanceledException)
            {
                Publish(InfrastructureViewerRuntimeState.Invalidated, Guid.Empty, DateTime.UnixEpoch,
                    "InfrastructureViewerAuthenticationCanceled");
                throw;
            }
            catch (Exception exception) when (
                exception is AuthenticationException or HttpRequestException or IOException or
                    InvalidOperationException or CryptographicException)
            {
                Publish(InfrastructureViewerRuntimeState.Invalidated, Guid.Empty, DateTime.UnixEpoch,
                    "InfrastructureViewerAuthenticationRejected");
                throw new InvalidOperationException(
                    "InfrastructureViewerAuthenticationRejected",
                    exception);
            }
        }
        finally
        {
            _sessionGate.Release();
        }
    }

    private async Task<AuthenticatedSession> ConnectAsync(DateTime nowUtc, CancellationToken cancellationToken)
    {
        var profile = _binding.Profile;
        var credential = _binding.Credential;
        var endpoint = new Uri(profile.ServerUri, UriKind.Absolute);
        X509Certificate2? certificate = null;
        HttpClient? client = null;
        try
        {
            certificate = _binding.CredentialSource.ResolveClientCertificate(profile, credential, nowUtc);
            var handler = CreateHandler(certificate, endpoint);
            client = new HttpClient(handler, disposeHandler: true)
            {
                BaseAddress = endpoint,
                DefaultRequestVersion = HttpVersion.Version20,
                DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Timeout = Timeout.InfiniteTimeSpan
            };

            using var setup = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            setup.CancelAfter(InfrastructureHttp2CarrierProtocol.CarrierSetupLifetime);
            var connectionGeneration = Guid.NewGuid();
            var challengeResponse = await SendAuthenticationAsync<InfrastructureHttp2ChallengeRequest,
                    InfrastructureHttp2ChallengeResponse>(
                    client,
                    InfrastructureHttp2CarrierProtocol.ChallengePath,
                    new InfrastructureHttp2ChallengeRequest
                    {
                        IdentityId = credential.IdentityId,
                        ConnectionGeneration = connectionGeneration
                    },
                    setup.Token)
                .ConfigureAwait(false);
            var challenge = challengeResponse.Challenge;
            if (!challengeResponse.Accepted || challenge == null ||
                !string.Equals(challenge.IdentityId, credential.IdentityId, StringComparison.Ordinal) ||
                challenge.ConnectionGeneration != connectionGeneration ||
                challenge.SessionChallenge.Length is < 32 or > 128 ||
                challenge.ExpiresAtUtc.Kind != DateTimeKind.Utc ||
                challenge.ExpiresAtUtc <= GetUtcNow())
            {
                throw new AuthenticationException("InfrastructureViewerChallengeRejected");
            }

            var request = new InfrastructureMutualAuthenticationRequest
            {
                IdentityKind = InfrastructureIdentityKind.ViewerUser,
                IdentityId = credential.IdentityId,
                ViewerUserId = credential.ViewerUserId,
                CredentialEpoch = credential.CredentialEpoch,
                ConnectionGeneration = connectionGeneration,
                CertificateSha256 = credential.CertificateSha256,
                CertificateProfileOid = InfrastructureCertificateProfiles.ViewerClientOid,
                ServerUri = profile.ServerUri,
                ProtocolGeneration = profile.ProtocolGeneration,
                ReleaseId = profile.ReleaseId,
                SessionChallenge = challenge.SessionChallenge.ToArray(),
                ProofCreatedAtUtc = GetUtcNow()
            };
            var proof = WindowsInfrastructureCredentialProof.Sign(request, certificate);
            InfrastructureHttp2AuthenticationResponse authentication;
            try
            {
                authentication = await SendAuthenticationAsync<InfrastructureHttp2AuthenticationRequest,
                        InfrastructureHttp2AuthenticationResponse>(
                        client,
                        InfrastructureHttp2CarrierProtocol.AuthenticationPath,
                        new InfrastructureHttp2AuthenticationRequest
                        {
                            Authentication = request,
                            ProofSignature = proof,
                            CorrelationId = Guid.NewGuid().ToString("N")
                        },
                        setup.Token)
                    .ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(proof);
            }

            var viewer = authentication.AuthenticatedViewer;
            var responseTimeUtc = GetUtcNow();
            if (!authentication.Accepted || viewer == null || authentication.AuthenticatedAgent != null ||
                authentication.CarrierId != Guid.Empty ||
                authentication.ExpiresAtUtc != viewer.FreshUntilUtc ||
                !string.Equals(viewer.ViewerUserId, credential.ViewerUserId, StringComparison.Ordinal) ||
                viewer.Role != credential.ViewerRole ||
                viewer.CredentialEpoch != credential.CredentialEpoch ||
                viewer.ConnectionGeneration != connectionGeneration ||
                viewer.ProtocolGeneration != profile.ProtocolGeneration ||
                !string.Equals(viewer.ReleaseId, profile.ReleaseId, StringComparison.Ordinal) ||
                viewer.AuthenticatedAtUtc.Kind != DateTimeKind.Utc ||
                viewer.FreshUntilUtc.Kind != DateTimeKind.Utc ||
                viewer.AuthenticatedAtUtc > responseTimeUtc + MaximumClockSkew ||
                viewer.FreshUntilUtc <= responseTimeUtc ||
                viewer.FreshUntilUtc > credential.NotAfterUtc)
            {
                throw new AuthenticationException("InfrastructureViewerAuthenticatedContextRejected");
            }

            var workspace = new InfrastructureHttpCaseWorkspaceClient(client, disposeClient: false);
            var session = new AuthenticatedSession(client, certificate, workspace, viewer with { });
            client = null;
            certificate = null;
            return session;
        }
        catch
        {
            client?.Dispose();
            certificate?.Dispose();
            throw;
        }
    }

    private SocketsHttpHandler CreateHandler(X509Certificate2 certificate, Uri endpoint)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = InfrastructureHttp2CarrierProtocol.CarrierSetupLifetime,
            Credentials = null,
            EnableMultipleHttp2Connections = false,
            MaxConnectionsPerServer = 1,
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(90),
            PreAuthenticate = false,
            Proxy = null,
            UseCookies = false,
            UseProxy = false
        };
        handler.SslOptions.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
        handler.SslOptions.AllowRenegotiation = false;
        handler.SslOptions.CertificateRevocationCheckMode = X509RevocationMode.Online;
        handler.SslOptions.ClientCertificates = new X509CertificateCollection { certificate };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, presented, _, _) =>
        {
            if (presented == null)
            {
                return false;
            }

            using var candidate = presented is X509Certificate2 certificate2
                ? X509CertificateLoader.LoadCertificate(certificate2.RawData)
                : X509CertificateLoader.LoadCertificate(presented.GetRawCertData());
            return _binding.ServerAuthority.Validate(candidate, endpoint, GetUtcNow()).IsValid;
        };
        return handler;
    }

    private static async Task<TResponse> SendAuthenticationAsync<TRequest, TResponse>(
        HttpClient client,
        string path,
        TRequest payload,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = JsonContent.Create(payload, options: AuthenticationJson)
        };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
            InfrastructureHttp2CarrierProtocol.AuthenticationContentType);
        using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken)
            .ConfigureAwait(false);
        if (!InfrastructureHttp2CarrierProtocol.IsExactHttp2(response.Version) ||
            response.StatusCode != HttpStatusCode.OK ||
            !string.Equals(
                response.Content.Headers.ContentType?.MediaType,
                InfrastructureHttp2CarrierProtocol.AuthenticationContentType,
                StringComparison.OrdinalIgnoreCase) ||
            response.Content.Headers.ContentLength >
            InfrastructureHttp2CarrierProtocol.MaximumAuthenticationDocumentBytes)
        {
            throw new HttpRequestException("InfrastructureViewerAuthenticationResponseRejected");
        }

        await response.Content.LoadIntoBufferAsync(
                InfrastructureHttp2CarrierProtocol.MaximumAuthenticationDocumentBytes,
                cancellationToken)
            .ConfigureAwait(false);
        return await response.Content.ReadFromJsonAsync<TResponse>(AuthenticationJson, cancellationToken)
                   .ConfigureAwait(false) ??
               throw new InvalidDataException("InfrastructureViewerAuthenticationResponseMissing");
    }

    private async Task InvalidateAsync(AuthenticatedSession session, string errorCode)
    {
        await _sessionGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (ReferenceEquals(_session, session))
            {
                DisposeSessionUnsafe();
                Publish(
                    InfrastructureViewerRuntimeState.Invalidated,
                    Guid.Empty,
                    DateTime.UnixEpoch,
                    errorCode);
            }
        }
        finally
        {
            _sessionGate.Release();
        }
    }

    private DateTime GetUtcNow()
    {
        var nowUtc = _binding.UtcNow();
        if (nowUtc.Kind != DateTimeKind.Utc)
        {
            throw new InvalidOperationException("InfrastructureViewerClockMustBeUtc");
        }
        return nowUtc;
    }

    private void Publish(
        InfrastructureViewerRuntimeState state,
        Guid connectionGeneration,
        DateTime freshUntilUtc,
        string errorCode) =>
        Volatile.Write(
            ref _snapshot,
            new InfrastructureViewerRuntimeSnapshot(
                state,
                new Uri(_binding.Profile.ServerUri).Authority,
                _binding.Profile.ViewerUserId,
                _binding.Profile.CredentialEpoch,
                connectionGeneration,
                freshUntilUtc,
                errorCode));

    private void DisposeSessionUnsafe()
    {
        var session = _session;
        _session = null;
        session?.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _sessionGate.WaitAsync().ConfigureAwait(false);
        try
        {
            DisposeSessionUnsafe();
            Publish(
                InfrastructureViewerRuntimeState.Disposed,
                Guid.Empty,
                DateTime.UnixEpoch,
                string.Empty);
        }
        finally
        {
            _sessionGate.Release();
            _sessionGate.Dispose();
        }
    }

    private sealed class AuthenticatedSession : IDisposable
    {
        private readonly HttpClient _client;
        private readonly X509Certificate2 _certificate;
        private int _disposed;

        public AuthenticatedSession(
            HttpClient client,
            X509Certificate2 certificate,
            InfrastructureHttpCaseWorkspaceClient workspaceClient,
            AuthenticatedInfrastructureViewerContext viewer)
        {
            _client = client;
            _certificate = certificate;
            WorkspaceClient = workspaceClient;
            Viewer = viewer;
        }

        public InfrastructureHttpCaseWorkspaceClient WorkspaceClient { get; }

        public AuthenticatedInfrastructureViewerContext Viewer { get; }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            WorkspaceClient.DisposeAsync().AsTask().GetAwaiter().GetResult();
            _client.Dispose();
            _certificate.Dispose();
        }
    }
}
