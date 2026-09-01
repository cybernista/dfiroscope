using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Channels;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.Infrastructure;
using Contracts = ProcInsider.Models.Infrastructure.InfrastructureConfigurationContracts;

namespace ProcInsider.Agent;

/// <summary>
/// Concrete outbound-only Agent carrier. One exact mTLS HTTP/2 connection performs the
/// fresh proof and owns two separately typed streaming requests.
/// </summary>
internal sealed class AgentInfrastructureHttp2Connector : IAgentInfrastructureGrpcConnector
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly IInfrastructureAgentCredentialSource _credentials;
    private readonly IInfrastructureAgentServerCertificateAuthority _serverAuthority;
    private readonly InfrastructureAgentCredentialBinding _binding;

    public AgentInfrastructureHttp2Connector(
        IInfrastructureAgentCredentialSource credentials,
        IInfrastructureAgentServerCertificateAuthority serverAuthority,
        InfrastructureAgentCredentialBinding binding)
    {
        _credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        _serverAuthority = serverAuthority ?? throw new ArgumentNullException(nameof(serverAuthority));
        _binding = binding ?? throw new ArgumentNullException(nameof(binding));
    }

    public async Task<AgentInfrastructureAuthenticatedTransport> ConnectAsync(
        Contracts.InfrastructureAgentConfiguration configuration,
        Guid connectionGeneration,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (connectionGeneration == Guid.Empty || configuration.ServerEndpoints.Count == 0 ||
            !Uri.TryCreate(configuration.ServerEndpoints[0].Uri, UriKind.Absolute, out var endpoint) ||
            !string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The exact Infrastructure endpoint or connection generation is invalid.");
        }

        var certificate = _credentials.ResolveClientCertificate(configuration, _binding);
        ValidateCredentialBinding(configuration, certificate, DateTime.UtcNow);
        HttpClient? client = null;
        try
        {
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
            var challengeResponse = await SendAuthenticationAsync<InfrastructureHttp2ChallengeRequest,
                    InfrastructureHttp2ChallengeResponse>(
                    client,
                    InfrastructureHttp2CarrierProtocol.ChallengePath,
                    new InfrastructureHttp2ChallengeRequest
                    {
                        IdentityId = _binding.Credential.IdentityId,
                        ConnectionGeneration = connectionGeneration
                    },
                    setup.Token)
                .ConfigureAwait(false);
            var challenge = challengeResponse.Challenge;
            if (!challengeResponse.Accepted || challenge == null ||
                !string.Equals(challenge.IdentityId, _binding.Credential.IdentityId, StringComparison.Ordinal) ||
                challenge.ConnectionGeneration != connectionGeneration ||
                challenge.SessionChallenge.Length is < 32 or > 128 ||
                challenge.ExpiresAtUtc.Kind != DateTimeKind.Utc || challenge.ExpiresAtUtc < DateTime.UtcNow)
            {
                throw new AuthenticationException("The Server authentication challenge was rejected or mismatched.");
            }

            var request = CreateAuthenticationRequest(configuration, certificate, challenge, connectionGeneration);
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
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(proof);
            }

            if (!authentication.Accepted || authentication.AuthenticatedAgent == null ||
                authentication.CarrierId == Guid.Empty ||
                authentication.ExpiresAtUtc.Kind != DateTimeKind.Utc ||
                authentication.ExpiresAtUtc < DateTime.UtcNow ||
                authentication.AuthenticatedAgent.ConnectionGeneration != connectionGeneration)
            {
                throw new AuthenticationException("The Server did not return one exact authenticated carrier binding.");
            }

            var controlStream = OpenStream(
                client,
                InfrastructureHttp2CarrierProtocol.ControlPath,
                authentication.CarrierId,
                connectionGeneration,
                setup.Token);
            var evidenceStream = OpenStream(
                client,
                InfrastructureHttp2CarrierProtocol.EvidencePath,
                authentication.CarrierId,
                connectionGeneration,
                setup.Token);

            var lifetime = new AgentInfrastructureHttp2Lifetime(client, certificate);
            client = null;
            certificate = null!;
            return new AgentInfrastructureAuthenticatedTransport(
                authentication.AuthenticatedAgent,
                controlStream,
                evidenceStream,
                lifetime);
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
            return _serverAuthority.Validate(candidate, endpoint, DateTime.UtcNow).IsValid;
        };
        return handler;
    }

    private void ValidateCredentialBinding(
        Contracts.InfrastructureAgentConfiguration configuration,
        X509Certificate2 certificate,
        DateTime nowUtc)
    {
        var credential = _binding.Credential;
        if (nowUtc.Kind != DateTimeKind.Utc || credential.IdentityKind != InfrastructureIdentityKind.AgentService ||
            string.IsNullOrWhiteSpace(credential.IdentityId) || credential.CredentialEpoch <= 0 ||
            credential.State != InfrastructureCredentialLifecycleState.Active ||
            !string.Equals(credential.AgentId, configuration.AgentId, StringComparison.Ordinal) ||
            !string.Equals(credential.HostId, configuration.HostId, StringComparison.Ordinal) ||
            !string.Equals(credential.ServerUri, configuration.ServerEndpoints[0].Uri,
                StringComparison.OrdinalIgnoreCase) ||
            credential.ProtocolGeneration != configuration.ProtocolGeneration ||
            !string.Equals(credential.ReleaseId, configuration.ReleaseId, StringComparison.Ordinal) ||
            !string.Equals(
                credential.CertificateProfileOid,
                InfrastructureCertificateProfiles.AgentClientOid,
                StringComparison.Ordinal) ||
            !string.Equals(
                certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256),
                credential.CertificateSha256,
                StringComparison.OrdinalIgnoreCase) ||
            credential.NotBeforeUtc.Kind != DateTimeKind.Utc || credential.NotAfterUtc.Kind != DateTimeKind.Utc ||
            nowUtc + TimeSpan.FromMinutes(5) < credential.NotBeforeUtc || nowUtc > credential.NotAfterUtc)
        {
            throw new AuthenticationException("The protected Agent credential metadata does not match the exact endpoint binding.");
        }

        var contextShape = new AuthenticatedAgentContext
        {
            AgentId = credential.AgentId,
            HostId = credential.HostId,
            AuthenticationKind = AgentAuthenticationKind.EnrolledWindowsService,
            EnrollmentState = AgentEnrollmentState.Active,
            CredentialEpoch = credential.CredentialEpoch,
            ConnectionGeneration = Guid.NewGuid(),
            ProtocolContractVersion = credential.ProtocolGeneration,
            ReleaseId = credential.ReleaseId,
            ReleaseMatch = AgentReleaseProfileMatch.Match,
            AuthenticatedAtUtc = nowUtc,
            FreshUntilUtc = Min(credential.NotAfterUtc, nowUtc + TimeSpan.FromMinutes(5)),
            CommandCapabilities = Array.AsReadOnly(_binding.CommandCapabilities.Distinct().ToArray()),
            Scope = _binding.Scope with { },
            IsAuthoritativeEvidenceWriter = true
        };
        if (!AgentAuthenticationPolicy.IsValidContext(contextShape))
        {
            throw new AuthenticationException("The local Agent scope or command-capability binding is malformed.");
        }
    }

    private static DateTime Min(DateTime left, DateTime right) => left <= right ? left : right;

    private InfrastructureMutualAuthenticationRequest CreateAuthenticationRequest(
        Contracts.InfrastructureAgentConfiguration configuration,
        X509Certificate2 certificate,
        InfrastructureAuthenticationChallenge challenge,
        Guid connectionGeneration)
    {
        var credential = _binding.Credential;
        if (!string.Equals(
                certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256),
                credential.CertificateSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new AuthenticationException("The selected certificate does not match the credential epoch.");
        }

        return new InfrastructureMutualAuthenticationRequest
        {
            IdentityKind = InfrastructureIdentityKind.AgentService,
            IdentityId = credential.IdentityId,
            AgentId = configuration.AgentId,
            HostId = configuration.HostId,
            CredentialEpoch = credential.CredentialEpoch,
            ConnectionGeneration = connectionGeneration,
            CertificateSha256 = credential.CertificateSha256,
            CertificateProfileOid = InfrastructureCertificateProfiles.AgentClientOid,
            ServerUri = configuration.ServerEndpoints[0].Uri,
            ProtocolGeneration = configuration.ProtocolGeneration,
            ReleaseId = configuration.ReleaseId,
            SessionChallenge = challenge.SessionChallenge.ToArray(),
            ProofCreatedAtUtc = DateTime.UtcNow,
            AgentScope = _binding.Scope with { },
            AgentCommandCapabilities = Array.AsReadOnly(_binding.CommandCapabilities.Distinct().ToArray())
        };
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
            Content = JsonContent.Create(payload, options: JsonOptions)
        };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
            InfrastructureHttp2CarrierProtocol.AuthenticationContentType);
        using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken)
            .ConfigureAwait(false);
        EnsureExactResponse(response, InfrastructureHttp2CarrierProtocol.AuthenticationContentType);
        if (response.Content.Headers.ContentLength > InfrastructureHttp2CarrierProtocol.MaximumAuthenticationDocumentBytes)
        {
            throw new InvalidDataException("The authentication response exceeded its compiled ceiling.");
        }

        await response.Content.LoadIntoBufferAsync(
                InfrastructureHttp2CarrierProtocol.MaximumAuthenticationDocumentBytes,
                cancellationToken)
            .ConfigureAwait(false);
        return await response.Content.ReadFromJsonAsync<TResponse>(JsonOptions, cancellationToken)
                   .ConfigureAwait(false) ??
               throw new InvalidDataException("The authentication response was empty or malformed.");
    }

    private static Stream OpenStream(
        HttpClient client,
        string path,
        Guid carrierId,
        Guid connectionGeneration,
        CancellationToken cancellationToken)
    {
        var upload = new BoundedChannelHttpContent();
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = upload
        };
        request.Headers.TryAddWithoutValidation(InfrastructureHttp2CarrierProtocol.CarrierIdHeader,
            carrierId.ToString("D"));
        request.Headers.TryAddWithoutValidation(InfrastructureHttp2CarrierProtocol.ConnectionGenerationHeader,
            connectionGeneration.ToString("D"));
        request.Headers.TE.Add(new TransferCodingWithQualityHeaderValue("trailers"));
        var response = client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        return new AgentInfrastructureDeferredHttp2DuplexStream(upload, request, response);
    }

    private static void EnsureExactResponse(HttpResponseMessage response, string contentType)
    {
        if (!InfrastructureHttp2CarrierProtocol.IsExactHttp2(response.Version) ||
            response.StatusCode != HttpStatusCode.OK ||
            !string.Equals(response.Content.Headers.ContentType?.MediaType, contentType,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new HttpRequestException("The Server response was not exact HTTP/2 with the required content type.");
        }
    }
}

internal sealed class BoundedChannelHttpContent : HttpContent
{
    private readonly Channel<byte[]> _chunks = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(8)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
        SingleWriter = false
    });

    public BoundedChannelHttpContent()
    {
        Headers.ContentType = MediaTypeHeaderValue.Parse(InfrastructureHttp2CarrierProtocol.GrpcContentType);
        _chunks.Writer.TryWrite(Array.Empty<byte>());
    }

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override async Task SerializeToStreamAsync(
        Stream stream,
        TransportContext? context,
        CancellationToken cancellationToken)
    {
        await foreach (var chunk in _chunks.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            await stream.WriteAsync(chunk, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public Stream CreateWriter() => new ChannelWriteStream(_chunks.Writer);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _chunks.Writer.TryComplete();
        }
        base.Dispose(disposing);
    }
}

internal sealed class ChannelWriteStream : Stream
{
    private readonly ChannelWriter<byte[]> _writer;
    private int _closed;

    public ChannelWriteStream(ChannelWriter<byte[]> writer) =>
        _writer = writer ?? throw new ArgumentNullException(nameof(writer));

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => Volatile.Read(ref _closed) == 0;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        if (!CanWrite)
        {
            throw new ObjectDisposedException(nameof(ChannelWriteStream));
        }
        await _writer.WriteAsync(buffer.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _closed, 1) == 0)
        {
            _writer.TryComplete();
        }
        base.Dispose(disposing);
    }

    public override ValueTask DisposeAsync()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }
}

internal sealed class AgentInfrastructureDeferredHttp2DuplexStream : Stream
{
    private readonly BoundedChannelHttpContent _upload;
    private readonly HttpRequestMessage _request;
    private readonly Task<HttpResponseMessage> _responseTask;
    private readonly Stream _writer;
    private HttpResponseMessage? _response;
    private Stream? _download;
    private int _disposed;
    private bool _trailersVerified;

    public AgentInfrastructureDeferredHttp2DuplexStream(
        BoundedChannelHttpContent upload,
        HttpRequestMessage request,
        Task<HttpResponseMessage> responseTask)
    {
        _upload = upload;
        _request = request;
        _responseTask = responseTask;
        _writer = upload.CreateWriter();
    }

    public override bool CanRead => Volatile.Read(ref _disposed) == 0;
    public override bool CanSeek => false;
    public override bool CanWrite => _writer.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => _writer.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _writer.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => _writer.Write(buffer, offset, count);

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        var download = await GetDownloadAsync(cancellationToken).ConfigureAwait(false);
        var read = await download.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (read == 0 && !_trailersVerified)
        {
            _trailersVerified = true;
            if (!_response!.TrailingHeaders.TryGetValues(
                    InfrastructureHttp2CarrierProtocol.GrpcStatusTrailer,
                    out var values) || values.SingleOrDefault() != "0")
            {
                throw new InvalidDataException("The gRPC stream ended without one successful status trailer.");
            }
        }
        return read;
    }

    private async Task<Stream> GetDownloadAsync(CancellationToken cancellationToken)
    {
        if (_download != null)
        {
            return _download;
        }

        var response = await _responseTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (!InfrastructureHttp2CarrierProtocol.IsExactHttp2(response.Version) ||
            response.StatusCode != HttpStatusCode.OK ||
            !string.Equals(
                response.Content.Headers.ContentType?.MediaType,
                InfrastructureHttp2CarrierProtocol.GrpcContentType,
                StringComparison.OrdinalIgnoreCase))
        {
            response.Dispose();
            throw new HttpRequestException("The gRPC stream response was not exact HTTP/2.");
        }

        _response = response;
        _download = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        return _download;
    }

    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default) =>
        _writer.WriteAsync(buffer, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _writer.Dispose();
            _download?.Dispose();
            _response?.Dispose();
            _request.Dispose();
            _upload.Dispose();
            if (!_responseTask.IsCompleted)
            {
                _ = _responseTask.ContinueWith(
                    completed =>
                    {
                        if (completed.Status == TaskStatus.RanToCompletion)
                        {
                            completed.Result.Dispose();
                        }
                        _ = completed.Exception;
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            await _writer.DisposeAsync().ConfigureAwait(false);
            if (_download != null)
            {
                await _download.DisposeAsync().ConfigureAwait(false);
            }
            _response?.Dispose();
            _request.Dispose();
            _upload.Dispose();
            if (!_responseTask.IsCompleted)
            {
                _ = _responseTask.ContinueWith(
                    completed =>
                    {
                        if (completed.Status == TaskStatus.RanToCompletion)
                        {
                            completed.Result.Dispose();
                        }
                        _ = completed.Exception;
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
        GC.SuppressFinalize(this);
    }
}

internal sealed class AgentInfrastructureHttp2Lifetime : IAsyncDisposable
{
    private readonly HttpClient _client;
    private readonly X509Certificate2 _certificate;

    public AgentInfrastructureHttp2Lifetime(HttpClient client, X509Certificate2 certificate)
    {
        _client = client;
        _certificate = certificate;
    }

    public ValueTask DisposeAsync()
    {
        _client.Dispose();
        _certificate.Dispose();
        return ValueTask.CompletedTask;
    }
}
