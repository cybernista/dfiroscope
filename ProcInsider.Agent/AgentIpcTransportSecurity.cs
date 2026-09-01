using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal sealed class AgentIpcTransportPolicy
{
    public const int DefaultMaxConcurrentConnectionsPerEndpoint = 4;
    public const int DefaultMaxRequestBytes = 1024 * 1024;
    public static readonly TimeSpan DefaultRequestReadTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan DefaultResponseWriteTimeout = TimeSpan.FromSeconds(5);

    public static AgentIpcTransportPolicy InteractiveLocal { get; } = new(
        DefaultMaxConcurrentConnectionsPerEndpoint,
        DefaultMaxRequestBytes,
        DefaultRequestReadTimeout,
        DefaultResponseWriteTimeout);

    public AgentIpcTransportPolicy(
        int maxConcurrentConnectionsPerEndpoint,
        int maxRequestBytes,
        TimeSpan requestReadTimeout,
        TimeSpan responseWriteTimeout)
    {
        if (maxConcurrentConnectionsPerEndpoint is < 1 or > 253)
        {
            throw new ArgumentOutOfRangeException(nameof(maxConcurrentConnectionsPerEndpoint));
        }

        if (maxRequestBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxRequestBytes));
        }

        if (requestReadTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(requestReadTimeout));
        }

        if (responseWriteTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(responseWriteTimeout));
        }

        MaxConcurrentConnectionsPerEndpoint = maxConcurrentConnectionsPerEndpoint;
        MaxRequestBytes = maxRequestBytes;
        RequestReadTimeout = requestReadTimeout;
        ResponseWriteTimeout = responseWriteTimeout;
    }

    public int MaxConcurrentConnectionsPerEndpoint { get; }

    public int MaxPipeServerInstances => MaxConcurrentConnectionsPerEndpoint + 1;

    public int MaxRequestBytes { get; }

    public TimeSpan RequestReadTimeout { get; }

    public TimeSpan ResponseWriteTimeout { get; }
}

internal sealed record AgentIpcEndpointDescriptor(string PipeName, bool ShutdownOnly);

internal static class AgentIpcEndpointCatalog
{
    public static IReadOnlyList<AgentIpcEndpointDescriptor> Endpoints { get; } =
    [
        new(AgentContracts.PipeName, ShutdownOnly: false),
        new(AgentContracts.LegacyPipeName, ShutdownOnly: false),
        new(AgentContracts.ShutdownControlPipeName, ShutdownOnly: true),
        new(AgentContracts.LegacyShutdownControlPipeName, ShutdownOnly: true)
    ];
}

internal enum AgentPipeListenerOperationResult
{
    Completed,
    RecoverableConnectionFailure,
    Shutdown
}

internal static class AgentPipeListenerConnectionBoundary
{
    public static async Task<AgentPipeListenerOperationResult> RunAsync(
        Func<CancellationToken, Task> operation,
        CancellationToken cancellationToken,
        Action<IOException> logRecoverableFailure)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(logRecoverableFailure);

        try
        {
            await operation(cancellationToken).ConfigureAwait(false);
            return AgentPipeListenerOperationResult.Completed;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return AgentPipeListenerOperationResult.Shutdown;
        }
        catch (IOException) when (cancellationToken.IsCancellationRequested)
        {
            return AgentPipeListenerOperationResult.Shutdown;
        }
        catch (IOException ex)
        {
            logRecoverableFailure(ex);
            return AgentPipeListenerOperationResult.RecoverableConnectionFailure;
        }
    }
}

internal static class AgentNamedPipeServerStreamFactory
{
    public static NamedPipeServerStream Create(
        string pipeName,
        int maxNumberOfServerInstances)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);

        using var identity = WindowsIdentity.GetCurrent();
        var accountSid = identity.User ??
            throw new InvalidOperationException(
                "The interactive agent account SID is unavailable for named-pipe authorization.");
        return Create(pipeName, maxNumberOfServerInstances, accountSid);
    }

    internal static NamedPipeServerStream Create(
        string pipeName,
        int maxNumberOfServerInstances,
        SecurityIdentifier accountSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        ArgumentNullException.ThrowIfNull(accountSid);

        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            CreateAccountSecurity(accountSid),
            HandleInheritability.None,
            additionalAccessRights: 0);
    }

    internal static PipeSecurity CreateAccountSecurity(SecurityIdentifier accountSid)
    {
        ArgumentNullException.ThrowIfNull(accountSid);

        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(accountSid);
        security.AddAccessRule(new PipeAccessRule(
            accountSid,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        return security;
    }
}

internal readonly record struct AgentPipePrincipalIdentity(string AccountSid, bool IsServiceIdentity);

internal interface IAgentPipeClientIdentitySource
{
    AgentPipePrincipalIdentity GetHostIdentity();

    AgentPipePrincipalIdentity GetConnectedClientIdentity(NamedPipeServerStream pipe);
}

internal sealed class WindowsAgentPipeClientIdentitySource : IAgentPipeClientIdentitySource
{
    public AgentPipePrincipalIdentity GetHostIdentity()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new AgentPipePrincipalIdentity(
            identity.User?.Value ?? string.Empty,
            identity.IsSystem);
    }

    public AgentPipePrincipalIdentity GetConnectedClientIdentity(NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        var accountName = pipe.GetImpersonationUserName();
        if (string.IsNullOrWhiteSpace(accountName))
        {
            return new AgentPipePrincipalIdentity(string.Empty, IsServiceIdentity: false);
        }

        var sid = (SecurityIdentifier)new NTAccount(accountName).Translate(typeof(SecurityIdentifier));
        return new AgentPipePrincipalIdentity(sid.Value, IsServiceIdentity: false);
    }
}

internal readonly record struct AgentPipeAuthorizationResult(bool Allowed, string DiagnosticCode)
{
    public static AgentPipeAuthorizationResult Permit() => new(true, "Allowed");

    public static AgentPipeAuthorizationResult Deny(string diagnosticCode) => new(false, diagnosticCode);
}

internal interface IAgentPipeConnectionAuthorizer
{
    AgentPipeAuthorizationResult Authorize(NamedPipeServerStream pipe);
}

internal sealed class CurrentUserAgentPipeConnectionAuthorizer : IAgentPipeConnectionAuthorizer
{
    private readonly IAgentPipeClientIdentitySource _identitySource;
    private readonly AgentPipePrincipalIdentity _hostIdentity;

    public CurrentUserAgentPipeConnectionAuthorizer(IAgentPipeClientIdentitySource? identitySource = null)
    {
        _identitySource = identitySource ?? new WindowsAgentPipeClientIdentitySource();
        _hostIdentity = _identitySource.GetHostIdentity();
    }

    public AgentPipeAuthorizationResult Authorize(NamedPipeServerStream pipe)
    {
        if (_hostIdentity.IsServiceIdentity)
        {
            return AgentPipeAuthorizationResult.Deny("ServiceHostingUnsupported");
        }

        if (string.IsNullOrWhiteSpace(_hostIdentity.AccountSid))
        {
            return AgentPipeAuthorizationResult.Deny("HostIdentityUnavailable");
        }

        try
        {
            var clientIdentity = _identitySource.GetConnectedClientIdentity(pipe);
            return !string.IsNullOrWhiteSpace(clientIdentity.AccountSid) &&
                   string.Equals(
                       clientIdentity.AccountSid,
                       _hostIdentity.AccountSid,
                       StringComparison.OrdinalIgnoreCase)
                ? AgentPipeAuthorizationResult.Permit()
                : AgentPipeAuthorizationResult.Deny("CallerIdentityMismatch");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   IdentityNotMappedException or InvalidOperationException or
                                   PlatformNotSupportedException)
        {
            return AgentPipeAuthorizationResult.Deny("CallerIdentityUnavailable");
        }
    }
}

internal sealed record AgentIpcDispatchResult(
    AgentIpcResponse Response,
    string? RequestJson,
    string DiagnosticCode);

internal static class AgentIpcRequestDispatcher
{
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public static async Task<AgentIpcDispatchResult> DispatchAsync(
        Stream stream,
        AgentPipeAuthorizationResult authorization,
        AgentIpcTransportPolicy policy,
        Func<string, CancellationToken, Task<AgentIpcResponse>> dispatchRequestAsync,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(dispatchRequestAsync);

        if (!authorization.Allowed)
        {
            return new AgentIpcDispatchResult(
                AgentIpcResponse.Failure(
                    Guid.Empty,
                    "UnauthorizedCaller",
                    "The local agent pipe caller is not authorized for this interactive agent."),
                RequestJson: null,
                authorization.DiagnosticCode);
        }

        AgentIpcRequestReadResult readResult;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeout.CancelAfter(policy.RequestReadTimeout);
            try
            {
                readResult = await ReadBoundedLineAsync(
                    stream,
                    policy.MaxRequestBytes,
                    timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new AgentIpcDispatchResult(
                    AgentIpcResponse.Failure(
                        Guid.Empty,
                        "RequestTimeout",
                        $"The agent pipe did not receive a complete request within {policy.RequestReadTimeout.TotalSeconds:0} seconds."),
                    RequestJson: null,
                    "RequestTimeout");
            }
        }

        if (readResult.Oversized)
        {
            return new AgentIpcDispatchResult(
                AgentIpcResponse.Failure(
                    Guid.Empty,
                    "RequestTooLarge",
                    $"The agent pipe request exceeded the {policy.MaxRequestBytes} byte limit."),
                RequestJson: null,
                "RequestTooLarge");
        }

        if (string.IsNullOrWhiteSpace(readResult.RequestJson))
        {
            return new AgentIpcDispatchResult(
                AgentIpcResponse.Failure(Guid.Empty, "EmptyRequest", "The agent received an empty pipe request."),
                readResult.RequestJson,
                "EmptyRequest");
        }

        var response = await dispatchRequestAsync(readResult.RequestJson, cancellationToken).ConfigureAwait(false);
        return new AgentIpcDispatchResult(response, readResult.RequestJson, "Dispatched");
    }

    private static async Task<AgentIpcRequestReadResult> ReadBoundedLineAsync(
        Stream stream,
        int maxRequestBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[(int)Math.Min(4096L, (long)maxRequestBytes + 1)];
        using var requestBytes = new MemoryStream(Math.Min(4096, maxRequestBytes));

        while (true)
        {
            var remaining = maxRequestBytes - checked((int)requestBytes.Length);
            var readLength = (int)Math.Min(buffer.Length, (long)remaining + 1);
            var bytesRead = await stream.ReadAsync(
                buffer.AsMemory(0, readLength),
                cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }

            var newlineIndex = buffer.AsSpan(0, bytesRead).IndexOf((byte)'\n');
            var payloadLength = newlineIndex >= 0 ? newlineIndex : bytesRead;
            if (requestBytes.Length + payloadLength > maxRequestBytes)
            {
                if (newlineIndex < 0)
                {
                    await DrainToLineEndAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
                }

                return new AgentIpcRequestReadResult(null, Oversized: true);
            }

            requestBytes.Write(buffer, 0, payloadLength);
            if (newlineIndex >= 0)
            {
                break;
            }
        }

        var bytes = requestBytes.ToArray();
        var length = bytes.Length;
        if (length > 0 && bytes[length - 1] == (byte)'\r')
        {
            length--;
        }

        try
        {
            return new AgentIpcRequestReadResult(StrictUtf8.GetString(bytes, 0, length), Oversized: false);
        }
        catch (DecoderFallbackException)
        {
            return new AgentIpcRequestReadResult("{ invalid utf8", Oversized: false);
        }
    }

    private static async Task DrainToLineEndAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var bytesRead = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0 || buffer.AsSpan(0, bytesRead).IndexOf((byte)'\n') >= 0)
            {
                return;
            }
        }
    }

    private readonly record struct AgentIpcRequestReadResult(string? RequestJson, bool Oversized);
}

internal sealed class AgentIpcConnectionLimiter : IDisposable
{
    private readonly SemaphoreSlim _semaphore;
    private int _activeCount;
    private int _peakActiveCount;

    public AgentIpcConnectionLimiter(int maxConcurrentConnections)
    {
        if (maxConcurrentConnections < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxConcurrentConnections));
        }

        MaxConcurrentConnections = maxConcurrentConnections;
        _semaphore = new SemaphoreSlim(maxConcurrentConnections, maxConcurrentConnections);
    }

    public int MaxConcurrentConnections { get; }

    public int ActiveCount => Volatile.Read(ref _activeCount);

    public int PeakActiveCount => Volatile.Read(ref _peakActiveCount);

    public bool TryAcquire(out IDisposable? lease)
    {
        if (!_semaphore.Wait(0))
        {
            lease = null;
            return false;
        }

        var active = Interlocked.Increment(ref _activeCount);
        UpdatePeak(active);
        lease = new Lease(this);
        return true;
    }

    public void Dispose() => _semaphore.Dispose();

    private void Release()
    {
        Interlocked.Decrement(ref _activeCount);
        _semaphore.Release();
    }

    private void UpdatePeak(int active)
    {
        while (true)
        {
            var current = Volatile.Read(ref _peakActiveCount);
            if (active <= current || Interlocked.CompareExchange(ref _peakActiveCount, active, current) == current)
            {
                return;
            }
        }
    }

    private sealed class Lease(AgentIpcConnectionLimiter owner) : IDisposable
    {
        private AgentIpcConnectionLimiter? _owner = owner;

        public void Dispose()
        {
            Interlocked.Exchange(ref _owner, null)?.Release();
        }
    }
}
