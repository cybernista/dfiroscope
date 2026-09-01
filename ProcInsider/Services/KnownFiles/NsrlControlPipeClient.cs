using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services.KnownFiles;

public sealed class NsrlControlPipeClient : INsrlControlClient
{
    private const int MaxResponseBytes = 1024 * 1024;
    private const int MaxRequestBytes = 64 * 1024;
    private static readonly string ExpectedServerReleaseId =
        typeof(NsrlControlPipeClient).Assembly.GetName().Version?.ToString() ?? "0.0.0.0";
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();
    private readonly HttpClient _httpClient;

    public NsrlControlPipeClient(HttpMessageHandler? handler = null)
    {
        _httpClient = handler is null
            ? new HttpClient(new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseProxy = false,
                AutomaticDecompression = DecompressionMethods.None,
                MaxConnectionsPerServer = 2
            }, disposeHandler: true)
            : new HttpClient(handler, disposeHandler: true);
        _httpClient.Timeout = TimeSpan.FromSeconds(10);
    }

    public async Task<NsrlServerInfo> GetInfoAsync(Uri endpoint, CancellationToken cancellationToken)
    {
        ValidateEndpoint(endpoint);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(endpoint, "info"));
        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
        {
            throw new InvalidDataException("The managed NSRL info response exceeds its byte limit.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var info = await JsonSerializer.DeserializeAsync<NsrlServerInfo>(
            new BoundedReadStream(stream, MaxResponseBytes),
            JsonOptions,
            cancellationToken).ConfigureAwait(false);
        return info ?? throw new InvalidDataException("The managed NSRL info response was empty.");
    }

    public async Task<NsrlControlResponse> SendAuthenticatedAsync(
        string pipeName,
        NsrlServerInfo expectedServer,
        NsrlControlRequest request,
        CancellationToken cancellationToken)
    {
        ValidatePipeName(pipeName);
        ValidateServerInfo(expectedServer);
        var challengeRequest = new NsrlControlRequest
        {
            RequestId = Guid.NewGuid().ToString("N"),
            ControlGeneration = expectedServer.ControlGeneration,
            Command = NsrlControlCommand.Challenge
        };
        var challenge = await SendAsync(pipeName, challengeRequest, cancellationToken).ConfigureAwait(false);
        if (!challenge.Succeeded || challenge.Challenge.Length != 64 || !challenge.Challenge.All(Uri.IsHexDigit))
        {
            throw new InvalidDataException("The managed NSRL control endpoint did not return a valid fresh challenge.");
        }

        var authenticated = new NsrlControlRequest
        {
            RequestId = string.IsNullOrWhiteSpace(request.RequestId) ? Guid.NewGuid().ToString("N") : request.RequestId,
            ControlGeneration = expectedServer.ControlGeneration,
            ChallengeProof = challenge.Challenge,
            Command = request.Command,
            ExpectedActiveGenerationId = request.ExpectedActiveGenerationId,
            ExpectedOperationId = request.ExpectedOperationId,
            ExpectedReleaseId = request.ExpectedReleaseId
        };
        var response = await SendAsync(pipeName, authenticated, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(response.RequestId, authenticated.RequestId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The managed NSRL control response request identity did not match.");
        }

        if (response.Server is not null)
        {
            ValidateServerInfo(response.Server);
            if (response.Server.ProcessId != expectedServer.ProcessId ||
                response.Server.ProcessStartUtc != expectedServer.ProcessStartUtc ||
                !string.Equals(response.Server.ControlGeneration, expectedServer.ControlGeneration, StringComparison.Ordinal))
            {
                throw new InvalidDataException("The managed NSRL control response came from a replaced server identity.");
            }
        }

        return response;
    }

    public void Dispose() => _httpClient.Dispose();

    private static async Task<NsrlControlResponse> SendAsync(
        string pipeName,
        NsrlControlRequest request,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);
        if (payload.Length is <= 0 or > MaxRequestBytes)
        {
            throw new InvalidDataException("The managed NSRL control request is empty or oversized.");
        }

        await using var pipe = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(5000, cancellationToken).ConfigureAwait(false);
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await pipe.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await pipe.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await pipe.FlushAsync(cancellationToken).ConfigureAwait(false);
        await pipe.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > MaxResponseBytes)
        {
            throw new InvalidDataException("The managed NSRL control response is empty or oversized.");
        }

        var responseBytes = new byte[length];
        await pipe.ReadExactlyAsync(responseBytes, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<NsrlControlResponse>(responseBytes, JsonOptions)
            ?? throw new InvalidDataException("The managed NSRL control response was empty.");
    }

    private static void ValidateEndpoint(Uri endpoint)
    {
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttp ||
            !IPAddress.TryParse(endpoint.Host, out var address) || !IPAddress.IsLoopback(address) ||
            !string.IsNullOrEmpty(endpoint.UserInfo) || !string.IsNullOrEmpty(endpoint.Query) ||
            !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new InvalidDataException("Managed NSRL lifecycle requires an absolute numeric loopback HTTP endpoint.");
        }
    }

    private static void ValidateServerInfo(NsrlServerInfo info)
    {
        if (info.SchemaVersion != NsrlServerProtocol.SchemaVersion ||
            !string.Equals(info.CompatibilityVersion, NsrlServerProtocol.CompatibilityVersion, StringComparison.Ordinal) ||
            !string.Equals(info.ProviderVersion, NsrlServerProtocol.ProviderVersion, StringComparison.Ordinal) ||
            !string.Equals(info.ServerReleaseId, ExpectedServerReleaseId, StringComparison.Ordinal) ||
            info.ProcessId <= 0 || info.ProcessStartUtc == default ||
            info.ControlGeneration.Length != 32 || !info.ControlGeneration.All(Uri.IsHexDigit))
        {
            throw new InvalidDataException("The managed NSRL server identity or protocol is incompatible.");
        }
    }

    private static void ValidatePipeName(string pipeName)
    {
        if (string.IsNullOrWhiteSpace(pipeName) || pipeName.Length > 128 ||
            pipeName.Any(character => !(char.IsLetterOrDigit(character) || character is '.' or '_' or '-')))
        {
            throw new InvalidDataException("The managed NSRL control pipe name is invalid.");
        }
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            MaxDepth = 32
        };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    private sealed class BoundedReadStream(Stream inner, long maximumBytes) : Stream
    {
        private long _read;
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => _read; set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var remaining = maximumBytes - _read;
            if (remaining <= 0)
            {
                var probe = new byte[1];
                var extra = await inner.ReadAsync(probe, cancellationToken).ConfigureAwait(false);
                if (extra == 0)
                {
                    return 0;
                }

                throw new InvalidDataException("The managed NSRL response exceeds its byte limit.");
            }

            var read = await inner.ReadAsync(buffer[..(int)Math.Min(buffer.Length, remaining)], cancellationToken).ConfigureAwait(false);
            _read += read;
            return read;
        }
    }
}
