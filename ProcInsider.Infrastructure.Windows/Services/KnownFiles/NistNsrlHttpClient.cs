using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace ProcInsider.Services.KnownFiles;

public enum NistNsrlRemoteResourceKind
{
    ReleasePage = 0,
    Distribution = 1
}

public sealed class NistNsrlHttpClient : IDisposable
{
    private const int MaxRedirects = 5;
    private readonly HttpClient _client;
    private readonly bool _disposeClient;

    public NistNsrlHttpClient(HttpMessageHandler handler, bool disposeHandler = false)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _client = new HttpClient(handler, disposeHandler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        _disposeClient = true;
    }

    private NistNsrlHttpClient(HttpClient client)
    {
        _client = client;
        _disposeClient = true;
    }

    public static NistNsrlHttpClient CreateDefault()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(30),
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            MaxConnectionsPerServer = 2
        };
        return new NistNsrlHttpClient(new HttpClient(handler, disposeHandler: true)
        {
            Timeout = Timeout.InfiniteTimeSpan
        });
    }

    public async Task<HttpResponseMessage> SendAsync(
        Uri uri,
        NistNsrlRemoteResourceKind kind,
        long? rangeStart,
        EntityTagHeaderValue? ifRangeEntityTag,
        DateTimeOffset? ifRangeLastModified,
        CancellationToken cancellationToken)
    {
        ValidateUri(uri, kind);
        var current = uri;
        for (var redirect = 0; redirect <= MaxRedirects; redirect++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            request.Headers.UserAgent.ParseAdd("DFIRoscope-NSRL-Catalog/1");
            request.Headers.AcceptEncoding.Clear();
            if (rangeStart is not null)
            {
                request.Headers.Range = new RangeHeaderValue(rangeStart, null);
                request.Headers.IfRange = ifRangeEntityTag is not null
                    ? new RangeConditionHeaderValue(ifRangeEntityTag)
                    : ifRangeLastModified is not null
                        ? new RangeConditionHeaderValue(ifRangeLastModified.Value)
                        : null;
            }

            var response = await _client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (!IsRedirect(response.StatusCode))
            {
                if (response.RequestMessage is null)
                {
                    response.RequestMessage = new HttpRequestMessage(HttpMethod.Get, current);
                }

                var responseUri = response.RequestMessage.RequestUri ?? current;
                ValidateUri(responseUri, kind);
                return response;
            }

            if (redirect == MaxRedirects)
            {
                response.Dispose();
                throw new HttpRequestException("The NIST NSRL request exceeded the redirect limit.");
            }

            var location = response.Headers.Location;
            response.Dispose();
            if (location is null)
            {
                throw new HttpRequestException("The NIST NSRL redirect did not include a destination.");
            }

            current = location.IsAbsoluteUri ? location : new Uri(current, location);
            ValidateUri(current, kind);
        }

        throw new HttpRequestException("The NIST NSRL redirect pipeline did not terminate.");
    }

    public async Task<string> GetBoundedTextAsync(
        Uri uri,
        NistNsrlRemoteResourceKind kind,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        if (maxBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }

        using var response = await SendAsync(
            uri,
            kind,
            rangeStart: null,
            ifRangeEntityTag: null,
            ifRangeLastModified: null,
            cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > maxBytes)
        {
            throw new InvalidDataException("The NIST NSRL support document exceeded its byte limit.");
        }

        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var destination = new MemoryStream(Math.Min(maxBytes, 64 * 1024));
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (destination.Length + read > maxBytes)
            {
                throw new InvalidDataException("The NIST NSRL support document exceeded its byte limit.");
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        return Encoding.UTF8.GetString(destination.ToArray());
    }

    public static void ValidateUri(Uri uri, NistNsrlRemoteResourceKind kind)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !uri.IsDefaultPort ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidDataException("NIST NSRL resources must use credential-free, query-free HTTPS URLs on their default port.");
        }

        var isNistPage =
            (string.Equals(uri.Host, "www.nist.gov", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(uri.Host, "nist.gov", StringComparison.OrdinalIgnoreCase)) &&
            uri.AbsolutePath.StartsWith(
                "/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl/",
                StringComparison.Ordinal);
        var isNistDistribution =
            string.Equals(uri.Host, "s3.amazonaws.com", StringComparison.OrdinalIgnoreCase) &&
            uri.AbsolutePath.StartsWith("/rds.nsrl.nist.gov/RDS/", StringComparison.Ordinal) ||
            string.Equals(uri.Host, "rds.nsrl.nist.gov", StringComparison.OrdinalIgnoreCase) &&
            uri.AbsolutePath.StartsWith("/RDS/", StringComparison.Ordinal);

        if (kind == NistNsrlRemoteResourceKind.ReleasePage ? !isNistPage : !(isNistPage || isNistDistribution))
        {
            throw new InvalidDataException("The NIST NSRL resource escaped the approved publication/distribution hosts.");
        }
    }

    public void Dispose()
    {
        if (_disposeClient)
        {
            _client.Dispose();
        }
    }

    private static bool IsRedirect(HttpStatusCode statusCode)
        => statusCode is HttpStatusCode.Moved or
            HttpStatusCode.Redirect or
            HttpStatusCode.RedirectMethod or
            HttpStatusCode.TemporaryRedirect or
            HttpStatusCode.PermanentRedirect;
}
