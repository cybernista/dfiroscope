using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models.Infrastructure;

namespace ProcInsider.Services;

/// <summary>
/// Concrete Viewer-to-Server HTTP/2 adapter. The package supplies an already configured
/// mutually authenticated HttpClient. Viewer identity and grants are never serialized; the
/// Server reconstructs them from its authenticated connection and authorization store.
/// </summary>
public sealed class InfrastructureHttpCaseWorkspaceClient : IInfrastructureCaseWorkspaceClient
{
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();
    private readonly HttpClient _httpClient;
    private readonly bool _disposeClient;
    private bool _disposed;

    public InfrastructureHttpCaseWorkspaceClient(HttpClient httpClient, bool disposeClient = false)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        if (_httpClient.BaseAddress is not { IsAbsoluteUri: true } baseAddress ||
            !string.Equals(baseAddress.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "InfrastructureHttpClientRequiresHttpsBaseAddress", nameof(httpClient));
        }

        _disposeClient = disposeClient;
    }

    public Task<InfrastructureCaseRevisionResponse> OpenCaseRevisionAsync(
        InfrastructureCaseRevisionRequest request,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(grants);
        return PostAsync<InfrastructureCaseRevisionWireRequest, InfrastructureCaseRevisionResponse>(
            InfrastructureViewerTransportContract.OpenCaseRevisionPath,
            new InfrastructureCaseRevisionWireRequest
            {
                CaseId = request.CaseId,
                WorkspaceGeneration = request.WorkspaceGeneration,
                RequestGeneration = request.RequestGeneration,
                ExpectedReleaseId = request.ExpectedReleaseId,
                ExpectedProtocolGeneration = request.ExpectedProtocolGeneration
            },
            cancellationToken);
    }

    public Task<InfrastructureViewerQueryResponse> QueryAsync(
        InfrastructureViewerQueryRequest request,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(grants);
        return PostAsync<InfrastructureViewerQueryWireRequest, InfrastructureViewerQueryResponse>(
            InfrastructureViewerTransportContract.QueryPath,
            new InfrastructureViewerQueryWireRequest
            {
                Revision = request.Revision,
                Scope = request.Scope,
                Kind = request.Kind,
                SearchText = request.SearchText,
                FilterExpression = request.FilterExpression,
                SortField = request.SortField,
                SortDirection = request.SortDirection,
                ContinuationToken = request.ContinuationToken,
                MaximumRows = request.MaximumRows,
                WorkspaceGeneration = request.WorkspaceGeneration,
                RequestGeneration = request.RequestGeneration,
                ExpectedReleaseId = request.ExpectedReleaseId,
                ExpectedProtocolGeneration = request.ExpectedProtocolGeneration
            },
            cancellationToken);
    }

    public Task<InfrastructureAnnotationMutationResponse> MutateAnnotationAsync(
        InfrastructureAnnotationMutationRequest request,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(grants);
        return PostAsync<InfrastructureAnnotationMutationWireRequest, InfrastructureAnnotationMutationResponse>(
            InfrastructureViewerTransportContract.AnnotationPath,
            new InfrastructureAnnotationMutationWireRequest
            {
                Revision = request.Revision,
                Kind = request.Kind,
                AnnotationId = request.AnnotationId,
                TargetIdentity = request.TargetIdentity,
                BodyJson = request.BodyJson,
                ExpectedAnnotationRevision = request.ExpectedAnnotationRevision,
                WorkspaceGeneration = request.WorkspaceGeneration,
                RequestGeneration = request.RequestGeneration,
                ExpectedReleaseId = request.ExpectedReleaseId,
                ExpectedProtocolGeneration = request.ExpectedProtocolGeneration
            },
            cancellationToken);
    }

    private async Task<TResponse> PostAsync<TRequest, TResponse>(
        string path,
        TRequest payload,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var message = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions))
        };
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
        {
            CharSet = "utf-8"
        };
        using var response = await _httpClient.SendAsync(
                message,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken)
            .ConfigureAwait(false);
        if (response.Version.Major != 2 || response.StatusCode != HttpStatusCode.OK)
        {
            throw new HttpRequestException(
                "InfrastructureViewerHttp2ResponseRejected",
                inner: null,
                response.StatusCode);
        }

        if (response.Content.Headers.ContentLength is > InfrastructureViewerTransportContract.MaximumResponseBytes)
        {
            throw new InvalidDataException("InfrastructureViewerResponseBoundsExceeded");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            if (bounded.Length + read > InfrastructureViewerTransportContract.MaximumResponseBytes)
            {
                throw new InvalidDataException("InfrastructureViewerResponseBoundsExceeded");
            }
            bounded.Write(buffer, 0, read);
        }

        return JsonSerializer.Deserialize<TResponse>(bounded.GetBuffer().AsSpan(0, checked((int)bounded.Length)), JsonOptions)
               ?? throw new InvalidDataException("InfrastructureViewerResponseMissing");
    }

    public ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return ValueTask.CompletedTask;
        }
        _disposed = true;
        if (_disposeClient)
        {
            _httpClient.Dispose();
        }
        return ValueTask.CompletedTask;
    }

    internal static JsonSerializerOptions CreateJsonOptions() => new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
        MaxDepth = 32
    };
}
