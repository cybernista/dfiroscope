using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models.Infrastructure;

namespace ProcInsider.Services.Infrastructure;

public enum InfrastructureSessionFrameOutcome
{
    Success = 0,
    EndOfStream = 1,
    Truncated = 2,
    TooLarge = 3,
    CompressionRejected = 4,
    Malformed = 5
}

public sealed record InfrastructureSessionFrameReadResult<T>(
    InfrastructureSessionFrameOutcome Outcome,
    T? Value,
    string ErrorCode)
    where T : class;

/// <summary>
/// Encodes one bounded application message with the standard five-byte gRPC message prefix.
/// HTTP/2 stream ownership is intentionally outside this dependency-light codec. Compression is
/// rejected at the gRPC prefix. Evidence payload compression is negotiated and bounded inside
/// the typed #339 batch manifest so decompression ratios are checked before authoritative commit.
/// </summary>
public static class InfrastructureSessionFrameCodec
{
    private const int PrefixBytes = 5;
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public static ValueTask WriteNegotiationRequestAsync(
        Stream stream,
        InfrastructureSessionNegotiationRequest request,
        CancellationToken cancellationToken = default) =>
        WriteAsync(stream, request, InfrastructureSessionLimits.CompiledMaximumControlEnvelopeBytes, cancellationToken);

    public static ValueTask WriteNegotiationResponseAsync(
        Stream stream,
        InfrastructureSessionNegotiationResponse response,
        CancellationToken cancellationToken = default) =>
        WriteAsync(stream, response, InfrastructureSessionLimits.CompiledMaximumControlEnvelopeBytes, cancellationToken);

    public static ValueTask WriteEnvelopeAsync(
        Stream stream,
        InfrastructureSessionEnvelope envelope,
        int maximumBytes,
        CancellationToken cancellationToken = default) =>
        WriteAsync(stream, envelope, maximumBytes, cancellationToken);

    public static int MeasureEnvelopeBytes(InfrastructureSessionEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return checked(PrefixBytes + JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions).Length);
    }

    public static ValueTask<InfrastructureSessionFrameReadResult<InfrastructureSessionNegotiationRequest>>
        ReadNegotiationRequestAsync(
            Stream stream,
            CancellationToken cancellationToken = default) =>
        ReadAsync<InfrastructureSessionNegotiationRequest>(
            stream,
            InfrastructureSessionLimits.CompiledMaximumControlEnvelopeBytes,
            cancellationToken);

    public static ValueTask<InfrastructureSessionFrameReadResult<InfrastructureSessionNegotiationResponse>>
        ReadNegotiationResponseAsync(
            Stream stream,
            CancellationToken cancellationToken = default) =>
        ReadAsync<InfrastructureSessionNegotiationResponse>(
            stream,
            InfrastructureSessionLimits.CompiledMaximumControlEnvelopeBytes,
            cancellationToken);

    public static ValueTask<InfrastructureSessionFrameReadResult<InfrastructureSessionEnvelope>> ReadEnvelopeAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken = default) =>
        ReadAsync<InfrastructureSessionEnvelope>(stream, maximumBytes, cancellationToken);

    private static async ValueTask WriteAsync<T>(
        Stream stream,
        T value,
        int maximumBytes,
        CancellationToken cancellationToken)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(value);
        ValidateMaximum(maximumBytes);
        var payload = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        if (payload.Length == 0 || payload.Length > maximumBytes)
        {
            throw new InvalidDataException("The encoded session frame exceeds its compiled plane limit.");
        }

        var prefix = new byte[PrefixBytes];
        BinaryPrimitives.WriteInt32BigEndian(prefix.AsSpan(1), payload.Length);
        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<InfrastructureSessionFrameReadResult<T>> ReadAsync<T>(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(stream);
        ValidateMaximum(maximumBytes);
        var prefix = new byte[PrefixBytes];
        var prefixBytes = await ReadExactAsync(stream, prefix, cancellationToken).ConfigureAwait(false);
        if (prefixBytes == 0)
        {
            return new(InfrastructureSessionFrameOutcome.EndOfStream, null, "FrameEndOfStream");
        }

        if (prefixBytes != PrefixBytes)
        {
            return new(InfrastructureSessionFrameOutcome.Truncated, null, "FramePrefixTruncated");
        }

        if (prefix[0] != 0)
        {
            return new(InfrastructureSessionFrameOutcome.CompressionRejected, null, "FrameCompressionRejected");
        }

        var length = BinaryPrimitives.ReadInt32BigEndian(prefix.AsSpan(1));
        if (length <= 0 || length > maximumBytes)
        {
            return new(InfrastructureSessionFrameOutcome.TooLarge, null, "FrameLengthRejected");
        }

        var payload = new byte[length];
        if (await ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false) != length)
        {
            return new(InfrastructureSessionFrameOutcome.Truncated, null, "FramePayloadTruncated");
        }

        try
        {
            var value = JsonSerializer.Deserialize<T>(payload, JsonOptions);
            return value == null
                ? new(InfrastructureSessionFrameOutcome.Malformed, null, "FramePayloadNull")
                : new(InfrastructureSessionFrameOutcome.Success, value, string.Empty);
        }
        catch (JsonException)
        {
            return new(InfrastructureSessionFrameOutcome.Malformed, null, "FrameJsonMalformed");
        }
    }

    private static async ValueTask<int> ReadExactAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    private static void ValidateMaximum(int maximumBytes)
    {
        if (maximumBytes <= 0 || maximumBytes > InfrastructureSessionLimits.CompiledMaximumEvidenceChunkBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        }
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            AllowDuplicateProperties = false,
            MaxDepth = 32
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false));
        return options;
    }
}
