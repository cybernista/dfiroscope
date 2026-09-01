using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services.KnownFiles;

public sealed record NsrlDownloadReceipt(
    string PartialPath,
    Uri FinalUri,
    long Length,
    bool Resumed,
    string EntityTag,
    DateTimeOffset? LastModified);

public sealed class NsrlResumableDownloader
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly NistNsrlHttpClient _http;
    private readonly NsrlCatalogPathService _paths;
    private readonly NsrlCatalogAcquisitionOptions _options;

    public NsrlResumableDownloader(
        NistNsrlHttpClient http,
        NsrlCatalogPathService paths,
        NsrlCatalogAcquisitionOptions options)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task<NsrlDownloadReceipt> DownloadAsync(
        NsrlReleaseDescriptor release,
        bool allowResume,
        IProgress<NsrlCatalogAcquisitionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var releaseKey = BuildReleaseKey(release);
        var partialPath = _paths.GetPartialArchivePath(releaseKey);
        var metadataPath = _paths.GetResumeMetadataPath(releaseKey);
        Directory.CreateDirectory(_paths.DownloadsRoot);

        Exception? lastFailure = null;
        for (var attempt = 1; attempt <= _options.MaxDownloadAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await DownloadAttemptAsync(
                    release,
                    partialPath,
                    metadataPath,
                    allowResume,
                    progress,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or TimeoutException)
            {
                lastFailure = ex;
                if (attempt == _options.MaxDownloadAttempts)
                {
                    break;
                }
            }
        }

        throw new IOException("The bounded NIST NSRL download attempts were exhausted.", lastFailure);
    }

    private async Task<NsrlDownloadReceipt> DownloadAttemptAsync(
        NsrlReleaseDescriptor release,
        string partialPath,
        string metadataPath,
        bool allowResume,
        IProgress<NsrlCatalogAcquisitionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var resume = allowResume ? TryReadResumeMetadata(metadataPath, partialPath, release) : null;
        var existingLength = resume is null ? 0L : new FileInfo(partialPath).Length;
        using var response = await _http.SendAsync(
            release.ArchiveUri,
            NistNsrlRemoteResourceKind.Distribution,
            resume is null ? null : existingLength,
            ParseEntityTag(resume?.EntityTag),
            resume?.LastModified,
            cancellationToken).ConfigureAwait(false);

        var append = resume is not null && IsValidResumeResponse(response, resume, existingLength);
        if (resume is not null && !append)
        {
            response.Dispose();
            DeleteCandidate(partialPath);
            DeleteCandidate(metadataPath);
            return await DownloadFreshAsync(
                release,
                partialPath,
                metadataPath,
                progress,
                cancellationToken).ConfigureAwait(false);
        }

        if (append)
        {
            if (response.StatusCode != HttpStatusCode.PartialContent)
            {
                throw new IOException("The NIST NSRL server did not honor the validated resume range.");
            }
        }
        else if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new HttpRequestException(
                $"The NIST NSRL archive request returned HTTP {(int)response.StatusCode}.",
                null,
                response.StatusCode);
        }

        return await CopyResponseAsync(
            release,
            response,
            partialPath,
            metadataPath,
            append ? existingLength : 0,
            append,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<NsrlDownloadReceipt> DownloadFreshAsync(
        NsrlReleaseDescriptor release,
        string partialPath,
        string metadataPath,
        IProgress<NsrlCatalogAcquisitionProgress>? progress,
        CancellationToken cancellationToken)
    {
        using var response = await _http.SendAsync(
            release.ArchiveUri,
            NistNsrlRemoteResourceKind.Distribution,
            rangeStart: null,
            ifRangeEntityTag: null,
            ifRangeLastModified: null,
            cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new HttpRequestException(
                $"The NIST NSRL archive request returned HTTP {(int)response.StatusCode}.",
                null,
                response.StatusCode);
        }

        return await CopyResponseAsync(
            release,
            response,
            partialPath,
            metadataPath,
            0,
            resumed: false,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<NsrlDownloadReceipt> CopyResponseAsync(
        NsrlReleaseDescriptor release,
        HttpResponseMessage response,
        string partialPath,
        string metadataPath,
        long existingLength,
        bool resumed,
        IProgress<NsrlCatalogAcquisitionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var finalUri = response.RequestMessage?.RequestUri ?? release.ArchiveUri;
        NistNsrlHttpClient.ValidateUri(finalUri, NistNsrlRemoteResourceKind.Distribution);
        var entityTag = response.Headers.ETag?.ToString() ?? string.Empty;
        var lastModified = response.Content.Headers.LastModified;
        var expectedTotal = response.Content.Headers.ContentRange?.Length ??
            (response.Content.Headers.ContentLength is long responseLength
                ? checked(existingLength + responseLength)
                : (long?)null);
        if (expectedTotal > _options.MaxArchiveBytes || existingLength > _options.MaxArchiveBytes)
        {
            throw new InvalidDataException("The NIST NSRL archive exceeds the configured byte limit.");
        }

        var metadata = new ResumeMetadata
        {
            SchemaVersion = ResumeMetadata.CurrentSchemaVersion,
            SourceUri = release.ArchiveUri.AbsoluteUri,
            FinalUri = finalUri.AbsoluteUri,
            ArchiveFileName = release.ArchiveFileName,
            EntityTag = entityTag,
            LastModified = lastModified,
            ExpectedTotalBytes = expectedTotal
        };
        WriteJsonAtomically(metadataPath, metadata);

        await using var destination = new FileStream(
            partialPath,
            resumed ? FileMode.Open : FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            _options.CopyBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough);
        if (resumed)
        {
            destination.Position = existingLength;
        }

        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var buffer = new byte[_options.CopyBufferBytes];
        var completed = existingLength;
        while (true)
        {
            using var stall = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            stall.CancelAfter(_options.ReadStallTimeout);
            int read;
            try
            {
                read = await source.ReadAsync(buffer, stall.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("The NIST NSRL download stopped making progress.");
            }

            if (read == 0)
            {
                break;
            }

            completed = checked(completed + read);
            if (completed > _options.MaxArchiveBytes)
            {
                throw new InvalidDataException("The NIST NSRL archive exceeds the configured byte limit.");
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            progress?.Report(new NsrlCatalogAcquisitionProgress(
                NsrlCatalogAcquisitionPhase.Download,
                resumed ? "Resuming the exact validated NIST archive object." : "Downloading the NIST archive into a contained partial file.",
                completed,
                expectedTotal));
        }

        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        destination.Flush(flushToDisk: true);
        if (expectedTotal is not null && completed != expectedTotal.Value)
        {
            throw new IOException("The NIST NSRL archive transfer ended before the advertised byte count.");
        }

        return new NsrlDownloadReceipt(partialPath, finalUri, completed, resumed, entityTag, lastModified);
    }

    private static bool IsValidResumeResponse(
        HttpResponseMessage response,
        ResumeMetadata metadata,
        long existingLength)
    {
        if (response.StatusCode != HttpStatusCode.PartialContent ||
            response.Content.Headers.ContentRange?.From != existingLength ||
            !string.Equals(
                response.RequestMessage?.RequestUri?.AbsoluteUri,
                metadata.FinalUri,
                StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(metadata.EntityTag))
        {
            return string.Equals(response.Headers.ETag?.ToString(), metadata.EntityTag, StringComparison.Ordinal);
        }

        return metadata.LastModified is not null && response.Content.Headers.LastModified == metadata.LastModified;
    }

    private static EntityTagHeaderValue? ParseEntityTag(string? value)
        => !string.IsNullOrWhiteSpace(value) && EntityTagHeaderValue.TryParse(value, out var entityTag)
            ? entityTag
            : null;

    private static ResumeMetadata? TryReadResumeMetadata(
        string metadataPath,
        string partialPath,
        NsrlReleaseDescriptor release)
    {
        if (!File.Exists(metadataPath) || !File.Exists(partialPath))
        {
            return null;
        }

        try
        {
            var metadata = JsonSerializer.Deserialize<ResumeMetadata>(File.ReadAllText(metadataPath), JsonOptions);
            if (metadata is null ||
                metadata.SchemaVersion != ResumeMetadata.CurrentSchemaVersion ||
                !string.Equals(metadata.SourceUri, release.ArchiveUri.AbsoluteUri, StringComparison.Ordinal) ||
                !string.Equals(metadata.ArchiveFileName, release.ArchiveFileName, StringComparison.Ordinal) ||
                new FileInfo(partialPath).Length <= 0 ||
                new FileInfo(partialPath).Length >= metadata.ExpectedTotalBytes ||
                string.IsNullOrWhiteSpace(metadata.FinalUri) ||
                string.IsNullOrWhiteSpace(metadata.EntityTag) && metadata.LastModified is null)
            {
                return null;
            }

            NistNsrlHttpClient.ValidateUri(new Uri(metadata.FinalUri), NistNsrlRemoteResourceKind.Distribution);
            return metadata;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UriFormatException or InvalidDataException)
        {
            return null;
        }
    }

    private static void WriteJsonAtomically<T>(string path, T value)
    {
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(value, JsonOptions));
        File.Move(temporary, path, overwrite: true);
    }

    private static void DeleteCandidate(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static string BuildReleaseKey(NsrlReleaseDescriptor release)
        => NsrlCatalogPathService.SafeName($"rds-{release.ReleaseId}-{release.DataSet}-{release.Profile}");

    private sealed class ResumeMetadata
    {
        public const int CurrentSchemaVersion = 1;

        public int SchemaVersion { get; init; }

        public string SourceUri { get; init; } = string.Empty;

        public string FinalUri { get; init; } = string.Empty;

        public string ArchiveFileName { get; init; } = string.Empty;

        public string EntityTag { get; init; } = string.Empty;

        public DateTimeOffset? LastModified { get; init; }

        public long? ExpectedTotalBytes { get; init; }
    }
}
