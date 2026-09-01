using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services.KnownFiles;

public interface INsrlCatalogPointerWriter
{
    void WriteAtomically(string path, string content);
}

public sealed class NsrlCatalogPointerWriter : INsrlCatalogPointerWriter
{
    public void WriteAtomically(string path, string content)
    {
        var temporary = path + ".tmp";
        var bytes = System.Text.Encoding.UTF8.GetBytes(content);
        using (var stream = new FileStream(
                   temporary,
                   FileMode.Create,
                   FileAccess.Write,
                   FileShare.None,
                   64 * 1024,
                   FileOptions.WriteThrough))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporary, path, overwrite: true);
    }
}

public sealed partial class NsrlCatalogAcquisitionService : INsrlCatalogAcquisitionService, IDisposable
{
    private const string AcquisitionToolVersion = "DFIRoscope.NsrlCatalog/1";
    private const int MaxPointerBytes = 64 * 1024;
    private const int MaxManifestBytes = 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();
    private readonly NsrlCatalogPathService _paths;
    private readonly NsrlCatalogAcquisitionOptions _options;
    private readonly INsrlCatalogStorageProbe _storageProbe;
    private readonly NistNsrlHttpClient _http;
    private readonly bool _disposeHttp;
    private readonly NsrlResumableDownloader _downloader;
    private readonly NsrlArchiveExtractor _extractor;
    private readonly NsrlRdsV3DatabaseValidator _databaseValidator;
    private readonly INsrlCatalogPointerWriter _pointerWriter;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _mutationGate = new(1, 1);
    private readonly ConcurrentDictionary<string, string> _validatedGenerationManifests = new(StringComparer.Ordinal);

    public NsrlCatalogAcquisitionService(NsrlCatalogPathService paths)
        : this(
            paths,
            NistNsrlHttpClient.CreateDefault(),
            new NsrlCatalogAcquisitionOptions(),
            new NsrlCatalogStorageProbe(),
            new NsrlCatalogPointerWriter(),
            TimeProvider.System,
            disposeHttp: true)
    {
    }

    public NsrlCatalogAcquisitionService(
        NsrlCatalogPathService paths,
        NistNsrlHttpClient http,
        NsrlCatalogAcquisitionOptions? options = null,
        INsrlCatalogStorageProbe? storageProbe = null,
        INsrlCatalogPointerWriter? pointerWriter = null,
        TimeProvider? timeProvider = null,
        bool disposeHttp = false)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _options = options ?? new NsrlCatalogAcquisitionOptions();
        _storageProbe = storageProbe ?? new NsrlCatalogStorageProbe();
        _pointerWriter = pointerWriter ?? new NsrlCatalogPointerWriter();
        _timeProvider = timeProvider ?? TimeProvider.System;
        _disposeHttp = disposeHttp;
        ValidateOptions(_options);
        _downloader = new NsrlResumableDownloader(_http, _paths, _options);
        _extractor = new NsrlArchiveExtractor(_options);
        _databaseValidator = new NsrlRdsV3DatabaseValidator();
    }

    public NsrlCatalogPreflight GetPreflight(NsrlCatalogAcquisitionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRelease(request.Release);
        var archiveBytes = request.Release.ArchiveSizeBytes
            ?? throw new InvalidDataException("The selected NIST NSRL release has no bounded archive-size preflight.");
        var required = checked(archiveBytes + request.Release.EstimatedExtractedSizeBytes + _options.DiskReserveBytes);
        var available = _storageProbe.GetAvailableFreeSpace(_paths.Root);
        return new NsrlCatalogPreflight(
            _paths.Root,
            request.Release.ReleaseId,
            request.Release.DataSet,
            request.Release.Profile,
            request.Release.ArchiveUri,
            request.Release.ArchiveSizeBytes,
            request.Release.EstimatedExtractedSizeBytes,
            required,
            available,
            available >= required);
    }

    public async Task<NsrlCatalogAcquisitionResult> AcquireAsync(
        NsrlCatalogAcquisitionRequest request,
        IProgress<NsrlCatalogAcquisitionProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        string? stagingRoot = null;
        try
        {
            NsrlCatalogPreflight preflight;
            try
            {
                preflight = GetPreflight(request);
            }
            catch (Exception ex) when (ex is InvalidDataException or MissingExpectedDigestException)
            {
                return Failure(ClassifyReleaseFailure(ex), "The selected NIST NSRL release descriptor failed closed validation.");
            }

            progress?.Report(new NsrlCatalogAcquisitionProgress(
                NsrlCatalogAcquisitionPhase.Preflight,
                "Validated the explicit destination, release, source, size, and free-space bounds."));
            if (!preflight.HasEnoughFreeSpace)
            {
                return Failure(
                    NsrlCatalogAcquisitionOutcome.InsufficientDiskSpace,
                    "The explicit reference-data volume does not have the bounded free space required for the archive, extraction, and reserve.",
                    preflight: preflight);
            }

            _paths.EnsureWritableLayout();
            NsrlDownloadReceipt receipt;
            try
            {
                receipt = await _downloader.DownloadAsync(
                    request.Release,
                    request.AllowResume,
                    progress,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.Canceled, "The explicit NSRL acquisition was canceled; a validator-bound partial may be resumed later.", preflight: preflight);
            }
            catch (InvalidDataException)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.DownloadFailed, "The NIST NSRL transfer exceeded a configured bound.", preflight: preflight);
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or TimeoutException)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.DownloadFailed, "The bounded NIST NSRL transfer did not complete.", preflight: preflight);
            }

            progress?.Report(new NsrlCatalogAcquisitionProgress(
                NsrlCatalogAcquisitionPhase.ArchiveVerification,
                "Computing the selected NIST-published archive digest.",
                receipt.Length,
                receipt.Length));
            var actualArchiveDigest = await ComputeDigestAsync(
                receipt.PartialPath,
                request.Release.ExpectedArchiveDigest!,
                cancellationToken).ConfigureAwait(false);
            if (!DigestsEqual(request.Release.ExpectedArchiveDigest!, actualArchiveDigest))
            {
                return Failure(
                    NsrlCatalogAcquisitionOutcome.ArchiveHashMismatch,
                    "The downloaded archive does not match the exact NIST-published digest; the current active generation was not changed.",
                    preflight: preflight);
            }

            var generationId = BuildGenerationId(request.Release);
            stagingRoot = _paths.GetStagingGenerationRoot(generationId);
            progress?.Report(new NsrlCatalogAcquisitionProgress(
                NsrlCatalogAcquisitionPhase.Extraction,
                "Inspecting every ZIP entry and extracting only the exact RDSv3 database into contained staging."));
            NsrlArchiveExtractionResult extraction;
            try
            {
                extraction = await _extractor.ExtractDatabaseAsync(
                    receipt.PartialPath,
                    stagingRoot,
                    request.Release.DatabaseFileName,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.Canceled, "The explicit NSRL extraction was canceled; no generation was activated.", preflight: preflight);
            }
            catch (NsrlArchiveSafetyException)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.ArchiveUnsafe, "The archive contains an unsafe path, duplicate target, link, or reparse-point entry.", preflight: preflight);
            }
            catch (NsrlArchiveLimitException)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.ArchiveLimitExceeded, "The archive exceeds its entry, expansion, or uncompressed-byte bound.", preflight: preflight);
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.ArchiveInvalid, "The NIST NSRL archive is corrupt, truncated, or missing the exact expected database.", preflight: preflight);
            }

            progress?.Report(new NsrlCatalogAcquisitionProgress(
                NsrlCatalogAcquisitionPhase.DatabaseIntegrity,
                "Running SQLite integrity and schema validation through a read-only connection."));
            NsrlDatabaseValidationResult databaseValidation;
            NsrlExpectedDigest actualDatabaseDigest;
            try
            {
                using var mutationGuard = new FileStream(
                    extraction.DatabasePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 1,
                    FileOptions.RandomAccess);
                databaseValidation = await _databaseValidator.ValidateAsync(
                        extraction.DatabasePath,
                        request.Release,
                        cancellationToken)
                    .ConfigureAwait(false);
                progress?.Report(new NsrlCatalogAcquisitionProgress(
                    NsrlCatalogAcquisitionPhase.DatabaseVerification,
                    "Computing the NIST-published SQLite dbhash logical content digest.",
                    extraction.DatabaseSizeBytes,
                    extraction.DatabaseSizeBytes));
                actualDatabaseDigest = await ComputeDigestAsync(
                        extraction.DatabasePath,
                        request.Release.ExpectedDatabaseDigest!,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.Canceled, "The explicit NSRL database validation was canceled; no generation was activated.", preflight: preflight);
            }
            catch (NsrlDatabaseSchemaException)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.DatabaseSchemaUnsupported, "The candidate database does not match the explicit supported RDSv3 Modern Minimal schema/version.", preflight: preflight);
            }
            catch (NsrlDatabaseIntegrityException)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.DatabaseIntegrityFailure, "The candidate database failed read-only SQLite integrity validation.", preflight: preflight);
            }
            catch (IOException)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.DatabaseIntegrityFailure, "The candidate database could not be held read-only throughout validation.", preflight: preflight);
            }

            if (!DigestsEqual(request.Release.ExpectedDatabaseDigest!, actualDatabaseDigest))
            {
                return Failure(
                    NsrlCatalogAcquisitionOutcome.DatabaseHashMismatch,
                    "The extracted database content does not match the exact NIST-published SQLite dbhash; no generation was activated.",
                    preflight: preflight);
            }

            progress?.Report(new NsrlCatalogAcquisitionProgress(
                NsrlCatalogAcquisitionPhase.Manifest,
                "Writing the bounded immutable generation manifest after every verification gate passed."));
            NsrlCatalogGeneration generation;
            try
            {
                generation = await PublishGenerationAsync(
                    request.Release,
                    receipt,
                    extraction,
                    actualArchiveDigest,
                    actualDatabaseDigest,
                    databaseValidation,
                    generationId,
                    stagingRoot,
                    cancellationToken).ConfigureAwait(false);
                stagingRoot = null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or JsonException)
            {
                return Failure(NsrlCatalogAcquisitionOutcome.ManifestInvalid, "The verified candidate could not be published as one immutable generation.", preflight: preflight);
            }

            progress?.Report(new NsrlCatalogAcquisitionProgress(
                NsrlCatalogAcquisitionPhase.Activation,
                "Atomically promoting the complete immutable generation while retaining the prior valid generation."));
            try
            {
                await ActivateGenerationAsync(generation, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or JsonException)
            {
                return Failure(
                    NsrlCatalogAcquisitionOutcome.PromotionFailed,
                    "The complete generation could not be atomically activated; the prior active pointer remains authoritative.",
                    generation,
                    preflight);
            }

            DeleteDownloadCandidates(request.Release);
            progress?.Report(new NsrlCatalogAcquisitionProgress(
                NsrlCatalogAcquisitionPhase.Completed,
                "The verified immutable NIST RDSv3 generation is active."));
            return new NsrlCatalogAcquisitionResult(
                NsrlCatalogAcquisitionOutcome.Succeeded,
                "The verified immutable NIST RDSv3 generation was atomically activated. NSRL presence remains reference provenance, not a benign verdict.",
                generation,
                preflight);
        }
        finally
        {
            if (stagingRoot is not null)
            {
                TryDeleteStaging(stagingRoot);
            }

            _mutationGate.Release();
        }
    }

    public async Task<NsrlCatalogGeneration?> GetActiveGenerationAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!File.Exists(_paths.ActivePointerPath))
        {
            return null;
        }

        var pointer = await ReadPointerAsync(_paths.ActivePointerPath, cancellationToken).ConfigureAwait(false);
        return await ReadGenerationAsync(pointer, cancellationToken).ConfigureAwait(false);
    }

    public async Task<NsrlCatalogAcquisitionResult> RollbackAsync(
        string expectedActiveGenerationId,
        CancellationToken cancellationToken = default)
    {
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (string.IsNullOrWhiteSpace(expectedActiveGenerationId) ||
                !File.Exists(_paths.ActivePointerPath) ||
                !File.Exists(_paths.PreviousPointerPath))
            {
                return Failure(NsrlCatalogAcquisitionOutcome.RollbackFailed, "Rollback requires an exact active generation and one retained previous generation.");
            }

            var activePointer = await ReadPointerAsync(_paths.ActivePointerPath, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(activePointer.GenerationId, expectedActiveGenerationId, StringComparison.Ordinal))
            {
                return Failure(NsrlCatalogAcquisitionOutcome.RollbackFailed, "The active generation changed before rollback; no pointer was changed.");
            }

            var previousPointer = await ReadPointerAsync(_paths.PreviousPointerPath, cancellationToken).ConfigureAwait(false);
            var previousGeneration = await ReadGenerationAsync(previousPointer, cancellationToken).ConfigureAwait(false);
            _pointerWriter.WriteAtomically(_paths.PreviousPointerPath, SerializePointer(activePointer));
            _pointerWriter.WriteAtomically(_paths.ActivePointerPath, SerializePointer(previousPointer with
            {
                UpdatedUtc = _timeProvider.GetUtcNow().UtcDateTime
            }));
            return new NsrlCatalogAcquisitionResult(
                NsrlCatalogAcquisitionOutcome.Succeeded,
                "The previous complete verified NSRL generation is active; the displaced generation remains available for rollback.",
                previousGeneration);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or JsonException)
        {
            return Failure(NsrlCatalogAcquisitionOutcome.RollbackFailed, "Rollback failed closed; the existing active pointer remains authoritative.");
        }
        finally
        {
            _mutationGate.Release();
        }
    }

    public void Dispose()
    {
        _mutationGate.Dispose();
        if (_disposeHttp)
        {
            _http.Dispose();
        }
    }

    private async Task<NsrlCatalogGeneration> PublishGenerationAsync(
        NsrlReleaseDescriptor release,
        NsrlDownloadReceipt receipt,
        NsrlArchiveExtractionResult extraction,
        NsrlExpectedDigest actualArchiveDigest,
        NsrlExpectedDigest actualDatabaseDigest,
        NsrlDatabaseValidationResult databaseValidation,
        string generationId,
        string stagingRoot,
        CancellationToken cancellationToken)
    {
        var generationRoot = _paths.GetGenerationRoot(generationId);
        if (Directory.Exists(generationRoot))
        {
            TryDeleteStaging(stagingRoot);
            var pointer = await BuildPointerForExistingGenerationAsync(generationId, cancellationToken).ConfigureAwait(false);
            return await ReadGenerationAsync(pointer, cancellationToken).ConfigureAwait(false);
        }

        var finalDatabasePath = Path.Combine(stagingRoot, release.DatabaseFileName);
        if (!string.Equals(Path.GetFullPath(extraction.DatabasePath), Path.GetFullPath(finalDatabasePath), StringComparison.OrdinalIgnoreCase))
        {
            File.Move(extraction.DatabasePath, finalDatabasePath, overwrite: false);
            DeleteEmptyDirectories(stagingRoot);
        }

        var manifest = new NsrlCatalogGenerationManifest
        {
            GenerationId = generationId,
            ReleaseId = release.ReleaseId,
            ReleaseDateUtc = release.ReleaseDateUtc,
            DataSet = release.DataSet,
            Profile = release.Profile,
            PublicationKind = release.PublicationKind,
            DatabaseRelativePath = release.DatabaseFileName,
            ArchiveSizeBytes = receipt.Length,
            DatabaseSizeBytes = extraction.DatabaseSizeBytes,
            ExpectedArchiveDigest = NormalizeDigest(release.ExpectedArchiveDigest!),
            ActualArchiveDigest = actualArchiveDigest,
            ExpectedDatabaseDigest = NormalizeDigest(release.ExpectedDatabaseDigest!),
            ActualDatabaseDigest = actualDatabaseDigest,
            SourceUris =
            [
                release.ReleasePageUri.AbsoluteUri,
                release.ReadmeUri.AbsoluteUri,
                release.VersionDocumentUri.AbsoluteUri,
                release.DatabaseHashDocumentUri.AbsoluteUri,
                release.ArchiveUri.AbsoluteUri,
                release.ArchiveHashUri.AbsoluteUri
            ],
            RetrievedUtc = _timeProvider.GetUtcNow().UtcDateTime,
            AcquisitionToolVersion = AcquisitionToolVersion,
            Validation = new NsrlCatalogValidationSummary
            {
                ArchiveHashMatched = true,
                DatabaseHashMatched = true,
                IntegrityCheckPassed = databaseValidation.IntegrityCheckPassed,
                SupportedSchema = databaseValidation.SupportedSchema,
                ReleaseIdentityMatched = databaseValidation.ReleaseIdentityMatched,
                DatabaseVersion = databaseValidation.Version,
                BuildSet = databaseValidation.BuildSet
            }
        };

        var manifestPath = Path.Combine(stagingRoot, NsrlCatalogPathService.ManifestFileName);
        var manifestJson = JsonSerializer.Serialize(manifest, JsonOptions);
        File.WriteAllText(manifestPath, manifestJson);
        var manifestSha256 = await ComputeSha256Async(manifestPath, cancellationToken).ConfigureAwait(false);
        File.SetAttributes(finalDatabasePath, File.GetAttributes(finalDatabasePath) | FileAttributes.ReadOnly);
        File.SetAttributes(manifestPath, File.GetAttributes(manifestPath) | FileAttributes.ReadOnly);
        Directory.Move(stagingRoot, generationRoot);
        var generation = new NsrlCatalogGeneration(
            generationId,
            generationRoot,
            Path.Combine(generationRoot, release.DatabaseFileName),
            Path.Combine(generationRoot, NsrlCatalogPathService.ManifestFileName),
            manifestSha256,
            manifest);
        _validatedGenerationManifests[generation.GenerationId] = generation.ManifestSha256;
        await ValidateGenerationAsync(generation, cancellationToken).ConfigureAwait(false);
        return generation;
    }

    private async Task ActivateGenerationAsync(NsrlCatalogGeneration generation, CancellationToken cancellationToken)
    {
        await ValidateGenerationAsync(generation, cancellationToken).ConfigureAwait(false);
        if (File.Exists(_paths.ActivePointerPath))
        {
            var current = await ReadPointerAsync(_paths.ActivePointerPath, cancellationToken).ConfigureAwait(false);
            _ = await ReadGenerationAsync(current, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(current.GenerationId, generation.GenerationId, StringComparison.Ordinal))
            {
                _pointerWriter.WriteAtomically(_paths.PreviousPointerPath, SerializePointer(current));
            }
        }

        var pointer = new CatalogPointer(
            CatalogPointer.CurrentSchemaVersion,
            generation.GenerationId,
            generation.ManifestSha256,
            _timeProvider.GetUtcNow().UtcDateTime);
        _pointerWriter.WriteAtomically(_paths.ActivePointerPath, SerializePointer(pointer));
    }

    private async Task<CatalogPointer> BuildPointerForExistingGenerationAsync(
        string generationId,
        CancellationToken cancellationToken)
    {
        var manifestPath = _paths.GetGenerationManifestPath(generationId);
        var manifestHash = await ComputeSha256Async(manifestPath, cancellationToken).ConfigureAwait(false);
        return new CatalogPointer(
            CatalogPointer.CurrentSchemaVersion,
            generationId,
            manifestHash,
            _timeProvider.GetUtcNow().UtcDateTime);
    }

    private async Task<NsrlCatalogGeneration> ReadGenerationAsync(
        CatalogPointer pointer,
        CancellationToken cancellationToken)
    {
        if (pointer.SchemaVersion != CatalogPointer.CurrentSchemaVersion)
        {
            throw new InvalidDataException("The NSRL active-generation pointer version is unsupported.");
        }

        var generationId = NsrlCatalogPathService.SafeName(pointer.GenerationId);
        var generationRoot = _paths.GetGenerationRoot(generationId);
        var manifestPath = _paths.GetGenerationManifestPath(generationId);
        if (!Directory.Exists(generationRoot) || !File.Exists(manifestPath))
        {
            throw new InvalidDataException("The NSRL active-generation pointer targets an incomplete generation.");
        }

        var manifestHash = await ComputeSha256Async(manifestPath, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(manifestHash, pointer.ManifestSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The NSRL generation manifest does not match the active pointer.");
        }

        var manifest = await ReadBoundedJsonAsync<NsrlCatalogGenerationManifest>(
            manifestPath,
            MaxManifestBytes,
            cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("The NSRL generation manifest is empty.");
        if (manifest.SchemaVersion != NsrlCatalogGenerationManifest.CurrentSchemaVersion ||
            !string.Equals(manifest.GenerationId, generationId, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(manifest.DatabaseRelativePath) ||
            Path.IsPathRooted(manifest.DatabaseRelativePath))
        {
            throw new InvalidDataException("The NSRL generation manifest is incompatible or inconsistent.");
        }

        var databasePath = Path.GetFullPath(Path.Combine(generationRoot, manifest.DatabaseRelativePath));
        var generationPrefix = Path.TrimEndingDirectorySeparator(generationRoot) + Path.DirectorySeparatorChar;
        if (!databasePath.StartsWith(generationPrefix, StringComparison.OrdinalIgnoreCase) || !File.Exists(databasePath))
        {
            throw new InvalidDataException("The NSRL generation manifest references a missing or uncontained database.");
        }

        var generation = new NsrlCatalogGeneration(
            generationId,
            generationRoot,
            databasePath,
            manifestPath,
            manifestHash,
            manifest);
        await ValidateGenerationAsync(generation, cancellationToken).ConfigureAwait(false);
        return generation;
    }

    private async Task ValidateGenerationAsync(
        NsrlCatalogGeneration generation,
        CancellationToken cancellationToken)
    {
        if ((File.GetAttributes(generation.DatabasePath) & FileAttributes.ReadOnly) == 0 ||
            (File.GetAttributes(generation.ManifestPath) & FileAttributes.ReadOnly) == 0)
        {
            throw new InvalidDataException("The NSRL catalog generation files are not marked immutable.");
        }

        if (_validatedGenerationManifests.TryGetValue(generation.GenerationId, out var validatedManifest) &&
            string.Equals(validatedManifest, generation.ManifestSha256, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var actualDatabaseDigest = await ComputeDigestAsync(
            generation.DatabasePath,
            generation.Manifest.ActualDatabaseDigest,
            cancellationToken).ConfigureAwait(false);
        if (!DigestsEqual(generation.Manifest.ActualDatabaseDigest, actualDatabaseDigest))
        {
            throw new InvalidDataException("The immutable NSRL generation database no longer matches its manifest.");
        }

        _validatedGenerationManifests[generation.GenerationId] = generation.ManifestSha256;
    }

    private async Task<CatalogPointer> ReadPointerAsync(string path, CancellationToken cancellationToken)
    {
        CatalogPointer? pointer = null;
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            try
            {
                pointer = await ReadBoundedJsonAsync<CatalogPointer>(path, MaxPointerBytes, cancellationToken).ConfigureAwait(false);
                break;
            }
            catch (IOException) when (attempt < 5)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(10 * attempt), cancellationToken).ConfigureAwait(false);
            }
        }

        if (pointer is null)
        {
            throw new InvalidDataException("The NSRL catalog pointer is empty.");
        }
        if (pointer.SchemaVersion != CatalogPointer.CurrentSchemaVersion ||
            string.IsNullOrWhiteSpace(pointer.GenerationId) ||
            pointer.ManifestSha256.Length != 64 ||
            !pointer.ManifestSha256.All(Uri.IsHexDigit))
        {
            throw new InvalidDataException("The NSRL catalog pointer is malformed or incompatible.");
        }

        return pointer;
    }

    private static async Task<T?> ReadBoundedJsonAsync<T>(
        string path,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (info.Length <= 0 || info.Length > maxBytes)
        {
            throw new InvalidDataException("The NSRL catalog metadata file is empty or oversized.");
        }

        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateRelease(NsrlReleaseDescriptor release)
    {
        ArgumentNullException.ThrowIfNull(release);
        if (release.SchemaVersion != NsrlReleaseDescriptor.CurrentSchemaVersion ||
            !ReleaseIdRegex().IsMatch(release.ReleaseId) ||
            !string.Equals(release.DataSet, "Modern", StringComparison.Ordinal) ||
            !string.Equals(release.Profile, "Minimal", StringComparison.Ordinal) ||
            !string.Equals(release.PublicationKind, "FullSql", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Only the explicit supported full Modern Minimal RDSv3 release contract is accepted.");
        }

        NistNsrlHttpClient.ValidateUri(release.ReleasePageUri, NistNsrlRemoteResourceKind.ReleasePage);
        foreach (var uri in new[]
                 {
                     release.ReadmeUri,
                     release.VersionDocumentUri,
                     release.DatabaseHashDocumentUri,
                     release.ArchiveUri,
                     release.ArchiveHashUri
                 })
        {
            NistNsrlHttpClient.ValidateUri(uri, NistNsrlRemoteResourceKind.Distribution);
        }

        var expectedArchiveName = $"RDS_{release.ReleaseId}_modern_minimal.zip";
        var expectedDatabaseName = $"RDS_{release.ReleaseId}_modern_minimal.db";
        if (!string.Equals(release.ArchiveFileName, expectedArchiveName, StringComparison.Ordinal) ||
            !string.Equals(release.DatabaseFileName, expectedDatabaseName, StringComparison.Ordinal) ||
            !release.ArchiveUri.AbsolutePath.EndsWith("/" + expectedArchiveName, StringComparison.Ordinal) ||
            !string.Equals(release.ArchiveHashUri.AbsoluteUri, release.ArchiveUri.AbsoluteUri + ".sha", StringComparison.Ordinal))
        {
            throw new InvalidDataException("The NIST NSRL release files do not match the exact Modern Minimal naming contract.");
        }

        ValidateDigest(release.ExpectedArchiveDigest, "archive");
        ValidateDigest(release.ExpectedDatabaseDigest, "database");
        if (release.ExpectedArchiveDigest!.Algorithm == NsrlDigestAlgorithm.SqliteDbHashSha1 ||
            release.ExpectedDatabaseDigest!.Algorithm != NsrlDigestAlgorithm.SqliteDbHashSha1)
        {
            throw new InvalidDataException("The NIST archive requires a raw file digest and dbhashes.txt requires SQLite dbhash SHA-1.");
        }

        if (release.ArchiveSizeBytes is null or <= 0 ||
            release.ArchiveSizeBytes > 256L * 1024 * 1024 * 1024 ||
            release.EstimatedExtractedSizeBytes <= 0 ||
            string.IsNullOrWhiteSpace(release.ExtractedSizeEstimateSource))
        {
            throw new InvalidDataException("The NIST NSRL release is missing bounded size preflight data.");
        }
    }

    private static void ValidateDigest(NsrlExpectedDigest? digest, string description)
    {
        if (digest is null || string.IsNullOrWhiteSpace(digest.Value))
        {
            throw new MissingExpectedDigestException($"The NIST {description} expected digest is missing.");
        }

        var expectedLength = digest.Algorithm switch
        {
            NsrlDigestAlgorithm.Sha1 or NsrlDigestAlgorithm.SqliteDbHashSha1 => 40,
            NsrlDigestAlgorithm.Sha256 => 64,
            _ => throw new InvalidDataException($"The NIST {description} digest algorithm is unsupported.")
        };
        if (digest.Value.Length != expectedLength || !digest.Value.All(Uri.IsHexDigit))
        {
            throw new InvalidDataException($"The NIST {description} expected digest is malformed.");
        }
    }

    private static void ValidateOptions(NsrlCatalogAcquisitionOptions options)
    {
        if (options.MaxArchiveBytes <= 0 ||
            options.MaxExtractedBytes <= 0 ||
            options.MaxArchiveEntries <= 0 ||
            options.MaxCompressionRatio < 1 ||
            options.DiskReserveBytes < 0 ||
            options.MaxDownloadAttempts is < 1 or > 5 ||
            options.ReadStallTimeout <= TimeSpan.Zero ||
            options.CopyBufferBytes is < 4096 or > 4 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The NSRL acquisition bounds are invalid.");
        }
    }

    private static NsrlCatalogAcquisitionOutcome ClassifyReleaseFailure(Exception exception)
        => exception is MissingExpectedDigestException
            ? NsrlCatalogAcquisitionOutcome.MissingExpectedHash
            : exception.Message.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) ||
              exception.Message.Contains("approved", StringComparison.OrdinalIgnoreCase)
                ? NsrlCatalogAcquisitionOutcome.UnsafeSource
                : NsrlCatalogAcquisitionOutcome.InvalidRequest;

    private static string BuildGenerationId(NsrlReleaseDescriptor release)
        => NsrlCatalogPathService.SafeName(
            $"rds-{release.ReleaseId}-modern-minimal-{NormalizeDigest(release.ExpectedDatabaseDigest!).Value[..12].ToLowerInvariant()}");

    private static NsrlExpectedDigest NormalizeDigest(NsrlExpectedDigest digest)
        => new(digest.Algorithm, digest.Value.ToUpperInvariant());

    private static async Task<NsrlExpectedDigest> ComputeDigestAsync(
        string path,
        NsrlExpectedDigest expected,
        CancellationToken cancellationToken)
    {
        if (expected.Algorithm == NsrlDigestAlgorithm.SqliteDbHashSha1)
        {
            var dbHash = await NsrlSqliteDbHash.ComputeAsync(path, cancellationToken).ConfigureAwait(false);
            return new NsrlExpectedDigest(expected.Algorithm, dbHash);
        }

        using HashAlgorithm algorithm = expected.Algorithm switch
        {
            NsrlDigestAlgorithm.Sha1 => SHA1.Create(),
            NsrlDigestAlgorithm.Sha256 => SHA256.Create(),
            _ => throw new InvalidDataException("The NIST digest algorithm is unsupported.")
        };
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var hash = await algorithm.ComputeHashAsync(stream, cancellationToken).ConfigureAwait(false);
        return new NsrlExpectedDigest(expected.Algorithm, Convert.ToHexString(hash));
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        var digest = await ComputeDigestAsync(
            path,
            new NsrlExpectedDigest(NsrlDigestAlgorithm.Sha256, new string('0', 64)),
            cancellationToken).ConfigureAwait(false);
        return digest.Value;
    }

    private static bool DigestsEqual(NsrlExpectedDigest left, NsrlExpectedDigest right)
        => left.Algorithm == right.Algorithm &&
           CryptographicOperations.FixedTimeEquals(
               Convert.FromHexString(left.Value),
               Convert.FromHexString(right.Value));

    private void DeleteDownloadCandidates(NsrlReleaseDescriptor release)
    {
        var releaseKey = NsrlCatalogPathService.SafeName($"rds-{release.ReleaseId}-{release.DataSet}-{release.Profile}");
        foreach (var path in new[]
                 {
                     _paths.GetPartialArchivePath(releaseKey),
                     _paths.GetResumeMetadataPath(releaseKey)
                 })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private static void DeleteEmptyDirectories(string root)
    {
        foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                     .OrderByDescending(path => path.Length))
        {
            if (!Directory.EnumerateFileSystemEntries(directory).Any())
            {
                Directory.Delete(directory);
            }
        }
    }

    private static void TryDeleteStaging(string stagingRoot)
    {
        try
        {
            if (!Directory.Exists(stagingRoot))
            {
                return;
            }

            foreach (var file in Directory.EnumerateFiles(stagingRoot, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(file, FileAttributes.Normal);
            }

            Directory.Delete(stagingRoot, recursive: true);
        }
        catch
        {
            // The bounded contained staging root remains recoverable; never touch a completed generation here.
        }
    }

    private static string SerializePointer(CatalogPointer pointer)
        => JsonSerializer.Serialize(pointer, JsonOptions);

    private static NsrlCatalogAcquisitionResult Failure(
        NsrlCatalogAcquisitionOutcome outcome,
        string detail,
        NsrlCatalogGeneration? generation = null,
        NsrlCatalogPreflight? preflight = null)
        => new(outcome, detail, generation, preflight);

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            MaxDepth = 32
        };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    [GeneratedRegex("^20\\d{2}\\.\\d{2}\\.\\d+$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex ReleaseIdRegex();

    private sealed record CatalogPointer(
        int SchemaVersion,
        string GenerationId,
        string ManifestSha256,
        DateTime UpdatedUtc)
    {
        public const int CurrentSchemaVersion = 1;
    }

    private sealed class MissingExpectedDigestException : Exception
    {
        public MissingExpectedDigestException(string message)
            : base(message)
        {
        }
    }
}
