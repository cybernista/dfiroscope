using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services;

public sealed class HashLookupRestProviderFactory : IKnownFileLookupProviderFactory
{
    private readonly Func<HttpMessageHandler>? _handlerFactory;

    public HashLookupRestProviderFactory(Func<HttpMessageHandler>? handlerFactory = null)
    {
        _handlerFactory = handlerFactory;
    }

    public IKnownFileLookupProvider Create(KnownFileLookupSettings settings)
        => new HashLookupRestProvider(settings, _handlerFactory?.Invoke());
}

/// <summary>
/// Read-only adapter for the hashlookup-server REST shape documented by CIRCL.
/// It intentionally performs only GET /lookup/sha256/{hash}; no public fallback,
/// upload, server lifecycle, session tracking, or durable cache is present.
/// </summary>
public sealed class HashLookupRestProvider : IKnownFileLookupProvider
{
    private const int MaxTextLength = 1024;
    private const int MaxFileNamesPerRecord = 16;
    private readonly KnownFileLookupSettings _settings;
    private readonly HttpClient _client;

    public HashLookupRestProvider(
        KnownFileLookupSettings settings,
        HttpMessageHandler? handler = null)
    {
        _settings = KnownFileLookupSettingsService.Normalize(settings);
        _client = handler == null
            ? new HttpClient(new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                UseProxy = false
            })
            : new HttpClient(handler);
        _client.Timeout = Timeout.InfiniteTimeSpan;
    }

    public string ProviderName => "hashlookup-server REST";

    public bool SupportsFilenameSearch => false;

    public async Task<KnownFileLookupResult> LookupSha256Async(
        KnownFileLookupRequest request,
        CancellationToken cancellationToken)
    {
        var startedUtc = DateTime.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        if (!TryNormalizeSha256(request.Sha256, out var sha256))
        {
            return Result(
                KnownFileLookupOutcome.Error,
                startedUtc,
                stopwatch.Elapsed,
                "The selected process does not have a valid 64-character SHA-256 value.");
        }

        if (!KnownFileLookupSettingsService.TryResolveEndpoint(_settings, out var endpoint, out var endpointError))
        {
            return Result(KnownFileLookupOutcome.Error, startedUtc, stopwatch.Elapsed, endpointError);
        }

        if (!KnownFileLookupSettingsService.IsLoopback(endpoint) && !_settings.AllowNonLoopback)
        {
            return Result(
                KnownFileLookupOutcome.Unavailable,
                startedUtc,
                stopwatch.Elapsed,
                "The configured endpoint is not loopback. Enable the explicit non-loopback disclosure mode before lookup.",
                provenance: BuildProvenance(endpoint));
        }

        var requestUri = new Uri(endpoint, $"lookup/sha256/{sha256}");
        using var requestMessage = new HttpRequestMessage(HttpMethod.Get, requestUri);
        requestMessage.Headers.Accept.ParseAdd("application/json");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(_settings.TimeoutSeconds));

        try
        {
            using var response = await _client.SendAsync(
                requestMessage,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token).ConfigureAwait(false);
            var statusCode = (int)response.StatusCode;
            var provenance = BuildProvenance(endpoint);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return Result(
                    KnownFileLookupOutcome.NoMatch,
                    startedUtc,
                    stopwatch.Elapsed,
                    "No exact SHA-256 match was reported. Absence is not evidence of maliciousness.",
                    statusCode,
                    provenance);
            }

            if (!response.IsSuccessStatusCode)
            {
                var outcome = statusCode >= 500 || response.StatusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests
                    ? KnownFileLookupOutcome.Unavailable
                    : KnownFileLookupOutcome.Error;
                return Result(
                    outcome,
                    startedUtc,
                    stopwatch.Elapsed,
                    $"Provider returned HTTP {statusCode} ({response.ReasonPhrase ?? "no reason"}).",
                    statusCode,
                    provenance);
            }

            if (response.Content.Headers.ContentLength > _settings.MaxResponseBytes)
            {
                return Result(
                    KnownFileLookupOutcome.Error,
                    startedUtc,
                    stopwatch.Elapsed,
                    $"Provider response exceeds the {_settings.MaxResponseBytes:N0}-byte limit.",
                    statusCode,
                    provenance);
            }

            var payload = await ReadBoundedAsync(
                await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false),
                _settings.MaxResponseBytes,
                timeout.Token).ConfigureAwait(false);
            stopwatch.Stop();
            NormalizedResponse normalized;
            try
            {
                using var document = JsonDocument.Parse(payload, new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32
                });
                normalized = Normalize(document.RootElement, _settings.MaxRecords);
            }
            catch (JsonException)
            {
                return Result(
                    KnownFileLookupOutcome.Error,
                    startedUtc,
                    stopwatch.Elapsed,
                    "Provider returned malformed or excessively deep JSON.",
                    statusCode,
                    provenance,
                    responseLength: payload.Length);
            }

            if (normalized.Records.Count == 0)
            {
                return Result(
                    KnownFileLookupOutcome.Error,
                    startedUtc,
                    stopwatch.Elapsed,
                    "Provider returned success without a recognizable bounded file or package record.",
                    statusCode,
                    provenance,
                    normalized.ProviderVersion,
                    normalized.CatalogVersion,
                    payload.Length);
            }

            return new KnownFileLookupResult
            {
                Outcome = KnownFileLookupOutcome.Match,
                ProviderName = ProviderName,
                ProviderVersion = normalized.ProviderVersion,
                CatalogVersion = normalized.CatalogVersion,
                ProviderProvenance = provenance,
                StatusDetail = "Known application file; not a known-good verdict.",
                LookupUtc = startedUtc,
                Elapsed = stopwatch.Elapsed,
                HttpStatusCode = statusCode,
                ResponseLength = payload.Length,
                TotalRecordCount = normalized.TotalRecordCount,
                IsTruncated = normalized.IsTruncated,
                Records = normalized.Records
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            return Result(
                KnownFileLookupOutcome.Unavailable,
                startedUtc,
                stopwatch.Elapsed,
                $"Provider request timed out after {_settings.TimeoutSeconds} seconds.",
                provenance: BuildProvenance(endpoint));
        }
        catch (HttpRequestException ex)
        {
            stopwatch.Stop();
            return Result(
                KnownFileLookupOutcome.Unavailable,
                startedUtc,
                stopwatch.Elapsed,
                $"Provider connection failed: {Bound(ex.Message)}",
                provenance: BuildProvenance(endpoint));
        }
        catch (InvalidDataException ex)
        {
            stopwatch.Stop();
            return Result(
                KnownFileLookupOutcome.Error,
                startedUtc,
                stopwatch.Elapsed,
                ex.Message,
                provenance: BuildProvenance(endpoint));
        }
    }

    public void Dispose()
    {
        _client.Dispose();
    }

    private KnownFileLookupResult Result(
        KnownFileLookupOutcome outcome,
        DateTime lookupUtc,
        TimeSpan elapsed,
        string detail,
        int? statusCode = null,
        string provenance = "",
        string providerVersion = "",
        string catalogVersion = "",
        int responseLength = 0) => new()
    {
        Outcome = outcome,
        ProviderName = ProviderName,
        ProviderVersion = providerVersion,
        CatalogVersion = catalogVersion,
        ProviderProvenance = provenance,
        StatusDetail = Bound(detail),
        LookupUtc = lookupUtc,
        Elapsed = elapsed,
        HttpStatusCode = statusCode,
        ResponseLength = responseLength
    };

    private static async Task<byte[]> ReadBoundedAsync(
        Stream stream,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(Math.Min(maxBytes, 64 * 1024));
        var chunk = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return buffer.ToArray();
            }

            if (buffer.Length + read > maxBytes)
            {
                throw new InvalidDataException($"Provider response exceeds the {maxBytes:N0}-byte limit.");
            }

            buffer.Write(chunk, 0, read);
        }
    }

    private static NormalizedResponse Normalize(JsonElement root, int maxRecords)
    {
        var providerVersion = FirstRootString(root, "hashlookup-version", "provider-version", "server-version");
        var catalogVersion = FirstRootString(root, "nsrl-version", "rds-version", "catalog-version", "catalogVersion");
        var declaredTotal = ReadInt(root, "total", "count", "record_count", "match_count", "hashlookup:parent-total");
        var extracted = new List<KnownFilePackageRecord>();

        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in root.EnumerateArray().Take(maxRecords * 4))
            {
                AddEntryRecords(entry, null, null, extracted, maxRecords * 4);
            }
        }
        else if (root.ValueKind == JsonValueKind.Object &&
                 TryGet(root, out var collection, "records", "results", "matches", "items", "data") &&
                 collection.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in collection.EnumerateArray().Take(maxRecords * 4))
            {
                AddEntryRecords(entry, null, null, extracted, maxRecords * 4);
            }
        }
        else if (root.ValueKind == JsonValueKind.Object)
        {
            AddEntryRecords(root, null, null, extracted, maxRecords * 4);
        }

        var rawCount = extracted.Count;
        var ordered = extracted
            .GroupBy(RecordKey, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(record => record.ProductName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => record.ProductVersion, StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => record.Manufacturer, StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => string.Join("|", record.FileNames), StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => record.OperatingSystemName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => record.OperatingSystemVersion, StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => record.Language, StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => record.ApplicationType, StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => record.ProviderSource, StringComparer.OrdinalIgnoreCase)
            .Take(maxRecords)
            .ToList();
        var total = Math.Max(Math.Max(declaredTotal ?? 0, rawCount), ordered.Count);
        return new NormalizedResponse(
            providerVersion,
            catalogVersion,
            total,
            total > ordered.Count || rawCount > maxRecords,
            ordered);
    }

    private static void AddEntryRecords(
        JsonElement entry,
        IReadOnlyList<string>? inheritedFileNames,
        long? inheritedFileSize,
        List<KnownFilePackageRecord> destination,
        int extractionLimit)
    {
        if (entry.ValueKind != JsonValueKind.Object || destination.Count >= extractionLimit)
        {
            return;
        }

        var fileNames = ReadStrings(entry, MaxFileNamesPerRecord, "FileName", "filename", "file_name", "filenames");
        if (fileNames.Count == 0 && inheritedFileNames != null)
        {
            fileNames = inheritedFileNames;
        }

        var fileSize = ReadLong(entry, "FileSize", "file_size", "size") ?? inheritedFileSize;
        var addedProduct = false;
        if (TryGet(entry, out var products, "ProductCode", "product", "products", "package", "packages"))
        {
            if (products.ValueKind == JsonValueKind.Array)
            {
                foreach (var product in products.EnumerateArray().Take(extractionLimit - destination.Count))
                {
                    if (product.ValueKind == JsonValueKind.Object)
                    {
                        destination.Add(BuildRecord(entry, product, fileNames, fileSize));
                        addedProduct = true;
                    }
                }
            }
            else if (products.ValueKind == JsonValueKind.Object)
            {
                destination.Add(BuildRecord(entry, products, fileNames, fileSize));
                addedProduct = true;
            }
        }

        if (!addedProduct && HasRecognizableRecord(entry, fileNames, fileSize))
        {
            destination.Add(BuildRecord(entry, entry, fileNames, fileSize));
        }

        if (destination.Count < extractionLimit &&
            TryGet(entry, out var parents, "parents", "records", "packages") &&
            parents.ValueKind == JsonValueKind.Array)
        {
            foreach (var parent in parents.EnumerateArray().Take(extractionLimit - destination.Count))
            {
                AddEntryRecords(parent, fileNames, fileSize, destination, extractionLimit);
            }
        }
    }

    private static KnownFilePackageRecord BuildRecord(
        JsonElement entry,
        JsonElement product,
        IReadOnlyList<string> fileNames,
        long? fileSize)
    {
        var os = FindObject(product, "OpSystemCode", "OperatingSystem", "OS") ??
                 FindObject(entry, "OpSystemCode", "OperatingSystem", "OS");
        var manufacturer = FirstString(product, "Manufacturer", "ManufacturerName", "MfgName");
        if (string.IsNullOrWhiteSpace(manufacturer))
        {
            var manufacturerCode = FirstString(product, "MfgCode", "ManufacturerCode");
            manufacturer = string.IsNullOrWhiteSpace(manufacturerCode) ? string.Empty : $"Code {manufacturerCode}";
        }

        var sourceParts = new[]
        {
            FirstString(entry, "source", "Source"),
            FirstString(entry, "db", "database", "dataset")
        }.Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase);

        return new KnownFilePackageRecord
        {
            FileNames = fileNames.Select(Bound).Where(value => value.Length > 0).ToList(),
            FileSizeBytes = fileSize,
            ProductName = FirstNonEmpty(
                FirstString(product, "ProductName", "PackageName", "product_name", "package_name"),
                FirstString(entry, "ProductName", "PackageName", "product_name", "package_name")),
            ProductVersion = FirstNonEmpty(
                FirstString(product, "ProductVersion", "PackageVersion", "product_version", "package_version"),
                FirstString(entry, "ProductVersion", "PackageVersion", "product_version", "package_version")),
            Manufacturer = Bound(manufacturer),
            OperatingSystemName = Bound(os.HasValue
                ? FirstString(os.Value, "OpSystemName", "OperatingSystemName", "Name", "name")
                : FirstString(product, "OpSystemName", "OperatingSystemName", "os_name")),
            OperatingSystemVersion = Bound(os.HasValue
                ? FirstString(os.Value, "OpSystemVersion", "OperatingSystemVersion", "Version", "version")
                : FirstString(product, "OpSystemVersion", "OperatingSystemVersion", "os_version")),
            Language = FirstNonEmpty(
                FirstString(product, "Language", "language"),
                FirstString(entry, "Language", "language")),
            ApplicationType = FirstNonEmpty(
                FirstString(product, "ApplicationType", "application_type", "Type"),
                FirstString(entry, "ApplicationType", "application_type")),
            ProviderSource = Bound(string.Join(" / ", sourceParts))
        };
    }

    private static bool HasRecognizableRecord(
        JsonElement entry,
        IReadOnlyList<string> fileNames,
        long? fileSize)
        => fileNames.Count > 0 ||
           fileSize.HasValue ||
           !string.IsNullOrWhiteSpace(FirstString(
               entry,
               "ProductName",
               "PackageName",
               "source",
               "db",
               "SHA-256",
               "sha256"));

    private static string RecordKey(KnownFilePackageRecord record) => string.Join(
        "\u001f",
        string.Join("|", record.FileNames),
        record.FileSizeBytes?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
        record.ProductName,
        record.ProductVersion,
        record.Manufacturer,
        record.OperatingSystemName,
        record.OperatingSystemVersion,
        record.Language,
        record.ApplicationType,
        record.ProviderSource);

    private static JsonElement? FindObject(JsonElement element, params string[] names)
        => TryGet(element, out var value, names) && value.ValueKind == JsonValueKind.Object
            ? value
            : null;

    private static string FirstRootString(JsonElement root, params string[] names)
    {
        var value = FirstString(root, names);
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        if (TryGet(root, out var metadata, "meta", "metadata", "provider") &&
            metadata.ValueKind == JsonValueKind.Object)
        {
            return FirstString(metadata, names);
        }

        return string.Empty;
    }

    private static string FirstString(JsonElement element, params string[] names)
    {
        if (!TryGet(element, out var value, names))
        {
            return string.Empty;
        }

        return Bound(value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => string.Empty
        });
    }

    private static IReadOnlyList<string> ReadStrings(JsonElement element, int maxCount, params string[] names)
    {
        if (!TryGet(element, out var value, names))
        {
            return [];
        }

        if (value.ValueKind == JsonValueKind.String)
        {
            var single = Bound(value.GetString() ?? string.Empty);
            return single.Length == 0 ? [] : [single];
        }

        if (value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return value.EnumerateArray()
            .Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => Bound(item.GetString() ?? string.Empty))
            .Where(item => item.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(item => item, StringComparer.OrdinalIgnoreCase)
            .Take(maxCount)
            .ToList();
    }

    private static long? ReadLong(JsonElement element, params string[] names)
    {
        if (!TryGet(element, out var value, names))
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number))
        {
            return number >= 0 ? number : null;
        }

        return value.ValueKind == JsonValueKind.String &&
               long.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out number) &&
               number >= 0
            ? number
            : null;
    }

    private static int? ReadInt(JsonElement element, params string[] names)
    {
        var value = ReadLong(element, names);
        return value is >= 0 and <= int.MaxValue ? (int)value.Value : null;
    }

    private static bool TryGet(JsonElement element, out JsonElement value, params string[] names)
    {
        value = default;
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (names.Any(name => string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                value = property.Value;
                return true;
            }
        }

        return false;
    }

    private static bool TryNormalizeSha256(string value, out string normalized)
    {
        normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length != 64 || normalized.Any(character => !Uri.IsHexDigit(character)))
        {
            normalized = string.Empty;
            return false;
        }

        normalized = normalized.ToLowerInvariant();
        return true;
    }

    private static string BuildProvenance(Uri endpoint)
        => $"hashlookup-server REST GET at {endpoint.GetLeftPart(UriPartial.Authority)}{endpoint.AbsolutePath}lookup/sha256/<hash>";

    private static string FirstNonEmpty(params string[] values)
        => Bound(values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty);

    private static string Bound(string value)
    {
        var trimmed = value?.Trim() ?? string.Empty;
        return trimmed.Length <= MaxTextLength ? trimmed : trimmed[..MaxTextLength];
    }

    private sealed record NormalizedResponse(
        string ProviderVersion,
        string CatalogVersion,
        int TotalRecordCount,
        bool IsTruncated,
        IReadOnlyList<KnownFilePackageRecord> Records);
}
